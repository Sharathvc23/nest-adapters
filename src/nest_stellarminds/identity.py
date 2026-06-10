# SPDX-License-Identifier: Apache-2.0
"""Ed25519 rotating identity adapter (Nanda Town problem 5).

Real Ed25519 signing with key rotation and *historical* (as-of) verification.
A signature carries the id of the key that made it and the logical tick it was
made at (packed into ``Signature.value`` by :mod:`nest_stellarminds.determinism`).
Verification is parameterised by an ``as_of`` time so a signature from a key
that has since rotated out still verifies when audited within that key's
validity window, but is rejected for observations after rotation.

This implements the ``nest_core.layers.identity.Identity`` ``Protocol`` and is
registered under ``("identity", "sm_ed25519_rotating")`` via entry points.

Example::

    ident = Ed25519RotatingIdentity(AgentId("a1"), seed=b"seed")
    sig = ident.sign(b"hello")
    ok = ident.verify(b"hello", sig, AgentId("a1"))
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from nest_core.types import AgentId, AgentIdentity, Signature

from nest_stellarminds.determinism import (
    KeyId,
    decode_signature_value,
    derive_signing_key,
    did_key,
    encode_signature_value,
    key_id_for,
    public_bytes,
    signing_bytes,
)

ALGORITHM = "ed25519-rotating/0.1"
_INF = float("inf")


@dataclass
class _KeyRecord:
    """One key in an agent's history, with its validity window ``[issued, rotated_out)``."""

    key_id: KeyId
    public_key: bytes
    issued_at: float
    rotated_out: float = _INF
    private_key: Ed25519PrivateKey | None = None


class Ed25519RotatingIdentity:
    """Per-agent Ed25519 identity with rotation and as-of verification.

    Example::

        ident = Ed25519RotatingIdentity(AgentId("a1"), seed=b"seed")
        sig = ident.sign(b"data")
    """

    def __init__(self, agent_id: AgentId, seed: bytes = b"") -> None:
        self._agent_id = agent_id
        self._seed = seed
        self._rotation_count = 0
        self._clock = 0.0
        self._last_rotation: dict[str, object] | None = None
        key = derive_signing_key(seed, agent_id, 0)
        pub = public_bytes(key.public_key())
        record = _KeyRecord(key_id_for(pub), pub, issued_at=0.0, private_key=key)
        self._records: dict[AgentId, list[_KeyRecord]] = {agent_id: [record]}

    # -- clock -------------------------------------------------------------

    def advance_to(self, tick: float) -> None:
        """Set this identity's view of logical time (driven by the agent's ``ctx.time``).

        Example::

            ident.advance_to(ctx.time)
        """
        self._clock = tick

    # -- own key state -----------------------------------------------------

    @property
    def current_key_id(self) -> KeyId:
        """Key id of the agent's currently active key.

        Example::

            kid = ident.current_key_id
        """
        return self._active_record(self._agent_id).key_id

    @property
    def public_key(self) -> bytes:
        """Raw 32-byte public key of the agent's currently active key.

        Example::

            pk = ident.public_key
        """
        return self._active_record(self._agent_id).public_key

    def _active_record(self, agent: AgentId) -> _KeyRecord:
        for record in self._records[agent]:
            if record.rotated_out == _INF:
                return record
        return self._records[agent][-1]

    # -- signing -----------------------------------------------------------

    def sign(self, payload: bytes, at_tick: float | None = None) -> Signature:
        """Sign a payload with the agent's active key.

        ``at_tick`` is the logical tick the signature asserts; honest callers
        omit it (it defaults to the current clock). Verification independently
        checks that assertion against key windows, so a dishonest tick does not
        help an attacker.

        Example::

            sig = ident.sign(b"data")
        """
        record = self._active_record(self._agent_id)
        if record.private_key is None:  # pragma: no cover - own keys always private
            msg = "Cannot sign without a private key"
            raise ValueError(msg)
        tick = self._clock if at_tick is None else at_tick
        raw = record.private_key.sign(signing_bytes(payload, record.key_id, tick))
        value = encode_signature_value(record.key_id, tick, raw)
        return Signature(signer=self._agent_id, value=value, algorithm=ALGORITHM)

    # -- rotation ----------------------------------------------------------

    def rotate_key(self) -> KeyId:
        """Rotate to a fresh key, closing the current key's window at ``now``.

        The new public key is signed by the *old* key (continuity), so peers
        can prove the new key descends from the one they already trust.

        Example::

            new_kid = ident.rotate_key()
        """
        old = self._active_record(self._agent_id)
        if old.private_key is None:  # pragma: no cover - own keys always private
            msg = "Cannot rotate without the current private key"
            raise ValueError(msg)
        old.rotated_out = self._clock
        self._rotation_count += 1
        new_key = derive_signing_key(self._seed, self._agent_id, self._rotation_count)
        new_pub = public_bytes(new_key.public_key())
        new_kid = key_id_for(new_pub)
        continuity = old.private_key.sign(new_pub)
        self._records[self._agent_id].append(
            _KeyRecord(new_kid, new_pub, issued_at=self._clock, private_key=new_key)
        )
        self._last_rotation = {
            "agent": str(self._agent_id),
            "prev_kid": old.key_id,
            "new_kid": new_kid,
            "new_pub": new_pub.hex(),
            "issued_at": self._clock,
            "continuity": continuity.hex(),
        }
        return new_kid

    def rotation_announcement(self) -> bytes:
        """Serialise the most recent rotation for broadcast to peers.

        Example::

            await ctx.broadcast(ident.rotation_announcement())
        """
        if self._last_rotation is None:
            msg = "No rotation has occurred yet"
            raise ValueError(msg)
        return json.dumps(self._last_rotation, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )

    def observe_rotation(self, announcement: bytes) -> None:
        """Learn a peer's rotation, verifying continuity against its prior key.

        Raises ``ValueError`` if continuity cannot be established (unknown prior
        key, or a continuity signature not made by that key).

        Example::

            ident.observe_rotation(payload)
        """
        data = json.loads(announcement.decode("ascii"))
        agent = AgentId(str(data["agent"]))
        prev_kid = str(data["prev_kid"])
        new_pub = bytes.fromhex(str(data["new_pub"]))
        issued_at = float(data["issued_at"])
        continuity = bytes.fromhex(str(data["continuity"]))

        prev = self._find_record(agent, KeyId(prev_kid))
        if prev is None:
            msg = "cannot verify rotation continuity: unknown prior key"
            raise ValueError(msg)
        try:
            Ed25519PublicKey.from_public_bytes(prev.public_key).verify(continuity, new_pub)
        except InvalidSignature as exc:
            msg = "rotation continuity signature is invalid"
            raise ValueError(msg) from exc

        prev.rotated_out = issued_at
        self._records.setdefault(agent, []).append(
            _KeyRecord(key_id_for(new_pub), new_pub, issued_at=issued_at)
        )

    # -- peer registration & verification ---------------------------------

    def register_peer(
        self, agent_id: AgentId, public_key: bytes, private_key: bytes | None = None
    ) -> None:
        """Register a peer's initial public key (validity window opens at tick 0).

        Example::

            ident.register_peer(AgentId("a2"), peer_pk)
        """
        if private_key is not None:
            msg = "register_peer accepts public keys only"
            raise ValueError(msg)
        self._records[agent_id] = [_KeyRecord(key_id_for(public_key), public_key, issued_at=0.0)]

    def _find_record(self, agent: AgentId, key_id: KeyId) -> _KeyRecord | None:
        for record in self._records.get(agent, []):
            if record.key_id == key_id:
                return record
        return None

    def verify(self, payload: bytes, sig: Signature, agent: AgentId) -> bool:
        """Verify a signature as-of the current clock (lenient default).

        Example::

            ok = ident.verify(b"data", sig, AgentId("a1"))
        """
        return self.verify_as_of(payload, sig, agent, as_of=self._clock)

    def verify_as_of(self, payload: bytes, sig: Signature, agent: AgentId, as_of: float) -> bool:
        """Verify a signature as-of a specific logical time.

        Returns ``True`` only if all three hold: the Ed25519 signature is valid,
        the *claimed signing tick* falls in the signing key's window (check A,
        kills backdating), and ``as_of`` falls in that same window (check B,
        kills post-rotation forgery). The two window checks are independent;
        dropping either lets exactly one attack through.

        Note: check B assumes honest verification happens within the signing
        key's window. Under the default zero-latency transport (send tick ==
        receive tick) that always holds; a latency transport delivering an
        honest message across a rotation boundary would be a known edge case.

        Example::

            ok = ident.verify_as_of(b"data", sig, AgentId("a1"), as_of=5.0)
        """
        if sig.signer != agent:
            return False
        try:
            kid, claimed_tick, raw = decode_signature_value(sig.value)
        except ValueError:
            return False
        record = self._find_record(agent, kid)
        if record is None:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(record.public_key).verify(
                raw, signing_bytes(payload, kid, claimed_tick)
            )
        except InvalidSignature:
            return False
        if not (record.issued_at <= claimed_tick < record.rotated_out):  # check A
            return False
        return record.issued_at <= as_of < record.rotated_out  # check B

    async def resolve(self, agent: AgentId) -> AgentIdentity:
        """Resolve an agent to its current did:key identity record.

        Example::

            info = await ident.resolve(AgentId("a1"))
        """
        record = self._active_record(agent)
        return AgentIdentity(
            agent_id=agent,
            public_key=record.public_key,
            method="did:key",
            metadata={"did": did_key(record.public_key), "key_id": record.key_id},
        )
