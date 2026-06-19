# SPDX-License-Identifier: Apache-2.0
"""Real Ed25519 ``did:key`` identity for Nanda Town (NEST).

NEST's reference identity plugin (``did_key.py``) is a *toy*: its docstring
says "not production cryptography; for real deployments, swap to a proper
Ed25519 implementation." This module is that swap. It implements the
``nest_core.layers.identity.Identity`` ``Protocol`` with real Ed25519
(RFC 8032) signing via the published ``sm-arp`` library.

Determinism — the property that lets NEST replay a trace byte-for-byte — is
preserved for two independent reasons:

* Each agent's keypair derives **deterministically** from its ``AgentId``
  (``Identity.from_seed(sha256(str(agent_id))[:32])``), so the same agent
  always holds the same key across runs.
* Ed25519 signing is itself deterministic (RFC 8032 §5.1.6 derives the per
  message nonce from the key and message, with no randomness), so signing the
  same payload with the same key always yields the same 64 signature bytes.

Signatures use ``algorithm="ed25519"`` and carry the raw 64-byte Ed25519
signature in ``Signature.value`` — no envelope, unlike the sibling rotating
identity plugin (which packs a key id + tick for as-of verification). This
plugin is the simple, non-rotating real-crypto baseline.

Registered under ``("identity", "ed25519_didkey")`` via entry points.

Example::

    ident = Ed25519DidKeyIdentity(AgentId("a1"))
    sig = ident.sign(b"payload")
    ok = ident.verify(b"payload", sig, AgentId("a1"))
    did = ident.did_of(AgentId("a1"))  # did:key:z6Mk...
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from nest_core.types import AgentId, AgentIdentity, Signature
from sm_arp.identity import Identity as ArpIdentity
from sm_arp.identity import pubkey_from_did

ALGORITHM = "ed25519"


def seed_for(agent_id: AgentId) -> bytes:
    """Deterministically derive an agent's 32-byte Ed25519 seed from its id.

    This is the single source of truth for AgentId -> key material; the trust
    plugin reuses it so a receipt's ``principal_did`` byte-matches the identity
    this plugin would mint for the same agent.

    Example::

        seed = seed_for(AgentId("a1"))
    """
    return hashlib.sha256(str(agent_id).encode()).digest()[:32]


def did_for(agent_id: AgentId) -> str:
    """Return the ``did:key`` an agent's deterministic Ed25519 key resolves to.

    Example::

        did = did_for(AgentId("a1"))  # did:key:z6Mk...
    """
    return ArpIdentity.from_seed(seed_for(agent_id)).did


def _raw_public_key(seed: bytes) -> bytes:
    """Raw 32-byte Ed25519 public key for a seed."""
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


class Ed25519DidKeyIdentity:
    """Real Ed25519 ``did:key`` identity implementing the NEST ``Identity`` Protocol.

    The owning agent's keypair is derived from its :class:`AgentId`; peers'
    public keys are learned through :meth:`register_peer` (or recovered from a
    ``did:key`` they present). Verification needs only public keys, so a peer's
    signature verifies once its ``did:key`` is known.

    Example::

        ident = Ed25519DidKeyIdentity(AgentId("a1"))
        sig = ident.sign(b"hello")
    """

    def __init__(self, agent_id: AgentId, seed: bytes | None = None) -> None:
        self._agent_id = agent_id
        # `seed` override exists only for tests that want an explicit key; the
        # default is the deterministic per-agent seed used everywhere else.
        self._seed = seed_for(agent_id) if seed is None else seed
        self._arp = ArpIdentity.from_seed(self._seed)
        self._public_key = _raw_public_key(self._seed)
        # AgentId -> raw 32-byte public key, for verifying peers.
        self._known_keys: dict[AgentId, bytes] = {agent_id: self._public_key}

    @property
    def public_key(self) -> bytes:
        """This agent's raw 32-byte Ed25519 public key.

        Example::

            pk = ident.public_key
        """
        return self._public_key

    @property
    def did(self) -> str:
        """This agent's ``did:key`` string.

        Example::

            did = ident.did
        """
        return self._arp.did

    def did_of(self, agent: AgentId) -> str:
        """Return the ``did:key`` for any agent (deterministic from its id).

        Used by the trust plugin to map a NEST ``AgentId`` to the ``principal_did``
        carried inside ARP receipts.

        Example::

            did = ident.did_of(AgentId("a2"))
        """
        return did_for(agent)

    def register_peer(
        self,
        agent_id: AgentId,
        public_key: bytes,
        private_key: bytes | None = None,
    ) -> None:
        """Register a peer's raw 32-byte public key for verification.

        Mirrors the reference plugin's signature. ``private_key`` is rejected:
        an identity never holds a peer's private key.

        Example::

            ident.register_peer(AgentId("a2"), peer_pk)
        """
        if private_key is not None:
            msg = "register_peer accepts public keys only"
            raise ValueError(msg)
        if len(public_key) != 32:
            msg = f"Ed25519 public key must be 32 bytes, got {len(public_key)}"
            raise ValueError(msg)
        self._known_keys[agent_id] = public_key

    def register_peer_did(self, agent_id: AgentId, did: str) -> None:
        """Register a peer from its ``did:key`` (recovers the raw public key).

        Example::

            ident.register_peer_did(AgentId("a2"), "did:key:z6Mk...")
        """
        pub = pubkey_from_did(did).public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._known_keys[agent_id] = pub

    def sign(self, payload: bytes) -> Signature:
        """Sign a payload with this agent's Ed25519 private key.

        Example::

            sig = ident.sign(b"data")
        """
        raw = self._arp.sign(payload)
        return Signature(signer=self._agent_id, value=raw, algorithm=ALGORITHM)

    def verify(self, payload: bytes, sig: Signature, agent: AgentId) -> bool:
        """Verify an Ed25519 signature from a given agent.

        Returns ``False`` (never raises) on signer mismatch, unknown agent, or
        an invalid signature.

        Example::

            ok = ident.verify(b"data", sig, AgentId("a1"))
        """
        if sig.signer != agent:
            return False
        public_key = self._known_keys.get(agent)
        if public_key is None:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(sig.value, payload)
        except InvalidSignature:
            return False
        return True

    async def resolve(self, agent: AgentId) -> AgentIdentity:
        """Resolve an agent id to its ``did:key`` identity record.

        Falls back to the agent's deterministic key when the agent is unknown,
        so resolution is total (every ``AgentId`` has a derivable did:key).

        Example::

            info = await ident.resolve(AgentId("a2"))
        """
        public_key = self._known_keys.get(agent)
        if public_key is None:
            public_key = _raw_public_key(seed_for(agent))
        return AgentIdentity(
            agent_id=agent,
            public_key=public_key,
            method="did:key",
            metadata={"did": did_for(agent)},
        )
