# SPDX-License-Identifier: Apache-2.0
"""Deterministic Ed25519 + signature-envelope primitives.

Every byte of key material here derives from a seed via
``Ed25519PrivateKey.from_private_bytes`` — never ``generate()`` — so a scenario
replays byte-identically under a fixed seed, which is what Nanda Town's
seed-bank check enforces. The signature *envelope* (key id + signing tick +
raw signature) is packed into ``Signature.value`` as inspectable JSON so it
round-trips through a JSONL trace.

Example::

    key = derive_signing_key(b"seed", AgentId("a1"), 0)
    value = encode_signature_value(key_id_for(public_bytes(key.public_key())), 0.0, b"sig")
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, NewType

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

if TYPE_CHECKING:
    from nest_core.types import AgentId

KeyId = NewType("KeyId", str)
"""Short stable identifier for a public key (16 hex chars of its SHA-256).

Example::

    kid = key_id_for(pub)
"""

# Multicodec prefix for an Ed25519 public key (varint 0xed01), per the did:key
# specification. Prepended to the 32-byte raw key before base58btc encoding.
_ED25519_MULTICODEC = b"\xed\x01"
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_FIELD_SEP = b"\x1f"


def derive_signing_key(seed: bytes, agent_id: AgentId, rotation_count: int) -> Ed25519PrivateKey:
    """Derive an Ed25519 private key deterministically from a seed.

    The same ``(seed, agent_id, rotation_count)`` always yields the same key;
    bumping ``rotation_count`` produces the agent's next key.

    Example::

        key = derive_signing_key(b"seed", AgentId("a1"), 0)
    """
    material = b"%s:%s:%d" % (seed, str(agent_id).encode(), rotation_count)
    digest = hashlib.sha256(material).digest()
    return Ed25519PrivateKey.from_private_bytes(digest)


def public_bytes(public_key: Ed25519PublicKey) -> bytes:
    """Return the raw 32-byte Ed25519 public key.

    Example::

        pub = public_bytes(key.public_key())
    """
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def key_id_for(pub: bytes) -> KeyId:
    """Compute the stable :data:`KeyId` for a raw public key.

    Example::

        kid = key_id_for(pub)
    """
    return KeyId(hashlib.sha256(pub).hexdigest()[:16])


def signing_bytes(payload: bytes, kid: str, tick: float) -> bytes:
    """Build the canonical bytes that get signed, binding payload, kid, and tick.

    Binding ``kid`` and ``tick`` under the signature makes them tamper-evident:
    a verifier reconstructs these exact bytes, so an attacker cannot relabel a
    signature with a different key id or signing time.

    Example::

        msg = signing_bytes(b"hello", "ab12", 0.0)
    """
    return payload + _FIELD_SEP + kid.encode("ascii") + _FIELD_SEP + repr(tick).encode("ascii")


def encode_signature_value(kid: str, tick: float, raw_sig: bytes) -> bytes:
    """Pack ``(kid, tick, raw_sig)`` into inspectable JSON for ``Signature.value``.

    Example::

        value = encode_signature_value("ab12", 0.0, b"\\x00")
    """
    obj = {"kid": kid, "t": tick, "sig": raw_sig.hex()}
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")


def decode_signature_value(value: bytes) -> tuple[KeyId, float, bytes]:
    """Unpack a ``Signature.value`` produced by :func:`encode_signature_value`.

    Raises ``ValueError`` on a malformed or non-rotating envelope.

    Example::

        kid, tick, raw = decode_signature_value(value)
    """
    try:
        obj = json.loads(value.decode("ascii"))
        return KeyId(str(obj["kid"])), float(obj["t"]), bytes.fromhex(str(obj["sig"]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        msg = "Not a rotating-identity signature envelope"
        raise ValueError(msg) from exc


def did_key(pub: bytes) -> str:
    """Encode a raw Ed25519 public key as a ``did:key`` string.

    Format is ``did:key:z<base58btc(0xed01 ‖ pub)>`` — byte-compatible with the
    ``sm-arp`` / chapter-protocol did:key encoding.

    Example::

        did = did_key(pub)
    """
    return "did:key:z" + _b58encode(_ED25519_MULTICODEC + pub)


def public_key_from_did(did: str) -> bytes:
    """Recover the raw 32-byte public key from a ``did:key`` string.

    Example::

        pub = public_key_from_did("did:key:z6Mk...")
    """
    prefix = "did:key:z"
    if not did.startswith(prefix):
        msg = f"Not a did:key value: {did!r}"
        raise ValueError(msg)
    decoded = _b58decode(did[len(prefix) :])
    if not decoded.startswith(_ED25519_MULTICODEC):
        msg = "did:key is not an Ed25519 key"
        raise ValueError(msg)
    return decoded[len(_ED25519_MULTICODEC) :]


def _b58encode(data: bytes) -> str:
    """Base58btc-encode bytes (Bitcoin alphabet), preserving leading zeros."""
    n = int.from_bytes(data, "big")
    chars: list[str] = []
    while n > 0:
        n, rem = divmod(n, 58)
        chars.append(_BASE58_ALPHABET[rem])
    pad = len(data) - len(data.lstrip(b"\x00"))
    return _BASE58_ALPHABET[0] * pad + "".join(reversed(chars))


def _b58decode(text: str) -> bytes:
    """Inverse of :func:`_b58encode`."""
    n = 0
    for char in text:
        idx = _BASE58_ALPHABET.find(char)
        if idx == -1:
            msg = f"Invalid base58 character: {char!r}"
            raise ValueError(msg)
        n = n * 58 + idx
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    pad = len(text) - len(text.lstrip(_BASE58_ALPHABET[0]))
    return b"\x00" * pad + body
