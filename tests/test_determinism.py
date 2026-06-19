# SPDX-License-Identifier: Apache-2.0
"""Tests for the deterministic crypto + signature-envelope primitives.

These primitives are the foundation both the honest identity adapter and any
adversarial (compromised-key) model compose. They must be byte-deterministic:
Nanda Town's seed-bank check replays a scenario under several seeds and demands
byte-identical traces, so no key material may come from ``os.urandom``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from nest_core.types import AgentId

from nest_adapters.determinism import (
    decode_signature_value,
    derive_signing_key,
    did_key,
    encode_signature_value,
    key_id_for,
    public_bytes,
    signing_bytes,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_derive_signing_key_is_deterministic() -> None:
    a = derive_signing_key(b"seed", AgentId("agent-1"), 0)
    b = derive_signing_key(b"seed", AgentId("agent-1"), 0)
    assert public_bytes(a.public_key()) == public_bytes(b.public_key())


def test_rotation_count_changes_the_key() -> None:
    v0 = derive_signing_key(b"seed", AgentId("agent-1"), 0)
    v1 = derive_signing_key(b"seed", AgentId("agent-1"), 1)
    assert public_bytes(v0.public_key()) != public_bytes(v1.public_key())


def test_agent_id_changes_the_key() -> None:
    a = derive_signing_key(b"seed", AgentId("agent-1"), 0)
    b = derive_signing_key(b"seed", AgentId("agent-2"), 0)
    assert public_bytes(a.public_key()) != public_bytes(b.public_key())


def test_key_id_is_stable_and_short() -> None:
    key = derive_signing_key(b"seed", AgentId("agent-1"), 0)
    pub = public_bytes(key.public_key())
    kid = key_id_for(pub)
    assert kid == key_id_for(pub)
    assert len(kid) == 16


def test_signing_bytes_binds_kid_and_tick() -> None:
    base = signing_bytes(b"hello", "kid-a", 0.0)
    assert base == signing_bytes(b"hello", "kid-a", 0.0)
    assert base != signing_bytes(b"hello", "kid-b", 0.0)  # kid bound
    assert base != signing_bytes(b"hello", "kid-a", 1.0)  # tick bound
    assert base != signing_bytes(b"world", "kid-a", 0.0)  # payload bound


def test_signature_value_roundtrips() -> None:
    raw = b"\x01\x02\x03\x04"
    value = encode_signature_value("kid-a", 12.5, raw)
    kid, tick, sig = decode_signature_value(value)
    assert (kid, tick, sig) == ("kid-a", 12.5, raw)


def test_did_key_is_ed25519_multicodec_and_reversible() -> None:
    key = derive_signing_key(b"seed", AgentId("agent-1"), 0)
    pub = public_bytes(key.public_key())
    did = did_key(pub)
    assert did.startswith("did:key:z")
    # round-trips back to the same raw public key
    from nest_adapters.determinism import public_key_from_did

    assert public_key_from_did(did) == pub


def test_real_ed25519_signature_verifies() -> None:
    # Proves we use real Ed25519, not a simulation.
    key: Ed25519PrivateKey = derive_signing_key(b"seed", AgentId("agent-1"), 0)
    msg = signing_bytes(b"payload", "kid-a", 3.0)
    sig = key.sign(msg)
    key.public_key().verify(sig, msg)  # raises on failure
