# SPDX-License-Identifier: Apache-2.0
"""Tests for Ed25519DidKeyIdentity — the real-crypto did:key identity plugin."""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, Signature

from nest_stellarminds.identity_didkey import (
    ALGORITHM,
    Ed25519DidKeyIdentity,
    did_for,
    seed_for,
)


def test_sign_verify_roundtrip() -> None:
    ident = Ed25519DidKeyIdentity(AgentId("a1"))
    sig = ident.sign(b"hello world")
    assert sig.algorithm == ALGORITHM
    assert sig.signer == AgentId("a1")
    assert len(sig.value) == 64  # raw Ed25519 signature
    assert ident.verify(b"hello world", sig, AgentId("a1")) is True


def test_verify_rejects_tampered_payload() -> None:
    ident = Ed25519DidKeyIdentity(AgentId("a1"))
    sig = ident.sign(b"hello")
    assert ident.verify(b"goodbye", sig, AgentId("a1")) is False


def test_verify_rejects_signer_mismatch() -> None:
    ident = Ed25519DidKeyIdentity(AgentId("a1"))
    sig = ident.sign(b"hello")
    # Same bytes but claim a different agent: signer field guards this.
    assert ident.verify(b"hello", sig, AgentId("a2")) is False


def test_deterministic_keys_same_agent_same_did() -> None:
    a = Ed25519DidKeyIdentity(AgentId("a1"))
    b = Ed25519DidKeyIdentity(AgentId("a1"))
    assert a.public_key == b.public_key
    assert a.did == b.did
    assert a.did == did_for(AgentId("a1"))


def test_deterministic_signing_is_byte_identical() -> None:
    # Ed25519 (RFC 8032) is deterministic: same key + payload -> same 64 bytes.
    a = Ed25519DidKeyIdentity(AgentId("a1"))
    b = Ed25519DidKeyIdentity(AgentId("a1"))
    assert a.sign(b"replay me").value == b.sign(b"replay me").value


def test_distinct_agents_get_distinct_keys() -> None:
    a = Ed25519DidKeyIdentity(AgentId("a1"))
    b = Ed25519DidKeyIdentity(AgentId("a2"))
    assert a.public_key != b.public_key
    assert a.did != b.did


def test_cross_agent_verify_via_register_peer() -> None:
    a = Ed25519DidKeyIdentity(AgentId("a1"))
    b = Ed25519DidKeyIdentity(AgentId("a2"))
    sig = b.sign(b"from b")
    # a does not know b yet.
    assert a.verify(b"from b", sig, AgentId("a2")) is False
    a.register_peer(AgentId("a2"), b.public_key)
    assert a.verify(b"from b", sig, AgentId("a2")) is True


def test_register_peer_via_did() -> None:
    a = Ed25519DidKeyIdentity(AgentId("a1"))
    b = Ed25519DidKeyIdentity(AgentId("a2"))
    a.register_peer_did(AgentId("a2"), b.did)
    sig = b.sign(b"payload")
    assert a.verify(b"payload", sig, AgentId("a2")) is True


def test_register_peer_rejects_private_key() -> None:
    ident = Ed25519DidKeyIdentity(AgentId("a1"))
    with pytest.raises(ValueError, match="public keys only"):
        ident.register_peer(AgentId("a2"), b"\x00" * 32, private_key=b"\x01" * 32)


def test_register_peer_rejects_wrong_length() -> None:
    ident = Ed25519DidKeyIdentity(AgentId("a1"))
    with pytest.raises(ValueError, match="32 bytes"):
        ident.register_peer(AgentId("a2"), b"\x00" * 16)


def test_verify_unknown_agent_returns_false() -> None:
    ident = Ed25519DidKeyIdentity(AgentId("a1"))
    forged = Signature(signer=AgentId("a9"), value=b"\x00" * 64, algorithm=ALGORITHM)
    assert ident.verify(b"x", forged, AgentId("a9")) is False


@pytest.mark.asyncio
async def test_resolve_known_agent() -> None:
    ident = Ed25519DidKeyIdentity(AgentId("a1"))
    info = await ident.resolve(AgentId("a1"))
    assert info.agent_id == AgentId("a1")
    assert info.method == "did:key"
    assert info.public_key == ident.public_key
    assert info.metadata["did"] == ident.did


@pytest.mark.asyncio
async def test_resolve_unknown_agent_is_total() -> None:
    # Resolution never fails: every AgentId has a derivable did:key.
    ident = Ed25519DidKeyIdentity(AgentId("a1"))
    info = await ident.resolve(AgentId("stranger"))
    assert info.metadata["did"] == did_for(AgentId("stranger"))
    assert info.public_key  # non-empty derived key


def test_seed_is_32_bytes() -> None:
    assert len(seed_for(AgentId("anything"))) == 32
