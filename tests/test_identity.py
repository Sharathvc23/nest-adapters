# SPDX-License-Identifier: Apache-2.0
"""Tests for Ed25519RotatingIdentity (Nanda Town problem 5).

The attack matrix (advisor-reviewed) each verify_as_of check must enforce:

    attack                              | kid | t_claimed | as_of | caught by
    ------------------------------------|-----|-----------|-------|----------
    honest old msg, audited as-of old   | v0  | old       | old   | passes
    post-rotation forgery, honest stamp | v0  | now       | now   | (A) t-window
    post-rotation forgery, backdated    | v0  | old       | now   | (B) as_of-window
    backdating with the new key         | v1  | old       | now   | (A) t-window
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, Signature

from nest_adapters.determinism import (
    derive_signing_key,
    encode_signature_value,
    key_id_for,
    public_bytes,
    signing_bytes,
)
from nest_adapters.identity import Ed25519RotatingIdentity

ALG = "ed25519-rotating/0.1"


def _forged_signature(
    seed: bytes, agent: AgentId, rotation_count: int, payload: bytes, claimed_tick: float
) -> Signature:
    """Build a crypto-valid signature from a (compromised) key the attacker holds.

    Models 'attacker recovered key vN and signs whatever they like, stamping
    whatever tick they like'. The key is recoverable because it derives from a
    known seed — that is exactly what key compromise means.
    """
    key = derive_signing_key(seed, agent, rotation_count)
    kid = key_id_for(public_bytes(key.public_key()))
    raw = key.sign(signing_bytes(payload, kid, claimed_tick))
    return Signature(
        signer=agent, value=encode_signature_value(kid, claimed_tick, raw), algorithm=ALG
    )


def test_sign_verify_roundtrip() -> None:
    a = AgentId("agent-1")
    ident = Ed25519RotatingIdentity(a, seed=b"s")
    sig = ident.sign(b"hello")
    assert sig.algorithm == ALG
    assert ident.verify(b"hello", sig, a) is True


def test_tampered_payload_fails() -> None:
    a = AgentId("agent-1")
    ident = Ed25519RotatingIdentity(a, seed=b"s")
    sig = ident.sign(b"hello")
    assert ident.verify(b"goodbye", sig, a) is False


async def test_resolve_returns_did_key() -> None:
    a = AgentId("agent-1")
    ident = Ed25519RotatingIdentity(a, seed=b"s")
    info = await ident.resolve(a)
    assert info.method == "did:key"
    assert info.public_key == ident.public_key
    assert info.metadata["did"].startswith("did:key:z")


def test_rotation_changes_key_id() -> None:
    a = AgentId("agent-1")
    ident = Ed25519RotatingIdentity(a, seed=b"s")
    kid0 = ident.current_key_id
    ident.advance_to(10.0)
    kid1 = ident.rotate_key()
    assert kid1 == ident.current_key_id
    assert kid1 != kid0


def test_old_signature_verifies_within_window_only() -> None:
    a = AgentId("agent-1")
    ident = Ed25519RotatingIdentity(a, seed=b"s")
    sig = ident.sign(b"hello")  # v0 at tick 0
    ident.advance_to(10.0)
    ident.rotate_key()  # v0 window closes at 10
    assert ident.verify_as_of(b"hello", sig, a, as_of=5.0) is True
    assert ident.verify_as_of(b"hello", sig, a, as_of=20.0) is False  # post-rotation


def test_post_rotation_forgery_honest_stamp_rejected() -> None:
    a = AgentId("agent-1")
    ident = Ed25519RotatingIdentity(a, seed=b"s")
    ident.sign(b"hello")
    ident.advance_to(10.0)
    ident.rotate_key()
    # attacker re-uses compromised v0, honestly stamps the current tick (12)
    forged = _forged_signature(b"s", a, 0, b"fresh-lie", claimed_tick=12.0)
    assert ident.verify_as_of(b"fresh-lie", forged, a, as_of=12.0) is False  # check A


def test_post_rotation_forgery_backdated_rejected() -> None:
    a = AgentId("agent-1")
    ident = Ed25519RotatingIdentity(a, seed=b"s")
    ident.sign(b"hello")
    ident.advance_to(10.0)
    ident.rotate_key()
    # attacker backdates the stamp into v0's window, but is observed at tick 20
    forged = _forged_signature(b"s", a, 0, b"fresh-lie", claimed_tick=5.0)
    assert ident.verify_as_of(b"fresh-lie", forged, a, as_of=20.0) is False  # check B


def test_backdating_with_new_key_rejected() -> None:
    a = AgentId("agent-1")
    ident = Ed25519RotatingIdentity(a, seed=b"s")
    ident.sign(b"hello")
    ident.advance_to(10.0)
    ident.rotate_key()
    # attacker uses the NEW key (v1) but claims a tick in v0's old window
    forged = _forged_signature(b"s", a, 1, b"backdated", claimed_tick=5.0)
    assert ident.verify_as_of(b"backdated", forged, a, as_of=20.0) is False  # check A


def test_peer_key_history_via_announcement() -> None:
    a, b = AgentId("agent-a"), AgentId("agent-b")
    alice = Ed25519RotatingIdentity(a, seed=b"sa")
    bob = Ed25519RotatingIdentity(b, seed=b"sb")
    bob.register_peer(a, alice.public_key)

    sig0 = alice.sign(b"m0")  # v0 at tick 0
    assert bob.verify(b"m0", sig0, a) is True

    alice.advance_to(10.0)
    alice.rotate_key()
    bob.observe_rotation(alice.rotation_announcement())

    alice.advance_to(10.0)
    sig1 = alice.sign(b"m1")  # v1 at tick 10
    bob.advance_to(10.0)
    assert bob.verify(b"m1", sig1, a) is True
    # old v0 message: valid as-of its window, invalid afterwards
    assert bob.verify_as_of(b"m0", sig0, a, as_of=5.0) is True
    assert bob.verify_as_of(b"m0", sig0, a, as_of=20.0) is False


def test_forged_rotation_announcement_rejected() -> None:
    a, b = AgentId("agent-a"), AgentId("agent-b")
    bob = Ed25519RotatingIdentity(b, seed=b"sb")
    # bob knows agent-a's genuine v0
    alice = Ed25519RotatingIdentity(a, seed=b"sa")
    bob.register_peer(a, alice.public_key)
    # an impostor announces a rotation for agent-a not signed by a's real v0
    impostor = Ed25519RotatingIdentity(a, seed=b"EVIL")
    impostor.advance_to(10.0)
    impostor.rotate_key()
    with pytest.raises(ValueError, match="continuity"):
        bob.observe_rotation(impostor.rotation_announcement())


def test_determinism_same_seed_same_signature() -> None:
    a = AgentId("agent-1")
    one = Ed25519RotatingIdentity(a, seed=b"s")
    two = Ed25519RotatingIdentity(a, seed=b"s")
    assert one.sign(b"x").value == two.sign(b"x").value
