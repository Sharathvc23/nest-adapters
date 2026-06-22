# SPDX-License-Identifier: Apache-2.0
"""Tests for the did:key auth adapter + the auth_handshake scenario.

Assert the headline properties — tokens are signed by the subject's did:key (no
shared secret, verifiable across instances), and forgery / impersonation /
tamper / revocation / expiry are all rejected — plus that the bundled scenario
runs and peers grant on verifying a did:key token.
"""

from __future__ import annotations

import json
from pathlib import Path

from nest_core.layers.auth import Auth
from nest_core.types import AgentId, Token

from nest_adapters.auth_didkey import DidAuth
from nest_adapters.run import run_scenario

SCENARIO = Path(__file__).parent.parent / "scenarios" / "auth_handshake.yaml"


def test_runtime_checkable_auth_protocol() -> None:
    assert isinstance(DidAuth(), Auth)


async def test_issue_verify_roundtrip() -> None:
    auth = DidAuth()
    token = await auth.issue(AgentId("alice"), ["read", "write"])
    ctx = await auth.verify(token)
    assert ctx.subject == AgentId("alice")
    assert ctx.scopes == ["read", "write"]


async def test_verifies_across_instances_no_shared_secret() -> None:
    """A token from one instance verifies on another — no shared secret, did:key only."""
    token = await DidAuth().issue(AgentId("alice"), ["read"])
    ctx = await DidAuth().verify(token)  # different instance, no shared state
    assert ctx.subject == AgentId("alice")


async def test_tampered_scope_is_rejected() -> None:
    auth = DidAuth()
    token = await auth.issue(AgentId("alice"), ["read"])
    payload, sig = str(token).rsplit("|", 1)
    tampered = Token(payload.replace("read", "admin") + "|" + sig)
    try:
        await auth.verify(tampered)
    except ValueError as exc:
        assert "signature" in str(exc)
    else:
        raise AssertionError("tampered token verified — signature gate failed")


async def test_impersonation_is_rejected() -> None:
    """Relabelling alice's token as bob's (keeping alice's did+sig) is caught."""
    auth = DidAuth()
    token = await auth.issue(AgentId("alice"), ["read"])
    payload, sig = str(token).rsplit("|", 1)
    data = json.loads(payload)
    data["sub"] = "bob"  # claim bob, but did + signature are still alice's
    forged = Token(json.dumps(data, sort_keys=True, separators=(",", ":")) + "|" + sig)
    try:
        await auth.verify(forged)
    except ValueError as exc:
        assert "subject" in str(exc)
    else:
        raise AssertionError("impersonated token verified — did/subject gate failed")


async def test_revoked_token_is_rejected() -> None:
    auth = DidAuth()
    token = await auth.issue(AgentId("alice"), ["read"])
    await auth.revoke(token)
    try:
        await auth.verify(token)
    except ValueError as exc:
        assert "revoked" in str(exc)
    else:
        raise AssertionError("revoked token still verified")


async def test_expired_token_is_rejected() -> None:
    """A token is rejected by a verifier whose clock is past its expiry."""
    token = await DidAuth(clock=0.0).issue(AgentId("alice"), ["read"])  # exp = 3600
    try:
        await DidAuth(clock=10_000.0).verify(token)
    except ValueError as exc:
        assert "expired" in str(exc)
    else:
        raise AssertionError("expired token still verified")


def test_scenario_runs_and_peers_grant(tmp_path: Path) -> None:
    trace = run_scenario(SCENARIO, out=tmp_path / "trace.jsonl")
    lines = trace.read_text(encoding="utf-8").splitlines()
    grants = [line for line in lines if "granted:" in line]
    assert grants, "no grant events — did:key token verification produced nothing"
