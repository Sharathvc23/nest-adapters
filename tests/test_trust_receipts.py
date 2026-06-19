# SPDX-License-Identifier: Apache-2.0
"""Tests for AgentReceiptsTrust — the receipt-based ("nest-arp") trust plugin."""

from __future__ import annotations

import json
from typing import Any

import pytest
from nest_core.types import AgentId, Claim, Evidence
from sm_arp.identity import Identity as ArpIdentity
from sm_arp.receipts import build_action, issue_receipt, verify_receipt
from sm_arp.vrp import is_corroborated, reputation_score_v2

from nest_adapters.identity_didkey import seed_for
from nest_adapters.trust_receipts import (
    NORMALIZATION_K,
    AgentReceiptsTrust,
    _normalize,
)


def _arp(agent: AgentId) -> ArpIdentity:
    """The ARP identity the plugin would mint for an AgentId."""
    return ArpIdentity.from_seed(seed_for(agent))


def _make_receipt(
    issuer_agent: AgentId,
    counterparty_agent: AgentId | None,
    *,
    category: str = "purchase",
    corroborate: bool = True,
) -> dict[str, Any]:
    """Build an ARP receipt; optionally have the counterparty co-sign it.

    Cross-signing requires the witness signature to be embedded BEFORE the
    issuer signs (the issuer's signature covers ``evidence``), so we draft,
    cosign the draft's corroboration payload, then re-issue with the witness
    signature pinned to the same receipt_id/issued_at.
    """
    from sm_arp.vrp import cosign_receipt

    issuer = _arp(issuer_agent)
    cp = _arp(counterparty_agent) if counterparty_agent is not None else None
    action = build_action(
        category=category,
        human_summary="test action",
        outcome="completed",
        counterparty_did=cp.did if cp is not None else None,
        counterparty_label="cp",
    )
    draft = issue_receipt(issuer, principal_did=issuer.did, action=action)
    if not corroborate or cp is None:
        return draft
    co = cosign_receipt(draft, signing_key_bytes=cp.sk_bytes, witness_did=cp.did)
    return issue_receipt(
        issuer,
        principal_did=issuer.did,
        action=action,
        evidence={"witness_signatures": [co]},
        receipt_id=draft["receipt_id"],
        issued_at=draft["issued_at"],
    )


def _evidence(detail: str, kind: str = "receipt") -> Evidence:
    return Evidence(
        reporter=AgentId("reporter"),
        subject=AgentId("subject"),
        kind=kind,
        detail=detail,
    )


# -- normalization -----------------------------------------------------------


def test_normalize_in_unit_interval() -> None:
    # Closed interval [0, 1]: for very large raw scores the float curve
    # saturates to exactly 1.0, which is a valid normalized reputation.
    for raw in (0.0, 0.5, 5.0, 10.0, 50.0, 1_000.0):
        s = _normalize(raw)
        assert 0.0 <= s <= 1.0


def test_normalize_zero_is_zero() -> None:
    assert _normalize(0.0) == 0.0
    assert _normalize(-1.0) == 0.0


def test_normalize_one_corroborated_receipt_clears_marketplace_gate() -> None:
    # A single corroborated 'purchase' receipt is raw=5.0; must exceed 0.2.
    assert _normalize(5.0) > 0.2
    assert NORMALIZATION_K == 10.0


# -- report + score ----------------------------------------------------------


@pytest.mark.asyncio
async def test_corroborated_scores_higher_than_uncorroborated() -> None:
    a, seller = AgentId("buyer_a"), AgentId("seller_x")
    b = AgentId("buyer_b")

    corroborated = _make_receipt(a, seller, corroborate=True)
    uncorroborated = _make_receipt(b, seller, corroborate=False)
    assert is_corroborated(corroborated) is True
    assert is_corroborated(uncorroborated) is False

    trust = AgentReceiptsTrust()
    await trust.report(a, _evidence(json.dumps(corroborated)))
    await trust.report(b, _evidence(json.dumps(uncorroborated)))

    score_a = await trust.score(a)
    score_b = await trust.score(b)
    assert score_a.score > score_b.score
    assert score_a.score > 0.0
    assert score_b.score == 0.0  # uncorroborated earns zero in VRP
    assert score_a.sample_count == 1
    assert score_a.confidence == 1.0


@pytest.mark.asyncio
async def test_score_is_normalized_in_unit_interval() -> None:
    a, seller = AgentId("buyer_a"), AgentId("seller_x")
    trust = AgentReceiptsTrust()
    for _ in range(10):
        await trust.report(a, _evidence(json.dumps(_make_receipt(a, seller))))
    score = await trust.score(a)
    assert 0.0 <= score.score <= 1.0


@pytest.mark.asyncio
async def test_no_receipts_returns_neutral_prior() -> None:
    trust = AgentReceiptsTrust()
    score = await trust.score(AgentId("nobody"))
    assert score.score == 0.5
    assert score.sample_count == 0
    assert score.confidence == 0.0


# -- plain-string fallback (stock scenario compatibility) --------------------


@pytest.mark.asyncio
async def test_plain_string_detail_falls_back_without_crashing() -> None:
    trust = AgentReceiptsTrust()
    agent = AgentId("marketplace_agent")
    await trust.report(agent, _evidence("delivered on time", kind="positive"))
    await trust.report(agent, _evidence("delivered on time", kind="positive"))
    score = await trust.score(agent)
    assert score.score == 1.0  # both positive
    assert score.sample_count == 2


@pytest.mark.asyncio
async def test_negative_fallback_scores_low() -> None:
    trust = AgentReceiptsTrust()
    agent = AgentId("bad_agent")
    await trust.report(agent, _evidence("scammed me", kind="negative"))
    score = await trust.score(agent)
    assert score.score == 0.0


@pytest.mark.asyncio
async def test_malformed_json_dict_non_receipt_falls_back() -> None:
    # Valid JSON object that is not an ARP receipt -> heuristic fallback, no crash.
    trust = AgentReceiptsTrust()
    agent = AgentId("agent")
    await trust.report(agent, _evidence(json.dumps({"not": "a receipt"}), kind="positive"))
    score = await trust.score(agent)
    assert score.score == 1.0
    assert score.sample_count == 1


# -- collusion-ring severing (library-level, full ledger) --------------------


def _ring_receipt(issuer: ArpIdentity, cp: ArpIdentity) -> dict[str, Any]:
    from sm_arp.vrp import cosign_receipt

    action = build_action(
        category="purchase",
        human_summary="x",
        outcome="completed",
        counterparty_did=cp.did,
        counterparty_label="cp",
    )
    draft = issue_receipt(issuer, principal_did=issuer.did, action=action)
    co = cosign_receipt(draft, signing_key_bytes=cp.sk_bytes, witness_did=cp.did)
    return issue_receipt(
        issuer,
        principal_did=issuer.did,
        action=action,
        evidence={"witness_signatures": [co]},
        receipt_id=draft["receipt_id"],
        issued_at=draft["issued_at"],
    )


def test_collusion_ring_severed_while_honest_core_scores_high() -> None:
    valid = lambda r: verify_receipt(r).ok  # noqa: E731

    # Honest core: a mutually-corroborating cycle of 4 agents forms the
    # LARGEST SCC, so it is the anchor and never severed.
    honest_ids = [ArpIdentity.from_seed(bytes([10 + i]) * 32) for i in range(4)]
    honest: list[dict[str, Any]] = []
    for i in range(4):
        a, b = honest_ids[i], honest_ids[(i + 1) % 4]
        honest.append(_ring_receipt(a, b))
        honest.append(_ring_receipt(b, a))  # back-edge -> strongly connected

    # Collusion ring: 3 agents co-signing ONLY each other, isolated from honest.
    ring_ids = [ArpIdentity.from_seed(bytes([200 + i]) * 32) for i in range(3)]
    ring: list[dict[str, Any]] = []
    for i in range(3):
        a, b = ring_ids[i], ring_ids[(i + 1) % 3]
        ring.append(_ring_receipt(a, b))
        ring.append(_ring_receipt(b, a))

    ledger = honest + ring

    # The collusion ring is severed only by the GLOBAL corroboration graph, so
    # we exercise reputation_score_v2 over the full ledger (public API).
    full = reputation_score_v2(ledger, is_valid=valid)
    honest_only = reputation_score_v2(honest, is_valid=valid)
    ring_isolated = reputation_score_v2(ring, is_valid=valid)

    # In the full ledger the ring contributes nothing: the gated total equals
    # the honest core's total. The ring is severed, not merely invalid.
    assert honest_only > 0.0
    assert full == honest_only
    # Proof the severing is graph-driven (not bad receipts): in isolation the
    # ring becomes its own anchor and DOES score high.
    assert ring_isolated > 0.0


# -- attest + stake ----------------------------------------------------------


@pytest.mark.asyncio
async def test_attest_signs_with_ed25519() -> None:
    trust = AgentReceiptsTrust()
    claim = Claim(subject=AgentId("a1"), predicate="reliable", value="true")
    att = await trust.attest(AgentId("a1"), claim)
    assert att.claim == claim
    assert att.signature.algorithm == "ed25519"
    assert len(att.signature.value) == 64
    # Signature verifies against the plugin's own identity.
    assert trust._identity.verify(
        claim.model_dump_json().encode(), att.signature, att.signature.signer
    )


@pytest.mark.asyncio
async def test_stake_is_parity_noop() -> None:
    trust = AgentReceiptsTrust()
    await trust.stake(AgentId("a1"), 100)
    await trust.stake(AgentId("a1"), 50)
    assert trust._stakes[AgentId("a1")] == 150
