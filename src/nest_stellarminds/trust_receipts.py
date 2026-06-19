# SPDX-License-Identifier: Apache-2.0
"""Agent-receipt reputation for Nanda Town (NEST) — the "nest-arp" trust plugin.

Implements the ``nest_core.layers.trust.Trust`` ``Protocol`` on top of
Stellarminds' published ``sm-arp`` library. Instead of the reference plugin's
running mean of self-asserted feedback, reputation here is derived from
**cross-signed ARP receipts** (VRP ``nanda-rep/0.2``):

* a receipt only counts if its Ed25519 signature verifies (:func:`verify_receipt`),
* and it is *corroborated* — the counterparty co-signed it (:func:`is_corroborated`),
* and it does not sit inside a collusion ring that VRP severs from the honest
  core (handled inside :func:`reputation_score_v2` over a full ledger).

NEST's ``Evidence`` has no receipt field, so a cross-signed receipt is carried
as JSON in ``evidence.detail``. Stock scenarios (e.g. the marketplace) pass a
plain-string ``detail``; those fall back to the reference score-average
heuristic so this plugin still works as a drop-in replacement.

Registered under ``("trust", "agent_receipts")`` via entry points.

Example::

    trust = AgentReceiptsTrust()
    await trust.report(AgentId("a1"), Evidence(reporter=..., subject=...,
        kind="receipt", detail=json.dumps(cross_signed_receipt)))
    rep = await trust.score(AgentId("a1"))
"""

from __future__ import annotations

import json
import logging
import math
from typing import Any, cast

from nest_core.types import (
    AgentId,
    Attestation,
    Claim,
    Evidence,
    ReputationScore,
)
from sm_arp.receipts import verify_receipt
from sm_arp.vrp import corroboration_rate, reputation_score_v2

from nest_stellarminds.identity_didkey import Ed25519DidKeyIdentity, did_for

logger = logging.getLogger(__name__)

ALGORITHM = "ed25519"

# Saturation constant for the unbounded VRP score -> [0, 1] map
# (``1 - exp(-raw/K)``). reputation_score_v2 sums category weights, so a single
# corroborated 'purchase' receipt is raw=5.0. K=10 maps that to ~0.39 — safely
# above the marketplace gate's 0.2 threshold — while keeping the curve from
# saturating too fast (raw=10 -> 0.63, raw=30 -> 0.95). See README for rationale.
NORMALIZATION_K = 10.0


def _normalize(raw: float) -> float:
    """Map an unbounded non-negative VRP score to ``[0, 1]`` via a saturating curve.

    ``1 - exp(-raw/K)``: 0 stays 0, larger scores asymptotically approach 1
    (and reach exactly 1.0 once ``raw/K`` is large enough that ``exp`` underflows
    to 0.0 in IEEE-754 — a valid top-of-range reputation).

    Example::

        s = _normalize(5.0)  # ~0.39 at K=10
    """
    if raw <= 0.0:
        return 0.0
    return 1.0 - math.exp(-raw / NORMALIZATION_K)


class AgentReceiptsTrust:
    """Receipt-based reputation implementing the NEST ``Trust`` Protocol.

    The constructor is **no-arg-callable** — the NEST runner does ``trust_cls()``
    with no injected identity — so this plugin mints and holds its own
    deterministic Ed25519 identity (for attestations) and maintains an
    ``AgentId -> did:key`` map reusing the identity plugin's derivation, so a
    receipt's ``principal_did`` byte-matches the agent it scores.

    Example::

        trust = AgentReceiptsTrust()
        rep = await trust.score(AgentId("a1"))
    """

    # The id under which this trust authority issues attestations.
    _SYSTEM_AGENT = AgentId("trust:agent_receipts")

    def __init__(self) -> None:
        # Our own Ed25519 identity, used to sign attestations.
        self._identity = Ed25519DidKeyIdentity(self._SYSTEM_AGENT)
        # In-memory ledger of verified, reported receipts.
        self._ledger: list[dict[str, Any]] = []
        # Plain-string-detail fallback scores (stock-scenario compatibility).
        self._fallback_scores: dict[AgentId, list[float]] = {}
        # Parity-only stake tracking (sm-arp has no staking primitive).
        self._stakes: dict[AgentId, int] = {}

    def _did_of(self, agent: AgentId) -> str:
        """Map a NEST AgentId to its ARP ``principal_did`` (deterministic)."""
        return did_for(agent)

    async def score(self, agent: AgentId) -> ReputationScore:
        """Reputation for an agent, from its corroborated ARP receipts.

        Gathers the agent's receipts (``principal_did == did_of(agent)``),
        computes the unbounded VRP ``reputation_score_v2`` and the
        ``corroboration_rate`` confidence, and normalizes the score into
        ``[0, 1]``. When the agent has no receipts, falls back to the mean of
        any plain-string-detail reports; absent both, returns the reference
        neutral prior (0.5, confidence 0).

        Note (known boundary): per-agent ``score`` reflects *this agent's* own
        corroborated receipts. Collusion-ring severing is a property of the
        *global* corroboration graph and is exercised at the library level
        (``reputation_score_v2`` over a full ledger) — see the
        ``reputation_receipts`` benchmark follow-up.

        Example::

            rep = await trust.score(AgentId("a1"))
        """
        did = self._did_of(agent)
        mine = [r for r in self._ledger if r.get("principal_did") == did]
        if mine:
            raw = reputation_score_v2(mine, is_valid=lambda r: verify_receipt(r).ok)
            conf = corroboration_rate(mine, is_valid=lambda r: verify_receipt(r).ok)
            return ReputationScore(
                agent_id=agent,
                score=_normalize(raw),
                confidence=conf,
                sample_count=len(mine),
            )
        # No receipts: fall back to plain-string-detail heuristic if present.
        fallback = self._fallback_scores.get(agent)
        if fallback:
            avg = sum(fallback) / len(fallback)
            return ReputationScore(
                agent_id=agent,
                score=avg,
                confidence=min(1.0, len(fallback) / 100.0),
                sample_count=len(fallback),
            )
        return ReputationScore(agent_id=agent, score=0.5, confidence=0.0, sample_count=0)

    async def attest(self, agent: AgentId, claim: Claim) -> Attestation:
        """Issue an Ed25519-signed attestation about an agent.

        Signs ``claim.model_dump_json()`` with this plugin's own identity
        (``algorithm="ed25519"``), mirroring the reference plugin's shape.

        Example::

            att = await trust.attest(AgentId("a1"), claim)
        """
        sig = self._identity.sign(claim.model_dump_json().encode())
        return Attestation(issuer=self._SYSTEM_AGENT, claim=claim, signature=sig)

    async def report(self, agent: AgentId, evidence: Evidence) -> None:
        """Report evidence — a cross-signed ARP receipt, or a stock heuristic.

        ``evidence.detail`` is tried as JSON: if it decodes to a dict that
        passes :func:`verify_receipt`, it is appended to the receipt ledger.
        If ``detail`` is a plain string (e.g. the marketplace scenario), or a
        JSON value that is not a verifying receipt, we fall back to the
        reference score-average heuristic (positive -> 1.0, negative/byzantine
        -> 0.0, else 0.5) so the plugin still works in stock scenarios.

        Failures are handled explicitly — never silently swallowed.

        Example::

            await trust.report(AgentId("a1"), Evidence(reporter=r, subject=s,
                kind="receipt", detail=json.dumps(receipt)))
        """
        try:
            parsed: object = json.loads(evidence.detail)
        except (json.JSONDecodeError, TypeError):
            # Plain-string detail (stock scenario): heuristic fallback.
            self._record_fallback(agent, evidence)
            return

        if isinstance(parsed, dict):
            receipt = cast("dict[str, Any]", parsed)
            result = verify_receipt(receipt)
            if result.ok:
                self._ledger.append(receipt)
                return
            # Decoded to a dict but is not a valid receipt: log and fall back so
            # a malformed receipt never silently vanishes.
            logger.warning(
                "report: detail decoded to a dict but failed ARP verification "
                "(stage=%s, detail=%s); using heuristic fallback",
                result.stage,
                result.detail,
            )

        # JSON that is not a receipt dict (or a non-verifying one): heuristic.
        self._record_fallback(agent, evidence)

    def _record_fallback(self, agent: AgentId, evidence: Evidence) -> None:
        """Apply the reference score-average heuristic for non-receipt evidence."""
        score_val = 0.5
        if evidence.kind == "positive":
            score_val = 1.0
        elif evidence.kind in ("negative", "byzantine"):
            score_val = 0.0
        self._fallback_scores.setdefault(agent, []).append(score_val)

    async def stake(self, agent: AgentId, amount: int) -> None:
        """Stake reputation on an agent (parity-only no-op).

        ``sm-arp`` has no staking primitive; this is kept purely for Protocol
        parity with the reference plugin and records the amount in memory.

        Example::

            await trust.stake(AgentId("a1"), 100)
        """
        self._stakes[agent] = self._stakes.get(agent, 0) + amount
