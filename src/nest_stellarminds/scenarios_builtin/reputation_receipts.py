# SPDX-License-Identifier: Apache-2.0
"""reputation_receipts scenario — the proof that ``agent_receipts`` beats ``score_average``.

A population of **16 honest** agents and a **4-agent collusion ring** transact,
each emitting *identical-shaped* trust evidence:

* a NEST ``Evidence`` with ``kind="positive"`` (so the reference ``score_average``
  plugin credits a 1.0 to the receipt's issuer), AND
* ``detail`` carrying a real, cross-signed ARP receipt as JSON (so the
  ``agent_receipts`` plugin records a corroborated receipt for the same issuer).

The two populations are indistinguishable to ``score_average``'s running mean —
both look like a stream of mutually-positive interactions, so the wash-trading
ring inflates its own score and escapes detection. ``agent_receipts``, by
contrast, runs ``sm-arp``'s VRP severance over the *global* corroboration graph:
the ring is an isolated dense clique with zero corroborated cross-edges to the
honest anchor SCC, so it is severed and collapses to score 0 / confidence 0.

Topology (enforced deliberately — see :func:`build_topology`):

* **Honest core (16):** a single large SCC. Agents form a directed cycle
  ``h0 -> h1 -> ... -> h15 -> h0`` with back-edges, every edge a corroborated
  receipt. This is the *largest* SCC, hence the VRP anchor — never severed.
* **Collusion ring (4):** a **complete clique** (every ordered pair co-signs),
  giving internal density ``1.0`` (>= 0.8) so VRP's dense-ring rule fires. A
  size-4 *cycle* is only density ``0.667`` and would NOT sever — the clique is
  required, and the scenario asserts it. The ring has **zero** corroborated
  edges to the honest core, so it is isolated from the anchor.

Receipts are passed only to ``trust.report()`` (never put on the wire), so the
trace stays byte-identical across runs despite ``issue_receipt`` minting a
fresh uuid4 ``receipt_id``/timestamp each call — severance keys on ``did``, not
``receipt_id``. Agents send a fixed deterministic handshake so the trace is
non-empty.

Example::

    from nest_core.scenarios import register_scenario
    register_scenario("reputation_receipts", reputation_receipts_factory)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Evidence
from sm_arp.identity import Identity as ArpIdentity
from sm_arp.receipts import build_action, issue_receipt
from sm_arp.vrp import cosign_receipt

from nest_stellarminds.identity_didkey import seed_for

if TYPE_CHECKING:
    from nest_core.scenario import ScenarioConfig

HONEST_COUNT = 16
RING_COUNT = 4

_HANDSHAKE = b"reputation_receipts:hello"


def honest_ids() -> list[AgentId]:
    """The 16 honest agent ids, ``honest-0 .. honest-15``."""
    return [AgentId(f"honest-{i}") for i in range(HONEST_COUNT)]


def ring_ids() -> list[AgentId]:
    """The 4 collusion-ring agent ids, ``ring-0 .. ring-3``."""
    return [AgentId(f"ring-{i}") for i in range(RING_COUNT)]


def _arp(agent: AgentId) -> ArpIdentity:
    """The ARP identity the receipts/identity plugins would mint for an AgentId.

    Keys derive from the SAME deterministic seed the ``ed25519_didkey`` identity
    plugin uses, so a receipt's ``principal_did`` byte-matches the did the trust
    plugin resolves for that agent. (Co-signing a peer's receipt from its
    AgentId-derived key is a simulation artifact, but produces the exact bytes a
    real co-signer holding that key would.)
    """
    return ArpIdentity.from_seed(seed_for(agent))


def make_corroborated_receipt(issuer_agent: AgentId, counterparty_agent: AgentId) -> dict[str, Any]:
    """Build a real ARP ``purchase`` receipt issued by ``issuer_agent`` and
    co-signed (corroborated) by ``counterparty_agent``.

    The witness signature must be embedded *before* the issuer signs (the
    issuer's signature covers ``evidence``), so we draft, co-sign the draft, then
    re-issue with the witness pinned to the same ``receipt_id``/``issued_at``.

    Example::

        r = make_corroborated_receipt(AgentId("honest-0"), AgentId("honest-1"))
    """
    issuer = _arp(issuer_agent)
    cp = _arp(counterparty_agent)
    action = build_action(
        category="purchase",
        human_summary="goods exchanged",
        outcome="completed",
        counterparty_did=cp.did,
        counterparty_label=str(counterparty_agent),
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


def build_topology() -> list[tuple[AgentId, AgentId]]:
    """Deterministic list of ``(issuer, counterparty)`` corroborated edges.

    * Honest core: a directed cycle with back-edges over all 16 honest agents,
      yielding one strongly-connected component of size 16 (the VRP anchor).
    * Ring: a complete clique over the 4 ring agents (every ordered pair),
      density ``1.0`` so VRP's dense-ring severance fires.
    * No edge crosses between the two populations.

    Example::

        edges = build_topology()
    """
    honest = honest_ids()
    ring = ring_ids()
    edges: list[tuple[AgentId, AgentId]] = []

    # Honest core: cycle h_i -> h_{i+1} plus the back-edge h_{i+1} -> h_i.
    # Both directions make the whole population one strongly-connected SCC.
    for i in range(HONEST_COUNT):
        a, b = honest[i], honest[(i + 1) % HONEST_COUNT]
        edges.append((a, b))
        edges.append((b, a))

    # Ring: complete clique — every ORDERED pair issues a corroborated receipt.
    for a in ring:
        for b in ring:
            if a != b:
                edges.append((a, b))

    return edges


class ReceiptIssuerAgent(StateMachineAgent):
    """An agent that, on start, reports its prescribed corroborated receipts.

    Each agent owns the edges where it is the *issuer*. For every such edge it
    builds a real cross-signed ARP receipt and reports it to the shared trust
    plugin as ``Evidence(kind="positive", detail=<receipt json>)`` — crediting
    *itself* (the receipt's ``principal_did``), so both trust plugins score the
    same population. It then sends a fixed handshake so the trace is non-empty.

    Critically, the agent does NOT branch on ``trust.score()``: emitted evidence
    is byte-identical under either trust plugin, isolating the scoring algorithm
    as the only variable in the comparison.

    Example::

        edge = (AgentId("honest-0"), AgentId("honest-1"))
        agent = ReceiptIssuerAgent(AgentId("honest-0"), [edge])
    """

    def __init__(self, agent_id: AgentId, my_edges: list[tuple[AgentId, AgentId]]) -> None:
        self._id = agent_id
        self._my_edges = my_edges

    async def on_start(self, ctx: AgentContext) -> None:
        """Report every receipt this agent issues, then emit a handshake.

        Example::

            await agent.on_start(ctx)
        """
        trust = ctx.plugins.get("trust")
        for issuer, counterparty in self._my_edges:
            if trust is not None:
                receipt = make_corroborated_receipt(issuer, counterparty)
                await trust.report(
                    issuer,
                    Evidence(
                        reporter=issuer,
                        subject=counterparty,
                        kind="positive",
                        detail=json.dumps(receipt),
                    ),
                )
            # Deterministic, receipt-free wire traffic keeps the trace stable.
            await ctx.send(counterparty, _HANDSHAKE)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """No-op: this scenario's interactions all complete in ``on_start``.

        Example::

            await agent.on_message(ctx, sender, b"reputation_receipts:hello")
        """
        return


def _instantiate_trust(plugins: dict[str, Any]) -> None:
    """Instantiate the trust plugin CLASS into a single shared instance in-place.

    The simulator passes this shared instance to every agent context, so all
    agents report into one ledger — exactly what global severance needs.
    """
    if not plugins:
        return
    trust_cls = plugins.get("trust")
    if trust_cls is not None and isinstance(trust_cls, type):
        plugins["trust"] = trust_cls()


def reputation_receipts_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the honest + collusion-ring agents for the reputation_receipts scenario.

    Builds the fixed corroboration topology, instantiates the shared trust
    plugin, and assigns each agent the edges it issues.

    Example::

        agents = reputation_receipts_factory(config, plugins)
    """
    _instantiate_trust(plugins)

    edges = build_topology()
    by_issuer: dict[AgentId, list[tuple[AgentId, AgentId]]] = {}
    for issuer, counterparty in edges:
        by_issuer.setdefault(issuer, []).append((issuer, counterparty))

    agents: dict[AgentId, StateMachineAgent] = {}
    for aid in honest_ids() + ring_ids():
        agents[aid] = ReceiptIssuerAgent(aid, by_issuer.get(aid, []))
    return agents
