# SPDX-License-Identifier: Apache-2.0
"""sm_marketplace scenario — all four sm-* layers in one flow.

A small data marketplace that exercises every adapter this repo ships, end to end:

* **Identity** (``ed25519_didkey``) — the did:key under every agent.
* **Registry** (``sm_bridge_facts``) — sellers register an AgentCard advertising
  ``sell_data``; buyers discover them as canonical NANDA AgentFacts.
* **Data Facts** (``arp_receipts``) — sellers publish a dataset with signed ARP
  provenance; buyers ``fetch`` it through the integrity gate and request access.
* **Trust** (``agent_receipts``) — after a successful, integrity-verified
  purchase, the buyer credits the seller with a cross-signed ARP ``purchase``
  receipt, so the seller accrues corroborated, severance-resistant reputation.

Run it with the four ``nest_adapters`` plugins (see ``scenarios/sm_marketplace.yaml``)
and discovery, provenance, and reputation are all real receipts/AgentFacts; swap
any layer for its stock plugin and the agent logic is unchanged.

Example::

    from nest_core.scenarios import register_scenario
    register_scenario("sm_marketplace", sm_marketplace_factory)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentCard, AgentId, DataFactsUrl, DatasetMetadata, Evidence, Query

from nest_adapters.scenarios_builtin.reputation_receipts import make_corroborated_receipt

if TYPE_CHECKING:
    from nest_core.scenario import ScenarioConfig

_OFFER = "sell_data"
# Self-scheduled signal: "sellers are listed + published, go transact".
_TRANSACT_SIGNAL = b"__transact__"
# The shared layers the marketplace drives (instantiated once, per-run).
_SHARED_LAYERS = ("registry", "datafacts", "trust")


class SellerAgent(StateMachineAgent):
    """Lists itself in the registry and publishes a dataset with provenance.

    Example::

        agent = SellerAgent()
    """

    async def on_start(self, ctx: AgentContext) -> None:
        """Register an AgentCard and publish this seller's dataset.

        Example::

            await agent.on_start(ctx)
        """
        registry = ctx.plugins.get("registry")
        datafacts = ctx.plugins.get("datafacts")
        if registry is None or datafacts is None:
            return
        card = AgentCard(agent_id=ctx.agent_id, name=str(ctx.agent_id), capabilities=[_OFFER])
        await registry.register(card)
        meta = DatasetMetadata(
            name=f"ds-{ctx.agent_id}",
            owner=ctx.agent_id,
            description=f"dataset sold by {ctx.agent_id}",
            checksum=f"sha256:{ctx.agent_id}",
        )
        await datafacts.publish(meta)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Receive buyer purchase confirmations silently (passive seller).

        Example::

            await agent.on_message(ctx, AgentId("agent-1"), b"...")
        """
        return


class BuyerAgent(StateMachineAgent):
    """Discovers sellers, integrity-fetches their data, and credits their trust.

    Example::

        agent = BuyerAgent(transact_at=5.0)
    """

    def __init__(self, transact_at: float) -> None:
        self._transact_at = transact_at

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule the transaction tick (after sellers have listed).

        Example::

            await agent.on_start(ctx)
        """
        await ctx.schedule(self._transact_at, _TRANSACT_SIGNAL)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On the transact signal, run the full marketplace flow per seller.

        For each discovered seller: fetch its dataset through the DataFacts
        integrity gate, request access, credit it with a cross-signed ARP
        purchase receipt via the Trust layer, and send a purchase confirmation.

        Example::

            await agent.on_message(ctx, ctx.agent_id, b"__transact__")
        """
        if payload != _TRANSACT_SIGNAL:
            return
        registry = ctx.plugins.get("registry")
        datafacts = ctx.plugins.get("datafacts")
        trust = ctx.plugins.get("trust")
        if registry is None or datafacts is None or trust is None:
            return
        sellers = await registry.lookup(Query(capabilities=[_OFFER]))
        for card in sellers:
            seller = card.agent_id
            url = DataFactsUrl(f"df://ds-{seller}")
            meta = await datafacts.fetch(url)  # raises unless provenance + content verify
            grant = await datafacts.request_access(url, ctx.agent_id)
            # Credit the seller (principal) with a receipt the buyer co-signs.
            receipt = make_corroborated_receipt(seller, ctx.agent_id)
            await trust.report(
                seller,
                Evidence(
                    reporter=ctx.agent_id,
                    subject=seller,
                    kind="positive",
                    detail=json.dumps(receipt),
                ),
            )
            confirm = f"{ctx.agent_id} bought {meta.name} from {seller} (tier={grant.tier})"
            await ctx.send(seller, confirm.encode("utf-8"))


def sm_marketplace_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Even-indexed agents are sellers; odd-indexed agents are buyers.

    Example::

        agents = sm_marketplace_factory(config, plugins)
    """
    _instantiate_shared(plugins)

    count = config.agents.count
    transact_at = float(config.task.config.get("transact_at_tick", 5))
    agents: dict[AgentId, StateMachineAgent] = {}
    for i in range(count):
        aid = AgentId(f"agent-{i}")
        agents[aid] = SellerAgent() if i % 2 == 0 else BuyerAgent(transact_at=transact_at)
    return agents


def _instantiate_shared(plugins: dict[str, Any]) -> None:
    """Replace each shared layer's CLASS with one per-run instance.

    The simulator shares each instance across agent contexts, so all buyers and
    sellers use the same registry, datafacts store, and trust ledger.

    Example::

        _instantiate_shared(plugins)
    """
    if not plugins:
        return
    for layer in _SHARED_LAYERS:
        layer_cls = plugins.get(layer)
        if layer_cls is not None and isinstance(layer_cls, type):
            plugins[layer] = layer_cls()
