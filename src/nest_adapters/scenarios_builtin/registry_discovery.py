# SPDX-License-Identifier: Apache-2.0
"""registry_discovery scenario — agents find each other through NANDA AgentFacts.

Half the agents advertise a ``sell_data`` capability; the other half seek it.
On start, every agent registers its ``AgentCard`` with the shared registry layer
and schedules a discovery tick. At that tick it ``lookup``s peers offering
``sell_data`` and greets each one.

Run with ``registry: sm_bridge_facts`` (this repo's :class:`SmBridgeRegistry`)
and discovery happens over **canonical NANDA AgentFacts** — every registered
agent is projected to an ``SmAgentFacts`` whose ``id`` is the agent's did:key,
the same identity the ``ed25519_didkey`` layer derives. Run it with the stock
``in_memory`` registry instead and the agent logic is identical: the scenario is
a drop-in demonstration that the registry layer is swappable.

Example::

    from nest_core.scenarios import register_scenario
    register_scenario("registry_discovery", registry_discovery_factory)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentCard, AgentId, Query

if TYPE_CHECKING:
    from nest_core.scenario import ScenarioConfig

# Capability advertised by sellers and sought by buyers.
_OFFER = "sell_data"
# Buyers advertise a (different) capability so the registry holds a mix.
_BUYER_OFFER = "analyze_data"
# Self-scheduled signal: "everyone has registered, go discover".
_DISCOVER_SIGNAL = b"__discover__"


class DiscoveringAgent(StateMachineAgent):
    """Registers its card, then discovers and greets peers offering ``seeks``.

    Example::

        agent = DiscoveringAgent(offers=["sell_data"], seeks="sell_data", discover_at=5.0)
    """

    def __init__(self, offers: list[str], seeks: str, discover_at: float) -> None:
        self._offers = offers
        self._seeks = seeks
        self._discover_at = discover_at

    async def on_start(self, ctx: AgentContext) -> None:
        """Register this agent's card, then schedule the discovery tick.

        Example::

            await agent.on_start(ctx)
        """
        registry = ctx.plugins.get("registry")
        if registry is None:
            return
        card = AgentCard(agent_id=ctx.agent_id, name=str(ctx.agent_id), capabilities=self._offers)
        await registry.register(card)
        await ctx.schedule(self._discover_at, _DISCOVER_SIGNAL)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On the discovery signal, look up peers offering ``seeks`` and greet them.

        Greetings (any other payload) are received silently — their presence in
        the trace is the proof that discovery resolved a real peer.

        Example::

            await agent.on_message(ctx, ctx.agent_id, b"__discover__")
        """
        if payload != _DISCOVER_SIGNAL:
            return
        registry = ctx.plugins.get("registry")
        if registry is None:
            return
        peers = await registry.lookup(Query(capabilities=[self._seeks]))
        for peer in peers:
            if peer.agent_id != ctx.agent_id:
                greeting = f"hello {peer.agent_id} from {ctx.agent_id}".encode()
                await ctx.send(peer.agent_id, greeting)


def registry_discovery_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create alternating seller/buyer agents sharing one registry instance.

    Even-indexed agents offer ``sell_data``; odd-indexed agents offer
    ``analyze_data``. Both seek ``sell_data``, so every agent discovers the
    sellers (including, for sellers, their peers) through the registry layer.

    Example::

        agents = registry_discovery_factory(config, plugins)
    """
    _instantiate_registry(plugins)

    count = config.agents.count
    discover_at = float(config.task.config.get("discover_at_tick", 5))
    agents: dict[AgentId, StateMachineAgent] = {}
    for i in range(count):
        aid = AgentId(f"agent-{i}")
        offers = [_OFFER] if i % 2 == 0 else [_BUYER_OFFER]
        agents[aid] = DiscoveringAgent(offers=offers, seeks=_OFFER, discover_at=discover_at)
    return agents


def _instantiate_registry(plugins: dict[str, Any]) -> None:
    """Replace the resolved registry CLASS with a single shared instance.

    The simulator hands this one instance to every agent context, so all agents
    register into — and discover from — the same registry (mirroring
    ``reputation_receipts``'s shared-trust wiring).

    Example::

        _instantiate_registry(plugins)
    """
    if not plugins:
        return
    registry_cls = plugins.get("registry")
    if registry_cls is not None and isinstance(registry_cls, type):
        plugins["registry"] = registry_cls()
