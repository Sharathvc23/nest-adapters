# SPDX-License-Identifier: Apache-2.0
"""datafacts_provenance scenario — datasets exchanged with signed provenance.

Each agent publishes a dataset (owned by itself) into the shared DataFacts layer,
then fetches a peer's dataset and requests access. With ``datafacts: arp_receipts``
(this repo's :class:`ArpDataFacts`) every ``fetch`` verifies the peer's signed
provenance receipt and re-checks the content hash — so the access only happens
because the data's integrity held. Swap ``datafacts: datafacts_v1`` and the agent
logic is identical: the scenario is a drop-in demonstration of the swappable layer.

Example::

    from nest_core.scenarios import register_scenario
    register_scenario("datafacts_provenance", datafacts_provenance_factory)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata

if TYPE_CHECKING:
    from nest_core.scenario import ScenarioConfig

# Self-scheduled signal: "everyone has published, go consume a peer's dataset".
_CONSUME_SIGNAL = b"__consume__"


class DataAgent(StateMachineAgent):
    """Publishes its own dataset, then fetches + accesses ``peer``'s dataset.

    Example::

        agent = DataAgent(peer=AgentId("agent-1"), consume_at=5.0)
    """

    def __init__(self, peer: AgentId, consume_at: float) -> None:
        self._peer = peer
        self._consume_at = consume_at

    async def on_start(self, ctx: AgentContext) -> None:
        """Publish this agent's dataset, then schedule the consume tick.

        Example::

            await agent.on_start(ctx)
        """
        datafacts = ctx.plugins.get("datafacts")
        if datafacts is None:
            return
        meta = DatasetMetadata(
            name=f"ds-{ctx.agent_id}",
            owner=ctx.agent_id,
            description=f"dataset owned by {ctx.agent_id}",
            checksum=f"sha256:{ctx.agent_id}",
        )
        await datafacts.publish(meta)
        await ctx.schedule(self._consume_at, _CONSUME_SIGNAL)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On the consume signal, fetch the peer's dataset and request access.

        The fetch verifies the peer's signed provenance + content hash, so the
        access message in the trace is proof the integrity check passed.

        Example::

            await agent.on_message(ctx, ctx.agent_id, b"__consume__")
        """
        if payload != _CONSUME_SIGNAL:
            return
        datafacts = ctx.plugins.get("datafacts")
        if datafacts is None:
            return
        url = DataFactsUrl(f"df://ds-{self._peer}")
        meta = await datafacts.fetch(url)
        grant = await datafacts.request_access(url, ctx.agent_id)
        msg = f"{ctx.agent_id} accessed {url} owned by {meta.owner} (tier={grant.tier})"
        await ctx.send(self._peer, msg.encode("utf-8"))


def datafacts_provenance_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create a ring of agents that publish, then fetch + access a peer's dataset.

    Example::

        agents = datafacts_provenance_factory(config, plugins)
    """
    _instantiate_datafacts(plugins)

    count = config.agents.count
    consume_at = float(config.task.config.get("consume_at_tick", 5))
    ids = [AgentId(f"agent-{i}") for i in range(count)]
    agents: dict[AgentId, StateMachineAgent] = {}
    for i, aid in enumerate(ids):
        peer = ids[(i + 1) % count]
        agents[aid] = DataAgent(peer=peer, consume_at=consume_at)
    return agents


def _instantiate_datafacts(plugins: dict[str, Any]) -> None:
    """Replace the resolved DataFacts CLASS with one shared instance.

    The simulator hands this one instance to every agent context, so all agents
    publish into — and fetch from — the same dataset registry.

    Example::

        _instantiate_datafacts(plugins)
    """
    if not plugins:
        return
    datafacts_cls = plugins.get("datafacts")
    if datafacts_cls is not None and isinstance(datafacts_cls, type):
        plugins["datafacts"] = datafacts_cls()
