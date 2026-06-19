# SPDX-License-Identifier: Apache-2.0
"""identity_rotation scenario — agents rotate their key mid-run and sign before and after.

Each agent, on start, announces its initial public key, sends a signed message,
and schedules a key rotation. At the rotation tick it rotates, broadcasts a
continuity-signed rotation announcement, and signs a fresh message with the new
key. The trace therefore contains signatures from two keys per agent, each
inside its own validity window — exactly what the as-of validator checks.

Example::

    from nest_core.scenarios import register_scenario
    register_scenario("identity_rotation", identity_rotation_factory)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

from nest_adapters.wire import encode_identity, encode_rotation_event, encode_signed

if TYPE_CHECKING:
    from nest_core.scenario import ScenarioConfig

# Fixed scenario salt so key material is identical across runs (determinism).
SCENARIO_SEED = b"identity_rotation"
_ROTATE_SIGNAL = b"__rotate__"


class HonestSigner(StateMachineAgent):
    """An agent that signs, rotates its key once, then signs again.

    Example::

        agent = HonestSigner(peer=AgentId("signer-1"), rotate_at=10.0)
    """

    def __init__(self, peer: AgentId, rotate_at: float) -> None:
        self._peer = peer
        self._rotate_at = rotate_at

    async def on_start(self, ctx: AgentContext) -> None:
        """Announce the initial key, send a pre-rotation signed message, schedule rotation.

        Example::

            await agent.on_start(ctx)
        """
        identity = ctx.plugins.get("identity")
        if identity is None:
            return
        identity.advance_to(ctx.time)
        await ctx.broadcast(
            encode_identity(
                ctx.agent_id, identity.current_key_id, identity.public_key, ctx.time
            ).encode("utf-8")
        )
        body = f"{ctx.agent_id}-pre".encode()
        sig = identity.sign(body)
        await ctx.send(self._peer, encode_signed(ctx.agent_id, body, sig.value).encode("utf-8"))
        await ctx.schedule(self._rotate_at, _ROTATE_SIGNAL)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On the scheduled signal, rotate the key and sign a post-rotation message.

        Example::

            await agent.on_message(ctx, ctx.agent_id, b"__rotate__")
        """
        if payload != _ROTATE_SIGNAL:
            return
        identity = ctx.plugins.get("identity")
        if identity is None:
            return
        identity.advance_to(ctx.time)
        identity.rotate_key()
        await ctx.broadcast(encode_rotation_event(identity.rotation_announcement()).encode("utf-8"))
        body = f"{ctx.agent_id}-post".encode()
        sig = identity.sign(body)
        await ctx.send(self._peer, encode_signed(ctx.agent_id, body, sig.value).encode("utf-8"))


def identity_rotation_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create signer agents arranged in a ring, with per-agent rotating identities.

    Example::

        agents = identity_rotation_factory(config, plugins)
    """
    count = config.agents.count
    ids = [AgentId(f"signer-{i}") for i in range(count)]
    rotate_at = float(config.task.config.get("rotate_at_tick", 10))

    _instantiate_identities(plugins, ids)

    agents: dict[AgentId, StateMachineAgent] = {}
    for i, aid in enumerate(ids):
        peer = ids[(i + 1) % count]
        agents[aid] = HonestSigner(peer=peer, rotate_at=rotate_at)
    return agents


def _instantiate_identities(plugins: dict[str, Any], ids: list[AgentId]) -> None:
    """Build one rotating-identity instance per agent and cross-register initial keys.

    Mirrors the per-agent identity wiring in nest-core's marketplace factory:
    instances are stored under ``plugins["_agent_plugins"]`` for the runner to
    apply as per-agent overrides.

    Example::

        _instantiate_identities(plugins, [AgentId("signer-0")])
    """
    identity_cls = plugins.get("identity")
    if identity_cls is None or not isinstance(identity_cls, type):
        return
    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    identities: dict[AgentId, Any] = {aid: identity_cls(aid, seed=SCENARIO_SEED) for aid in ids}
    for aid, ident in identities.items():
        for peer_id, peer_ident in identities.items():
            if peer_id != aid:
                ident.register_peer(peer_id, peer_ident.public_key)
        agent_plugins.setdefault(aid, {})["identity"] = ident
