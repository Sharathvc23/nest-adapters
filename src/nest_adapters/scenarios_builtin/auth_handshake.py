# SPDX-License-Identifier: Apache-2.0
"""auth_handshake scenario — did:key tokens issued, presented, and verified.

Each agent issues a token for itself (signed by its own Ed25519 key via the Auth
layer) and presents it to a peer. The peer verifies the token against the
subject's did:key and, if it carries the ``read`` scope, replies with a grant.

With ``auth: did_key`` (this repo's :class:`DidAuth`) the verification is a real
signature check against ``pubkey_from_did`` — no shared secret — so a grant in
the trace means the presenter genuinely holds the key for the did it claims. Swap
``auth: jwt`` and the agent logic is identical.

Example::

    from nest_core.scenarios import register_scenario
    register_scenario("auth_handshake", auth_handshake_factory)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

if TYPE_CHECKING:
    from nest_core.scenario import ScenarioConfig

_SCOPE = "read"
# Grant replies are prefixed so a peer doesn't try to verify them as tokens.
_GRANT_PREFIX = "granted:"


class AuthAgent(StateMachineAgent):
    """Presents a self-issued token to ``peer``; grants on verifying a peer's.

    Example::

        agent = AuthAgent(peer=AgentId("agent-1"))
    """

    def __init__(self, peer: AgentId) -> None:
        self._peer = peer

    async def on_start(self, ctx: AgentContext) -> None:
        """Issue a token signed by this agent's did:key and present it to ``peer``.

        Example::

            await agent.on_start(ctx)
        """
        auth = ctx.plugins.get("auth")
        if auth is None:
            return
        token = await auth.issue(ctx.agent_id, [_SCOPE])
        await ctx.send(self._peer, str(token).encode("utf-8"))

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Verify a presented token by did:key and reply with a grant.

        Grant acknowledgements (prefixed) are ignored; anything else is verified
        as a token and, if it carries the scope, answered with a grant — proof
        the signature checked out against the subject's did:key.

        Example::

            await agent.on_message(ctx, AgentId("agent-1"), b"<token>")
        """
        text = payload.decode("utf-8", errors="replace")
        if text.startswith(_GRANT_PREFIX):
            return
        auth = ctx.plugins.get("auth")
        if auth is None:
            return
        try:
            authctx = await auth.verify(Token(text))
        except ValueError:
            return
        if _SCOPE in authctx.scopes:
            reply = f"{_GRANT_PREFIX}{authctx.subject} scopes={authctx.scopes}"
            await ctx.send(authctx.subject, reply.encode("utf-8"))


def auth_handshake_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create agents arranged in a ring, each presenting a token to the next.

    Example::

        agents = auth_handshake_factory(config, plugins)
    """
    _instantiate_auth(plugins)

    count = config.agents.count
    ids = [AgentId(f"agent-{i}") for i in range(count)]
    agents: dict[AgentId, StateMachineAgent] = {}
    for i, aid in enumerate(ids):
        agents[aid] = AuthAgent(peer=ids[(i + 1) % count])
    return agents


def _instantiate_auth(plugins: dict[str, Any]) -> None:
    """Replace the resolved Auth CLASS with one shared instance.

    The simulator shares this instance across agents, so all agents issue and
    verify against the same Auth layer.

    Example::

        _instantiate_auth(plugins)
    """
    if not plugins:
        return
    auth_cls = plugins.get("auth")
    if auth_cls is not None and isinstance(auth_cls, type):
        plugins["auth"] = auth_cls()
