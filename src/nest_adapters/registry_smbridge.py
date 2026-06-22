# SPDX-License-Identifier: Apache-2.0
"""NANDA-AgentFacts registry for Nanda Town (NEST) — the "nest-bridge" registry plugin.

Implements ``nest_core.layers.registry.Registry`` on top of the published
``sm-bridge`` library. Where the reference ``in_memory`` plugin stores a bare
``AgentCard``, this plugin projects every registered card to a **canonical NANDA
AgentFacts** (``SmAgentFacts``) — so discovery in a Nanda Town run speaks the
real NANDA discovery format (did:key identity, NANDA capabilities/endpoints),
the same shape an Orrery agent serves at ``/agentfacts.json`` and ``/sm-bridge/index``.

Two properties make this more than a reskin of the reference plugin:

* **Registration is a conformance gate.** ``register`` builds the card's
  ``SmAgentFacts`` first; a card that cannot be expressed as valid NANDA
  AgentFacts is rejected (``ValueError``), not stored.
* **One identity per agent.** Each card's AgentFacts ``id`` is
  :func:`nest_adapters.identity_didkey.did_for` of the agent — the *same*
  did:key the ``ed25519_didkey`` identity layer derives — so the Registry and
  Identity layers agree on a single did:key per agent.

``lookup`` / ``subscribe`` / ``deregister`` keep the reference plugin's
capability/name-pattern semantics so this is a drop-in ``registry`` layer.
:meth:`agentfacts` and :meth:`index` expose the canonical AgentFacts (the
in-process analogue of the HTTP discovery surfaces).

Registered under ``("registry", "sm_bridge_facts")`` via entry points.

Example::

    reg = SmBridgeRegistry()
    await reg.register(AgentCard(agent_id=AgentId("a1"), name="A1", capabilities=["sell"]))
    facts = reg.agentfacts(AgentId("a1"))   # canonical NANDA AgentFacts, id == did:key
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from nest_core.types import AgentCard, AgentId, Query
from sm_bridge import SmAgentFacts

from nest_adapters.identity_didkey import did_for

# Provider recorded in every AgentFacts: these agents live in a Nanda Town run.
_PROVIDER_NAME = "nanda-town"
_PROVIDER_URL = "https://nandatown.projectnanda.org"


def _skill_urn(capability: str) -> str:
    """Map a NEST capability string to a NANDA skill URN."""
    return f"urn:nanda:skill:{capability.lower().replace(' ', '-')}"


def card_to_agentfacts(card: AgentCard) -> SmAgentFacts:
    """Project a NEST ``AgentCard`` to a canonical NANDA ``SmAgentFacts``.

    The AgentFacts ``id`` is the agent's deterministic did:key
    (:func:`did_for`), so it matches the ``ed25519_didkey`` identity layer.
    Raises whatever ``sm-bridge`` raises if the card is not expressible as
    valid AgentFacts.

    Example::

        facts = card_to_agentfacts(AgentCard(agent_id=AgentId("a1"), name="A1"))
    """
    did = did_for(card.agent_id)
    skill_urns = [_skill_urn(cap) for cap in card.capabilities]
    # Built as a dict and validated through sm-bridge's canonical model. (Going
    # via ``model_validate`` rather than the typed constructor keeps optional
    # AgentFacts fields — which the upstream models default at runtime but don't
    # expose statically — from tripping the strict type checkers.)
    data: dict[str, Any] = {
        "id": did,
        "agent_name": str(card.agent_id),
        "label": card.name,
        "description": card.name or str(card.agent_id),
        "version": "1.0.0",
        "provider": {"name": _PROVIDER_NAME, "url": _PROVIDER_URL, "did": did},
        "endpoints": {"static": [card.endpoint]} if card.endpoint else {},
        "capabilities": {
            "modalities": ["text"],
            "skills": skill_urns,
            "authentication": {"methods": ["ed25519", "did-auth"]},
        },
        "skills": [
            {"id": urn, "description": cap}
            for urn, cap in zip(skill_urns, card.capabilities, strict=True)
        ],
    }
    return SmAgentFacts.model_validate(data)


class SmBridgeRegistry:
    """Registry layer whose discovery format is canonical NANDA AgentFacts.

    No-arg-callable, like the reference plugin: the NEST runner does
    ``registry_cls()`` with no injected state.

    Example::

        reg = SmBridgeRegistry()
        await reg.register(AgentCard(agent_id=AgentId("a1"), name="A1"))
        results = await reg.lookup(Query(capabilities=["sell"]))
    """

    def __init__(self) -> None:
        self._cards: dict[AgentId, AgentCard] = {}
        self._subscribers: list[asyncio.Queue[AgentCard]] = []

    async def register(self, card: AgentCard) -> None:
        """Register an agent — but only if it is expressible as valid NANDA AgentFacts.

        The AgentFacts is built before the card is stored, so a card that cannot
        be projected is rejected rather than silently kept.

        Example::

            await reg.register(card)
        """
        try:
            card_to_agentfacts(card)
        except Exception as exc:
            msg = f"card for {card.agent_id!r} is not expressible as NANDA AgentFacts: {exc}"
            raise ValueError(msg) from exc
        self._cards[card.agent_id] = card
        for q in self._subscribers:
            await q.put(card)

    async def lookup(self, query: Query) -> list[AgentCard]:
        """Return registered cards matching ``query`` (capabilities + name pattern).

        Example::

            results = await reg.lookup(Query(capabilities=["sell"]))
        """
        return [card for card in self._cards.values() if self._matches(card, query)]

    async def subscribe(self, query: Query) -> AsyncIterator[AgentCard]:
        """Yield each newly-registered card matching ``query``.

        Example::

            async for card in reg.subscribe(query):
                print(card.name)
        """
        q: asyncio.Queue[AgentCard] = asyncio.Queue()
        self._subscribers.append(q)
        try:
            while True:
                card = await q.get()
                if self._matches(card, query):
                    yield card
        finally:
            self._subscribers.remove(q)

    async def deregister(self, agent: AgentId) -> None:
        """Remove an agent from the registry.

        Example::

            await reg.deregister(AgentId("a1"))
        """
        self._cards.pop(agent, None)

    def agentfacts(self, agent: AgentId) -> dict[str, Any] | None:
        """Canonical NANDA AgentFacts for one agent as a JSON dict, or ``None``.

        Example::

            facts = reg.agentfacts(AgentId("a1"))
        """
        card = self._cards.get(agent)
        if card is None:
            return None
        return card_to_agentfacts(card).model_dump(mode="json", exclude_none=True)

    def index(self) -> list[dict[str, Any]]:
        """Every registered agent as canonical NANDA AgentFacts (``/sm-bridge/index``).

        Example::

            for facts in reg.index():
                assert facts["id"].startswith("did:key:")
        """
        return [
            card_to_agentfacts(card).model_dump(mode="json", exclude_none=True)
            for card in self._cards.values()
        ]

    @staticmethod
    def _matches(card: AgentCard, query: Query) -> bool:
        if query.capabilities and not all(cap in card.capabilities for cap in query.capabilities):
            return False
        return not (query.name_pattern and query.name_pattern not in card.name)
