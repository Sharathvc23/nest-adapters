# SPDX-License-Identifier: Apache-2.0
"""Tests for the sm-bridge registry adapter + the registry_discovery scenario.

Assert the headline property — discovery is over canonical NANDA AgentFacts whose
``id`` is the agent's did:key, agreeing with the ``ed25519_didkey`` identity
layer — plus the reference registry semantics (capability/name lookup,
subscribe, deregister) and that the bundled scenario runs and discovers peers.
"""

from __future__ import annotations

from pathlib import Path

from nest_core.layers.registry import Registry
from nest_core.types import AgentCard, AgentId, Query

from nest_adapters.identity_didkey import did_for
from nest_adapters.registry_smbridge import SmBridgeRegistry, card_to_agentfacts
from nest_adapters.run import run_scenario

SCENARIO = Path(__file__).parent.parent / "scenarios" / "registry_discovery.yaml"


def _card(agent: str, *, name: str | None = None, caps: list[str] | None = None) -> AgentCard:
    return AgentCard(
        agent_id=AgentId(agent),
        name=name if name is not None else agent,
        capabilities=caps or [],
    )


# -- canonical AgentFacts projection ------------------------------------------


def test_agentfacts_id_is_the_agents_didkey() -> None:
    """The projected AgentFacts id == the identity layer's did:key for the agent."""
    facts = card_to_agentfacts(_card("a1", caps=["sell_data"]))
    assert facts.id == did_for(AgentId("a1"))
    assert facts.id.startswith("did:key:z")


def test_agentfacts_is_valid_smagentfacts_with_capabilities_as_skills() -> None:
    """Capabilities become NANDA skill URNs; auth is ed25519, not hmac."""
    facts = card_to_agentfacts(_card("a1", name="Alice", caps=["sell_data", "rank"]))
    assert facts.agent_name == "a1"
    assert facts.label == "Alice"
    assert [s.id for s in facts.skills] == ["urn:nanda:skill:sell_data", "urn:nanda:skill:rank"]
    assert facts.capabilities.authentication is not None
    assert "ed25519" in facts.capabilities.authentication.methods


def test_runtime_checkable_registry_protocol() -> None:
    """SmBridgeRegistry structurally satisfies the NEST Registry Protocol."""
    assert isinstance(SmBridgeRegistry(), Registry)


# -- registry semantics -------------------------------------------------------


async def test_register_then_lookup_by_capability() -> None:
    reg = SmBridgeRegistry()
    await reg.register(_card("seller", caps=["sell_data"]))
    await reg.register(_card("other", caps=["analyze"]))

    hits = await reg.lookup(Query(capabilities=["sell_data"]))
    assert [c.agent_id for c in hits] == [AgentId("seller")]


async def test_lookup_by_name_pattern() -> None:
    reg = SmBridgeRegistry()
    await reg.register(_card("data-seller", name="DataSeller"))
    await reg.register(_card("buyer", name="Buyer"))

    hits = await reg.lookup(Query(name_pattern="Data"))
    assert [c.agent_id for c in hits] == [AgentId("data-seller")]


async def test_index_exposes_every_agent_as_didkey_agentfacts() -> None:
    reg = SmBridgeRegistry()
    for a in ("a1", "a2", "a3"):
        await reg.register(_card(a, caps=["x"]))

    index = reg.index()
    assert len(index) == 3
    assert all(f["id"].startswith("did:key:z") for f in index)
    assert {f["id"] for f in index} == {did_for(AgentId(a)) for a in ("a1", "a2", "a3")}


async def test_agentfacts_for_unknown_agent_is_none() -> None:
    reg = SmBridgeRegistry()
    assert reg.agentfacts(AgentId("ghost")) is None


async def test_deregister_removes_the_agent() -> None:
    reg = SmBridgeRegistry()
    await reg.register(_card("a1", caps=["x"]))
    await reg.deregister(AgentId("a1"))
    assert await reg.lookup(Query(capabilities=["x"])) == []
    assert reg.agentfacts(AgentId("a1")) is None


# -- scenario -----------------------------------------------------------------


def test_scenario_runs_and_discovers_peers(tmp_path: Path) -> None:
    """The registry_discovery scenario runs over sm_bridge_facts and the agents
    actually discover + greet peers (a non-empty set of greeting events)."""
    trace = run_scenario(SCENARIO, out=tmp_path / "trace.jsonl")
    lines = trace.read_text(encoding="utf-8").splitlines()
    greetings = [line for line in lines if "hello" in line]
    assert greetings, "no greeting events — discovery through the registry produced nothing"
