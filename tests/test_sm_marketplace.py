# SPDX-License-Identifier: Apache-2.0
"""Tests for the sm_marketplace scenario — all four sm-* adapters end to end.

Drives Registry + Data Facts + Trust (over the did:key Identity all share) through
one marketplace flow and asserts the headline: a seller that is discovered,
whose data passes the integrity gate, and who is credited by buyers accrues real
corroborated reputation — while an un-transacted stranger stays at the neutral
prior. Plus the bundled scenario runs and produces purchases.
"""

from __future__ import annotations

import json
from pathlib import Path

from nest_core.types import (
    AgentCard,
    AgentId,
    DataFactsUrl,
    DatasetMetadata,
    Evidence,
    Query,
)

from nest_adapters.datafacts_arp import ArpDataFacts
from nest_adapters.registry_smbridge import SmBridgeRegistry
from nest_adapters.run import run_scenario
from nest_adapters.scenarios_builtin.reputation_receipts import make_corroborated_receipt
from nest_adapters.trust_receipts import AgentReceiptsTrust

SCENARIO = Path(__file__).parent.parent / "scenarios" / "sm_marketplace.yaml"


async def test_full_stack_flow_accrues_seller_reputation() -> None:
    """Registry discovery -> DataFacts integrity fetch -> Trust credit, four buyers."""
    registry = SmBridgeRegistry()
    datafacts = ArpDataFacts()
    trust = AgentReceiptsTrust()
    seller = AgentId("seller")

    # Seller lists itself (Registry) and publishes its data with provenance (DataFacts).
    await registry.register(AgentCard(agent_id=seller, name="Seller", capabilities=["sell_data"]))
    await datafacts.publish(DatasetMetadata(name=f"ds-{seller}", owner=seller, checksum="sha256:x"))

    for i in range(4):
        buyer = AgentId(f"buyer-{i}")
        # Discover via the registry...
        hits = await registry.lookup(Query(capabilities=["sell_data"]))
        assert seller in [c.agent_id for c in hits]
        # ...fetch through the integrity gate...
        meta = await datafacts.fetch(DataFactsUrl(f"df://ds-{seller}"))
        assert meta.owner == seller
        # ...and credit the seller with a cross-signed purchase receipt.
        receipt = make_corroborated_receipt(seller, buyer)
        await trust.report(
            seller,
            Evidence(reporter=buyer, subject=seller, kind="positive", detail=json.dumps(receipt)),
        )

    # The seller now carries corroborated reputation; a stranger carries none.
    rep = await trust.score(seller)
    assert rep.sample_count == 4
    assert rep.confidence == 1.0
    assert rep.score > 0.5

    stranger = await trust.score(AgentId("stranger"))
    assert stranger.confidence == 0.0
    assert stranger.sample_count == 0


def test_scenario_runs_full_stack(tmp_path: Path) -> None:
    """The sm_marketplace scenario runs over all four adapters and records purchases."""
    trace = run_scenario(SCENARIO, out=tmp_path / "trace.jsonl")
    lines = trace.read_text(encoding="utf-8").splitlines()
    purchases = [line for line in lines if "bought" in line]
    assert purchases, "no purchase events — the four-layer marketplace flow produced nothing"
