# SPDX-License-Identifier: Apache-2.0
"""Tests for the sm-arp DataFacts adapter + the datafacts_provenance scenario.

Assert the headline properties — provenance is a signed ARP receipt attributable
to the owner's did:key, ``fetch`` is a tamper gate, and grants are signed — plus
that the bundled scenario runs and agents access peers' datasets.
"""

from __future__ import annotations

from pathlib import Path

from nest_core.layers.datafacts import DataFacts
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata
from sm_arp.receipts import verify_receipt

from nest_adapters.datafacts_arp import ArpDataFacts, content_hash
from nest_adapters.identity_didkey import did_for
from nest_adapters.run import run_scenario

SCENARIO = Path(__file__).parent.parent / "scenarios" / "datafacts_provenance.yaml"


def _meta(name: str = "weather", owner: str = "a1") -> DatasetMetadata:
    return DatasetMetadata(name=name, owner=AgentId(owner), checksum=f"sha256:{name}")


# -- content commitment -------------------------------------------------------


def test_content_hash_is_deterministic_and_sensitive() -> None:
    a = content_hash(_meta())
    assert a == content_hash(_meta())  # stable
    assert a.startswith("sha256:")
    assert a != content_hash(_meta(name="weather-2"))  # changes with content


def test_runtime_checkable_datafacts_protocol() -> None:
    assert isinstance(ArpDataFacts(), DataFacts)


# -- provenance + integrity ---------------------------------------------------


async def test_publish_provenance_is_owner_signed_receipt() -> None:
    df = ArpDataFacts()
    url = await df.publish(_meta(owner="alice"))
    receipt = df.provenance(url)
    assert receipt is not None
    assert verify_receipt(receipt).ok
    # Provenance is attributable to the owner's did:key (the identity layer's did).
    assert receipt["principal_did"] == did_for(AgentId("alice"))


async def test_fetch_returns_metadata_when_intact() -> None:
    df = ArpDataFacts()
    url = await df.publish(_meta(name="weather"))
    meta = await df.fetch(url)
    assert meta.name == "weather"
    assert await df.verify_freshness(url) is True


async def test_fetch_rejects_tampered_content() -> None:
    df = ArpDataFacts()
    url = await df.publish(_meta(name="weather"))
    # Mutate the stored dataset out from under its signed commitment.
    df._datasets[url].description = "TAMPERED"
    try:
        await df.fetch(url)
    except ValueError as exc:
        assert "tampered" in str(exc)
    else:
        raise AssertionError("tampered content was served — integrity gate failed")


async def test_fetch_unknown_raises_keyerror() -> None:
    df = ArpDataFacts()
    try:
        await df.fetch(DataFactsUrl("df://ghost"))
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for unknown dataset")


# -- access grants ------------------------------------------------------------


async def test_request_access_records_a_signed_grant_receipt() -> None:
    df = ArpDataFacts()
    url = await df.publish(_meta(owner="alice"))
    grant = await df.request_access(url, AgentId("bob"))
    assert grant.grantee == AgentId("bob")
    assert grant.tier == "read"
    receipts = df._grant_receipts[url]
    assert len(receipts) == 1
    assert verify_receipt(receipts[0]).ok
    assert receipts[0]["action"]["category"] == "authority_granted"


# -- scenario -----------------------------------------------------------------


def test_scenario_runs_and_agents_access_peer_datasets(tmp_path: Path) -> None:
    trace = run_scenario(SCENARIO, out=tmp_path / "trace.jsonl")
    lines = trace.read_text(encoding="utf-8").splitlines()
    access = [line for line in lines if "accessed" in line]
    assert access, "no access events — integrity-gated fetch + grant produced nothing"
