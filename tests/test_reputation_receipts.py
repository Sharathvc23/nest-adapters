# SPDX-License-Identifier: Apache-2.0
"""Benchmark tests for the reputation_receipts scenario + compare_trust harness.

These assert the headline proof — ``agent_receipts`` catches the wash-trading
collusion ring (4/4) where ``score_average`` does not (0/4) — plus the topology
invariants that make VRP severance fire, and per-plugin determinism.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from sm_arp.receipts import verify_receipt
from sm_arp.vrp import (
    _corroboration_graph,  # noqa: PLC2701  (sibling-controlled dep; topology assertion)
    _internal_density,  # noqa: PLC2701
    _sccs,  # noqa: PLC2701
    _severed_dids,  # noqa: PLC2701
)

from nest_adapters.identity_didkey import did_for
from nest_adapters.run import run_scenario
from nest_adapters.scenarios_builtin.reputation_receipts import (
    HONEST_COUNT,
    RING_COUNT,
    build_topology,
    honest_ids,
    make_corroborated_receipt,
    ring_ids,
)

SCENARIO = Path(__file__).parent.parent / "scenarios" / "reputation_receipts.yaml"

# Import the comparator module by path (it lives under scenarios/, not the package).
_COMPARE_PATH = Path(__file__).parent.parent / "scenarios" / "compare_trust.py"
_spec = importlib.util.spec_from_file_location("compare_trust", _COMPARE_PATH)
assert _spec is not None and _spec.loader is not None
compare_trust = importlib.util.module_from_spec(_spec)
sys.modules["compare_trust"] = compare_trust
_spec.loader.exec_module(compare_trust)


# -- topology invariants (the preconditions for VRP severance) ----------------


def test_topology_severs_exactly_the_ring() -> None:
    """The full corroboration graph severs exactly the 4 ring dids — no more, no less."""
    valid = lambda r: verify_receipt(r).ok  # noqa: E731
    ledger = [make_corroborated_receipt(i, c) for i, c in build_topology()]
    graph = _corroboration_graph(ledger, is_valid=valid)
    severed = _severed_dids(graph)
    ring_dids = {did_for(a) for a in ring_ids()}
    assert severed == ring_dids


def test_ring_is_a_dense_clique_and_honest_is_the_largest_scc() -> None:
    """Ring density must be >= 0.8 (a 4-cycle's 0.667 would NOT sever), and the
    honest core must be the single largest SCC (the VRP anchor)."""
    valid = lambda r: verify_receipt(r).ok  # noqa: E731
    ledger = [make_corroborated_receipt(i, c) for i, c in build_topology()]
    graph = _corroboration_graph(ledger, is_valid=valid)
    comps = _sccs(graph)
    sizes = sorted((len(c) for c in comps), reverse=True)
    assert sizes == [HONEST_COUNT, RING_COUNT]  # one honest SCC of 16, one ring of 4

    ring_dids = {did_for(a) for a in ring_ids()}
    ring_comp = next(set(c) for c in comps if set(c) & ring_dids)
    assert _internal_density(graph, ring_comp) >= 0.8
    assert _internal_density(graph, ring_comp) == 1.0  # complete clique


def test_no_cross_edges_between_honest_and_ring() -> None:
    """The ring must be isolated: zero corroborated edges to the honest core."""
    honest = {did_for(a) for a in honest_ids()}
    ring = {did_for(a) for a in ring_ids()}
    for issuer, cp in build_topology():
        di, dc = did_for(issuer), did_for(cp)
        crosses = (di in honest and dc in ring) or (di in ring and dc in honest)
        assert not crosses, f"cross-edge {issuer}->{cp} would defeat severance"


# -- scenario determinism (same seed -> byte-identical trace) -----------------


@pytest.mark.parametrize("trust", ["agent_receipts", "score_average"])
def test_scenario_is_deterministic_per_plugin(trust: str, tmp_path: Path) -> None:
    from nest_core.scenario import ScenarioConfig

    from nest_adapters.run import run_config

    def run(out: Path) -> bytes:
        cfg = ScenarioConfig.from_yaml(str(SCENARIO))
        cfg = cfg.model_copy(update={"layers": cfg.layers.model_copy(update={"trust": trust})})
        cfg = cfg.model_copy(update={"seed": 42})
        cfg.output.trace = str(out)
        return run_config(cfg).read_bytes()

    a = run(tmp_path / "a.jsonl")
    b = run(tmp_path / "b.jsonl")
    assert a == b


def test_scenario_runs_and_writes_nonempty_trace(tmp_path: Path) -> None:
    trace = run_scenario(SCENARIO, out=tmp_path / "t.jsonl")
    assert trace.exists()
    assert trace.read_text().strip() != ""


# -- the headline proof: 4/4 vs 0/4 -------------------------------------------


@pytest.mark.asyncio
async def test_detection_rate_4_of_4_vs_0_of_4() -> None:
    rows = await compare_trust.run_comparison(seed=42)
    # Should not raise — encodes 4/4 caught (arp), 0/4 caught (avg), 0 honest FPs.
    compare_trust.assert_detection(rows)

    malicious = [r for r in rows if r.is_malicious]
    honest = [r for r in rows if not r.is_malicious]
    gate = compare_trust.GATE

    assert sum(1 for r in malicious if r.arp_score < gate) == 4
    assert sum(1 for r in malicious if r.avg_score < gate) == 0
    assert all(r.arp_conf == 0.0 for r in malicious)  # collapsed confidence
    assert all(r.arp_score >= gate for r in honest)  # honest retained


@pytest.mark.asyncio
async def test_comparison_is_seed_stable() -> None:
    """Same seed -> identical score rows across two comparison runs."""
    a = await compare_trust.run_comparison(seed=42)
    b = await compare_trust.run_comparison(seed=42)
    assert {(r.agent_id, r.arp_score, r.avg_score) for r in a} == {
        (r.agent_id, r.arp_score, r.avg_score) for r in b
    }
