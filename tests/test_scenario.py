# SPDX-License-Identifier: Apache-2.0
"""End-to-end scenario tests: the identity_rotation scenario runs deterministically
under the seed bank and passes its own validator."""

from __future__ import annotations

from pathlib import Path

from nest_stellarminds.run import run_scenario
from nest_stellarminds.validators import validate_identity_rotation

SCENARIO = Path(__file__).parent.parent / "scenarios" / "identity_rotation.yaml"


def test_scenario_runs_and_writes_trace(tmp_path: Path) -> None:
    out = tmp_path / "t.jsonl"
    trace = run_scenario(SCENARIO, out=out)
    assert trace.exists()
    assert trace.read_text().strip() != ""


def test_scenario_is_deterministic_per_seed(tmp_path: Path) -> None:
    a = run_scenario(SCENARIO, seed=42, out=tmp_path / "a.jsonl").read_bytes()
    b = run_scenario(SCENARIO, seed=42, out=tmp_path / "b.jsonl").read_bytes()
    assert a == b  # same seed -> byte-identical trace


def test_scenario_replays_under_seed_bank(tmp_path: Path) -> None:
    # Each seed in the bank must produce a stable, validating trace.
    for seed in (42, 7, 1337):
        trace = run_scenario(SCENARIO, seed=seed, out=tmp_path / f"{seed}.jsonl")
        results = validate_identity_rotation(trace)
        assert all(r.passed for r in results), [str(r) for r in results if not r.passed]


def test_validator_passes_on_our_trace(tmp_path: Path) -> None:
    trace = run_scenario(SCENARIO, out=tmp_path / "t.jsonl")
    results = validate_identity_rotation(trace)
    names = {r.name: r.passed for r in results}
    assert names["identity_rotation_real_windows"] is True
    assert names["identity_rotation_no_out_of_window_use"] is True
