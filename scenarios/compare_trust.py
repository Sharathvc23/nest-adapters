# SPDX-License-Identifier: Apache-2.0
"""Comparison harness — ``agent_receipts`` vs ``score_average`` on reputation_receipts.

Runs the ``reputation_receipts`` scenario twice on the **same seed**, swapping
only the trust layer, then queries ``await trust.score(aid)`` for every agent and
emits a detection table. The headline metric is the **malicious detection rate**:

* ``score_average`` cannot tell the wash-trading ring from honest agents (both
  emit ``kind="positive"`` evidence), so the ring's mutual-positive reports keep
  it at the top of the running mean — **0/4 caught**.
* ``agent_receipts`` runs VRP severance over the global corroboration graph: the
  isolated dense ring is severed, dropping to score 0 / confidence 0, while the
  honest anchor SCC keeps its score — **4/4 caught**.

A "catch" is ``score < GATE`` where ``GATE = 0.2`` is the marketplace plugin's
own reputation gate (``rep.score < 0.2`` in nest-core's marketplace seller).

Run as a regression gate::

    python scenarios/compare_trust.py        # prints table, exits nonzero on regression

Or import :func:`run_comparison` / :func:`assert_detection` from tests.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig

from nest_adapters.run import register_scenarios
from nest_adapters.scenarios_builtin.reputation_receipts import honest_ids, ring_ids

if TYPE_CHECKING:
    from nest_core.types import AgentId

# The marketplace seller's reputation gate (nest-core marketplace.py: rep.score < 0.2).
GATE = 0.2

_SCENARIO = Path(__file__).parent / "reputation_receipts.yaml"


@dataclass(frozen=True)
class AgentScores:
    """One agent's reputation under each trust plugin."""

    agent_id: str
    is_malicious: bool
    avg_score: float
    avg_conf: float
    arp_score: float
    arp_conf: float


async def _run_once(trust_name: str, seed: int, out: Path) -> dict[str, tuple[float, float, int]]:
    """Run reputation_receipts under one trust plugin; return per-agent (score, conf, n)."""
    register_scenarios()
    config = ScenarioConfig.from_yaml(str(_SCENARIO))
    config = config.model_copy(
        update={"layers": config.layers.model_copy(update={"trust": trust_name})}
    )
    config = config.model_copy(update={"seed": seed})
    config.output.trace = str(out)

    runner = ScenarioRunner(config)
    await runner.run()
    trust = runner.resolved_plugins["trust"]

    all_ids: list[AgentId] = honest_ids() + ring_ids()
    result: dict[str, tuple[float, float, int]] = {}
    for aid in all_ids:
        rep = await trust.score(aid)
        result[str(aid)] = (rep.score, rep.confidence, rep.sample_count)
    return result


async def run_comparison(seed: int = 42, out_dir: Path | None = None) -> list[AgentScores]:
    """Run the scenario under both trust plugins (same seed) and pair the scores.

    Example::

        rows = await run_comparison(seed=42)
    """
    ring = {str(a) for a in ring_ids()}
    if out_dir is None:
        tmp = tempfile.mkdtemp(prefix="compare_trust_")
        out_dir = Path(tmp)

    avg = await _run_once("score_average", seed, out_dir / "score_average.jsonl")
    arp = await _run_once("agent_receipts", seed, out_dir / "agent_receipts.jsonl")

    rows: list[AgentScores] = []
    for aid in honest_ids() + ring_ids():
        key = str(aid)
        a_score, a_conf, _ = avg[key]
        r_score, r_conf, _ = arp[key]
        rows.append(
            AgentScores(
                agent_id=key,
                is_malicious=key in ring,
                avg_score=a_score,
                avg_conf=a_conf,
                arp_score=r_score,
                arp_conf=r_conf,
            )
        )
    return rows


def format_table(rows: list[AgentScores]) -> str:
    """Render the detection table + headline detection rates as text.

    Example::

        print(format_table(rows))
    """
    lines: list[str] = []
    lines.append(
        f"{'agent':<12} {'kind':<9} "
        f"{'avg.score':>9} {'avg.conf':>9} | "
        f"{'arp.score':>9} {'arp.conf':>9}  detection"
    )
    lines.append("-" * 78)
    malicious = [r for r in rows if r.is_malicious]
    honest = [r for r in rows if not r.is_malicious]
    # Show all malicious, plus a few honest for context.
    shown = honest[:4] + malicious
    for r in shown:
        kind = "MALICIOUS" if r.is_malicious else "honest"
        caught_avg = "caught" if r.avg_score < GATE else "MISSED"
        caught_arp = "caught" if r.arp_score < GATE else "MISSED"
        det = ""
        if r.is_malicious:
            det = f"avg={caught_avg} arp={caught_arp}"
        else:
            # For honest agents the concern is false positives (collateral damage).
            fp_avg = "FP" if r.avg_score < GATE else "ok"
            fp_arp = "FP" if r.arp_score < GATE else "ok"
            det = f"avg={fp_avg} arp={fp_arp}"
        lines.append(
            f"{r.agent_id:<12} {kind:<9} "
            f"{r.avg_score:>9.3f} {r.avg_conf:>9.3f} | "
            f"{r.arp_score:>9.3f} {r.arp_conf:>9.3f}  {det}"
        )

    avg_caught = sum(1 for r in malicious if r.avg_score < GATE)
    arp_caught = sum(1 for r in malicious if r.arp_score < GATE)
    avg_fp = sum(1 for r in honest if r.avg_score < GATE)
    arp_fp = sum(1 for r in honest if r.arp_score < GATE)
    n_mal = len(malicious)
    n_hon = len(honest)
    lines.append("-" * 78)
    lines.append(
        f"malicious detection rate:  score_average {avg_caught}/{n_mal}   "
        f"agent_receipts {arp_caught}/{n_mal}"
    )
    lines.append(
        f"honest false positives:    score_average {avg_fp}/{n_hon}   "
        f"agent_receipts {arp_fp}/{n_hon}"
    )
    return "\n".join(lines)


def assert_detection(rows: list[AgentScores]) -> None:
    """Assert the proof outcome; raise ``AssertionError`` (nonzero exit) on regression.

    Required outcome at ``GATE = 0.2``:

    * ``score_average``: 0/4 malicious caught (all ring agents score >= GATE).
    * ``agent_receipts``: 4/4 malicious caught (all ring agents score < GATE)
      AND 0 honest false positives (all honest agents score >= GATE).

    Example::

        assert_detection(await run_comparison())
    """
    malicious = [r for r in rows if r.is_malicious]
    honest = [r for r in rows if not r.is_malicious]
    assert len(malicious) == 4, f"expected 4 malicious agents, got {len(malicious)}"
    assert len(honest) == 16, f"expected 16 honest agents, got {len(honest)}"

    # score_average is fooled: every ring agent escapes the gate.
    avg_missed = [r.agent_id for r in malicious if r.avg_score >= GATE]
    assert len(avg_missed) == 4, (
        f"score_average should miss all 4 malicious (0/4 caught); escaped={avg_missed}"
    )

    # agent_receipts catches all 4.
    arp_caught = [r.agent_id for r in malicious if r.arp_score < GATE]
    assert len(arp_caught) == 4, (
        f"agent_receipts should catch all 4 malicious (4/4); "
        f"caught={arp_caught}, scores="
        f"{[(r.agent_id, round(r.arp_score, 3)) for r in malicious]}"
    )

    # ...with collapsed confidence (corroboration_rate) on the severed ring.
    arp_conf_collapsed = [r.agent_id for r in malicious if r.arp_conf == 0.0]
    assert len(arp_conf_collapsed) == 4, (
        f"severed ring should have confidence 0.0; "
        f"confs={[(r.agent_id, round(r.arp_conf, 3)) for r in malicious]}"
    )

    # Zero honest false positives under agent_receipts (honest anchor retained).
    arp_fp = [r.agent_id for r in honest if r.arp_score < GATE]
    assert len(arp_fp) == 0, f"agent_receipts must not flag honest agents (0 FPs); flagged={arp_fp}"


def main() -> int:
    """Run the comparison, print the table, and gate on the proof outcome.

    Returns a process exit code: ``0`` on the expected 4/4-vs-0/4 outcome,
    ``1`` if the assertion fails (a real regression).

    Example::

        raise SystemExit(main())
    """
    rows = asyncio.run(run_comparison())
    print(format_table(rows))  # noqa: T201
    try:
        assert_detection(rows)
    except AssertionError as exc:
        print(f"\nREGRESSION: {exc}", file=sys.stderr)  # noqa: T201
        return 1
    print("\nOK: malicious detection 4/4 (agent_receipts) vs 0/4 (score_average).")  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
