# SPDX-License-Identifier: Apache-2.0
"""Run nest-adapters scenarios on the Nanda Town simulator.

Scenario factories are registered with ``nest_core`` by name; the stock ``nest``
CLI only knows its built-ins, so this module registers ours first and then
drives the standard ``ScenarioRunner``. Use it as a library
(:func:`run_scenario`) or as ``python -m nest_adapters.run <scenario.yaml>``.

Example::

    from nest_adapters.run import run_scenario
    trace = run_scenario("scenarios/identity_rotation.yaml")
"""

from __future__ import annotations

import argparse
import asyncio
from typing import TYPE_CHECKING

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.scenarios import register_scenario

if TYPE_CHECKING:
    from pathlib import Path


def register_scenarios() -> None:
    """Register every nest-adapters scenario factory with nest_core.

    Example::

        register_scenarios()
    """
    from nest_adapters.scenarios_builtin.identity_rotation import identity_rotation_factory
    from nest_adapters.scenarios_builtin.registry_discovery import registry_discovery_factory
    from nest_adapters.scenarios_builtin.reputation_receipts import (
        reputation_receipts_factory,
    )

    register_scenario("registry_discovery", registry_discovery_factory)
    register_scenario("identity_rotation", identity_rotation_factory)
    register_scenario("reputation_receipts", reputation_receipts_factory)


def run_config(config: ScenarioConfig) -> Path:
    """Register scenarios and run a fully-built config, returning the trace path.

    Example::

        trace = run_config(ScenarioConfig.from_yaml("scenarios/identity_rotation.yaml"))
    """
    register_scenarios()
    return asyncio.run(ScenarioRunner(config).run())


def run_scenario(
    path: str | Path, *, seed: int | None = None, out: str | Path | None = None
) -> Path:
    """Load a scenario YAML (optionally overriding seed/output) and run it.

    Example::

        trace = run_scenario("scenarios/identity_rotation.yaml", seed=7)
    """
    config = ScenarioConfig.from_yaml(str(path))
    if seed is not None:
        config = config.model_copy(update={"seed": seed})
    if out is not None:
        config.output.trace = str(out)
    return run_config(config)


def main() -> None:
    """CLI entry point: ``python -m nest_adapters.run <scenario.yaml>``.

    Example::

        main()
    """
    parser = argparse.ArgumentParser(description="Run a nest-adapters scenario.")
    parser.add_argument("scenario", help="Path to a scenario YAML file.")
    parser.add_argument("--seed", type=int, default=None, help="Override the scenario seed.")
    parser.add_argument("-o", "--out", default=None, help="Override the output trace path.")
    args = parser.parse_args()
    trace = run_scenario(args.scenario, seed=args.seed, out=args.out)
    print(f"Trace written to: {trace}")


if __name__ == "__main__":
    main()
