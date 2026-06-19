# SPDX-License-Identifier: Apache-2.0
"""Adversarial validator for the identity layer (Nanda Town problem 5).

Reads a JSONL trace and rebuilds each agent's key history from the identity and
rotation announcements it broadcast, then checks every signed message against
its signing key's validity window *as-of the tick the message was observed*.

It reports two properties:

- ``identity_rotation_real_windows`` — the trace actually exhibits windowed
  identity (≥1 rotation announcement and ≥1 rotating-envelope signature). This
  FAILS against the default ``did_key`` plugin, whose signatures carry no key
  id or validity window at all.
- ``identity_rotation_no_out_of_window_use`` — no signed message was honored
  outside its key's window. This catches post-rotation forgery and backdating.

Example::

    from nest_adapters.validators import validate_identity_rotation
    results = validate_identity_rotation(Path("traces/identity_rotation.jsonl"))
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from nest_core.types import AgentId, Signature
from nest_core.validators import ValidationResult

from nest_adapters.determinism import decode_signature_value
from nest_adapters.identity import ALGORITHM, Ed25519RotatingIdentity
from nest_adapters.wire import KIND_IDENTITY, KIND_ROTATION, KIND_SIGNED, parse_message

_EMITTING_KINDS = frozenset({"send", "broadcast"})


def validate_identity_rotation(trace_path: str | Path) -> list[ValidationResult]:
    """Validate identity-rotation invariants over a JSONL trace.

    Example::

        results = validate_identity_rotation("traces/identity_rotation.jsonl")
    """
    events = _load_events(Path(trace_path))
    verifier = Ed25519RotatingIdentity(AgentId("__validator__"), seed=b"validator")

    rotations = 0
    # Pass 1: learn initial keys, then apply rotations to build full windowed history.
    for event in events:
        parsed = _parsed_ours(event)
        if parsed is None or parsed["k"] != KIND_IDENTITY:
            continue
        verifier.register_peer(AgentId(parsed["agent"]), bytes.fromhex(parsed["pub"]))
    for event in events:
        parsed = _parsed_ours(event)
        if parsed is None or parsed["k"] != KIND_ROTATION:
            continue
        verifier.observe_rotation(parsed["ann"].encode("ascii"))
        rotations += 1

    # Pass 2: every signed message must verify as-of the tick it was observed.
    signed_count = 0
    violations: list[str] = []
    for event in events:
        parsed = _parsed_ours(event)
        if parsed is None or parsed["k"] != KIND_SIGNED:
            continue
        signer = AgentId(parsed["signer"])
        body = bytes.fromhex(parsed["body"])
        sig = Signature(signer=signer, value=parsed["sig"].encode("ascii"), algorithm=ALGORITHM)
        try:
            decode_signature_value(sig.value)
        except ValueError:
            continue  # not a rotating-envelope signature
        signed_count += 1
        as_of = float(cast("float | int | str", event["ts"]))
        if not verifier.verify_as_of(body, sig, signer, as_of=as_of):
            violations.append(f"{signer} sig observed at t={as_of} failed window check")

    real_windows = ValidationResult(
        "identity_rotation_real_windows",
        passed=rotations >= 1 and signed_count >= 1,
        detail=f"{rotations} rotation(s), {signed_count} rotating-signature(s)",
    )
    no_out_of_window = ValidationResult(
        "identity_rotation_no_out_of_window_use",
        passed=not violations,
        detail="; ".join(violations)
        if violations
        else f"all {signed_count} signatures within window",
    )
    return [real_windows, no_out_of_window]


def _load_events(path: Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def _parsed_ours(event: dict[str, object]) -> dict[str, str] | None:
    """Return our parsed message dict for an emitting event, else None."""
    if event.get("kind") not in _EMITTING_KINDS:
        return None
    msg = event.get("msg")
    if not isinstance(msg, str):
        return None
    return parse_message(msg)
