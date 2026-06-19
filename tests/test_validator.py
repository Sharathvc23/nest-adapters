# SPDX-License-Identifier: Apache-2.0
"""Adversarial validator tests.

The problem's pass condition is a two-direction check: the validator must PASS
against our plugin and FAIL against the default did_key plugin. It must also
catch a forged post-rotation signature injected into an otherwise-honest trace.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId

from nest_adapters.determinism import (
    derive_signing_key,
    encode_signature_value,
    key_id_for,
    public_bytes,
    signing_bytes,
)
from nest_adapters.run import run_config
from nest_adapters.validators import validate_identity_rotation
from nest_adapters.wire import encode_identity, encode_rotation_event, encode_signed

if TYPE_CHECKING:
    from pathlib import Path

    from nest_core.validators import ValidationResult

SEED = b"identity_rotation"


def _result(results: list[ValidationResult], name: str) -> bool:
    for r in results:
        if r.name == name:
            return r.passed
    raise AssertionError(f"no result named {name}")


def test_validator_fails_on_did_key_trace(tmp_path: Path) -> None:
    """A did_key marketplace trace has no key-windows; real_windows must FAIL."""
    cfg = ScenarioConfig.model_validate(
        {
            "name": "mp",
            "seed": 42,
            "agents": {
                "count": 4,
                "brain": "state-machine",
                "roles": [
                    {"name": "buyer", "count": 2},
                    {"name": "seller", "count": 2},
                ],
            },
            "layers": {"identity": "did_key"},
            "task": {"type": "marketplace", "config": {"rounds": 2}},
            "output": {"trace": str(tmp_path / "mp.jsonl")},
        }
    )
    trace = run_config(cfg)
    results = validate_identity_rotation(trace)
    assert _result(results, "identity_rotation_real_windows") is False


def test_validator_catches_post_rotation_forgery(tmp_path: Path) -> None:
    """Hand-built trace: agent rotates at t=10, attacker reuses old key at t=20."""
    a = AgentId("agent-a")
    v0 = derive_signing_key(SEED, a, 0)
    v0_pub = public_bytes(v0.public_key())
    v0_kid = key_id_for(v0_pub)
    v1 = derive_signing_key(SEED, a, 1)
    v1_pub = public_bytes(v1.public_key())
    v1_kid = key_id_for(v1_pub)

    # honest pre-rotation signature at t=0
    body0 = b"honest@0"
    sig0 = encode_signature_value(v0_kid, 0.0, v0.sign(signing_bytes(body0, v0_kid, 0.0)))

    # continuity: v1 pub signed by v0
    continuity = v0.sign(v1_pub).hex()
    rot = {
        "agent": str(a),
        "prev_kid": v0_kid,
        "new_kid": v1_kid,
        "new_pub": v1_pub.hex(),
        "issued_at": 10.0,
        "continuity": continuity,
    }

    # FORGERY: attacker holds compromised v0, signs a fresh message observed at t=20
    body_evil = b"forged@20"
    forged = encode_signature_value(v0_kid, 20.0, v0.sign(signing_bytes(body_evil, v0_kid, 20.0)))

    lines = [
        {
            "ts": 0.0,
            "agent": str(a),
            "kind": "broadcast",
            "msg": encode_identity(a, v0_kid, v0_pub, 0.0),
        },
        {"ts": 0.0, "agent": str(a), "kind": "broadcast", "msg": encode_signed(a, body0, sig0)},
        {
            "ts": 10.0,
            "agent": str(a),
            "kind": "broadcast",
            "msg": encode_rotation_event(
                json.dumps(rot, sort_keys=True, separators=(",", ":")).encode()
            ),
        },
        {
            "ts": 20.0,
            "agent": str(a),
            "kind": "broadcast",
            "msg": encode_signed(a, body_evil, forged),
        },
    ]
    trace = tmp_path / "forge.jsonl"
    trace.write_text("\n".join(json.dumps(line) for line in lines) + "\n")

    results = validate_identity_rotation(trace)
    assert _result(results, "identity_rotation_real_windows") is True  # has windows
    assert _result(results, "identity_rotation_no_out_of_window_use") is False  # caught forgery
