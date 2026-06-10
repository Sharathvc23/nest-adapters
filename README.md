<!-- SPDX-License-Identifier: Apache-2.0 -->
# nest-stellarminds

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-orange.svg)]()

Stellarminds protocol adapters for [Nanda Town](https://github.com/projnanda/nandatown)
(NEST). Each adapter implements one of Nanda Town's 12 layer `Protocol`
interfaces and is discovered by `nest run` via the `nest.plugins.<layer>`
entry points — no fork of `nest-core` required.

## Install

```bash
pip install nest-core nest-stellarminds
```

Installing this package registers its plugins; point any scenario at them by
name in the YAML `layers:` block.

## Adapters

| Layer | Plugin name | Class | Solves |
|---|---|---|---|
| identity | `sm_ed25519_rotating` | `Ed25519RotatingIdentity` | Problem 5 — real Ed25519 identity with key rotation and historical (as-of) signature verification. |

More adapters (auth delegation, content-addressed datafacts, versioned comms,
gossip registry) are planned; see `docs/conformance.md`.

## Identity: `sm_ed25519_rotating`

Real Ed25519 signing (via [`cryptography`](https://cryptography.io)), did:key
identities, and **key rotation with continuity**: a new key is signed by the
key it replaces, and every signature carries the `key_id` and signing tick that
produced it. Verification is *as-of* a point in logical time, so a signature
made by a now-rotated key still verifies when audited within that key's
validity window — but is rejected for observations after rotation.

This defeats two attacks the default `did_key` plugin cannot express:

- **Post-rotation forgery** — an attacker who compromised an old key signs a
  message observed *after* rotation. Rejected: the audit `as_of` time falls
  outside the old key's window.
- **Backdating** — an attacker stamps a new-key signature with a tick inside
  the old key's window. Rejected: the claimed signing tick falls outside the
  new key's window.

```python
from nest_stellarminds.identity import Ed25519RotatingIdentity
from nest_core.types import AgentId

ident = Ed25519RotatingIdentity(AgentId("a1"), seed=b"scenario-seed")
sig = ident.sign(b"hello")                       # signed by key v1 at tick 0
ident.advance_to(10.0)
ident.rotate_key()                               # v2, signed-over by v1 (continuity)
assert ident.verify_as_of(b"hello", sig, AgentId("a1"), as_of=0.0)   # within v1 window
assert not ident.verify_as_of(b"hello", sig, AgentId("a1"), as_of=20.0)  # post-rotation
```

### Determinism

All key material derives from `H(seed ‖ agent_id ‖ rotation_count)` via
`Ed25519PrivateKey.from_private_bytes` — never `generate()`. Rotation time
comes from the simulator's logical clock, never the wall clock. Same seed →
byte-identical trace, which is what Nanda Town's seed-bank check enforces.

### did:key format

did:key values are `did:key:z<base58btc(0xed01 ‖ pubkey32)>`, byte-compatible
with the Stellarminds `sm-arp` / chapter-protocol did:key encoding.

## Validators

`nest_stellarminds.validators.validate_identity_rotation(trace_path)` reads a
JSONL trace and fails if any signed message used a key outside its validity
window or backdated its signing tick. It **passes** against this plugin and
**fails** against the default `did_key` plugin (which has no key-window
concept) — the two-direction check that defines the problem's pass condition.

## Develop

```bash
make ci-local   # uv sync, ruff check, ruff format --check, pyright (strict), pytest
```

---

<sub>Built by [labs.stellarminds.ai](https://labs.stellarminds.ai). Apache-2.0.</sub>
