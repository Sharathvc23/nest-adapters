<!-- SPDX-License-Identifier: Apache-2.0 -->
# nest-adapters

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-orange.svg)]()

NANDA protocol adapters for [Nanda Town](https://github.com/projnanda/nandatown)
(NEST). Each adapter implements one of Nanda Town's 12 layer `Protocol`
interfaces and is discovered by `nest run` via the `nest.plugins.<layer>`
entry points — no fork of `nest-core` required.

## Install

```bash
pip install nest-core nest-adapters
```

Installing this package registers its plugins; point any scenario at them by
name in the YAML `layers:` block.

## Adapters

| Layer | Plugin name | Class | Solves |
|---|---|---|---|
| identity | `ed25519_rotating` | `Ed25519RotatingIdentity` | Problem 5 — real Ed25519 identity with key rotation and historical (as-of) signature verification. |
| identity | `ed25519_didkey` | `Ed25519DidKeyIdentity` | Real Ed25519 `did:key` baseline (replaces the toy `sim-rsa-sha256` reference), backed by `sm-arp`. |
| trust | `agent_receipts` | `AgentReceiptsTrust` | Reputation from cross-signed ARP receipts (VRP `nanda-rep/0.2`): corroboration + collusion severing, backed by `sm-arp`. |

More adapters (auth delegation, content-addressed datafacts, versioned comms,
gossip registry) are planned; see `docs/conformance.md`.

## Identity: `ed25519_rotating`

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
from nest_adapters.identity import Ed25519RotatingIdentity
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
with the `sm-arp` / chapter-protocol did:key encoding.

## Identity: `ed25519_didkey`

The non-rotating real-crypto baseline. NEST's reference `did_key` plugin is a
toy (`sim-rsa-sha256`, textbook RSA); its own docstring says to "swap to a
proper Ed25519 implementation." This is that swap, backed by `sm-arp`.

Each agent's keypair derives deterministically from its `AgentId`
(`Identity.from_seed(sha256(str(agent_id))[:32])`), and Ed25519 (RFC 8032) is
itself deterministic, so traces replay byte-for-byte. Signatures use
`algorithm="ed25519"` and carry the raw 64-byte Ed25519 signature (no envelope).
`did_of(agent)` exposes the `did:key`, which is byte-identical to the receipt
`principal_did` the trust plugin keys on.

```python
from nest_adapters.identity_didkey import Ed25519DidKeyIdentity
from nest_core.types import AgentId

ident = Ed25519DidKeyIdentity(AgentId("a1"))
sig = ident.sign(b"hello")                       # algorithm="ed25519", 64-byte raw sig
assert ident.verify(b"hello", sig, AgentId("a1"))
did = ident.did_of(AgentId("a1"))                # did:key:z6Mk...
```

## Trust: `agent_receipts`

Reputation from **cross-signed ARP receipts** instead of self-asserted feedback.
A report carries an ARP receipt as JSON in `Evidence.detail`; the plugin
verifies it (`sm_arp.receipts.verify_receipt`) and, if valid, appends it to an
in-memory ledger. `score(agent)` gathers that agent's receipts (matched on
`principal_did`) and runs `sm_arp.vrp.reputation_score_v2` (corroboration-gated,
collusion-severing) with `corroboration_rate` as confidence.

`reputation_score_v2` is **unbounded** (it sums category weights), so the raw
score is normalized to `[0, 1]` for `ReputationScore.score` via a saturating map
`1 - exp(-raw / K)` with **`K = 10`** (`NORMALIZATION_K`). At `K = 10` a single
corroborated `purchase` receipt (raw = 5.0) maps to ≈ 0.39 — safely above the
marketplace gate's 0.2 threshold — while the curve stays unsaturated for small
ledgers (raw = 10 → 0.63, raw = 30 → 0.95).

Stock scenarios pass a plain-string `detail` (no receipt); those fall back to
the reference score-average heuristic (positive → 1.0, negative/byzantine →
0.0), so the plugin is a drop-in replacement. The constructor is no-arg-callable
(the runner does `trust_cls()`); the plugin mints its own deterministic Ed25519
identity for attestations. `stake` is a parity-only no-op (`sm-arp` has no
staking primitive).

> Known boundary: per-agent `score()` reflects that agent's *own* corroborated
> receipts. Collusion-ring severing is a property of the *global* corroboration
> graph and is exercised at the library level (`reputation_score_v2` over a full
> ledger) — see the `reputation_receipts` benchmark follow-up.

```python
import json
from nest_adapters.trust_receipts import AgentReceiptsTrust
from nest_core.types import AgentId, Evidence

trust = AgentReceiptsTrust()
await trust.report(AgentId("a1"), Evidence(
    reporter=AgentId("a2"), subject=AgentId("a1"),
    kind="receipt", detail=json.dumps(cross_signed_receipt)))
rep = await trust.score(AgentId("a1"))           # corroborated, normalized to [0, 1]
```

## Validators

`nest_adapters.validators.validate_identity_rotation(trace_path)` reads a
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
