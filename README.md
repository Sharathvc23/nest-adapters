<!-- SPDX-License-Identifier: Apache-2.0 -->
# nest-adapters

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-orange.svg)]()

**Drop a real accountability stack into [Nanda Town](https://github.com/projnanda/nandatown) (NEST).**

Nanda Town simulates agent networks over **12 swappable protocol layers**, each
shipping with a deliberately simple reference plugin (textbook RSA identity, a
shared-secret JWT, a self-asserted-feedback trust score, a bare in-memory
registry…). `nest-adapters` replaces five of those defaults with
**cryptographically-backed** implementations on the `sm-*` stack — real Ed25519
identity, signature-based auth, receipt-backed reputation, NANDA-AgentFacts
discovery, and signed data provenance — so a `nest run` exercises the *actual*
NANDA accountability model, not a toy.

Each adapter implements one layer's `Protocol` and is discovered by `nest run`
through `nest.plugins.<layer>` entry points — **no fork of `nest-core`**. Point
any scenario at one by name in its YAML `layers:` block.

## Features

Five layers, each swapping a reference default for the real thing:

### 🔑 Identity — real Ed25519, with key rotation
`ed25519_didkey` replaces the reference's toy `sim-rsa-sha256` with real Ed25519
`did:key` identities (backed by `sm-arp`). `ed25519_rotating` adds **key rotation
with continuity**: a new key is signed by the one it replaces, and verification
is *as-of* a point in logical time — so a now-rotated key's old signature still
verifies when audited inside its window, but **post-rotation forgery** and
**backdating** are rejected. (A bundled validator passes against this plugin and
fails against the default.)

### 🔐 Auth — `did_key` tokens, no shared secret
The reference `jwt` plugin signs every token with **one shared HMAC secret** —
whoever holds it can mint a token for any agent. `did_key` instead signs each
token with the **subject's own Ed25519 key** and verifies it against the
subject's **did:key**. A token can't be forged for an agent whose key you don't
hold, can't be relabelled as someone else's, and verifies **offline across
parties** (no issuer to call). Tamper, impersonation, revocation, and expiry are
all rejected.

### ⭐ Trust — reputation from cross-signed receipts
The reference `score_average` is a running mean of self-asserted feedback —
trivially gamed by wash-trading. `agent_receipts` derives reputation from
**cross-signed ARP receipts** (`sm-arp` VRP `nanda-rep/0.2`): a score only counts
verified, *corroborated* receipts, and runs global **collusion-ring severance**,
so a clique that mutually inflates its own scores collapses to zero while honest
agents keep theirs.

### 🧭 Registry — discovery as canonical NANDA AgentFacts
The reference `in_memory` registry stores a bare `AgentCard`. `sm_bridge_facts`
(backed by `sm-bridge`) projects every registered agent to a **canonical NANDA
`SmAgentFacts`** whose `id` is the agent's **did:key** — the same identity the
Identity layer derives. Registration is a conformance gate (a card that isn't
NANDA-expressible is rejected), and discovery speaks the real NANDA AgentFacts
format an Orrery agent serves at `/agentfacts.json`.

### 📄 Data Facts — signed provenance + an integrity gate
The reference `datafacts_v1` is a trust-me dict that grants access
unconditionally. `arp_receipts` (backed by `sm-arp`) binds every dataset to a
signed `data_shared` receipt by its **owner's did:key**; `fetch` is an
**integrity gate** that returns metadata only if the provenance verifies *and*
the content hash still matches — a tampered entry raises. Access grants are
signed `authority_granted` receipts (auditable), and "freshness" means "the
provenance still verifies," not a wall-clock guess.

## Scenarios

Runnable end-to-end with `python -m nest_adapters.run scenarios/<name>.yaml`
(or `nest run` once installed). Each is deterministic from its seed.

| Scenario | Demonstrates |
|---|---|
| `identity_rotation` | Key rotation + as-of verification; post-rotation forgery & backdating rejected. |
| `reputation_receipts` | Wash-trading collusion ring (4/4) caught by `agent_receipts` where `score_average` misses it (0/4). |
| `registry_discovery` | Agents register + discover peers as canonical NANDA AgentFacts. |
| `datafacts_provenance` | Datasets published with signed provenance; peers fetch through the integrity gate. |
| `auth_handshake` | Agents present did:key-signed tokens; peers verify by did:key and grant. |
| **`sm_marketplace`** | **All four accountability layers together** — sellers register + publish, buyers discover, integrity-fetch, and credit seller reputation. A discovered, verified, credited seller reaches reputation 0.865; a stranger stays at the 0.5 neutral prior. |

## Layer coverage

Of Nanda Town's 12 layers, `nest-adapters` covers **5** today:

| Layer | nest-adapters plugin | Backed by |
|---|---|---|
| Identity | `ed25519_rotating`, `ed25519_didkey` | Ed25519 / did:key |
| Auth | `did_key` | Ed25519 signatures (no shared secret) |
| Trust | `agent_receipts` | `sm-arp` (VRP) |
| Registry | `sm_bridge_facts` | `sm-bridge` |
| Data Facts | `arp_receipts` | `sm-arp` |
| Transport · Comms · Coordination · Negotiation · Memory · Privacy | — | Pending |
| **Payments** | — | **Pending** |

## Install

```bash
pip install nest-core nest-adapters
```

Installing this package registers its plugins; reference them by name in a
scenario's YAML `layers:` block (e.g. `auth: did_key`). For local development:

```bash
git clone https://github.com/Sharathvc23/nest-adapters && cd nest-adapters
uv sync --extra scenarios
uv run python -m nest_adapters.run scenarios/sm_marketplace.yaml
```

## How the adapters work — details

### Identity: determinism + did:key

All key material derives from `H(seed ‖ agent_id ‖ rotation_count)` via
`Ed25519PrivateKey.from_private_bytes` — never `generate()` — and rotation time
comes from the simulator's logical clock, so the same seed yields a byte-identical
trace. did:key values are `did:key:z<base58btc(0xed01 ‖ pubkey32)>`,
byte-compatible with the `sm-arp` encoding the other layers key on.

```python
from nest_adapters.identity import Ed25519RotatingIdentity
from nest_core.types import AgentId

ident = Ed25519RotatingIdentity(AgentId("a1"), seed=b"scenario-seed")
sig = ident.sign(b"hello")                                   # key v1, tick 0
ident.advance_to(10.0); ident.rotate_key()                   # v2, signed-over by v1
assert ident.verify_as_of(b"hello", sig, AgentId("a1"), as_of=0.0)        # in v1 window
assert not ident.verify_as_of(b"hello", sig, AgentId("a1"), as_of=20.0)   # post-rotation
```

### Auth: did:key tokens

A token is `payload|sig`, where the payload pins `sub`, the subject's `did`, and
`scopes`, and `sig` is the subject's Ed25519 signature over it. `verify` recovers
the public key with `pubkey_from_did`, checks the signature, and requires the
embedded `did` to equal `did_for(sub)` — so neither tampering nor relabelling
survives.

```python
from nest_adapters.auth_didkey import DidAuth
from nest_core.types import AgentId

auth = DidAuth()
token = await auth.issue(AgentId("a1"), ["read"])
ctx = await DidAuth().verify(token)        # verifies on a *fresh* instance — no shared secret
assert ctx.subject == AgentId("a1")
```

### Trust: scoring + normalization

`reputation_score_v2` is unbounded (it sums category weights), so the raw score
is mapped to `[0, 1]` via `1 - exp(-raw / K)` with `K = 10`: a single corroborated
`purchase` receipt (raw = 5.0) → ≈ 0.39, raw = 10 → 0.63, raw = 30 → 0.95.
Stock scenarios that pass a plain-string `Evidence.detail` fall back to the
reference score-average heuristic, so the plugin is a drop-in replacement.

```python
import json
from nest_adapters.trust_receipts import AgentReceiptsTrust
from nest_core.types import AgentId, Evidence

trust = AgentReceiptsTrust()
await trust.report(AgentId("a1"), Evidence(
    reporter=AgentId("a2"), subject=AgentId("a1"),
    kind="receipt", detail=json.dumps(cross_signed_receipt)))
rep = await trust.score(AgentId("a1"))     # corroborated, severance-resistant, normalized
```

### Registry & Data Facts: canonical NANDA shapes

`SmBridgeRegistry.index()` returns every agent as `SmAgentFacts` (the in-process
analogue of `/sm-bridge/index`); `ArpDataFacts.provenance(url)` returns the signed
`data_shared` receipt committing a dataset's content hash.

### Validators

`validate_identity_rotation(trace_path)` reads a JSONL trace and fails if any
signed message used a key outside its validity window or backdated its signing
tick — passing against `ed25519_rotating`, failing against the default.

## Develop

```bash
uv sync --extra scenarios
uv run ruff check . && uv run ruff format --check src tests
uv run mypy && uv run pyright          # both strict
uv run pytest -q
```

CI runs the same gate on every push (`.github/workflows/ci.yml`).

---

<sub>Built by [labs.stellarminds.ai](https://labs.stellarminds.ai). Apache-2.0.</sub>
