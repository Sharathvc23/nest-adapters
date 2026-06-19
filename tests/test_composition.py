# SPDX-License-Identifier: Apache-2.0
"""End-to-end composition smoke test: identity + trust + sm-arp.

Proves the full chain: an agent signs a real ARP receipt using the
``ed25519_didkey`` identity, the counterparty co-signs it, it is reported to
the ``agent_receipts`` trust plugin, and the agent's reputation comes back as a
corroborated non-zero score. This is the integration that justifies both
plugins existing together.
"""

from __future__ import annotations

import json

import pytest
from nest_core.types import AgentId, Evidence
from sm_arp.identity import Identity as ArpIdentity
from sm_arp.receipts import build_action, issue_receipt, verify_receipt
from sm_arp.vrp import cosign_receipt, is_corroborated

from nest_adapters.identity_didkey import Ed25519DidKeyIdentity, did_for, seed_for
from nest_adapters.trust_receipts import AgentReceiptsTrust


@pytest.mark.asyncio
async def test_identity_trust_arp_chain_end_to_end() -> None:
    buyer = AgentId("buyer")
    seller = AgentId("seller")

    # 1. Both agents have real Ed25519 did:key identities from the identity plugin.
    buyer_ident = Ed25519DidKeyIdentity(buyer)
    seller_ident = Ed25519DidKeyIdentity(seller)

    # The did:key the identity plugin mints must equal the principal_did the
    # trust plugin will look the agent up by — otherwise score() finds nothing.
    assert buyer_ident.did == did_for(buyer)

    # 2. Buyer issues a real ARP receipt (signed by its own Ed25519 key).
    #    We use the same deterministic seed the identity plugin uses, so the
    #    receipt's issuer_did/principal_did == buyer_ident.did.
    buyer_arp = ArpIdentity.from_seed(seed_for(buyer))
    seller_arp = ArpIdentity.from_seed(seed_for(seller))
    assert buyer_arp.did == buyer_ident.did
    assert seller_arp.did == seller_ident.did

    action = build_action(
        category="purchase",
        human_summary="bought a widget",
        outcome="completed",
        counterparty_did=seller_arp.did,
        counterparty_label="seller",
    )
    draft = issue_receipt(buyer_arp, principal_did=buyer_arp.did, action=action)

    # 3. Counterparty (seller) co-signs the receipt.
    cosig = cosign_receipt(draft, signing_key_bytes=seller_arp.sk_bytes, witness_did=seller_arp.did)
    receipt = issue_receipt(
        buyer_arp,
        principal_did=buyer_arp.did,
        action=action,
        evidence={"witness_signatures": [cosig]},
        receipt_id=draft["receipt_id"],
        issued_at=draft["issued_at"],
    )
    assert verify_receipt(receipt).ok
    assert is_corroborated(receipt)

    # 4. Report the cross-signed receipt to the trust plugin via Evidence.detail.
    trust = AgentReceiptsTrust()
    await trust.report(
        buyer,
        Evidence(reporter=seller, subject=buyer, kind="receipt", detail=json.dumps(receipt)),
    )

    # 5. Trust returns a corroborated, non-zero, normalized score for the buyer.
    rep = await trust.score(buyer)
    assert rep.sample_count == 1
    assert 0.0 < rep.score < 1.0
    assert rep.confidence == 1.0  # fully corroborated
