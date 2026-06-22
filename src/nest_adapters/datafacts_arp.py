# SPDX-License-Identifier: Apache-2.0
"""Receipt-backed DataFacts for Nanda Town (NEST) — the "nest-arp" datafacts plugin.

Implements ``nest_core.layers.datafacts.DataFacts`` on top of the published
``sm-arp`` library. Where the reference ``datafacts_v1`` plugin keeps metadata in
a trust-me dictionary and grants access unconditionally, here every dataset is
bound to **signed ARP receipts**:

* **publish** commits the dataset's content hash inside a ``data_shared`` receipt
  issued by the OWNER's deterministic Ed25519 key (``seed_for(owner)`` — the same
  key the ``ed25519_didkey`` identity layer derives, so provenance is attributable
  to the owner's did:key).
* **fetch** is an *integrity gate*: it returns metadata only if the provenance
  receipt verifies AND the dataset's recomputed content hash still matches the
  signed commitment. A tampered entry raises — it is never silently served.
* **request_access** issues a signed ``authority_granted`` receipt naming the
  requester, so grants are auditable rather than ephemeral dict entries.
* **verify_freshness** redefines "fresh" deterministically as *the provenance
  receipt still verifies* (the reference plugin's wall-clock hour window is
  non-deterministic and proves nothing about integrity).

:meth:`provenance` exposes the signed receipt for a dataset.

Registered under ``("datafacts", "arp_receipts")`` via entry points.

Example::

    df = ArpDataFacts()
    url = await df.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))
    meta = await df.fetch(url)            # raises unless provenance verifies + content matches
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from nest_core.types import AccessGrant, AgentId, DataFactsUrl, DatasetMetadata
from sm_arp.identity import Identity as ArpIdentity
from sm_arp.receipts import build_action, issue_receipt, verify_receipt

from nest_adapters.identity_didkey import did_for, seed_for

# Dataset fields hashed for the content commitment. Wall-clock timestamps are
# excluded so the commitment is deterministic across runs.
_VOLATILE_FIELDS = frozenset({"created_at", "updated_at"})


def _arp(owner: AgentId) -> ArpIdentity:
    """The owner's deterministic ARP identity (same seed as ``ed25519_didkey``)."""
    return ArpIdentity.from_seed(seed_for(owner))


def content_hash(dataset: DatasetMetadata) -> str:
    """A deterministic ``sha256:`` commitment over a dataset's content fields.

    Excludes the volatile timestamp fields so re-hashing the same dataset is
    stable. Any change to a content field (name, owner, checksum, …) changes the
    hash, which is what makes :meth:`ArpDataFacts.fetch` a tamper check.

    Example::

        h = content_hash(DatasetMetadata(name="x", owner=AgentId("a1")))
    """
    payload = dataset.model_dump(mode="json", exclude=set(_VOLATILE_FIELDS))
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ArpDataFacts:
    """DataFacts layer whose provenance and grants are signed ARP receipts.

    No-arg-callable, like the reference plugin; the NEST runner does
    ``datafacts_cls()`` and shares the one instance across agents.

    Example::

        df = ArpDataFacts()
        url = await df.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))
    """

    def __init__(self) -> None:
        self._datasets: dict[DataFactsUrl, DatasetMetadata] = {}
        self._provenance: dict[DataFactsUrl, dict[str, Any]] = {}
        self._commit: dict[DataFactsUrl, str] = {}
        self._grants: dict[DataFactsUrl, list[AccessGrant]] = {}
        self._grant_receipts: dict[DataFactsUrl, list[dict[str, Any]]] = {}

    async def publish(self, dataset: DatasetMetadata) -> DataFactsUrl:
        """Publish metadata bound to a signed ``data_shared`` provenance receipt.

        Example::

            url = await df.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))
        """
        url = DataFactsUrl(f"df://{dataset.name}")
        commit = content_hash(dataset)
        owner = _arp(dataset.owner)
        action = build_action(
            category="data_shared",
            human_summary=f"published dataset {dataset.name}",
            machine_payload={
                "dataset_url": str(url),
                "content_hash": commit,
                "schema_version": dataset.schema_version,
            },
        )
        receipt = issue_receipt(owner, principal_did=owner.did, action=action)
        self._datasets[url] = dataset
        self._provenance[url] = receipt
        self._commit[url] = commit
        return url

    async def fetch(self, url: DataFactsUrl) -> DatasetMetadata:
        """Fetch metadata — only if provenance verifies and content is intact.

        Raises ``KeyError`` if unknown, ``ValueError`` if the provenance receipt
        fails ARP verification or the content no longer matches its signed hash.

        Example::

            meta = await df.fetch(DataFactsUrl("df://weather"))
        """
        meta = self._datasets.get(url)
        receipt = self._provenance.get(url)
        if meta is None or receipt is None:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)
        result = verify_receipt(receipt)
        if not result.ok:
            msg = f"provenance receipt for {url} failed ARP verification (stage={result.stage})"
            raise ValueError(msg)
        if content_hash(meta) != self._commit[url]:
            msg = f"dataset {url} content does not match its signed provenance hash — tampered"
            raise ValueError(msg)
        return meta

    async def request_access(self, url: DataFactsUrl, requester: AgentId) -> AccessGrant:
        """Grant read access and record a signed ``authority_granted`` receipt.

        Example::

            grant = await df.request_access(DataFactsUrl("df://weather"), AgentId("a2"))
        """
        dataset = self._datasets.get(url)
        if dataset is None:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)
        owner = _arp(dataset.owner)
        action = build_action(
            category="authority_granted",
            human_summary=f"granted read access to {url}",
            counterparty_did=did_for(requester),
            counterparty_label=str(requester),
            machine_payload={"dataset_url": str(url), "tier": "read"},
        )
        receipt = issue_receipt(owner, principal_did=owner.did, action=action)
        grant = AccessGrant(url=url, grantee=requester, tier="read")
        self._grants.setdefault(url, []).append(grant)
        self._grant_receipts.setdefault(url, []).append(receipt)
        return grant

    async def verify_freshness(self, url: DataFactsUrl) -> bool:
        """True iff the dataset's signed provenance receipt still verifies.

        Example::

            ok = await df.verify_freshness(DataFactsUrl("df://weather"))
        """
        receipt = self._provenance.get(url)
        return receipt is not None and verify_receipt(receipt).ok

    def provenance(self, url: DataFactsUrl) -> dict[str, Any] | None:
        """The signed provenance receipt for a dataset, or ``None``.

        Example::

            receipt = df.provenance(DataFactsUrl("df://weather"))
        """
        return self._provenance.get(url)
