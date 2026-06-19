# SPDX-License-Identifier: Apache-2.0
"""Stellarminds protocol adapters for Nanda Town (NEST).

This package adapts Stellarminds' agent-accountability protocol primitives to
Nanda Town's 12-layer plugin interfaces. Each adapter implements a
``nest_core.layers`` ``Protocol`` and is discovered by ``nest run`` via the
``nest.plugins.<layer>`` entry-point groups declared in ``pyproject.toml``.

Shipped adapters:

* :class:`~nest_stellarminds.identity.Ed25519RotatingIdentity` — real Ed25519
  identity with key rotation and historical signature verification (problem 5).
* :class:`~nest_stellarminds.identity_didkey.Ed25519DidKeyIdentity` — real
  Ed25519 ``did:key`` identity (the non-rotating baseline, backed by ``sm-arp``).
* :class:`~nest_stellarminds.trust_receipts.AgentReceiptsTrust` — reputation
  from cross-signed ARP receipts (VRP), backed by ``sm-arp``.

Example::

    from nest_stellarminds.identity_didkey import Ed25519DidKeyIdentity
    from nest_stellarminds.trust_receipts import AgentReceiptsTrust
"""

from __future__ import annotations

__version__ = "0.1.0"
