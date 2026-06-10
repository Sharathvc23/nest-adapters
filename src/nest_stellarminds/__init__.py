# SPDX-License-Identifier: Apache-2.0
"""Stellarminds protocol adapters for Nanda Town (NEST).

This package adapts Stellarminds' agent-accountability protocol primitives to
Nanda Town's 12-layer plugin interfaces. Each adapter implements a
``nest_core.layers`` ``Protocol`` and is discovered by ``nest run`` via the
``nest.plugins.<layer>`` entry-point groups declared in ``pyproject.toml``.

The first shipped adapter is :class:`~nest_stellarminds.identity.Ed25519RotatingIdentity`
(Nanda Town problem 5: real Ed25519 identity with key rotation and historical
signature verification).

Example::

    from nest_stellarminds.identity import Ed25519RotatingIdentity
"""

from __future__ import annotations

__version__ = "0.1.0"
