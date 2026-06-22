# SPDX-License-Identifier: Apache-2.0
"""did:key auth for Nanda Town (NEST) — the "nest-didauth" auth plugin.

Implements ``nest_core.layers.auth.Auth`` with **decentralised, signature-based**
tokens. The reference ``jwt`` plugin signs every token with one shared HMAC
secret — any holder of that secret can mint a valid token for *any* subject. Here
each token is instead signed by the **subject's own Ed25519 key** (``seed_for`` —
the same key the ``ed25519_didkey`` identity layer derives) and verified against
the subject's **did:key**:

* there is no shared secret to leak;
* a token's signature must verify against ``pubkey_from_did(token.did)`` AND the
  embedded did must equal ``did_for(subject)`` — so you cannot mint a token for an
  agent whose key you don't hold, nor relabel one agent's token as another's;
* anyone can verify a token offline from the did alone — no issuer to call.

(As elsewhere in this repo, the simulator can derive any agent's seed, so
"holding the key" is a sim artifact; the *verification* is exactly what a real
deployment with non-derivable keys enforces.)

Registered under ``("auth", "did_key")`` via entry points.

Example::

    auth = DidAuth()
    token = await auth.issue(AgentId("a1"), ["read"])
    ctx = await auth.verify(token)          # ctx.subject == AgentId("a1")
"""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from nest_core.types import AgentId, AuthContext, Token
from sm_arp.identity import Identity as ArpIdentity
from sm_arp.identity import pubkey_from_did

from nest_adapters.identity_didkey import did_for, seed_for

# Token validity window (in the layer's logical clock units). Deterministic by
# default so tokens are byte-stable across runs; ``clock`` can be injected.
_TTL = 3600.0


def _arp(subject: AgentId) -> ArpIdentity:
    """The subject's deterministic ARP identity (same seed as ``ed25519_didkey``)."""
    return ArpIdentity.from_seed(seed_for(subject))


class DidAuth:
    """Signature-based auth: tokens signed by the subject's did:key, no shared secret.

    No-arg-callable, like the reference plugin. The optional ``clock`` makes
    ``iat``/``exp`` deterministic (default ``0.0``) rather than wall-clock.

    Example::

        auth = DidAuth()
        token = await auth.issue(AgentId("a1"), ["read"])
    """

    def __init__(self, clock: float = 0.0) -> None:
        self._clock = clock
        self._revoked: set[str] = set()

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a token for ``subject`` signed by the subject's Ed25519 key.

        Example::

            token = await auth.issue(AgentId("a1"), ["read", "write"])
        """
        identity = _arp(subject)
        payload = {
            "sub": str(subject),
            "did": identity.did,
            "scopes": list(scopes),
            "iat": self._clock,
            "exp": self._clock + _TTL,
        }
        payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        sig = base64.b64encode(identity.sign(payload_str.encode("utf-8"))).decode("ascii")
        return Token(f"{payload_str}|{sig}")

    async def verify(self, token: Token) -> AuthContext:
        """Verify a token's signature against the subject's did:key.

        Raises ``ValueError`` if revoked, malformed, impersonating (did does not
        match the subject), signature-invalid, or expired.

        Example::

            ctx = await auth.verify(token)
            assert ctx.subject == AgentId("a1")
        """
        raw = str(token)
        if raw in self._revoked:
            msg = "Token has been revoked"
            raise ValueError(msg)
        parts = raw.rsplit("|", 1)
        if len(parts) != 2:
            msg = "Invalid token format"
            raise ValueError(msg)
        payload_str, sig_b64 = parts
        try:
            data: dict[str, Any] = json.loads(payload_str)
        except json.JSONDecodeError as exc:
            msg = "Invalid token payload"
            raise ValueError(msg) from exc

        sub = data.get("sub")
        did = data.get("did")
        if not isinstance(sub, str) or not isinstance(did, str):
            msg = "Token missing subject/did"
            raise ValueError(msg)
        # The did must be the subject's canonical did — no relabelling one agent's
        # token as another's.
        if did != did_for(AgentId(sub)):
            msg = "Token did does not match its subject"
            raise ValueError(msg)
        # The signature must verify against the subject's did:key.
        try:
            pubkey_from_did(did).verify(base64.b64decode(sig_b64), payload_str.encode("utf-8"))
        except (InvalidSignature, ValueError, TypeError) as exc:
            msg = "Invalid token signature"
            raise ValueError(msg) from exc

        exp = data.get("exp")
        if isinstance(exp, (int, float)) and exp < self._clock:
            msg = "Token has expired"
            raise ValueError(msg)
        return AuthContext(
            subject=AgentId(sub),
            scopes=list(data.get("scopes", [])),
            issued_at=float(data.get("iat", 0.0)),
            expires_at=float(data.get("exp", 0.0)),
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a previously issued token.

        Example::

            await auth.revoke(token)
        """
        self._revoked.add(str(token))
