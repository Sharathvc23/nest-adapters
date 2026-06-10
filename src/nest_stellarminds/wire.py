# SPDX-License-Identifier: Apache-2.0
"""On-the-wire message formats for the identity_rotation scenario.

The simulator records each payload into the trace as its utf-8 decoding (the
``msg`` field of a send/broadcast/receive event). Everything the adversarial
validator needs must therefore ride inside utf-8-safe payloads — there is no
side channel. All three message kinds are ascii JSON.

Example::

    payload = encode_signed(AgentId("a1"), b"body", sig.value).encode()
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from nest_core.types import AgentId

KIND_IDENTITY = "id"
KIND_ROTATION = "rot"
KIND_SIGNED = "msg"


def encode_identity(agent: AgentId, key_id: str, pub: bytes, issued_at: float) -> str:
    """Announce an agent's initial public key so verifiers can bootstrap from the trace.

    Example::

        s = encode_identity(AgentId("a1"), kid, pub, 0.0)
    """
    return json.dumps(
        {
            "k": KIND_IDENTITY,
            "agent": str(agent),
            "kid": key_id,
            "pub": pub.hex(),
            "issued_at": issued_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def encode_rotation_event(announcement: bytes) -> str:
    """Wrap a rotation announcement (from ``Ed25519RotatingIdentity``) for the wire.

    Example::

        s = encode_rotation_event(ident.rotation_announcement())
    """
    return json.dumps(
        {"k": KIND_ROTATION, "ann": announcement.decode("ascii")},
        sort_keys=True,
        separators=(",", ":"),
    )


def encode_signed(agent: AgentId, body: bytes, sig_value: bytes) -> str:
    """Encode a signed application message: the body plus its signature envelope.

    Example::

        s = encode_signed(AgentId("a1"), b"hello", sig.value)
    """
    return json.dumps(
        {
            "k": KIND_SIGNED,
            "signer": str(agent),
            "body": body.hex(),
            "sig": sig_value.decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def parse_message(msg: str) -> dict[str, str] | None:
    """Parse a trace ``msg`` string back into a typed dict, or ``None`` if it is not ours.

    Example::

        parsed = parse_message(event["msg"])
    """
    try:
        obj = json.loads(msg)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict) or "k" not in obj:
        return None
    items = cast("dict[object, object]", obj)
    return {str(key): str(value) for key, value in items.items()}
