"""Verify a NIP-98 (kind 27235) Authorization header on your server.

Uses the nostrkey package (pip install nostrkey). No framework needed.

    pubkey = verify_nip98(request.headers["Authorization"],
                          "https://example.com/api/auth/nostr", "POST")
    # pubkey is a verified 64-char hex key; start your session for it.

Raises ValueError with a short reason if anything is wrong.
"""

from __future__ import annotations

import base64
import json
import re
import time

from nostrkey.events import NostrEvent, verify_event

WINDOW_SECONDS = 60
_seen: dict[str, int] = {}  # event id -> expiry. Use a shared store if you run several servers.
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def verify_nip98(authorization: str, expected_url: str, expected_method: str,
                 now: int | None = None) -> str:
    now = int(time.time()) if now is None else now
    if not isinstance(authorization, str) or not authorization.startswith("Nostr "):
        raise ValueError("missing Nostr authorization")
    try:
        raw = json.loads(base64.b64decode(authorization[6:].strip(), validate=True))
    except Exception:
        raise ValueError("authorization is not base64 JSON") from None
    if not isinstance(raw, dict):
        raise ValueError("authorization is not an event")
    if raw.get("kind") != 27235:
        raise ValueError("wrong kind")
    pubkey = raw.get("pubkey")
    if not isinstance(pubkey, str) or not _HEX64.match(pubkey):
        raise ValueError("bad pubkey")

    created_at = raw.get("created_at")
    if not isinstance(created_at, int) or isinstance(created_at, bool) or abs(now - created_at) > WINDOW_SECONDS:
        raise ValueError("expired or future-dated")

    tags = raw.get("tags") if isinstance(raw.get("tags"), list) else []

    def tag(name: str):
        found = [t for t in tags if isinstance(t, list) and len(t) > 1 and t[0] == name]
        return found[0][1] if len(found) == 1 else None

    if tag("u") != expected_url:
        raise ValueError("url does not match")
    method = tag("method")
    if not isinstance(method, str) or method.upper() != expected_method.upper():
        raise ValueError("method does not match")

    try:
        event = NostrEvent(id=raw["id"], pubkey=pubkey, created_at=created_at, kind=27235,
                           tags=tags, content=raw.get("content", ""), sig=raw["sig"])
    except (KeyError, TypeError):
        raise ValueError("incomplete event") from None
    # Checks the id is the hash of the event and the signature is valid for pubkey.
    if not verify_event(event):
        raise ValueError("bad signature")

    # Refuse the same signed event twice inside the window.
    for event_id in [k for k, exp in _seen.items() if exp < now]:
        del _seen[event_id]
    if event.id in _seen:
        raise ValueError("already used")
    _seen[event.id] = now + WINDOW_SECONDS

    return pubkey
