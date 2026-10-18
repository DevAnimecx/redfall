"""Bearer tokens: an HMAC over a base64url payload, signed with a literal.

See VULN-005 (hardcoded secret) and VULN-006 (the same secret served by
`GET /api/config`). `scripts/replay_poc.py` forges an admin token with the
secret it reads from that endpoint, so the credential is live, not decorative.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

TOKEN_SECRET = "pythonbank-dev-secret-do-not-ship"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_token(username: str, role: str) -> str:
    payload = _b64url(
        json.dumps(
            {"username": username, "role": role, "iat": int(time.time())},
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signature = hmac.new(TOKEN_SECRET.encode("utf-8"), payload.encode("ascii"), hashlib.sha256)
    return f"{payload}.{signature.hexdigest()}"


def parse_token(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) != 2:
        return None
    payload, signature = parts
    expected = hmac.new(TOKEN_SECRET.encode("utf-8"), payload.encode("ascii"), hashlib.sha256)
    if not hmac.compare_digest(signature, expected.hexdigest()):
        return None
    try:
        claims = json.loads(_unb64url(payload))
    except (ValueError, json.JSONDecodeError):
        return None
    return claims if isinstance(claims, dict) else None
