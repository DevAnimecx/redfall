"""Stored artifacts and HMAC-signed URLs.

Tool results that become A2A artifacts are stored once with their SHA-256
digest. A signed URL (`/v1/artifacts/{id}?expires=...&sig=...`) serves the stored
copy without re-running the tool. The signing key comes from
``REDFALL_ARTIFACT_SECRET`` when set, otherwise a random key is generated once
and persisted, so URLs survive a server restart on the same database.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..store.models import InteropArtifact, InteropSetting, utcnow

ARTIFACT_SECRET_KEY = "artifact_secret"
DEFAULT_TTL_SECONDS = 900


def _new_id() -> str:
    return f"art-{secrets.token_hex(10)}"


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def store_artifact(
    session: Session,
    *,
    task_id: str,
    tool: str,
    payload: dict[str, Any],
) -> InteropArtifact:
    body = canonical_bytes(payload)
    row = InteropArtifact(
        id=_new_id(),
        task_id=task_id,
        tool=tool,
        sha256=hashlib.sha256(body).hexdigest(),
        payload=payload,
    )
    session.add(row)
    session.flush()
    return row


def get_artifact(session: Session, artifact_id: str) -> InteropArtifact | None:
    return session.get(InteropArtifact, artifact_id)


def artifact_secret(session: Session) -> str:
    """Return the signing key, creating and persisting one on first use."""

    from_env = os.environ.get("REDFALL_ARTIFACT_SECRET", "").strip()
    if from_env:
        return from_env
    row = session.get(InteropSetting, ARTIFACT_SECRET_KEY)
    if row is not None:
        value = (row.value or {}).get("secret")
        if isinstance(value, str) and value:
            return value
    generated = secrets.token_urlsafe(32)
    if row is None:
        row = InteropSetting(key=ARTIFACT_SECRET_KEY, value={"secret": generated})
        session.add(row)
    else:
        row.value = {"secret": generated}
        row.updated_at = utcnow()
    session.flush()
    return generated


def sign(secret: str, artifact_id: str, expires: int) -> str:
    message = f"{artifact_id}:{expires}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def signed_url(
    base_url: str,
    artifact_id: str,
    secret: str,
    *,
    ttl: int = DEFAULT_TTL_SECONDS,
    now: datetime | None = None,
) -> str:
    moment = now or datetime.now(timezone.utc)
    expires = int(moment.timestamp()) + max(1, ttl)
    digest = sign(secret, artifact_id, expires)
    root = base_url.rstrip("/")
    return f"{root}/v1/artifacts/{artifact_id}?expires={expires}&sig={digest}"


def verify(
    secret: str,
    artifact_id: str,
    expires: str | int,
    sig: str,
    *,
    now: datetime | None = None,
) -> bool:
    try:
        expires_at = int(expires)
    except (TypeError, ValueError):
        return False
    moment = now or datetime.now(timezone.utc)
    if expires_at < int(moment.timestamp()):
        return False
    expected = sign(secret, artifact_id, expires_at)
    return hmac.compare_digest(expected, str(sig))
