"""The gateway audit trail.

Every authenticated call through any transport writes one row, success or
denial, with the agent identity, the tool, a hash of the arguments, the outcome
and the measured duration. Quotas are counted from this same table, so an audit
gap would silently widen a quota.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..store.models import InteropAudit


def _new_id() -> str:
    return f"audit-{secrets.token_hex(10)}"


def input_hash(arguments: dict[str, Any] | None) -> str:
    """A stable digest of the arguments, so a call can be compared without storing it."""

    canonical = json.dumps(arguments or {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def campaign_of(arguments: dict[str, Any] | None) -> str | None:
    if not isinstance(arguments, dict):
        return None
    value = arguments.get("campaign_id")
    return str(value) if isinstance(value, str) and value else None


def record_call(
    session: Session,
    *,
    protocol: str,
    agent: str,
    tool: str,
    ok: bool,
    token_id: str | None = None,
    arguments: dict[str, Any] | None = None,
    error: str = "",
    duration_ms: int = 0,
) -> InteropAudit:
    row = InteropAudit(
        id=_new_id(),
        protocol=protocol,
        agent=agent,
        token_id=token_id,
        tool=tool,
        campaign_id=campaign_of(arguments),
        input_hash=input_hash(arguments),
        ok=ok,
        error=error[:2000],
        duration_ms=max(0, int(duration_ms)),
    )
    session.add(row)
    session.flush()
    return row


def list_calls(
    session: Session,
    *,
    limit: int = 50,
    agent: str = "",
    tool: str = "",
) -> list[InteropAudit]:
    query = select(InteropAudit).order_by(InteropAudit.created_at.desc()).limit(max(1, limit))
    if agent:
        query = query.where(InteropAudit.agent == agent)
    if tool:
        query = query.where(InteropAudit.tool == tool)
    return list(session.scalars(query).all())
