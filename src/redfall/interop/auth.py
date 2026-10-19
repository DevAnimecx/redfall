"""Agent identity for the interoperability gateway.

An agent reaches the gateway with a bearer token. The token maps to one durable
row that carries an explicit scope allow-list and an optional hourly quota. Every
decision here is enforced against persisted state: no environment variable can
widen a token's scopes, and no in-memory map can forget a revocation.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..store.models import AgentToken, InteropAudit

SCOPE_READ = "read"
SCOPE_EXECUTE = "execute"
SCOPE_WRITE = "write"
SCOPE_ADMIN = "admin"
ALL_SCOPES = (SCOPE_READ, SCOPE_EXECUTE, SCOPE_WRITE, SCOPE_ADMIN)

TOKEN_PREFIX = "rfl_"

# Every tool the registry advertises must appear here. `tests/test_interop_auth`
# asserts the mapping and the registry stay in step, so a new tool without a
# scope fails the suite instead of defaulting to something permissive.
TOOL_SCOPES: dict[str, str] = {
    # read: inspect state, evidence and reports
    "redfall_health": SCOPE_READ,
    "redfall_campaign_list": SCOPE_READ,
    "redfall_campaign_status": SCOPE_READ,
    "redfall_campaign_report": SCOPE_READ,
    "redfall_task_list": SCOPE_READ,
    "redfall_evidence_list": SCOPE_READ,
    "redfall_evidence_verify": SCOPE_READ,
    "redfall_report_readiness": SCOPE_READ,
    "redfall_graph_latest": SCOPE_READ,
    "redfall_graph_stats": SCOPE_READ,
    "redfall_graph_search": SCOPE_READ,
    "redfall_graph_node": SCOPE_READ,
    "redfall_graph_neighbors": SCOPE_READ,
    "redfall_graph_paths": SCOPE_READ,
    "redfall_graph_routes": SCOPE_READ,
    "redfall_graph_diff": SCOPE_READ,
    "redfall_graph_sources": SCOPE_READ,
    "redfall_graph_inventory": SCOPE_READ,
    "redfall_findings": SCOPE_READ,
    "redfall_finding": SCOPE_READ,
    "redfall_report": SCOPE_READ,
    "redfall_policy_check": SCOPE_READ,
    "redfall_adapter_certifications": SCOPE_READ,
    # execute: run real work inside the sandbox boundary
    "redfall_campaign_run": SCOPE_EXECUTE,
    "redfall_scan_run": SCOPE_EXECUTE,
    "redfall_reproduce": SCOPE_EXECUTE,
    "redfall_graph_index": SCOPE_EXECUTE,
    # write: mutate campaign state
    "redfall_campaign_create": SCOPE_WRITE,
    "redfall_campaign_scope": SCOPE_WRITE,
    "redfall_campaign_start": SCOPE_WRITE,
    "redfall_campaign_transition": SCOPE_WRITE,
    "redfall_campaign_pause": SCOPE_WRITE,
    "redfall_campaign_resume": SCOPE_WRITE,
    "redfall_campaign_cancel": SCOPE_WRITE,
    "redfall_campaign_fail": SCOPE_WRITE,
    "redfall_campaign_record_spend": SCOPE_WRITE,
    "redfall_campaign_reserve": SCOPE_WRITE,
    "redfall_campaign_release_reservation": SCOPE_WRITE,
    "redfall_campaign_settle_reservation": SCOPE_WRITE,
    "redfall_task_enqueue": SCOPE_WRITE,
    "redfall_task_claim": SCOPE_WRITE,
    "redfall_task_complete": SCOPE_WRITE,
    "redfall_task_fail": SCOPE_WRITE,
    "redfall_evidence_append": SCOPE_WRITE,
}


class AuthError(RuntimeError):
    """The caller is not an authenticated agent."""

    code = "unauthorized"
    status = 401


class ScopeError(RuntimeError):
    """The authenticated agent lacks the scope a tool requires."""

    code = "forbidden"
    status = 403


class QuotaError(RuntimeError):
    """The authenticated agent exceeded its hourly call quota."""

    code = "quota_exceeded"
    status = 429

    def __init__(self, used: int, quota: int) -> None:
        self.used = used
        self.quota = quota
        super().__init__(f"quota exceeded: {used}/{quota} calls in the last hour")


@dataclass(frozen=True)
class Identity:
    """A detached snapshot of a token, safe to carry across threads."""

    token_id: str
    name: str
    scopes: frozenset[str]


def identity_of(token: AgentToken) -> Identity:
    return Identity(
        token_id=token.id,
        name=token.name,
        scopes=frozenset(str(scope) for scope in (token.scopes or [])),
    )


def grant_satisfies(granted: frozenset[str] | set[str], required: str) -> bool:
    """Whether a granted scope set satisfies a required scope.

    Scopes are an explicit allow-list; ``admin`` is the only implicit grant.
    """

    return required in granted or SCOPE_ADMIN in granted


def required_scope(tool: str) -> str:
    try:
        return TOOL_SCOPES[tool]
    except KeyError as exc:
        raise AuthError(f"no scope policy for tool: {tool}") from exc


def generate_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tag(value: str) -> str:
    """A short non-secret handle for logs: first 8 hex characters of the digest."""

    return hash_token(value)[:8]


def create_token(
    session: Session,
    *,
    name: str,
    scopes: list[str],
    quota_per_hour: int = 0,
) -> tuple[AgentToken, str]:
    """Create a token and return ``(row, plaintext)``. Plaintext is shown once."""

    clean_name = name.strip()
    if not clean_name:
        raise ValueError("token name must be a non-empty string")
    clean_scopes = sorted({str(scope).strip().lower() for scope in scopes if str(scope).strip()})
    if not clean_scopes:
        raise ValueError("at least one scope is required")
    unknown = sorted(set(clean_scopes) - set(ALL_SCOPES))
    if unknown:
        raise ValueError(f"unknown scope(s): {', '.join(unknown)}")
    if quota_per_hour < 0:
        raise ValueError("quota_per_hour must be >= 0 (0 means unlimited)")
    plaintext = generate_token()
    row = AgentToken(
        id=f"tok-{secrets.token_hex(12)}",
        name=clean_name,
        token_sha256=hash_token(plaintext),
        scopes=clean_scopes,
        quota_per_hour=quota_per_hour,
    )
    session.add(row)
    session.flush()
    return row, plaintext


def authenticate(session: Session, token: str, *, now: datetime | None = None) -> AgentToken:
    """Resolve a bearer token to its row, or raise ``AuthError`` with the reason."""

    if not token or not token.strip():
        raise AuthError("missing bearer token")
    row = session.scalar(
        select(AgentToken).where(AgentToken.token_sha256 == hash_token(token.strip()))
    )
    if row is None:
        raise AuthError("unknown token")
    if row.revoked_at is not None:
        raise AuthError("token revoked")
    row.last_used_at = now or datetime.now(timezone.utc)
    session.flush()
    return row


def list_tokens(session: Session) -> list[AgentToken]:
    return list(session.scalars(select(AgentToken).order_by(AgentToken.created_at.desc())).all())


def revoke_token(
    session: Session,
    *,
    token_id: str = "",
    name: str = "",
    now: datetime | None = None,
) -> AgentToken:
    if token_id:
        row = session.get(AgentToken, token_id)
    elif name:
        row = session.scalar(
            select(AgentToken)
            .where(AgentToken.name == name, AgentToken.revoked_at.is_(None))
            .order_by(AgentToken.created_at.desc())
        )
    else:
        raise ValueError("either token_id or name is required")
    if row is None:
        raise ValueError(f"no token found for {'id' if token_id else 'name'}")
    if row.revoked_at is None:
        row.revoked_at = now or datetime.now(timezone.utc)
        session.flush()
    return row


def used_this_hour(session: Session, token_id: str, *, now: datetime | None = None) -> int:
    since = (now or datetime.now(timezone.utc)) - timedelta(hours=1)
    count = session.scalar(
        select(func.count(InteropAudit.id)).where(
            InteropAudit.token_id == token_id,
            InteropAudit.created_at >= since,
        )
    )
    return int(count or 0)


def check_quota(session: Session, token: AgentToken, *, now: datetime | None = None) -> int:
    """Raise ``QuotaError`` when the token has spent its rolling-hour budget."""

    quota = int(token.quota_per_hour or 0)
    if quota <= 0:
        return 0
    used = used_this_hour(session, token.id, now=now)
    if used >= quota:
        raise QuotaError(used=used, quota=quota)
    return used


def authorize_tool(
    session: Session,
    token: AgentToken,
    tool: str,
    *,
    now: datetime | None = None,
) -> None:
    """Check scope and quota for one tool call. Unknown tools pass scope checks.

    The caller resolves unknown tools to a 404 before reaching this function;
    when it does not, the registry raises its own unknown-tool error.
    """

    granted = frozenset(str(scope) for scope in (token.scopes or []))
    if tool in TOOL_SCOPES and not grant_satisfies(granted, TOOL_SCOPES[tool]):
        raise ScopeError(
            f"tool {tool} requires scope {TOOL_SCOPES[tool]!r}; "
            f"token has {', '.join(sorted(granted)) or 'none'}"
        )
    # Serialize the quota check per token on backends that support row locks so
    # two concurrent requests cannot both spend the last slot.
    session.execute(
        select(AgentToken.id).where(AgentToken.id == token.id).with_for_update()
    )
    check_quota(session, token, now=now)


def scope_coverage() -> dict[str, str]:
    """The full tool->scope map, for tools that advertise policy."""

    return dict(TOOL_SCOPES)
