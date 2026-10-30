"""Multi-tenancy rows: who a caller is, and which tenant their work belongs to.

Kept in its own module rather than appended to `models.py` so the tenancy
boundary is visible in the file layout. The tables are registered on the same
`Base`, so `create_all` builds them with everything else.

The design decision worth stating: tenancy is enforced by a *scope object*
carried into every read, not by trusting a caller-supplied tenant id. A token
belongs to exactly one tenant and resolves to that tenant's id; a request
naming a different tenant is refused before it reaches a query. See
`redfall.enterprise.tenancy` for the enforcement and `tests/test_tenancy.py` for
the adversarial cases — including one tenant attempting to read another's
campaign by id.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(Base):
    """An isolation boundary: its own campaigns, evidence, tokens and audit.

    ``slug`` is the human handle used in URLs and CLI flags; ``id`` is what
    every foreign key stores. Both are unique, and neither is derived from the
    other, so renaming a tenant's slug cannot silently re-point another row.
    """

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="active", index=True)

    # Per-tenant ceilings. ``None`` means "inherit the deployment default";
    # zero means zero, which is a different statement and is enforced as such.
    max_campaigns: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_concurrent_tasks: Mapped[int | None] = mapped_column(Integer, nullable=True)
    budget_usd: Mapped[float | None] = mapped_column(Float, nullable=True)

    # A tenant is never hard-deleted through the API; suspension is a status so
    # the audit trail keeps referring to a row that exists.
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def is_active(self) -> bool:
        return self.status == "active" and self.suspended_at is None

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "slug": self.slug,
            "name": self.name,
            "status": self.status,
            "max_campaigns": self.max_campaigns,
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "budget_usd": self.budget_usd,
            "suspended_at": self.suspended_at.isoformat() if self.suspended_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Principal(Base):
    """A person or service that acts within one tenant.

    Distinct from `AgentToken`, which is a *credential*. A principal is the
    identity a credential resolves to; several tokens can belong to one
    principal (a laptop, a CI runner, an agent), and rotating a token does not
    change who was responsible for past actions.
    """

    __tablename__ = "principals"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_principals_tenant_email"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    role: Mapped[str] = mapped_column(String(32), default="viewer", index=True)
    status: Mapped[str] = mapped_column(String(24), default="active")

    # An identity provider's stable subject claim. Absent for a principal
    # created locally; a name alone is never treated as authentication.
    idp_subject: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "email": self.email,
            "display_name": self.display_name,
            "role": self.role,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
        }


class PolicyRule(Base):
    """One operator-authored constraint, evaluated before an action runs.

    ``effect`` is ``allow`` or ``deny``; ``action`` is a glob over tool names
    (``redfall_campaign_*``), and ``condition`` is a small structured match
    against the call's arguments. Rules are per-tenant, so an operator can
    loosen one tenant without touching another — the opposite convention
    (global rules with per-tenant exceptions) makes a tenant's effective policy
    something you have to reconstruct from two places.

    ``priority`` breaks ties: the highest-priority matching rule decides, and a
    deny at the same priority as an allow wins, so an explicit prohibition is
    never accidentally overridden by a broad permission.
    """

    __tablename__ = "policy_rules"
    __table_args__ = (Index("ix_policy_rules_tenant_priority", "tenant_id", "priority"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    effect: Mapped[str] = mapped_column(String(8), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    condition: Mapped[dict] = mapped_column(JSON, default=dict)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "effect": self.effect,
            "action": self.action,
            "condition": self.condition or {},
            "priority": self.priority,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AuditExport(Base):
    """A requested audit export, tracked so a partial export is visible.

    An export that quietly produced half the rows would be worse than one that
    failed: an auditor would treat an incomplete record as the whole record.
    The row carries the count it actually wrote and the range it covered.
    """

    __tablename__ = "audit_exports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(String(64), default="")
    fmt: Mapped[str] = mapped_column(String(16), default="jsonl")
    since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    write_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(24), default="complete")
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "requested_by": self.requested_by,
            "format": self.fmt,
            "since": self.since.isoformat() if self.since else None,
            "until": self.until.isoformat() if self.until else None,
            "record_count": self.record_count,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
