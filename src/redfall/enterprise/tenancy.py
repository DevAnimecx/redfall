"""Tenant resolution and the scope object that carries it into every query.

The rule this module exists to enforce: **a tenant is derived, never accepted.**
A caller presents a credential; the credential resolves to a tenant; the scope
object built from that tenant is the only thing queries filter on. No API takes
a `tenant_id` parameter that a client can choose, so "read another tenant's
campaign by guessing its id" is not a policy that can be misconfigured — the id
simply never reaches the query as anything but a value to match *within* the
resolved tenant.

Two escape hatches are deliberate and explicit:

* ``REDFALL_TENANCY=off`` (the default) keeps the pre-0.5.0 behaviour: one
  implicit tenant, no filter, every existing test and deployment unchanged.
* ``adopt_orphans`` claims rows whose ``tenant_id`` is empty into the default
  tenant. Those rows are what a database written before this release looks like — the
  column is new and defaults to ``""``. Adoption is a one-shot, idempotent call
  an operator makes, not something a read silently does.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from ..store.models import AgentToken, Campaign
from ..store.models_tenant import Principal, Tenant

# The tenant every instalment starts with. Rows written before tenancy existed
# are adopted into it. The literal string is stable across releases because it
# appears in audit exports and in operator scripts.
DEFAULT_TENANT_ID = "ten-default"
DEFAULT_TENANT_SLUG = "default"

ENV_TENANCY = "REDFALL_TENANCY"
ENV_DEFAULT_TENANT = "REDFALL_TENANT"

# Tenant ids that would collide with a URL path segment or be mistaken for a
# missing value. Rejected at creation rather than escaped at every use.
RESERVED_IDS = frozenset({"", "self", "..", ".", "all", "any"})


class TenantError(RuntimeError):
    """A tenant is missing, suspended, or was named illegally."""

    code = "tenant_error"


def tenancy_enabled() -> bool:
    """Whether the deployment enforces tenancy.

    Off unless explicitly turned on. A shared install that never opted in must
    not start refusing requests because a new code path learned about tenants.
    """
    return os.getenv(ENV_TENANCY, "").strip().lower() in {"1", "on", "true", "yes", "enforce"}


def default_tenant_id() -> str:
    """The tenant id a scope falls back to when tenancy is off.

    An operator can name it explicitly; the default is a fixed id so that a
    fresh database and an adopted one agree.
    """
    named = os.getenv(ENV_DEFAULT_TENANT, "").strip()
    return named or DEFAULT_TENANT_ID


@dataclass(frozen=True)
class TenantScope:
    """The resolved tenant a session is acting within.

    Carried explicitly rather than read from a global, so a worker thread
    cannot inherit a neighbouring request's tenant simply because it was set
    first. Frozen for the same reason: nothing downstream can widen it.
    """

    tenant_id: str
    slug: str = ""
    principal_id: str | None = None
    role: str = ""
    enforced: bool = False
    tenant_ids: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.tenant_ids:
            object.__setattr__(self, "tenant_ids", (self.tenant_id,) if self.tenant_id else tuple())

    def owns(self, tenant_id: str | None) -> bool:
        """Whether a row's tenant is visible to this scope.

        An unenforced scope sees everything, which is what keeps a
        single-operator install working. An enforced scope sees its own tenant
        and, for a row that predates tenancy (empty string), nothing — the
        operator adopts those explicitly rather than every tenant reading them.
        """
        if not self.enforced:
            return True
        if tenant_id is None:
            return False
        return tenant_id in self.tenant_ids

    def filter_column(self, column):
        """A SQLAlchemy predicate a query can AND onto its own conditions.

        Returns ``None`` when no filter should be applied, so callers write
        ``if (clause := scope.filter_column(Campaign.tenant_id)) is not None``
        and a disabled tenancy costs nothing at all.
        """
        if not self.enforced:
            return None
        return column.in_(list(self.tenant_ids))

    def to_wire(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "slug": self.slug,
            "principal_id": self.principal_id,
            "role": self.role,
            "enforced": self.enforced,
        }


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(12)}"


def create_tenant(
    session: Session,
    *,
    slug: str,
    name: str = "",
    max_campaigns: int | None = None,
    max_concurrent_tasks: int | None = None,
    budget_usd: float | None = None,
) -> Tenant:
    """Create a tenant. The slug is the operator's handle and must be unique."""
    clean_slug = (slug or "").strip().lower()
    if not clean_slug:
        raise TenantError("tenant slug must be a non-empty string")
    if clean_slug in RESERVED_IDS:
        raise TenantError(f"tenant slug {clean_slug!r} is reserved")
    if not clean_slug.replace("-", "").replace("_", "").isalnum():
        raise TenantError("tenant slug may contain only letters, digits, '-' and '_'")
    existing = session.scalar(select(Tenant).where(Tenant.slug == clean_slug))
    if existing is not None:
        raise TenantError(f"tenant slug {clean_slug!r} already exists")
    if max_campaigns is not None and max_campaigns < 0:
        raise TenantError("max_campaigns must be >= 0 (None means unlimited)")
    if budget_usd is not None and budget_usd < 0:
        raise TenantError("budget_usd must be >= 0 (None means unlimited)")

    row = Tenant(
        id=_new_id("ten"),
        slug=clean_slug,
        name=(name or clean_slug).strip(),
        max_campaigns=max_campaigns,
        max_concurrent_tasks=max_concurrent_tasks,
        budget_usd=budget_usd,
    )
    session.add(row)
    session.flush()
    return row


def get_tenant(session: Session, *, tenant_id: str = "", slug: str = "") -> Tenant | None:
    if tenant_id:
        return session.get(Tenant, tenant_id)
    if slug:
        return session.scalar(select(Tenant).where(Tenant.slug == slug.strip().lower()))
    return None


def require_tenant(session: Session, *, tenant_id: str = "", slug: str = "") -> Tenant:
    row = get_tenant(session, tenant_id=tenant_id, slug=slug)
    if row is None:
        raise TenantError(f"no such tenant: {tenant_id or slug}")
    if not row.is_active():
        raise TenantError(f"tenant {row.slug} is {row.status}")
    return row


def list_tenants(session: Session, *, include_suspended: bool = True) -> list[Tenant]:
    stmt = select(Tenant).order_by(Tenant.created_at.desc())
    if not include_suspended:
        stmt = stmt.where(Tenant.status == "active", Tenant.suspended_at.is_(None))
    return list(session.scalars(stmt).all())


def suspend_tenant(
    session: Session,
    *,
    tenant_id: str = "",
    slug: str = "",
    reason: str = "",
    now: datetime | None = None,
) -> Tenant:
    """Stop a tenant's principals from acting. Nothing is deleted."""
    row = require_tenant(session, tenant_id=tenant_id, slug=slug)
    if row.status == "suspended":
        return row
    row.status = "suspended"
    row.suspended_at = now or datetime.now(timezone.utc)
    row.updated_at = row.suspended_at
    session.execute(
        update(Principal)
        .where(Principal.tenant_id == row.id)
        .values(status="suspended")
    )
    session.flush()
    return row


def resume_tenant(session: Session, *, tenant_id: str = "", slug: str = "") -> Tenant:
    row = get_tenant(session, tenant_id=tenant_id, slug=slug)
    if row is None:
        raise TenantError(f"no such tenant: {tenant_id or slug}")
    row.status = "active"
    row.suspended_at = None
    row.updated_at = datetime.now(timezone.utc)
    session.flush()
    return row


def resolve_scope(
    session: Session,
    token: AgentToken | None = None,
    *,
    tenant_id: str = "",
) -> TenantScope:
    """The scope a request acts within, from its credential.

    Order of precedence, and the reason for it:

    1. A token's own ``tenant_id``. This is the only source a request cannot
       influence, so it wins outright.
    2. An explicitly named tenant, when no token is present — the CLI operator
       path, where the name comes from the operator's own flag.
    3. The default tenant.

    When tenancy is off the scope is unenforced and sees everything, which is
    the pre-0.5.0 behaviour.
    """
    if not tenancy_enabled():
        return TenantScope(tenant_id=default_tenant_id(), slug=DEFAULT_TENANT_SLUG, enforced=False)

    chosen = (token.tenant_id if token is not None else "") or tenant_id or default_tenant_id()
    if token is not None and tenant_id and token.tenant_id and token.tenant_id != tenant_id:
        # A credential for tenant A asking to act as tenant B is not a
        # permission that exists.
        raise TenantError(
            f"token belongs to tenant {token.tenant_id!r} and cannot act as {tenant_id!r}"
        )
    if token is not None and not token.tenant_id:
        # A token made before tenancy was switched on. Refusing is the honest
        # answer; the operator adopts tokens with `adopt_orphans`.
        raise TenantError(
            "token has no tenant and tenancy is enforced; run `redfall tenant adopt` first"
        )
    row = get_tenant(session, tenant_id=chosen)
    if row is None:
        raise TenantError(
            f"tenant {chosen!r} does not exist; create it with `redfall tenant create`"
        )
    if not row.is_active():
        raise TenantError(f"tenant {row.slug} is {row.status}")
    return TenantScope(
        tenant_id=row.id,
        slug=row.slug,
        principal_id=(token.principal_id if token is not None else None),
        role="",
        enforced=True,
    )


def scope_for_principal(
    session: Session,
    tenant,
    principal: Principal,
) -> TenantScope:
    """A scope that also carries the principal's role, for RBAC checks."""
    return TenantScope(
        tenant_id=tenant.id,
        slug=tenant.slug,
        principal_id=principal.id,
        role=principal.role,
        enforced=tenancy_enabled(),
    )


def activate(
    session: Session,
    *,
    slug: str = DEFAULT_TENANT_SLUG,
    name: str = "Default tenant",
) -> Tenant:
    """Ensure a tenant exists, returning it. Idempotent."""
    existing = session.scalar(select(Tenant).where(Tenant.slug == slug.strip().lower()))
    if existing is not None:
        return existing
    return create_tenant(session, slug=slug, name=name)


def adopt_orphans(
    session: Session,
    *,
    tenant_id: str = "",
    slug: str = DEFAULT_TENANT_SLUG,
) -> dict[str, int]:
    """Claim pre-tenancy rows into a tenant. Idempotent and counted.

    A database written before this release has ``tenant_id = ''`` on every campaign and
    token. Left alone, an enforced deployment shows an operator an empty
    console and refuses every existing credential — which reads as data loss
    even though nothing was dropped. This is the explicit, reversible-by-inspect
    step that fixes it, and it reports how many rows it moved rather than doing
    it silently on first read.
    """
    target = tenant_id or activate(session, slug=slug).id
    require_tenant(session, tenant_id=target)
    campaigns = session.execute(
        update(Campaign).where(Campaign.tenant_id == "").values(tenant_id=target)
    ).rowcount
    tokens = session.execute(
        update(AgentToken).where(AgentToken.tenant_id == "").values(tenant_id=target)
    ).rowcount
    session.flush()
    return {"campaigns": int(campaigns or 0), "tokens": int(tokens or 0), "tenant_id": target}


def orphan_counts(session: Session) -> dict[str, int]:
    """How many rows still predate tenancy, for the preflight report."""
    campaigns = session.scalar(
        select(func.count(Campaign.id)).where(Campaign.tenant_id == "")
    )
    tokens = session.scalar(select(func.count(AgentToken.id)).where(AgentToken.tenant_id == ""))
    return {"campaigns": int(campaigns or 0), "tokens": int(tokens or 0)}


def create_principal(
    session: Session,
    *,
    tenant_id: str,
    email: str,
    role: str = "viewer",
    display_name: str = "",
    idp_subject: str | None = None,
) -> Principal:
    """Add a person to a tenant. The role is validated against the table."""
    from .roles import role_named

    role_named(role)
    clean_email = (email or "").strip().lower()
    if not clean_email or "@" not in clean_email:
        raise TenantError(f"invalid email: {email!r}")
    require_tenant(session, tenant_id=tenant_id)
    clash = session.scalar(
        select(Principal).where(
            Principal.tenant_id == tenant_id, Principal.email == clean_email
        )
    )
    if clash is not None:
        raise TenantError(f"{clean_email} is already a member of this tenant")
    row = Principal(
        id=_new_id("prn"),
        tenant_id=tenant_id,
        email=clean_email,
        display_name=(display_name or clean_email.split("@")[0]).strip(),
        role=role.strip().lower(),
        idp_subject=idp_subject,
    )
    session.add(row)
    session.flush()
    return row


def list_principals(session: Session, *, tenant_id: str) -> list[Principal]:
    return list(
        session.scalars(
            select(Principal)
            .where(Principal.tenant_id == tenant_id)
            .order_by(Principal.created_at.asc())
        ).all()
    )


def set_role(
    session: Session,
    *,
    tenant_id: str,
    principal_id: str = "",
    email: str = "",
    role: str,
) -> Principal:
    """Change a member's role. The only way a role ever changes."""
    from .roles import role_named

    role_named(role)
    if principal_id:
        row = session.get(Principal, principal_id)
    elif email:
        row = session.scalar(
            select(Principal).where(
                Principal.tenant_id == tenant_id, Principal.email == email.strip().lower()
            )
        )
    else:
        raise TenantError("either principal_id or email is required")
    if row is None or row.tenant_id != tenant_id:
        # Deliberately not distinguishing "does not exist" from "belongs to
        # another tenant" in the raised message: the caller is already inside
        # one tenant, and the difference is not theirs to learn.
        raise TenantError("no such principal in this tenant")
    row.role = role.strip().lower()
    session.flush()
    return row
