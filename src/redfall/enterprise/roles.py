"""Roles and the permissions they carry.

The role model is deliberately small and non-hierarchical by *name*: membership
is declared in a table rather than derived by a rank comparison, so adding a
role cannot accidentally widen an existing one. The table is the specification;
`tests/test_tenancy.py` asserts every permission is granted to at least one role
and that `owner` is the only role holding `tenant:admin`, so a future edit that
quietly hands administration to `analyst` fails the suite.

Two properties matter more than the specific grants:

* **A role is scoped to a tenant.** `owner` means owner *of this tenant*, never
  of the deployment. Cross-tenant reach is not a permission at all — there is no
  role that has it, which is why tenancy is enforced as a filter rather than as
  a check.
* **`admin` in the token-scope sense is not `owner` here.** The interop layer's
  `SCOPE_ADMIN` widens which tools a credential may call; this layer decides
  what those tools may touch. A token with `SCOPE_ADMIN` belonging to a
  `viewer` cannot read another tenant's campaign, because the tenant filter runs
  in the query and no scope value can remove it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Permission(str, Enum):
    """One thing a principal may do, within its own tenant."""

    CAMPAIGN_READ = "campaign:read"
    CAMPAIGN_WRITE = "campaign:write"
    CAMPAIGN_RUN = "campaign:run"
    FINDING_READ = "finding:read"
    FINDING_TRIAGE = "finding:triage"
    FIX_PROPOSE = "fix:propose"
    FIX_APPLY = "fix:apply"
    EVIDENCE_READ = "evidence:read"
    EVIDENCE_EXPORT = "evidence:export"
    AGENT_MANAGE = "agent:manage"
    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"
    TENANT_ADMIN = "tenant:admin"
    MEMBER_MANAGE = "member:manage"


ALL_PERMISSIONS: frozenset[Permission] = frozenset(Permission)

# The five shipped roles. Each maps to an explicit permission set rather than to
# "everything below me", so the blast radius of a change is visible in the diff.
ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    # Reads results, cannot change anything.
    "viewer": frozenset(
        {
            Permission.CAMPAIGN_READ,
            Permission.FINDING_READ,
            Permission.EVIDENCE_READ,
        }
    ),
    # A developer triaging findings and proposing fixes.
    "analyst": frozenset(
        {
            Permission.CAMPAIGN_READ,
            Permission.FINDING_READ,
            Permission.FINDING_TRIAGE,
            Permission.EVIDENCE_READ,
            Permission.FIX_PROPOSE,
            Permission.POLICY_READ,
        }
    ),
    # Runs campaigns and applies fixes, but does not administer people or rules.
    "engineer": frozenset(
        {
            Permission.CAMPAIGN_READ,
            Permission.CAMPAIGN_WRITE,
            Permission.CAMPAIGN_RUN,
            Permission.FINDING_READ,
            Permission.FINDING_TRIAGE,
            Permission.EVIDENCE_READ,
            Permission.EVIDENCE_EXPORT,
            Permission.FIX_PROPOSE,
            Permission.FIX_APPLY,
            Permission.AGENT_MANAGE,
            Permission.POLICY_READ,
        }
    ),
    # Everything an engineer has, plus the rule set and the member list.
    "owner": ALL_PERMISSIONS,
    # Explicitly forbids nothing an analyst can do and adds nothing beyond the
    # audit read: a read-only compliance seat that is *not* a viewer, so the
    # distinction survives in the audit trail.
    "auditor": frozenset(
        {
            Permission.CAMPAIGN_READ,
            Permission.FINDING_READ,
            Permission.EVIDENCE_READ,
            Permission.EVIDENCE_EXPORT,
            Permission.POLICY_READ,
            Permission.AUDIT_READ,
            Permission.AUDIT_EXPORT,
        }
    ),
}

ROLE_NAMES: tuple[str, ...] = tuple(ROLE_PERMISSIONS)


class RoleError(RuntimeError):
    """The requested role does not exist."""


@dataclass(frozen=True)
class Role:
    name: str
    permissions: frozenset[Permission]


def role_named(name: str) -> Role:
    clean = (name or "").strip().lower()
    try:
        return Role(name=clean, permissions=ROLE_PERMISSIONS[clean])
    except KeyError as exc:
        raise RoleError(
            f"unknown role {name!r}; known roles: {', '.join(ROLE_NAMES)}"
        ) from exc


def permissions_for(role: str) -> frozenset[Permission]:
    return role_named(role).permissions


def role_allows(role: str, permission: Permission | str) -> bool:
    """Whether a role carries a permission. An unknown role carries none.

    Returning False rather than raising is the safe direction for a function
    that gates an action: a caller with a stale or misspelled role in a database
    row is refused, not silently granted. Both the unknown-permission and the
    unknown-role cases land on the same answer and neither propagates, so a
    request carrying a bad value is denied rather than crashing the handler.
    """
    try:
        wanted = Permission(permission)
        return wanted in permissions_for(role)
    except (ValueError, RoleError):
        return False


def describe_roles() -> list[dict[str, object]]:
    """The role table, for the CLI and the policy endpoint."""
    return [
        {
            "role": name,
            "permissions": sorted(p.value for p in perms),
            "count": len(perms),
        }
        for name, perms in ROLE_PERMISSIONS.items()
    ]
