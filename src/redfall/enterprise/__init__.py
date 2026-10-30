"""Enterprise control plane: tenancy, roles, policy and audit.

Everything in this package is opt-in. A single-operator install never creates a
tenant and never has a rule evaluated against it, so the defaults preserve the
behaviour that predates this package. When the feature is turned on it is
enforced from persisted rows, never from a request field.
"""

from .audit import AuditEntry, AuditExporter
from .policy import Decision, PolicyEngine, Rule
from .roles import Permission, Role, permissions_for, role_allows
from .tenancy import (
    DEFAULT_TENANT_ID,
    TenantError,
    TenantScope,
    activate,
    adopt_orphans,
    create_tenant,
    require_tenant,
    resolve_scope,
    tenancy_enabled,
)

__all__ = [
    "DEFAULT_TENANT_ID",
    "AuditEntry",
    "AuditExporter",
    "Decision",
    "Permission",
    "PolicyEngine",
    "Role",
    "Rule",
    "TenantError",
    "TenantScope",
    "activate",
    "adopt_orphans",
    "create_tenant",
    "permissions_for",
    "require_tenant",
    "resolve_scope",
    "role_allows",
    "tenancy_enabled",
]
