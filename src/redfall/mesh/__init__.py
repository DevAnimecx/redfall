"""The agent mesh: roles, and which vendor's agent plays each one.

Two things this package adds on top of the 0.2.0 driver framework.

**Roles are named and separated.** Recon, analyst, planner, exploit author,
runtime operator, critic, fixer and verifier are distinct jobs with distinct
tool allowlists and, importantly, distinct *tendencies*. Asking one agent to
both propose an exploit and judge whether it worked invites it to agree with
itself. The mesh keeps them separate so the critic is not the author.

**A role can be bound to a different vendor's agent.** That is the whole point
of a mesh rather than a router: a deployment may want its exploit author on one
model and its critic on another, precisely so a shared blind spot does not
appear on both sides of the judgement. Binding is per role, resolved from
configuration, and any role may fall back to the default backend.

The separation is only real if the *tools* are separated too. A role carries an
`allowed_tools` allowlist, and `check_tool` refuses a call outside it. A critic
holding the fixer's toolset could apply the fix it was meant to review, and the
"independent verification" would be a formality.
"""

from .roles import (
    ROLE_DEFINITIONS,
    MeshError,
    RoleSpec,
    check_tool,
    describe_roles,
    role_named,
)
from .binding import (
    BindingError,
    MeshBinding,
    MeshPlan,
    bind_from_config,
    plan_for,
)

__all__ = [
    "ROLE_DEFINITIONS",
    "BindingError",
    "MeshBinding",
    "MeshError",
    "MeshPlan",
    "RoleSpec",
    "bind_from_config",
    "check_tool",
    "describe_roles",
    "plan_for",
    "role_named",
]
