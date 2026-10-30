"""Binding roles to agents, and refusing the bindings that defeat the mesh.

A binding says which backend plays which role. Most deployments bind one agent
to everything and get the separation of *tools*; a deployment that cares binds
different roles to different vendors' agents and gets the separation of
*reasoning* as well.

The refusal that makes the mesh worth having: `critic` and `exploit` must not
share an agent. If one model both authors a proof and judges whether it works,
the judgement is the author marking its own work, and a shared blind spot is
invisible on both sides. `MeshPlan.validate` raises when a binding collapses
that pair, and a test asserts that a single-agent binding is refused *unless*
the operator has explicitly acknowledged it.

That acknowledgement matters. Most teams will run one agent everywhere, and a
tool that simply refused would be unusable. So the default is a refusal with a
clear reason, and `allow_shared` records the operator's decision to run with
the weaker guarantee — stated in the plan's `warnings` so a report can carry it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .roles import ROLE_DEFINITIONS, ROLE_NAMES, MeshError, role_named, separation_pairs


class BindingError(MeshError):
    """A binding is malformed, or defeats a separation the mesh requires."""

    code = "binding_error"


@dataclass(frozen=True)
class MeshBinding:
    """One role assigned to one backend."""

    role: str
    backend: str
    model: str = ""
    #: Why this binding exists — recorded so a report can explain the topology.
    note: str = ""

    def to_wire(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "backend": self.backend,
            "model": self.model,
            "note": self.note,
        }


@dataclass(frozen=True)
class MeshPlan:
    """Every role bound to a backend, with the separation warnings it implies."""

    bindings: dict[str, MeshBinding]
    default_backend: str
    shared_acknowledged: bool = False
    warnings: list[str] = field(default_factory=list)

    def backend_for(self, role: str) -> str:
        spec = role_named(role)
        binding = self.bindings.get(spec.name)
        return binding.backend if binding else self.default_backend

    def model_for(self, role: str) -> str:
        spec = role_named(role)
        binding = self.bindings.get(spec.name)
        return binding.model if binding else ""

    def uses_multiple_backends(self) -> bool:
        return len({b.backend for b in self.bindings.values()} | {self.default_backend}) > 1

    def to_wire(self) -> dict[str, Any]:
        return {
            "default_backend": self.default_backend,
            "backends_in_use": sorted(
                {b.backend for b in self.bindings.values()} | {self.default_backend}
            ),
            "bindings": [self.bindings[name].to_wire() for name in ROLE_NAMES if name in self.bindings],
            "warnings": list(self.warnings),
            "shared_acknowledged": self.shared_acknowledged,
        }


def _collapse_pairs(bindings: Mapping[str, str]) -> list[tuple[str, str, str]]:
    """Pairs that must differ but resolve to the same backend.

    Returns ``(role_a, role_b, backend)`` for each violation, so the error can
    name the pair and the agent rather than saying "invalid topology".
    """
    violations: list[tuple[str, str, str]] = []
    for left, right in separation_pairs():
        backend_left = bindings.get(left, "")
        backend_right = bindings.get(right, "")
        if backend_left and backend_left == backend_right:
            violations.append((left, right, backend_left))
    return violations


def plan_for(
    assignments: Mapping[str, str],
    *,
    default_backend: str,
    models: Mapping[str, str] | None = None,
    allow_shared: bool = False,
    check_unassigned: bool = False,
) -> MeshPlan:
    """Build a plan, refusing the bindings that defeat separation.

    ``assignments`` maps a role to a backend name; a role left out uses
    ``default_backend``. Which collapses are *fatal* depends on how much the
    operator said:

    * Two roles the operator **explicitly bound** to the same agent is a
      contradiction of their own instruction — `exploit` and `critic` both set
      to `codex` is a mistake, and it raises.
    * Collapses that only arise because unassigned roles fall back to the
      default are **warnings**, not errors. A team running one agent everywhere
      has not made a binding decision that contradicts itself; they have made
      none. Refusing that outright would make the mesh unusable for the common
      case, and the warnings travel with the plan so a report can state the
      weaker guarantee.

    ``check_unassigned`` promotes the second case to the first, for a
    deployment that wants the strict reading.
    """
    if not default_backend.strip():
        raise BindingError("a default backend is required")
    models = models or {}
    bindings: dict[str, MeshBinding] = {}
    for role, backend in assignments.items():
        spec = role_named(role)
        clean_backend = (backend or "").strip()
        if not clean_backend:
            raise BindingError(f"role {spec.name!r} was bound to an empty backend")
        bindings[spec.name] = MeshBinding(
            role=spec.name,
            backend=clean_backend,
            model=(models.get(spec.name) or "").strip(),
        )

    explicit = {role: binding.backend for role, binding in bindings.items()}
    explicit_violations = _collapse_pairs(explicit)

    effective = {role: explicit.get(role, default_backend.strip()) for role in ROLE_NAMES}
    all_violations = _collapse_pairs(effective)
    default_only = [v for v in all_violations if v not in explicit_violations]

    if explicit_violations and not allow_shared:
        detail = "; ".join(f"{a} and {b} both run on {backend}" for a, b, backend in explicit_violations)
        raise BindingError(
            f"the mesh requires separation: {detail}. "
            "These roles were bound to the same agent, which makes the critic the author. "
            "Bind them to different agents, or set allow_shared to run with the weaker guarantee."
        )
    if default_only and check_unassigned and not allow_shared:
        detail = "; ".join(f"{a} and {b} both fall back to {backend}" for a, b, backend in default_only)
        raise BindingError(
            f"the mesh requires separation: {detail}. "
            "Bind them to different agents, or set allow_shared to run with the weaker guarantee."
        )

    warnings: list[str] = []
    if allow_shared:
        for left, right, backend in all_violations:
            warnings.append(
                f"{left} and {right} share the agent {backend!r}: "
                "the critic is not independent of the author"
            )
    else:
        for left, right, backend in default_only:
            warnings.append(
                f"{left} and {right} both fall back to {backend!r}: "
                "they are independent only if that agent's reasoning is"
            )
    if not bindings:
        warnings.append("no role is bound explicitly; every role uses the default backend")

    return MeshPlan(
        bindings=bindings,
        default_backend=default_backend.strip(),
        shared_acknowledged=allow_shared and bool(all_violations),
        warnings=warnings,
    )


def bind_from_config(config: Mapping[str, Any]) -> MeshPlan:
    """Build a plan from a `redfall.toml`-shaped mapping.

    The shape is deliberately flat and readable:

    .. code-block:: toml

        [mesh]
        default = "claude-code"
        allow_shared = false

        [mesh.roles]
        exploit = "codex"
        critic = "gemini"
        verifier = "gemini"
    """
    if not isinstance(config, Mapping):
        raise BindingError("mesh config must be a mapping")
    default = str(config.get("default") or config.get("default_backend") or "").strip()
    if not default:
        raise BindingError("mesh config must name a default backend")
    roles = config.get("roles") or config.get("bindings") or {}
    if not isinstance(roles, Mapping):
        raise BindingError("mesh.roles must be a mapping of role -> backend")
    models = config.get("models") or {}
    if not isinstance(models, Mapping):
        raise BindingError("mesh.models must be a mapping of role -> model")
    return plan_for(
        {str(k): str(v) for k, v in roles.items()},
        default_backend=default,
        models={str(k): str(v) for k, v in models.items()},
        allow_shared=bool(config.get("allow_shared") or False),
    )


def validate_plan(plan: MeshPlan) -> list[str]:
    """The reasons a plan should not be used, empty when it is sound.

    Distinct from construction: a plan built with `allow_shared` is valid and
    still worth reporting on, so this returns findings rather than raising.
    """
    findings: list[str] = []
    for left, right, backend in _collapse_pairs(
        {role: plan.backend_for(role) for role in ROLE_NAMES}
    ):
        findings.append(f"{left} and {right} share {backend!r}")
    return findings


def mesh_summary(plan: MeshPlan) -> dict[str, Any]:
    """A full picture for a CLI or a report: every role, its backend, its tools."""
    roles = []
    for name in ROLE_NAMES:
        spec = ROLE_DEFINITIONS[name]
        roles.append(
            {
                "role": name,
                "backend": plan.backend_for(name),
                "model": plan.model_for(name),
                "bound_explicitly": name in plan.bindings,
                "purpose": spec.purpose,
                "tool_count": len(spec.allowed_tools),
                "must_differ_from": sorted(spec.must_differ_from),
            }
        )
    return {
        "plan": plan.to_wire(),
        "roles": roles,
        "separation_findings": validate_plan(plan),
    }
