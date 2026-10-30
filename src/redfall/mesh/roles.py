"""The eight mesh roles, what each may do, and what each must not.

A role is a job, not a prompt. It carries:

* a **purpose**, so an operator reading the table knows why it exists;
* an **allowed tool set**, enforced at call time;
* a **separation constraint**, where the role must not be the same principal as
  another — the critic and the exploit author are the case that matters.

The tool allowlists are written as the *smallest* set that lets the role do its
job. That is not minimalism for its own sake: every tool a role holds is a way
it could do something the separation of duties was meant to prevent. A verifier
that can write files can make its own proof pass.

`check_tool` raises rather than returning false. A role reaching outside its
allowlist is a programming error or an attempt, and both should stop the work
rather than be logged and skipped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class MeshError(RuntimeError):
    """A role is unknown, or a call falls outside its allowlist."""

    code = "mesh_error"


@dataclass(frozen=True)
class RoleSpec:
    """One role: its purpose, its tools and its separation constraints."""

    name: str
    purpose: str
    allowed_tools: frozenset[str]
    #: Roles this one must not share a backing agent with.
    must_differ_from: frozenset[str] = field(default_factory=frozenset)
    #: Whether the role's output can put a finding in a report.
    can_assert_findings: bool = False
    #: Whether the role may spend money without a reservation.
    may_spend: bool = True


# Tool names are the engine's actual operations, not invented ones. The set is
# small on purpose: a role gets what its job needs and nothing adjacent to it.
_READ_TOOLS = frozenset(
    {
        "redfall_graph_search",
        "redfall_graph_node",
        "redfall_graph_neighbors",
        "redfall_graph_paths",
        "redfall_graph_routes",
        "redfall_graph_sources",
        "redfall_graph_inventory",
        "redfall_findings",
        "redfall_finding",
    }
)
_STATIC_TOOLS = _READ_TOOLS | frozenset({"redfall_graph_index", "redfall_graph_diff"})
_REPRODUCE_TOOLS = frozenset({"redfall_reproduce", "redfall_scan_run"})
_WRITE_FIX_TOOLS = frozenset({"redfall_fix_propose"})
_EVIDENCE_TOOLS = frozenset({"redfall_evidence_list", "redfall_evidence_verify", "redfall_evidence_append"})
_REPORT_TOOLS = frozenset({"redfall_report", "redfall_campaign_report", "redfall_report_readiness"})


ROLE_DEFINITIONS: dict[str, RoleSpec] = {
    "recon": RoleSpec(
        name="recon",
        purpose="Map the target: entry points, routes, data stores, trust boundaries.",
        allowed_tools=_STATIC_TOOLS,
        can_assert_findings=False,
    ),
    "analyst": RoleSpec(
        name="analyst",
        purpose="Turn the map into candidate flows worth chasing, with a reason each.",
        allowed_tools=_STATIC_TOOLS | _EVIDENCE_TOOLS,
        can_assert_findings=False,
    ),
    "planner": RoleSpec(
        name="planner",
        purpose="Rank the candidates and choose which to spend budget on.",
        allowed_tools=_STATIC_TOOLS | _EVIDENCE_TOOLS,
        can_assert_findings=False,
    ),
    "exploit": RoleSpec(
        name="exploit",
        purpose="Author and run a proof for one candidate.",
        allowed_tools=_STATIC_TOOLS | _REPRODUCE_TOOLS | _EVIDENCE_TOOLS,
        # The author must not be the judge; see `critic`.
        must_differ_from=frozenset({"critic", "verifier"}),
        can_assert_findings=True,
    ),
    "runtime_operator": RoleSpec(
        name="runtime_operator",
        purpose="Bring the target up in the sandbox and keep it reachable.",
        allowed_tools=_STATIC_TOOLS | _REPRODUCE_TOOLS,
        must_differ_from=frozenset({"critic"}),
        can_assert_findings=False,
    ),
    "critic": RoleSpec(
        name="critic",
        purpose="Attack a proposed finding: does it reproduce, does it matter, is it the same bug?",
        allowed_tools=_STATIC_TOOLS | _REPRODUCE_TOOLS | _EVIDENCE_TOOLS,
        must_differ_from=frozenset({"exploit"}),
        can_assert_findings=False,
    ),
    "fixer": RoleSpec(
        name="fixer",
        purpose="Propose a repair for a confirmed finding.",
        allowed_tools=_STATIC_TOOLS | _WRITE_FIX_TOOLS | _EVIDENCE_TOOLS,
        can_assert_findings=False,
    ),
    "verifier": RoleSpec(
        name="verifier",
        purpose="Judge a repair: do the tests pass and does the proof stop working?",
        allowed_tools=_STATIC_TOOLS | _REPRODUCE_TOOLS | _EVIDENCE_TOOLS | _REPORT_TOOLS,
        must_differ_from=frozenset({"exploit", "fixer"}),
        # A verifier confirms someone else's finding; it does not originate one.
        can_assert_findings=False,
    ),
}

ROLE_NAMES: tuple[str, ...] = tuple(ROLE_DEFINITIONS)


def role_named(name: str) -> RoleSpec:
    clean = (name or "").strip().lower()
    try:
        return ROLE_DEFINITIONS[clean]
    except KeyError as exc:
        raise MeshError(f"unknown role {name!r}; known: {', '.join(ROLE_NAMES)}") from exc


def check_tool(role: str, tool: str) -> None:
    """Raise unless ``role`` may call ``tool``.

    Raises rather than returning a boolean: a role reaching outside its
    allowlist is either a bug or an attempt, and both should stop the work
    instead of being logged and stepped over.
    """
    spec = role_named(role)
    clean_tool = (tool or "").strip()
    if clean_tool not in spec.allowed_tools:
        raise MeshError(
            f"role {spec.name!r} may not call {clean_tool!r}; "
            f"it holds {len(spec.allowed_tools)} tool(s) and this is not one of them"
        )


def tools_for(role: str) -> frozenset[str]:
    return role_named(role).allowed_tools


def separation_pairs() -> list[tuple[str, str]]:
    """Every (role, other) pair that must not share an agent, each once.

    The constraint is symmetric but is written on one side only — `exploit`
    says it must differ from `critic`, and `critic` says it must differ from
    `exploit` — so both directions are collected and deduplicated. Ordering
    each pair by role name makes the list stable, which matters because a plan
    reports these and two runs must not differ.
    """
    seen: set[tuple[str, str]] = set()
    for name, spec in ROLE_DEFINITIONS.items():
        for other in spec.must_differ_from:
            if other not in ROLE_DEFINITIONS:
                continue
            pair = (name, other) if name < other else (other, name)
            seen.add(pair)
    return sorted(seen)


def describe_roles() -> list[dict[str, object]]:
    """The role table for the CLI, the policy endpoint and the docs."""
    return [
        {
            "role": spec.name,
            "purpose": spec.purpose,
            "tools": sorted(spec.allowed_tools),
            "tool_count": len(spec.allowed_tools),
            "must_differ_from": sorted(spec.must_differ_from),
            "can_assert_findings": spec.can_assert_findings,
        }
        for spec in ROLE_DEFINITIONS.values()
    ]
