"""Recursive branch tree with adaptive spawning.

The tree is the first differentiator: the attack surface grows during a scan, in
response to what the scan finds. Two properties are enforced structurally rather
than by convention, because both are easy to fake and ruin the number:

* An adaptive branch records the finding that triggered it and the enumerated
  reason. There is no such thing as an adaptive branch with no trigger.
* `spawned_at` is set when the branch is created, which is necessarily after the
  trigger was discovered and after the parent started. A branch that was planned
  up front and labelled adaptive is detectable from the timestamps alone.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from ..triggers import TRIGGER_TYPES

# Which branch types a parent may decompose into.
DECOMPOSITION: dict[str, tuple[str, ...]] = {
    "route": ("input_validation", "auth_chain", "data_flow", "error_handling", "external_call"),
    "module": ("module", "route", "config", "dependency", "plugin"),
    "auth": ("token_generation", "token_verification", "session_storage", "lockout"),
    "data_flow": ("sanitization", "encoding", "sink_context"),
    "config": ("secret_usage", "flag_gated_code"),
    "plugin": ("route", "config", "dependency", "plugin"),
}


class TreeError(RuntimeError):
    """A branch could not be inserted. Callers log and continue."""


class MaxDepth(TreeError):
    """The branch would sit deeper than `max_depth` allows."""


class MaxBranches(TreeError):
    """The tree is at its branch cap; no further decomposition is admitted."""


class Cycle(TreeError):
    """The scope is already in the tree, so analysing it again would add nothing."""


class InvalidTrigger(TreeError):
    """An adaptive branch was requested without a real, enumerated trigger."""


def now() -> datetime:
    return datetime.now(timezone.utc)


def scope_fingerprint(
    scope_files: Iterable[str],
    scope_routes: Iterable[str],
    surface: str = "",
) -> str:
    """A stable identity for a scope, so the same surface is never scanned twice.

    The surface label is part of the identity on purpose. Two adaptive spawns can
    legitimately point at the same file — a single module may hold a feature
    flag, an environment conditional and a plugin loader — and those are three
    different investigations. Keying on files alone would silently drop all but
    the first, which loses whole trigger types rather than duplicate work.
    """
    payload = (
        "|".join(sorted(set(scope_files)))
        + "##"
        + "|".join(sorted(set(scope_routes)))
        + "##"
        + surface
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


@dataclass
class BranchSpec:
    """What to create. The tree assigns identity, depth and timestamps."""

    name: str
    type: str
    scope_files: list[str] = field(default_factory=list)
    scope_routes: list[str] = field(default_factory=list)
    priority: int = 0
    model_tier: str = "mid"
    token_budget: int = 0
    is_adaptive: bool = False
    triggering_finding_id: str | None = None
    trigger_reason: str | None = None

    def fingerprint(self) -> str:
        # An adaptive spawn is identified by what triggered it, so two different
        # triggers in one file get two branches instead of colliding.
        surface = f"{self.trigger_reason or ''}:{self.name}" if self.is_adaptive else ""
        return scope_fingerprint(self.scope_files, self.scope_routes, surface)


@dataclass
class BranchNode:
    id: str
    spec: BranchSpec
    depth: int
    parent_id: str | None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    status: str = "pending"
    children: list[str] = field(default_factory=list)

    @property
    def is_adaptive(self) -> bool:
        return self.spec.is_adaptive

    @property
    def trigger_reason(self) -> str | None:
        return self.spec.trigger_reason

    @property
    def triggering_finding_id(self) -> str | None:
        return self.spec.triggering_finding_id

    def spawn_latency_s(self, discovered_at: datetime) -> float:
        """Seconds between the trigger being discovered and this branch existing."""
        return (self.created_at - discovered_at).total_seconds()


class BranchTree:
    """Depth-, size- and cycle-bounded tree of analysis branches."""

    def __init__(
        self,
        *,
        max_depth: int = 5,
        max_branches: int = 500,
        root_name: str = "scan-root",
    ) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        self.max_depth = max_depth
        self.max_branches = max_branches
        self._nodes: dict[str, BranchNode] = {}
        self._fingerprints: set[str] = set()
        self._root_id = self._insert(
            None,
            BranchSpec(name=root_name, type="module", priority=0),
            depth=0,
        )

    # -- reads -------------------------------------------------------------
    @property
    def root(self) -> str:
        return self._root_id

    def __len__(self) -> int:
        return len(self._nodes)

    def get(self, branch_id: str) -> BranchNode:
        try:
            return self._nodes[branch_id]
        except KeyError as err:
            raise TreeError(f"unknown branch {branch_id}") from err

    def nodes(self) -> list[BranchNode]:
        return list(self._nodes.values())

    def adaptive_branches(self) -> list[BranchNode]:
        return [n for n in self._nodes.values() if n.is_adaptive]

    def depth_of(self, branch_id: str) -> int:
        return self.get(branch_id).depth

    def contains_scope(self, fingerprint: str) -> bool:
        return fingerprint in self._fingerprints

    def children_of(self, branch_id: str) -> list[BranchNode]:
        return [self._nodes[c] for c in self.get(branch_id).children if c in self._nodes]

    def descendants(self, branch_id: str) -> list[BranchNode]:
        out: list[BranchNode] = []
        stack = list(self.get(branch_id).children)
        while stack:
            current = stack.pop()
            node = self._nodes.get(current)
            if node is None:
                continue
            out.append(node)
            stack.extend(node.children)
        return out

    def allowed_child_types(self, branch_id: str) -> tuple[str, ...]:
        return DECOMPOSITION.get(self.get(branch_id).spec.type, ())

    # -- writes ------------------------------------------------------------
    def insert(self, parent_id: str, spec: BranchSpec) -> str:
        """Insert a child, enforcing depth, size and cycle limits.

        The parent must exist, and the child's type must be a legal
        decomposition of the parent's type unless the branch is adaptive — an
        adaptive spawn follows the evidence rather than the taxonomy.
        """
        parent = self.get(parent_id)
        depth = parent.depth + 1
        if depth > self.max_depth:
            raise MaxDepth(f"depth {depth} exceeds max_depth {self.max_depth}")
        if len(self._nodes) >= self.max_branches:
            raise MaxBranches(f"branch cap {self.max_branches} reached")
        if not spec.is_adaptive:
            allowed = self.allowed_child_types(parent_id)
            if allowed and spec.type not in allowed:
                raise TreeError(
                    f"{spec.type!r} is not a decomposition of {parent.spec.type!r}; "
                    f"allowed: {list(allowed)}"
                )
        self._validate_trigger(spec)
        return self._insert(parent_id, spec, depth)

    def spawn_adaptive(
        self,
        *,
        parent_id: str,
        spec: BranchSpec,
        triggering_finding_id: str,
        trigger_reason: str,
        trigger_discovered_at: datetime,
    ) -> BranchNode:
        """Create a branch because a finding revealed new surface.

        `spec.is_adaptive` is forced on and the trigger fields are filled here, so
        a caller cannot produce an adaptive branch without a real trigger. The
        discovery timestamp is checked against the clock: a branch cannot be
        spawned before the thing that triggered it was found.
        """
        if trigger_reason not in TRIGGER_TYPES:
            raise InvalidTrigger(
                f"trigger_reason {trigger_reason!r} is not one of {list(TRIGGER_TYPES)}"
            )
        if not triggering_finding_id:
            raise InvalidTrigger("an adaptive branch requires triggering_finding_id")

        parent = self.get(parent_id)
        if parent.started_at is None:
            raise InvalidTrigger(
                f"parent {parent_id} has not started; an adaptive branch must be spawned "
                "from a branch that is actually running"
            )
        created = now()
        if created < trigger_discovered_at:
            raise InvalidTrigger(
                "spawn precedes the triggering finding's discovery; the clock or the "
                "trigger is wrong"
            )
        if created < parent.started_at:
            raise InvalidTrigger("spawn precedes the parent branch's start; it was pre-planned")

        spec.is_adaptive = True
        spec.triggering_finding_id = triggering_finding_id
        spec.trigger_reason = trigger_reason
        self._validate_trigger(spec)

        fingerprint = spec.fingerprint()
        if fingerprint in self._fingerprints:
            raise Cycle(f"scope {fingerprint} is already in the tree")
        if parent.depth + 1 > self.max_depth:
            raise MaxDepth(f"depth {parent.depth + 1} exceeds max_depth {self.max_depth}")
        if len(self._nodes) >= self.max_branches:
            raise MaxBranches(f"branch cap {self.max_branches} reached")

        branch_id = self._identity(parent_id, spec)
        node = BranchNode(
            id=branch_id,
            spec=spec,
            depth=parent.depth + 1,
            parent_id=parent_id,
            created_at=created,
        )
        self._nodes[branch_id] = node
        self._fingerprints.add(fingerprint)
        parent.children.append(branch_id)
        return node

    def mark_started(self, branch_id: str, at: datetime | None = None) -> None:
        node = self.get(branch_id)
        # Idempotent: a branch starts once. Overwriting the timestamp would let
        # a later spawn silently move the parent's start forward, which is
        # exactly the erasure the ordering rules exist to prevent.
        if node.started_at is None:
            node.started_at = at or now()
        node.status = "running"

    def mark_completed(self, branch_id: str, at: datetime | None = None) -> None:
        node = self.get(branch_id)
        node.completed_at = at or now()
        node.status = "completed"

    # -- internals ---------------------------------------------------------
    def _validate_trigger(self, spec: BranchSpec) -> None:
        """Enforce the adaptive/trigger invariant on every insert path."""
        if not spec.is_adaptive:
            return
        if not spec.triggering_finding_id:
            raise InvalidTrigger("is_adaptive=true requires triggering_finding_id")
        if spec.trigger_reason not in TRIGGER_TYPES:
            raise InvalidTrigger(
                f"trigger_reason {spec.trigger_reason!r} is not one of {list(TRIGGER_TYPES)}"
            )

    def _identity(self, parent_id: str, spec: BranchSpec) -> str:
        return hashlib.sha256(
            f"{parent_id}:{spec.name}:{spec.fingerprint()}:{time.time_ns()}".encode()
        ).hexdigest()[:16]

    def _insert(self, parent_id: str | None, spec: BranchSpec, depth: int) -> str:
        fingerprint = spec.fingerprint()
        if fingerprint in self._fingerprints:
            raise Cycle(f"scope {fingerprint} is already in the tree")
        branch_id = self._identity(parent_id or "root", spec)
        node = BranchNode(
            id=branch_id,
            spec=spec,
            depth=depth,
            parent_id=parent_id,
            created_at=now(),
        )
        self._nodes[branch_id] = node
        self._fingerprints.add(fingerprint)
        if parent_id is not None:
            self._nodes[parent_id].children.append(branch_id)
        return branch_id


def priority_from_severity(severity: str) -> int:
    """Higher is more urgent. Critical findings get their follow-up scanned first."""
    return {"critical": 100, "high": 70, "medium": 40, "low": 10}.get(severity.lower(), 20)
