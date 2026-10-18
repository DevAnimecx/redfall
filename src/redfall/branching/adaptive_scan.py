"""Adaptive spawning inside a real scan.

`branching/tree.py` is the data structure and `adaptive.py` holds the detectors.
This module is what connects them to a running scan: it turns a reproduced
finding into new branches, persists them as real rows, and hands them back to the
engine to execute.

The distinction that matters is between a branch that was planned and one that
was discovered. A planned branch exists before anything is known. An adaptive
branch exists *because* a specific finding was reproduced, and it records which
one. That is what makes the ordering rules checkable after the fact rather than
merely asserted.

`BranchEngine` runs branches; it does not spawn them. This module spawns, so the
two stay separable and the static path keeps working unchanged.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Sequence

from sqlalchemy.orm import Session

from ..ingestion.ingest import IngestResult
from ..ingestion.parser_ts import parse_source
from ..store.models import Branch, Finding
from .adaptive import Surface, detect_new_surfaces
from .tree import (
    TRIGGER_TYPES,
    BranchSpec,
    BranchTree,
    Cycle,
    InvalidTrigger,
    MaxBranches,
    MaxDepth,
    TreeError,
)

log = logging.getLogger(__name__)


@dataclass
class SpawnRecord:
    """One adaptive branch that was created, with the evidence that justified it."""

    branch_id: str
    parent_id: str
    name: str
    trigger_type: str
    trigger_reason: str
    triggering_finding_id: str
    discovered_at: datetime
    spawned_at: datetime
    depth: int
    node_id: str = ""

    @property
    def latency_s(self) -> float:
        return (self.spawned_at - self.discovered_at).total_seconds()

    def as_dict(self) -> dict[str, Any]:
        return {
            "branch_id": self.branch_id,
            "parent_id": self.parent_id,
            "name": self.name,
            "trigger_type": self.trigger_type,
            "trigger_reason": self.trigger_reason,
            "triggering_finding_id": self.triggering_finding_id,
            "discovered_at": self.discovered_at.isoformat(),
            "spawned_at": self.spawned_at.isoformat(),
            "spawn_latency_s": round(self.latency_s, 4),
            "depth": self.depth,
        }


@dataclass
class SpawnOutcome:
    spawned: list[SpawnRecord] = field(default_factory=list)
    refused: list[dict[str, str]] = field(default_factory=list)
    surfaces_seen: int = 0

    @property
    def trigger_types(self) -> set[str]:
        return {record.trigger_type for record in self.spawned}

    def as_dict(self) -> dict[str, Any]:
        return {
            "spawned": len(self.spawned),
            "refused": len(self.refused),
            "surfaces_seen": self.surfaces_seen,
            "trigger_types": sorted(self.trigger_types),
            "branches": [r.as_dict() for r in self.spawned],
            "refusals": self.refused,
        }


class AdaptiveSpawner:
    """Creates adaptive branches from reproduced findings, and persists them."""

    def __init__(
        self,
        *,
        session: Session,
        scan_id: str,
        ingest: IngestResult,
        tree: BranchTree,
        max_depth: int = 5,
        model_tier: str = "mid",
    ) -> None:
        self.session = session
        self.scan_id = scan_id
        self.ingest = ingest
        self.tree = tree
        self.max_depth = max_depth
        self.model_tier = model_tier
        # Detector output for a source file cannot change during a scan, so it
        # is computed once per file. Repeated findings in one file therefore
        # re-run the spawn rules against the same surfaces rather than
        # re-parsing the file for every finding.
        self._surfaces_by_file: dict[str, list[Surface]] = {}

    # -- detection ---------------------------------------------------------
    def surfaces_for(self, files: Sequence[str]) -> list[Surface]:
        """Run the seven detectors over the files a finding touched."""
        surfaces: list[Surface] = []
        for rel in files:
            if not rel:
                continue
            if rel not in self._surfaces_by_file:
                self._surfaces_by_file[rel] = self._detect_in_file(rel)
            surfaces.extend(self._surfaces_by_file[rel])
        return surfaces

    def _detect_in_file(self, rel: str) -> list[Surface]:
        path = self._absolute(rel)
        if path is None:
            return []
        parsed = parse_source(path)
        if parsed is None:
            return []
        return detect_new_surfaces(parsed)

    # -- spawning ----------------------------------------------------------
    def spawn_from_finding(
        self,
        finding: Finding,
        *,
        parent_branch_id: str,
        tree_parent_id: str | None = None,
    ) -> SpawnOutcome:
        """Grow the tree in response to one reproduced finding.

        `finding.discovered_at` is the trigger's discovery time. The tree refuses
        a spawn that predates it, which is the structural form of rule 11 — a
        branch that was planned up front cannot be passed off as adaptive.
        """
        outcome = SpawnOutcome()
        parent_db = self.session.get(Branch, parent_branch_id)
        if parent_db is None:
            outcome.refused.append(
                {"reason": "unknown_parent", "detail": parent_branch_id}
            )
            return outcome

        parent_node_id = tree_parent_id or self.tree.root
        self.tree.mark_started(parent_node_id)

        surfaces = self.surfaces_for([finding.location_file])
        outcome.surfaces_seen = len(surfaces)

        for surface in surfaces:
            record = self._spawn_one(
                surface=surface,
                finding=finding,
                parent_db=parent_db,
                parent_node_id=parent_node_id,
            )
            if record is None:
                continue
            if isinstance(record, SpawnRecord):
                outcome.spawned.append(record)
            else:
                outcome.refused.append(record)

        return outcome

    def _spawn_one(
        self,
        *,
        surface: Surface,
        finding: Finding,
        parent_db: Branch,
        parent_node_id: str,
    ) -> SpawnRecord | dict[str, str] | None:
        trigger = surface.trigger_type
        if trigger not in TRIGGER_TYPES:
            return {"reason": "unknown_trigger", "detail": trigger}

        spec = BranchSpec(
            name=surface.branch_name(),
            type="route" if surface.kind in ("route", "directory") else "module",
            scope_files=[surface.file] if surface.file else list(parent_db.scope_files),
            scope_routes=list(surface.scope_routes),
            priority=_priority_for(trigger),
            model_tier=self.model_tier,
        )

        discovered_at = finding.discovered_at or datetime.now(timezone.utc)
        try:
            node = self.tree.spawn_adaptive(
                parent_id=parent_node_id,
                spec=spec,
                triggering_finding_id=finding.id,
                trigger_reason=trigger,
                trigger_discovered_at=discovered_at,
            )
        except (MaxDepth, MaxBranches) as err:
            return {"reason": type(err).__name__, "detail": str(err)[:120]}
        except Cycle:
            # Already in the tree. Not an error: it means the surface was found
            # before, which is the dedupe working rather than a missed spawn.
            return None
        except (InvalidTrigger, TreeError) as err:
            return {"reason": type(err).__name__, "detail": str(err)[:120]}

        row = Branch(
            id=self._branch_id(node.id),
            scan_id=self.scan_id,
            parent_id=parent_db.id,
            type=spec.type,
            name=spec.name,
            scope_files=list(spec.scope_files),
            scope_routes=list(spec.scope_routes),
            depth=node.depth,
            status="pending",
            priority=spec.priority,
            model_tier=spec.model_tier,
            is_adaptive=True,
            created_at=node.created_at,
            triggering_finding_id=finding.id,
            trigger_reason=trigger,
        )
        self.session.add(row)
        self.session.flush()

        return SpawnRecord(
            branch_id=row.id,
            parent_id=parent_db.id,
            name=spec.name,
            trigger_type=trigger,
            trigger_reason=node.trigger_reason or trigger,
            triggering_finding_id=finding.id,
            discovered_at=discovered_at,
            spawned_at=node.created_at,
            depth=node.depth,
            node_id=node.id,
        )

    # -- helpers -----------------------------------------------------------
    def _absolute(self, rel: str) -> Any:
        """The real file behind a repo-relative path.

        `IngestResult` records the target root as `target`; the test double used
        in the spawner tests carries the same value as `root`. Both are accepted
        so the resolution is against the ingested target rather than whatever
        directory the process happens to be in.
        """
        from pathlib import Path

        root = getattr(self.ingest, "target", None) or getattr(self.ingest, "root", None)
        if root is not None:
            candidate = Path(root) / rel
            if candidate.exists():
                return candidate
        fallback = Path(rel)
        return fallback if fallback.exists() else None

    def _branch_id(self, node_id: str) -> str:
        return hashlib.sha256(f"{self.scan_id}:adaptive:{node_id}".encode()).hexdigest()[:16]


def _priority_for(trigger: str) -> int:
    """Surfaces that widen the attack surface most are scanned first.

    A plugin loader or a dynamic import can hand over code execution, so they
    outrank a conditional route that only adds one endpoint.
    """
    return {
        "plugin_system": 95,
        "dynamic_import": 90,
        "db_stored_code": 85,
        "dynamic_route_registration": 70,
        "webhook_discovery": 60,
        "feature_flag": 45,
        "env_conditional": 40,
    }.get(trigger, 30)


def new_tree(*, max_depth: int = 5, max_branches: int = 500) -> BranchTree:
    return BranchTree(max_depth=max_depth, max_branches=max_branches)


def spawn_callback(
    spawner: AdaptiveSpawner,
    tree: BranchTree,
    sink: list[SpawnRecord],
    node_for: Callable[[str], str | None] | None = None,
) -> Callable[[Any, Finding], None]:
    """Adapt the spawner to the `on_finding(branch, finding)` hook the engine calls.

    The engine reports a finding as soon as it reproduces, which is the earliest
    honest moment to spawn: the trigger genuinely exists by then. `node_for`
    maps a persisted branch id onto its tree node so a spawn from an adaptive
    branch lands beneath it rather than at the root.
    """

    def on_finding(branch: Any, finding: Finding) -> None:
        tree_parent_id = node_for(branch.id) if node_for is not None else None
        try:
            outcome = spawner.spawn_from_finding(
                finding,
                parent_branch_id=branch.id,
                tree_parent_id=tree_parent_id or tree.root,
            )
        except Exception:  # a spawn failure must not abort the scan
            log.exception("adaptive spawn failed for %s", finding.id)
            return
        sink.extend(outcome.spawned)

    return on_finding
