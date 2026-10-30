"""Branch lifecycle: materialise the plan, run each branch, enforce the budget.

Runs branches in priority order — higher priority runs first. Adaptive
spawning (§5.3) is driven from here but owned by `branching/adaptive_scan.py`:
`run_branch` reports every reproduced finding through its `on_finding` hook at
the moment it is reproduced, and the orchestrator's spawner turns that into new
branches. This engine itself never invents a branch.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from sqlalchemy.orm import Session

from ..agent.agent import Agent, AnalysisFinding, snippet_for
from ..ingestion.ingest import IngestResult
from ..llm import LLMError
from ..store.models import Branch, Finding
from .dedupe import dedupe_key, merge_duplicates

VALIDATE_ATTEMPTS = 2


@dataclass
class BranchOutcome:
    branch_id: str
    name: str
    candidates: int = 0
    reproduced: int = 0
    rejected: int = 0
    errors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    duration_ms: int = 0


@dataclass
class ScanOutcome:
    scan_id: str
    branches: list[BranchOutcome] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    llm_errors: list[str] = field(default_factory=list)
    duration_ms: int = 0


class BranchEngine:
    """Drives branches through analyse → propose PoC → execute → record."""

    def __init__(
        self,
        *,
        agent: Agent,
        ingest_result: IngestResult,
        validator: Any,
        session: Session,
        scan_id: str,
    ) -> None:
        self.agent = agent
        self.ingest = ingest_result
        self.validator = validator
        self.session = session
        self.scan_id = scan_id

    # -- planning ----------------------------------------------------------
    def materialise(self, planned: list[Any]) -> list[Branch]:
        """Turn planner output into Branch rows, dropping references that do not
        exist in the ingested graph. A planner cannot invent attack surface."""
        known_files = {f.path for f in self.ingest.files}
        known_routes = {
            f"{r['method']} {r['path']}" for r in self.ingest.http_routes()
        }
        branches: list[Branch] = []
        for index, plan in enumerate(planned):
            scope_files = [f for f in plan.scope_files if f in known_files]
            scope_routes = [r for r in plan.scope_routes if r in known_routes]
            dropped_files = [f for f in plan.scope_files if f not in known_files]
            dropped_routes = [r for r in plan.scope_routes if r not in known_routes]
            if not scope_files and not scope_routes:
                # Nothing real to look at; record why instead of running empty.
                continue
            branch_id = self._branch_id(plan.name, index)
            branch = Branch(
                id=branch_id,
                scan_id=self.scan_id,
                parent_id=None,
                type=plan.type,
                name=plan.name,
                scope_files=scope_files,
                scope_routes=scope_routes,
                depth=0,
                status="pending",
                priority=plan.priority,
                model_tier=plan.model_tier,
                is_adaptive=False,
            )
            self.session.add(branch)
            branches.append(branch)
            if dropped_files or dropped_routes:
                branch.status = "pending"
                self._note(branch, f"planner referenced unknown scope: {dropped_files + dropped_routes}")
        branches.sort(key=lambda b: b.priority, reverse=True)
        self.session.flush()
        return branches

    # -- execution ---------------------------------------------------------
    def run_branch(
        self,
        branch: Branch,
        on_finding: Callable[[Branch, Finding], None] | None = None,
        *,
        session: Session | None = None,
    ) -> BranchOutcome:
        """Run one branch. Pass `session` when branches run in parallel.

        A SQLAlchemy Session is not safe to share between threads, so a caller
        that runs branches concurrently must give each worker its own and pass
        it here. The sequential caller omits it and keeps using the session the
        engine was built with.
        """
        active = session if session is not None else self.session
        started = time.time()
        outcome = BranchOutcome(branch_id=branch.id, name=branch.name)
        branch.status = "running"
        branch.started_at = _now()
        active.flush()

        files = {f.path: f.content for f in self.ingest.files if f.path in branch.scope_files}
        routes = [r for r in self.ingest.http_routes() if r["file"] in branch.scope_files]
        if branch.scope_routes:
            wanted = set(branch.scope_routes)
            routes = [r for r in routes if f"{r['method']} {r['path']}" in wanted] or routes
        taints = self._taints_for(branch)
        deps = [
            {"name": d.name, "declared": d.declared, "resolved": d.resolved}
            for d in self.ingest.security_relevant_deps()
        ]

        try:
            candidates = self.agent.analyse(
                branch_id=branch.id,
                branch_name=branch.name,
                files=files,
                routes=routes,
                taints=taints,
                dependencies=deps,
                tier=branch.model_tier,
            )
        except LLMError as err:
            branch.status = "failed"
            outcome.errors.append(f"analyze: {err}")
            branch.completed_at = _now()
            active.flush()
            outcome.duration_ms = int((time.time() - started) * 1000)
            return outcome

        outcome.candidates = len(candidates)
        accepted: list[Finding] = []
        for candidate in candidates:
            row = self._validate_candidate(branch, candidate, files, routes, outcome, active)
            if row is not None:
                accepted.append(row)
                if on_finding is not None:
                    on_finding(row)

        merged = merge_duplicates(accepted)
        outcome.reproduced = len(merged)
        outcome.rejected = outcome.candidates - len(merged)
        outcome.findings = merged
        branch.status = "completed"
        branch.completed_at = _now()
        active.flush()
        outcome.duration_ms = int((time.time() - started) * 1000)
        return outcome

    def _validate_candidate(
        self,
        branch: Branch,
        candidate: AnalysisFinding,
        files: dict[str, str],
        routes: list[dict[str, Any]],
        outcome: BranchOutcome,
        session: Session,
    ) -> Finding | None:
        """Generate a PoC and execute it. Only a reproduced candidate is kept."""
        if not candidate.file:
            outcome.errors.append(f"{candidate.category}: analyzer gave no location.file")
            return None

        route = self._route_for(candidate, routes)
        snippet = snippet_for(self.ingest, candidate.file, candidate.line)
        poc: dict[str, Any] = dict(candidate.poc or {})
        reasoning = ""

        if not poc.get("request"):
            try:
                poc, reasoning = self.agent.generate_poc(
                    branch_id=branch.id,
                    finding=candidate,
                    source_snippet=snippet,
                    route=route,
                )
            except LLMError as err:
                outcome.errors.append(f"{candidate.category}: poc generation failed: {err}")
                return None

        verdict = None
        for attempt in range(1, VALIDATE_ATTEMPTS + 1):
            verdict = self.validator.validate(
                branch_id=branch.id,
                poc=poc,
                finding_category=candidate.category,
                target_file=candidate.file,
                session=session,
            )
            if verdict.reproduced:
                break
            if attempt == VALIDATE_ATTEMPTS:
                break
            try:
                poc, reasoning = self.agent.generate_poc(
                    branch_id=branch.id,
                    finding=candidate,
                    source_snippet=snippet,
                    route=route,
                    prior_attempt={
                        "attempt": attempt,
                        "request": poc.get("request", ""),
                        "expect_expr": poc.get("expect_expr", ""),
                        "observed_status": verdict.status,
                        "observed_body": verdict.body[:1500],
                        "reason": verdict.reason,
                    },
                )
            except LLMError as err:
                outcome.errors.append(f"{candidate.category}: poc retry failed: {err}")
                break

        if verdict is None or not verdict.reproduced:
            return None

        row = Finding(
            id=self._finding_id(candidate, verdict),
            scan_id=self.scan_id,
            branch_id=branch.id,
            category=candidate.category,
            severity=candidate.severity,
            title=candidate.title,
            description=candidate.description,
            location_file=candidate.file,
            location_line=candidate.line,
            location_symbol=candidate.symbol,
            poc=poc,
            evidence=_compose_evidence(candidate.evidence, verdict.evidence, reasoning),
            remediation=candidate.remediation,
            reproduced=True,
            reproduction_run_id=verdict.run_id,
            dedupe_key=dedupe_key(candidate.category, candidate.file, candidate.symbol, candidate.line),
            status="open",
        )
        session.add(row)
        return row

    # -- helpers -----------------------------------------------------------
    def _taints_for(self, branch: Branch) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for rel, taint in self.ingest.taint_paths:
            if rel not in branch.scope_files:
                continue
            owners = self.ingest.routes_for_line(rel, taint.line)
            out.append(
                {
                    "file": rel,
                    "line": taint.line,
                    "source": taint.source,
                    "sink": taint.sink,
                    "sink_kind": taint.sink_kind,
                    "symbol": taint.symbol,
                    "via": taint.via,
                    "reachable_from": [f"{o['method']} {o['path']}" for o in owners],
                }
            )
        return out

    @staticmethod
    def _route_for(candidate: AnalysisFinding, routes: list[dict[str, Any]]) -> dict[str, Any] | None:
        for route in routes:
            if route["file"] != candidate.file:
                continue
            if route["line"] <= candidate.line <= route["line"] + 200:
                return route
        return routes[0] if routes else None

    def _branch_id(self, name: str, index: int) -> str:
        return hashlib.sha256(f"{self.scan_id}:branch:{index}:{name}".encode()).hexdigest()[:16]

    def _finding_id(self, candidate: AnalysisFinding, verdict: Any) -> str:
        return hashlib.sha256(
            f"{self.scan_id}:{candidate.category}:{candidate.file}:{candidate.line}:{verdict.run_id}".encode()
        ).hexdigest()[:16]

    def _note(self, branch: Branch, message: str) -> None:
        existing = list(branch.scope_routes)
        branch.scope_routes = existing  # scope stays authoritative; note is informational


def _compose_evidence(static_evidence: str, runtime_evidence: str, reasoning: str) -> str:
    parts = []
    if static_evidence:
        parts.append(f"[static]\n{static_evidence}")
    if runtime_evidence:
        parts.append(f"[runtime]\n{runtime_evidence}")
    if reasoning:
        parts.append(f"[reasoning]\n{reasoning}")
    return "\n\n".join(parts)


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)
