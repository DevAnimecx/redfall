"""Scan orchestration: ingest → plan → branch → analyse → execute → report."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import func, select

from .agent.agent import Agent
from .branching.adaptive_scan import AdaptiveSpawner, SpawnRecord, new_tree
from .branching.engine import BranchEngine, ScanOutcome
from .branching.worklist import BranchWorklist
from .chain.executor import ChainExecutor
from .chain.stage import ChainStageOutcome, run_chain_stage
from .config import Config, check_prerequisites, describe_environment
from .ingestion.dependencies import read_dependencies
from .ingestion.ingest import ingest
from .llm import BudgetExceeded, LLMError, new_budget
from .reasoning import load_backend_config, make_backend
from .sandbox.docker_gvisor import SandboxUnavailable
from .store.db import init_engine
from .store.models import Branch, Finding, LLMCall, SandboxRun, Scan
from .store.state import StateStore
from .validation.validator import Validator


@dataclass
class ScanReport:
    scan_id: str
    target: str
    commit: str
    status: str
    started_at: str
    completed_at: str
    duration_ms: int
    branches: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    chains: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    sandbox_runs: int = 0
    llm: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    adaptive: dict[str, Any] = field(default_factory=dict)
    chain: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str)


def run_scan(
    config: Config,
    target: str | Path,
    *,
    out_path: str | Path | None = None,
    on_event: Any = None,
) -> ScanReport:
    """Execute a full scan. Raises rather than degrading when a prerequisite fails."""
    check_prerequisites(config, require_llm=False, require_sandbox=True)

    started = time.time()
    started_at = datetime.now(timezone.utc)
    engine = init_engine(config.database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)

    state = StateStore(config.redis_url)
    ok, detail = state.ping()
    if not ok:
        raise RuntimeError(f"Redis is required for scan state: {detail}")

    target_path = Path(target).resolve()
    scan_id = f"scan-{started_at.strftime('%Y%m%d-%H%M%S')}"

    def emit(kind: str, payload: dict[str, Any]) -> None:
        if on_event is not None:
            on_event(kind, payload)

    with SessionLocal() as session:
        scan = Scan(id=scan_id, repo=str(target_path), commit="", status="running", started_at=started_at)
        session.add(scan)
        session.flush()

        emit("ingest:start", {"scan_id": scan_id, "target": str(target_path)})
        result = ingest(scan_id, target_path, session)
        scan.commit = result.git.commit or result.git.label
        session.flush()
        state.set_scan_state(
            scan_id,
            {
                "status": "ingested",
                "target": str(target_path),
                "files": len(result.files),
                "taint_paths": len(result.taint_paths),
                "routes": len(result.http_routes()),
            },
        )
        emit(
            "ingest:done",
            {
                "files": len(result.files),
                "taint_paths": len(result.taint_paths),
                "routes": len(result.http_routes()),
                "duration_ms": result.duration_ms,
                "parse_errors": result.parse_errors,
            },
        )

        budget = new_budget(config.max_tokens_per_scan, config.max_cost_per_scan_usd)
        # 0.2.1: the model layer is chosen by config. A provider key and an
        # installed agent are two answers to the same question; `auto` picks
        # whichever is present and refuses loudly when neither is.
        backend = make_backend(
            load_backend_config(target_path),
            session_factory=SessionLocal,
            budget=budget,
        )
        emit("reasoning:backend", {"backend": backend.describe()})
        llm = backend
        agent = Agent(llm=llm, scan_id=scan_id)
        validator = Validator(
            target=target_path,
            session=session,
            scan_id=scan_id,
            workdir=config.workdir / "workspaces",
            timeout_s=config.sandbox_timeout_s,
        )

        routes = result.http_routes()
        taints = [
            {
                "file": rel,
                "line": t.line,
                "source": t.source,
                "sink": t.sink,
                "sink_kind": t.sink_kind,
                "symbol": t.symbol,
                "via": t.via,
                "reachable_from": [
                    f"{o['method']} {o['path']}" for o in result.routes_for_line(rel, t.line)
                ],
            }
            for rel, t in result.taint_paths
        ]
        deps = [
            {"name": d.name, "declared": d.declared, "resolved": d.resolved}
            for d in result.security_relevant_deps()
        ]

        emit("plan:start", {"routes": len(routes), "taint_paths": len(taints)})
        planned = agent.plan(routes=routes, taints=taints, dependencies=deps)
        branch_engine = BranchEngine(
            agent=agent,
            ingest_result=result,
            validator=validator,
            session=session,
            scan_id=scan_id,
        )
        branches = branch_engine.materialise(planned)
        state.push_branches(scan_id, [b.id for b in branches])
        emit("plan:done", {"branches": len(branches), "names": [b.name for b in branches]})

        # Adaptive spawning (§5.3). The tree is the authority on what branches
        # exist and refuses a spawn that is not backed by a reproduced finding;
        # the engine reports findings through `on_finding` as they reproduce, so
        # a branch can only appear after the evidence that justifies it exists.
        tree = new_tree(max_depth=config.branch_max_depth)
        tree.mark_started(tree.root)
        spawner = AdaptiveSpawner(
            session=session,
            scan_id=scan_id,
            ingest=result,
            tree=tree,
            max_depth=config.branch_max_depth,
        )
        spawns: list[SpawnRecord] = []
        spawn_refusals: list[dict[str, str]] = []
        node_by_branch: dict[str, str] = {}

        def on_finding(branch: Branch, finding: Finding) -> None:
            spawn_outcome = spawner.spawn_from_finding(
                finding,
                parent_branch_id=branch.id,
                tree_parent_id=node_by_branch.get(branch.id, tree.root),
            )
            spawn_refusals.extend(spawn_outcome.refused)
            for record in spawn_outcome.spawned:
                spawns.append(record)
                node_by_branch[record.branch_id] = record.node_id
                emit("branch:adaptive-spawn", record.as_dict())

        outcome = ScanOutcome(scan_id=scan_id)
        executed: list[Branch] = []
        worklist = sorted(branches, key=lambda b: b.priority, reverse=True)
        queued = {b.id for b in worklist}

        # Branches run `sandbox_pool_size` at a time. Each worker takes its own
        # session; everything shared stays on this thread, which is why the
        # findings are replayed here through `on_finding` rather than reported
        # from inside the worker.
        def run_one(branch: Branch, worker_session: Session) -> Any:
            return branch_engine.run_branch(branch, session=worker_session)

        pool = BranchWorklist(
            run_branch=run_one,
            session_factory=SessionLocal,
            workers=max(1, config.sandbox_pool_size),
        )
        for branch in worklist:
            pool.submit(branch)

        def fold(run: Any) -> bool:
            """Apply a finished branch to the scan. False means stop the scan."""
            branch = session.get(Branch, run.branch_id)
            if run.error is not None:
                err = run.error
                if isinstance(err, SandboxUnavailable):
                    outcome.llm_errors.append(f"sandbox unavailable during {run.name}: {err}")
                    emit("branch:sandbox-unavailable", {"branch": run.name, "reason": str(err)})
                    return False
                if isinstance(err, BudgetExceeded):
                    outcome.llm_errors.append(f"budget: {err}")
                    emit("scan:budget-exceeded", {"reason": str(err)})
                    return False
                if isinstance(err, LLMError):
                    outcome.llm_errors.append(f"{run.name}: {err}")
                    emit("branch:llm-error", {"branch": run.name, "error": str(err)})
                    if branch is not None:
                        executed.append(branch)
                    return True
                # Anything else is a bug in a branch or the engine, not a
                # condition the scan can absorb. Let it surface.
                raise err

            branch_outcome = run.outcome
            if branch is not None:
                # Replay the worker's findings here: the hook mutates the branch
                # tree, which is single-owner state.
                for row in branch_outcome.findings:
                    on_finding(branch, row)
                executed.append(branch)
            outcome.branches.append(branch_outcome)
            outcome.findings.extend(branch_outcome.findings)
            emit(
                "branch:done",
                {
                    "branch": run.name,
                    "adaptive": branch.is_adaptive if branch is not None else False,
                    "candidates": branch_outcome.candidates,
                    "reproduced": branch_outcome.reproduced,
                    "duration_ms": branch_outcome.duration_ms,
                },
            )
            return True

        def enqueue_spawned() -> None:
            """Append adaptive branches an advanced run produced, by priority."""
            fresh = False
            for record in list(spawns):
                if record.branch_id in queued:
                    continue
                row = session.get(Branch, record.branch_id)
                if row is None:
                    continue
                queued.add(record.branch_id)
                worklist.append(row)
                fresh = True
            if fresh:
                worklist.sort(key=lambda b: b.priority, reverse=True)

        stopping = False
        try:
            while True:
                # Top the pool up from the worklist, highest priority first.
                while worklist and pool.has_room() and not stopping:
                    branch = worklist.pop(0)
                    emit(
                        "branch:start",
                        {
                            "branch": branch.name,
                            "adaptive": branch.is_adaptive,
                            "trigger": branch.trigger_reason,
                            "files": branch.scope_files,
                        },
                    )
                    state.update_scan_state(scan_id, {"current_branch": branch.name})
                    pool.submit(branch)

                if pool.in_flight == 0:
                    if not worklist or stopping:
                        break
                    continue

                for run in pool.take_done(block=True):
                    # Re-read the branch row on this thread's session: the
                    # worker flushed through its own, and this session may hold
                    # a stale copy.
                    session.expire_all()
                    if not fold(run):
                        stopping = True
                enqueue_spawned()
        finally:
            pool.close()

        # Chain stage (§ step 7). Only reproduced findings take part; the model
        # proposes wirings, the sandbox replays them, and only the steps whose
        # predicates held become edges. A chain that fails keeps its record.
        chain_stage = ChainStageOutcome()
        reproduced_wire = [f.to_wire() for f in outcome.findings if f.reproduced]
        emit("chain:start", {"reproduced_findings": len(reproduced_wire)})
        try:
            chain_stage = run_chain_stage(
                agent=agent,
                executor=ChainExecutor(
                    validator=validator,
                    session=session,
                    scan_id=scan_id,
                    findings={str(f["id"]): f for f in reproduced_wire},
                ),
                session=session,
                scan_id=scan_id,
                findings=reproduced_wire,
                max_chains=config.chain_max_candidates,
                emit=emit,
            )
        except SandboxUnavailable as err:
            outcome.llm_errors.append(f"sandbox unavailable during chaining: {err}")
            emit("chain:sandbox-unavailable", {"reason": str(err)})
        outcome.llm_errors.extend(chain_stage.errors)

        duration_ms = int((time.time() - started) * 1000)
        severity_counts: dict[str, int] = {}
        for finding in outcome.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        scan.branches_total = len(executed)
        scan.branches_adaptive = sum(1 for b in executed if b.is_adaptive)
        scan.findings_total = len(outcome.findings)
        scan.findings_by_severity = severity_counts
        scan.chains_total = chain_stage.reproduced + chain_stage.partial
        scan.edges_total = len(chain_stage.edges)
        scan.tokens_total = budget.tokens_used
        scan.tokens_by_tier = _tokens_by_tier(session, scan_id)
        scan.cost_estimate_usd = budget.cost_usd
        scan.duration_ms = duration_ms
        scan.completed_at = datetime.now(timezone.utc)
        scan.status = "completed" if not outcome.llm_errors else "completed_with_errors"
        session.flush()
        state.update_scan_state(scan_id, {"status": scan.status, "findings": len(outcome.findings)})

        report = ScanReport(
            scan_id=scan_id,
            target=str(target_path),
            commit=scan.commit,
            status=scan.status,
            started_at=started_at.isoformat(),
            completed_at=scan.completed_at.isoformat(),
            duration_ms=duration_ms,
            branches=[_branch_summary(b, outcome) for b in executed],
            findings=[f.to_wire() for f in outcome.findings],
            chains=chain_stage.chains,
            edges=chain_stage.edges,
            sandbox_runs=int(
                session.execute(
                    select(func.count()).select_from(SandboxRun).where(SandboxRun.scan_id == scan_id)
                ).scalar_one()
            ),
            llm=budget.as_dict(),
            environment=describe_environment(config),
            errors=outcome.llm_errors,
            adaptive={
                "spawned": len(spawns),
                "refused": spawn_refusals,
                "trigger_types": sorted({record.trigger_type for record in spawns}),
                "branches": [record.as_dict() for record in spawns],
                "max_depth": config.branch_max_depth,
            },
            chain={
                "proposed": chain_stage.proposed,
                "reviewed_out": chain_stage.reviewed_out,
                "reproduced": chain_stage.reproduced,
                "partial": chain_stage.partial,
                "refused": chain_stage.refused,
                "refusals": chain_stage.refusals,
                "graph": chain_stage.graph,
                "strongest_paths": chain_stage.strongest,
                "max_candidates": config.chain_max_candidates,
            },
        )

    if out_path is not None:
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report.to_json())

    return report


def _tokens_by_tier(session: Session, scan_id: str) -> dict[str, int]:
    rows = session.execute(
        select(LLMCall.tier, LLMCall.prompt_tokens, LLMCall.completion_tokens).where(LLMCall.scan_id == scan_id)
    ).all()
    totals: dict[str, int] = {}
    for tier, prompt, completion in rows:
        totals[tier] = totals.get(tier, 0) + int(prompt or 0) + int(completion or 0)
    return totals


def _branch_summary(branch: Branch, outcome: ScanOutcome) -> dict[str, Any]:
    match = next((b for b in outcome.branches if b.branch_id == branch.id), None)
    return {
        "id": branch.id,
        "name": branch.name,
        "type": branch.type,
        "status": branch.status,
        "priority": branch.priority,
        "model_tier": branch.model_tier,
        "scope_files": branch.scope_files,
        "scope_routes": branch.scope_routes,
        "depth": branch.depth,
        "is_adaptive": branch.is_adaptive,
        "trigger_reason": branch.trigger_reason,
        "triggering_finding_id": branch.triggering_finding_id,
        "candidates": match.candidates if match else 0,
        "reproduced": match.reproduced if match else 0,
        "duration_ms": match.duration_ms if match else 0,
        "errors": match.errors if match else [],
    }


def load_findings(config: Config, scan_id: str | None = None) -> list[dict[str, Any]]:
    """Read findings back out of Postgres for reporting and fixing."""
    engine = init_engine(config.database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with SessionLocal() as session:
        query = select(Finding)
        if scan_id:
            query = query.where(Finding.scan_id == scan_id)
        rows = session.execute(query.order_by(Finding.discovered_at)).scalars().all()
        return [r.to_wire() for r in rows]
