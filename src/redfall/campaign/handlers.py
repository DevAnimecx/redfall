"""Real task handlers for the durable campaign runner.

Each handler does one thing against persisted state and a real local target.
None of them invents a finding when the LLM, sandbox or graph is unavailable:
the task fails with the actual reason, and prerequisites that cannot change by
retrying move the campaign to blocked.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import PrerequisiteError
from ..evidence.ledger import EvidenceLedger
from ..graph.indexer import GraphIndexError, GraphIndexer
from ..graph.query import GraphQuery, GraphQueryError
from ..orchestrator import ScanReport, run_scan
from ..sandbox.docker_gvisor import SandboxUnavailable
from ..store.models import Campaign, SandboxRun, utcnow
from ..validation.reproducer import (
    ReproductionBlocked,
    ReproductionError,
    Reproducer,
)
from .execution import HandlerSpec, TaskBlocked, TaskContext, TaskResult
from .policy import PolicyError, require_campaign_path
from .service import CampaignService


def _target(context: TaskContext, key: str = "target") -> Path:
    raw = context.payload.get(key) or context.campaign.repo
    if not isinstance(raw, str) or not raw.strip():
        raise TaskBlocked("no target path was supplied and the campaign repo is not a local path")
    try:
        return require_campaign_path(
            context.campaign,
            raw,
            action=context.task.kind,
            require_directory=True,
        )
    except PolicyError as exc:
        raise TaskBlocked(str(exc)) from exc


def _latest_snapshot(context: TaskContext) -> str:
    payload_id = context.payload.get("snapshot_id")
    if isinstance(payload_id, str) and payload_id.strip():
        return payload_id.strip()
    query = GraphQuery(context.session)
    try:
        return query.snapshot(campaign_id=context.campaign.id).id
    except GraphQueryError as exc:
        raise TaskBlocked(
            "no graph snapshot exists for this campaign; run a graph.index task first"
        ) from exc


def _graph_estimate(context: TaskContext) -> dict[str, float | int]:
    return {"usd": 0.0, "tokens": 0, "sandbox_minutes": 0.0}


def _all_remaining_estimate(context: TaskContext) -> dict[str, float | int]:
    service = CampaignService(context.session)
    remaining = service.budget_remaining(context.campaign.id)
    if remaining["usd"] is not None and remaining["usd"] <= 0:
        raise TaskBlocked("USD budget is exhausted")
    if remaining["tokens"] is not None and remaining["tokens"] <= 0:
        raise TaskBlocked("token budget is exhausted")
    if remaining["sandbox_minutes"] is not None and remaining["sandbox_minutes"] <= 0:
        raise TaskBlocked("sandbox-minute budget is exhausted")
    return {
        "usd": float(remaining["usd"] or 0.0),
        "tokens": int(remaining["tokens"] or 0),
        "sandbox_minutes": float(remaining["sandbox_minutes"] or 0.0),
    }


def _reproduce_estimate(context: TaskContext) -> dict[str, float | int]:
    payload = context.payload.get("estimate")
    if isinstance(payload, dict):
        return {
            "usd": float(payload.get("usd", 0.0)),
            "tokens": int(payload.get("tokens", 0)),
            "sandbox_minutes": float(payload.get("sandbox_minutes", 0.0)),
        }
    minutes = max(1.0, (context.config.sandbox_timeout_s + 59) / 60.0)
    remaining = CampaignService(context.session).budget_remaining(context.campaign.id)
    if remaining["sandbox_minutes"] is not None and remaining["sandbox_minutes"] < minutes:
        raise TaskBlocked(
            "not enough sandbox-minute budget for one reproduction: "
            f"need {minutes:.2f}, have {remaining['sandbox_minutes']:.2f}"
        )
    return {"usd": 0.0, "tokens": 0, "sandbox_minutes": minutes}


def _sandbox_minutes(session: Session, scan_id: str) -> float:
    rows = session.scalars(select(SandboxRun).where(SandboxRun.scan_id == scan_id)).all()
    total = 0.0
    for row in rows:
        if row.started_at is None or row.finished_at is None:
            continue
        started = row.started_at
        finished = row.finished_at
        if started.tzinfo is None:
            started = started.replace(tzinfo=utcnow().tzinfo)
        if finished.tzinfo is None:
            finished = finished.replace(tzinfo=utcnow().tzinfo)
        total += max(0.0, (finished - started).total_seconds()) / 60.0
    return round(total, 4)


def _environment_digest(report: ScanReport) -> str:
    payload = json.dumps(
        {
            "environment": report.environment,
            "commit": report.commit,
            "target": report.target,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record_scan_evidence(
    session: Session,
    campaign: Campaign,
    report: ScanReport,
    *,
    target: Path,
) -> dict[str, Any]:
    """Attach a completed scan to a campaign and ledger its reproduced findings."""
    campaign.scan_id = report.scan_id
    campaign.commit = report.commit or campaign.commit
    campaign.updated_at = utcnow()
    ledger = EvidenceLedger(session)
    digest = _environment_digest(report)
    evidence_ids: list[str] = []
    skipped: list[dict[str, str]] = []
    for finding in report.findings:
        if not finding.get("reproduced"):
            continue
        execution_id = str(finding.get("reproduction_run_id") or "").strip()
        observable = str(finding.get("evidence") or "").strip()
        if not execution_id:
            skipped.append({"finding_id": str(finding.get("id")), "reason": "missing execution id"})
            continue
        if not observable:
            skipped.append({"finding_id": str(finding.get("id")), "reason": "missing observable"})
            continue
        finding_id = str(finding.get("id") or "")
        record = ledger.append(
            campaign.id,
            grade="E3",
            kind="execution",
            claim=f"Reproduced {finding.get('category')}: {finding.get('title')}",
            finding_id=finding_id or None,
            payload={
                "execution_id": execution_id,
                "observable": observable[:2000],
                "expected_observable": str(finding.get("title") or ""),
                "status_code": (finding.get("poc") or {}).get("expected_status"),
                "finding_category": finding.get("category"),
                "target_file": (finding.get("location") or {}).get("file"),
                "target_line": (finding.get("location") or {}).get("line"),
                "scan_id": report.scan_id,
                "reproduced": True,
            },
            reproduce_command=(
                f"redfall reproduce {finding_id} --target {target} "
                f"--campaign-id {campaign.id}"
            ),
            environment_digest=digest,
        )
        evidence_ids.append(record.id)
    session.flush()
    return {
        "scan_id": report.scan_id,
        "environment_digest": digest,
        "evidence_ids": evidence_ids,
        "skipped": skipped,
        "findings_total": len(report.findings),
        "reproduced_total": sum(1 for finding in report.findings if finding.get("reproduced")),
    }


def _graph_index(context: TaskContext) -> TaskResult:
    target = _target(context)
    label = str(context.payload.get("label") or "")
    try:
        snapshot = GraphIndexer(context.session).index(
            target,
            campaign_id=context.campaign.id,
            label=label,
        )
    except GraphIndexError as exc:
        raise TaskBlocked(str(exc)) from exc
    service = CampaignService(context.session)
    status = service.status(context.campaign.id)
    return TaskResult(
        result={
            "snapshot": snapshot.to_wire(),
            "stats": GraphQuery(context.session).stats(snapshot.id),
            "budget_remaining": status["budget_remaining"],
        }
    )


def _graph_inventory(context: TaskContext) -> TaskResult:
    snapshot_id = _latest_snapshot(context)
    limit = int(context.payload.get("limit", 200))
    try:
        inventory = GraphQuery(context.session).inventory(snapshot_id, limit=limit)
    except GraphQueryError as exc:
        raise TaskBlocked(str(exc)) from exc
    return TaskResult(result={"snapshot_id": snapshot_id, "inventory": inventory})


def _graph_diff(context: TaskContext) -> TaskResult:
    payload = context.payload
    base = str(payload.get("base_snapshot") or "").strip()
    head = str(payload.get("head_snapshot") or "").strip()
    if not base or not head:
        raise TaskBlocked("graph.diff requires payload.base_snapshot and payload.head_snapshot")
    try:
        diff = GraphQuery(context.session).diff(base, head, limit=int(payload.get("limit", 200)))
    except GraphQueryError as exc:
        raise TaskBlocked(str(exc)) from exc
    return TaskResult(result=diff)


def _graph_query(context: TaskContext) -> TaskResult:
    snapshot_id = _latest_snapshot(context)
    payload = context.payload
    try:
        data = GraphQuery(context.session).search(
            snapshot_id=snapshot_id,
            query=str(payload.get("query") or ""),
            kind=str(payload.get("kind") or ""),
            file=str(payload.get("file") or ""),
            limit=int(payload.get("limit", 50)),
            offset=int(payload.get("offset", 0)),
        )
    except GraphQueryError as exc:
        raise TaskBlocked(str(exc)) from exc
    return TaskResult(result=data)


def _scan_run(context: TaskContext) -> TaskResult:
    target = _target(context)
    try:
        report = run_scan(context.config, target)
    except PrerequisiteError as exc:
        raise TaskBlocked("scan prerequisites are not met", details=exc.failures) from exc
    except SandboxUnavailable as exc:
        raise TaskBlocked(str(exc), details=exc.reasons) from exc
    except RuntimeError as exc:
        raise TaskBlocked(str(exc)) from exc
    context.session.expire_all()
    evidence = record_scan_evidence(context.session, context.campaign, report, target=target)
    sandbox_minutes = _sandbox_minutes(context.session, report.scan_id)
    llm = report.llm or {}
    spend: dict[str, float | int] = {
        "usd": float(llm.get("cost_usd") or 0.0),
        "tokens": int(llm.get("tokens_used") or 0),
        "sandbox_minutes": sandbox_minutes,
    }
    return TaskResult(
        result={
            "scan_id": report.scan_id,
            "status": report.status,
            "target": report.target,
            "commit": report.commit,
            "duration_ms": report.duration_ms,
            "findings": report.findings,
            "chains": report.chains,
            "edges": report.edges,
            "sandbox_runs": report.sandbox_runs,
            "llm": report.llm,
            "environment": report.environment,
            "errors": report.errors,
            "evidence": evidence,
            "cost_unknown_calls": int(llm.get("cost_unknown_calls") or 0),
        },
        spend=spend,
    )


def _finding_reproduce(context: TaskContext) -> TaskResult:
    finding_id = context.require_payload_str("finding_id")
    target = _target(context)
    workdir = context.config.workdir / "workspaces"
    try:
        outcome = Reproducer(
            context.session,
            workdir=workdir,
            timeout_s=context.config.sandbox_timeout_s,
        ).reproduce(
            finding_id,
            campaign_id=context.campaign.id,
            target=target,
        )
    except (ReproductionBlocked, SandboxUnavailable) as exc:
        details = list(getattr(exc, "details", []) or getattr(exc, "reasons", []))
        raise TaskBlocked(str(exc), details=details) from exc
    except ReproductionError as exc:
        raise TaskBlocked(str(exc)) from exc
    return TaskResult(
        result=outcome.to_wire(),
        spend={"sandbox_minutes": round(outcome.duration_ms / 60000.0, 4)},
    )


def _evidence_verify(context: TaskContext) -> TaskResult:
    ledger = EvidenceLedger(context.session)
    chain = ledger.verify(context.campaign.id)
    records = ledger.list(context.campaign.id)
    return TaskResult(
        result={
            "chain": chain.to_wire(),
            "records": len(records),
            "reportable": sum(1 for record in records if record.grade in {"E3", "E4"}),
        }
    )


def _report_readiness(context: TaskContext) -> TaskResult:
    ledger = EvidenceLedger(context.session)
    chain = ledger.verify(context.campaign.id)
    reportable = ledger.reportable(context.campaign.id)
    ready = chain.ok and bool(reportable)
    return TaskResult(
        result={
            "ready": ready,
            "reason": "" if ready else ("evidence chain is broken" if not chain.ok else "no E3/E4 evidence"),
            "chain": chain.to_wire(),
            "evidence_ids": [record.id for record in reportable],
        }
    )


def _report_build(context: TaskContext) -> TaskResult:
    from ..reporting.campaign_report import ReportError, build_campaign_report

    try:
        report = build_campaign_report(
            context.session,
            context.campaign.id,
            report_format=str(context.payload.get("format") or "json"),
        )
    except ReportError as exc:
        raise TaskBlocked(str(exc)) from exc
    result = report["summary"]
    result["format"] = report["format"]
    return TaskResult(result=result)


def default_handlers() -> dict[str, HandlerSpec]:
    return {
        "graph.index": HandlerSpec("graph.index", _graph_index, _graph_estimate),
        "graph.inventory": HandlerSpec("graph.inventory", _graph_inventory, _graph_estimate),
        "graph.query": HandlerSpec("graph.query", _graph_query, _graph_estimate),
        "graph.diff": HandlerSpec("graph.diff", _graph_diff, _graph_estimate),
        "scan.run": HandlerSpec("scan.run", _scan_run, _all_remaining_estimate),
        "finding.reproduce": HandlerSpec(
            "finding.reproduce", _finding_reproduce, _reproduce_estimate
        ),
        "evidence.verify": HandlerSpec("evidence.verify", _evidence_verify, _graph_estimate),
        "report.readiness": HandlerSpec("report.readiness", _report_readiness, _graph_estimate),
        "report.build": HandlerSpec("report.build", _report_build, _graph_estimate),
    }
