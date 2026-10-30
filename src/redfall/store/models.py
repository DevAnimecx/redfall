"""SQLAlchemy models — the §7 data structures, persisted.

Column names and shapes follow §7 exactly; the TypeScript interfaces in the spec
are the wire format these rows serialise to.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from ..triggers import TRIGGER_TYPES


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base for every Redfall table."""


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    repo: Mapped[str] = mapped_column(Text, nullable=False)
    commit: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    branches_total: Mapped[int] = mapped_column(Integer, default=0)
    branches_adaptive: Mapped[int] = mapped_column(Integer, default=0)
    findings_total: Mapped[int] = mapped_column(Integer, default=0)
    findings_by_severity: Mapped[dict] = mapped_column(JSON, default=dict)
    chains_total: Mapped[int] = mapped_column(Integer, default=0)
    edges_total: Mapped[int] = mapped_column(Integer, default=0)
    tokens_total: Mapped[int] = mapped_column(Integer, default=0)
    tokens_by_tier: Mapped[dict] = mapped_column(JSON, default=dict)
    cost_estimate_usd: Mapped[float] = mapped_column(Float, default=0.0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="running")


class Branch(Base):
    __tablename__ = "branches"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    parent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    scope_files: Mapped[list] = mapped_column(JSON, default=list)
    scope_routes: Mapped[list] = mapped_column(JSON, default=list)
    depth: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    priority: Mapped[int] = mapped_column(Integer, default=0)
    model_tier: Mapped[str] = mapped_column(String(16), default="mid")
    token_budget: Mapped[int] = mapped_column(Integer, default=0)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    is_adaptive: Mapped[bool] = mapped_column(Boolean, default=False)
    # Rule 12: an adaptive branch records what triggered it and why. Both are
    # nullable only because static branches have no trigger; a row with
    # is_adaptive=true and either of these empty is a contract violation.
    triggering_finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trigger_reason: Mapped[str | None] = mapped_column(String(40), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_adaptive_contract_ok(self) -> bool:
        """Rule 12: an adaptive row must carry its trigger and a reason."""
        if not self.is_adaptive:
            return True
        return bool(self.triggering_finding_id) and self.trigger_reason in TRIGGER_TYPES

    def rule_11_ordering_ok(self, trigger_discovered_at: datetime | None) -> bool:
        """Rule 11: spawned after the parent started and after its trigger was found.

        A branch planned up front and mislabelled adaptive fails this check from
        the timestamps alone, which is the point.
        """
        if not self.is_adaptive:
            return True
        if self.started_at is not None and self.created_at is not None:
            if self.created_at < self.started_at:
                return False
        if trigger_discovered_at is not None and self.created_at is not None:
            if self.created_at < trigger_discovered_at:
                return False
        return True


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    branch_id: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    original_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    location_file: Mapped[str] = mapped_column(Text, nullable=False)
    location_line: Mapped[int] = mapped_column(Integer, default=0)
    location_symbol: Mapped[str] = mapped_column(Text, default="")
    poc: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    reproduced: Mapped[bool] = mapped_column(Boolean, default=False)
    reproduction_run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(24), default="open")
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def location(self) -> dict[str, object]:
        return {"file": self.location_file, "line": self.location_line, "symbol": self.location_symbol}

    def to_wire(self) -> dict[str, object]:
        """The §7 `Finding` interface."""
        from ..chain.cvss_compound import severity_score

        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "branch_id": self.branch_id,
            "category": self.category,
            "severity": self.severity,
            "cvss_score": severity_score(self.severity),
            "original_severity": self.original_severity,
            "title": self.title,
            "description": self.description,
            "location": self.location(),
            "poc": self.poc,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "reproduced": self.reproduced,
            "reproduction_run_id": self.reproduction_run_id,
            "dedupe_key": self.dedupe_key,
            "status": self.status,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }


class ChainRow(Base):
    """A proposed chain and what actually happened when it was replayed.

    A row is written for every proposal, reproduced or not: the report has to be
    able to say "the model claimed this path and it did not reproduce" as
    explicitly as it says the opposite. Only a reproduced chain carries edges.
    """

    __tablename__ = "chains"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="refused")
    reason: Mapped[str] = mapped_column(String(80), default="")
    finding_ids: Mapped[list] = mapped_column(JSON, default=list)
    states: Mapped[list] = mapped_column(JSON, default=list)
    steps: Mapped[list] = mapped_column(JSON, default=list)
    steps_passed: Mapped[int] = mapped_column(Integer, default=0)
    edges: Mapped[list] = mapped_column(JSON, default=list)
    narrative: Mapped[str] = mapped_column(Text, default="")
    cvss_compound: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="unknown")
    poc: Mapped[dict] = mapped_column(JSON, default=dict)
    run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "title": self.title,
            "rationale": self.rationale,
            "status": self.status,
            "reason": self.reason,
            "finding_ids": list(self.finding_ids or []),
            "states": list(self.states or []),
            "steps": list(self.steps or []),
            "steps_passed": self.steps_passed,
            "edges": list(self.edges or []),
            "narrative": self.narrative,
            "cvss_compound": self.cvss_compound,
            "severity": self.severity,
            "run_id": self.run_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class EdgeRow(Base):
    """One proven hop between two attack states, saved so the graph survives a crash.

    Rule 20: `build_graph` rebuilds the whole attack graph from rows like this
    one alone, with nothing held in memory.
    """

    __tablename__ = "edges"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    chain_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    finding_ids: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str] = mapped_column(Text, default="")
    source_kind: Mapped[str] = mapped_column(String(24), default="exploit_repro")
    reproduced: Mapped[bool] = mapped_column(Boolean, default=False)
    branch_id: Mapped[str] = mapped_column(String(64), default="")
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "chain_id": self.chain_id,
            "source": self.source,
            "target": self.target,
            "finding_ids": list(self.finding_ids or []),
            "description": self.description,
            "source_kind": self.source_kind,
            "reproduced": self.reproduced,
            "branch_id": self.branch_id,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }


class Fix(Base):
    __tablename__ = "fixes"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    patch: Mapped[str] = mapped_column(Text, default="")
    strategy: Mapped[str] = mapped_column(String(64), default="")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verify_log: Mapped[str] = mapped_column(Text, default="")
    test_result: Mapped[str] = mapped_column(String(16), default="not_run")
    poc_neutralized: Mapped[bool] = mapped_column(Boolean, default=False)
    rescan_result: Mapped[str] = mapped_column(String(16), default="not_run")
    status: Mapped[str] = mapped_column(String(32), default="needs_human_review")
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "patch": self.patch,
            "strategy": self.strategy,
            "attempts": self.attempts,
            "verified": self.verified,
            "verify_log": self.verify_log,
            "test_result": self.test_result,
            "poc_neutralized": self.poc_neutralized,
            "rescan_result": self.rescan_result,
            "status": self.status,
            "applied_at": self.applied_at.isoformat() if self.applied_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class LLMCall(Base):
    __tablename__ = "llm_calls"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), index=True)
    branch_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    stage: Mapped[str] = mapped_column(String(16), nullable=False)
    tier: Mapped[str] = mapped_column(String(16), default="mid")
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    cached: Mapped[bool] = mapped_column(Boolean, default=False)
    request_hash: Mapped[str] = mapped_column(String(64), default="", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "branch_id": self.branch_id,
            "stage": self.stage,
            "tier": self.tier,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cost_usd": self.cost_usd,
            "latency_ms": self.latency_ms,
            "cached": self.cached,
            "request_hash": self.request_hash,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class LLMResponse(Base):
    """Verbatim transcripts. §1 rule 4: the raw request and response are stored,
    so every claim about what the model said is checkable after the fact."""

    __tablename__ = "llm_responses"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    call_id: Mapped[str] = mapped_column(ForeignKey("llm_calls.id"), index=True)
    request_json: Mapped[dict] = mapped_column(JSON, default=dict)
    response_json: Mapped[dict] = mapped_column(JSON, default=dict)
    content: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FileRow(Base):
    __tablename__ = "files"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    language: Mapped[str] = mapped_column(String(16), default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    line_count: Mapped[int] = mapped_column(Integer, default=0)


class Symbol(Base):
    __tablename__ = "symbols"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    file_id: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    line: Mapped[int] = mapped_column(Integer, default=0)
    end_line: Mapped[int] = mapped_column(Integer, default=0)
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    route: Mapped[str | None] = mapped_column(Text, nullable=True)
    middleware: Mapped[list] = mapped_column(JSON, default=list)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class TaintPath(Base):
    __tablename__ = "taint_paths"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    file_id: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    sink: Mapped[str] = mapped_column(Text, nullable=False)
    line: Mapped[int] = mapped_column(Integer, default=0)
    symbol: Mapped[str] = mapped_column(Text, default="")
    via: Mapped[list] = mapped_column(JSON, default=list)


class Dep(Base):
    __tablename__ = "deps"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(Text, default="")
    resolved: Mapped[str] = mapped_column(Text, default="")
    is_dev: Mapped[bool] = mapped_column(Boolean, default=False)


class SandboxRun(Base):
    __tablename__ = "sandbox_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), index=True)
    branch_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    container_id: Mapped[str] = mapped_column(Text, default="")
    runtime: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    stdout_tail: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")


class Campaign(Base):
    """A long-lived security campaign, distinct from one linear scan.

    A campaign owns the task graph, budget and policy. A scan remains the
    execution record for a single ingestion/analysis pass; ``scan_id`` links the
    two when a campaign runs one.
    """

    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # The isolation boundary this campaign belongs to. Empty on rows created
    # before tenancy existed; those are adopted into the default tenant by
    # `redfall.enterprise.tenancy.adopt_orphans`.
    tenant_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    repo: Mapped[str] = mapped_column(Text, nullable=False)
    commit: Mapped[str] = mapped_column(String(64), default="")
    objective: Mapped[str] = mapped_column(String(32), default="discovery")
    status: Mapped[str] = mapped_column(String(24), default="draft", index=True)

    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    policy: Mapped[dict] = mapped_column(JSON, default=dict)

    # ``None`` means no ceiling on that dimension. A zero value means zero
    # spend is allowed, which is different and is enforced as such.
    budget_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    budget_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    budget_sandbox_minutes: Mapped[float | None] = mapped_column(Float, nullable=True)
    budget_wall_clock_s: Mapped[int | None] = mapped_column(Integer, nullable=True)

    spent_usd: Mapped[float] = mapped_column(Float, default=0.0)
    spent_tokens: Mapped[int] = mapped_column(Integer, default=0)
    spent_sandbox_minutes: Mapped[float] = mapped_column(Float, default=0.0)

    previous_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    scan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def budget_dict(self) -> dict[str, float | int | None]:
        return {
            "usd": self.budget_usd,
            "tokens": self.budget_tokens,
            "sandbox_minutes": self.budget_sandbox_minutes,
            "wall_clock_s": self.budget_wall_clock_s,
        }

    def spent_dict(self) -> dict[str, float | int]:
        return {
            "usd": self.spent_usd,
            "tokens": self.spent_tokens,
            "sandbox_minutes": self.spent_sandbox_minutes,
        }

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "repo": self.repo,
            "commit": self.commit,
            "objective": self.objective,
            "status": self.status,
            "scope": self.scope or {},
            "policy": self.policy or {},
            "budget": self.budget_dict(),
            "spent": self.spent_dict(),
            "previous_status": self.previous_status,
            "reason": self.reason,
            "scan_id": self.scan_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class CampaignTask(Base):
    """A durable unit of campaign work with leases and dependency edges."""

    __tablename__ = "campaign_tasks"
    __table_args__ = (Index("ix_campaign_tasks_campaign_status", "campaign_id", "status"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    priority: Mapped[int] = mapped_column(Integer, default=0)

    depends_on: Mapped[list] = mapped_column(JSON, default=list)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)

    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    lease_owner: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "campaign_id": self.campaign_id,
            "kind": self.kind,
            "status": self.status,
            "priority": self.priority,
            "depends_on": list(self.depends_on or []),
            "payload": self.payload or {},
            "result": self.result or {},
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "lease_owner": self.lease_owner,
            "lease_expires_at": self.lease_expires_at.isoformat() if self.lease_expires_at else None,
            "error": self.error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class CampaignEvent(Base):
    """Append-only campaign audit stream. Event order is per campaign."""

    __tablename__ = "campaign_events"
    __table_args__ = (
        UniqueConstraint("campaign_id", "seq", name="uq_campaign_events_campaign_seq"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(48), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "campaign_id": self.campaign_id,
            "seq": self.seq,
            "kind": self.kind,
            "payload": self.payload or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class CampaignReservation(Base):
    """A preflight budget reservation for one task.

    The reservation makes the budget a gate rather than a post-hoc report: a
    worker cannot start work whose worst-case allowance does not fit. Settlement
    removes the reservation and records the actual spend in the same
    transaction; failure releases it.
    """

    __tablename__ = "campaign_reservations"
    __table_args__ = (
        Index("ix_campaign_reservations_campaign_status", "campaign_id", "status"),
        Index("ix_campaign_reservations_task", "task_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), index=True)
    task_id: Mapped[str | None] = mapped_column(ForeignKey("campaign_tasks.id"), nullable=True, index=True)
    usd: Mapped[float] = mapped_column(Float, default=0.0)
    tokens: Mapped[int] = mapped_column(Integer, default=0)
    sandbox_minutes: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(16), default="held")
    source: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "campaign_id": self.campaign_id,
            "task_id": self.task_id,
            "usd": self.usd,
            "tokens": self.tokens,
            "sandbox_minutes": self.sandbox_minutes,
            "status": self.status,
            "source": self.source,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "settled_at": self.settled_at.isoformat() if self.settled_at else None,
        }


class GraphSnapshot(Base):
    """One immutable code-intelligence graph built from a real ingestion pass.

    A snapshot is the unit that later campaigns query. It records the commit,
    content digest and analyzer counts so two graphs can be compared without
    trusting a label. Nodes and edges are stored separately and carry their own
    provenance; this table is only the manifest.
    """

    __tablename__ = "graph_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    campaign_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    repo: Mapped[str] = mapped_column(Text, nullable=False)
    root: Mapped[str] = mapped_column(Text, nullable=False)
    commit: Mapped[str] = mapped_column(String(64), default="")
    branch: Mapped[str] = mapped_column(Text, default="")
    dirty: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="building")
    content_digest: Mapped[str] = mapped_column(String(64), default="")
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    route_count: Mapped[int] = mapped_column(Integer, default=0)
    taint_count: Mapped[int] = mapped_column(Integer, default=0)
    parse_errors: Mapped[list] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "campaign_id": self.campaign_id,
            "repo": self.repo,
            "root": self.root,
            "commit": self.commit,
            "branch": self.branch,
            "dirty": self.dirty,
            "status": self.status,
            "content_digest": self.content_digest,
            "files": self.file_count,
            "nodes": self.node_count,
            "edges": self.edge_count,
            "routes": self.route_count,
            "taints": self.taint_count,
            "parse_errors": list(self.parse_errors or []),
            "metadata": self.metadata_json or {},
            "duration_ms": self.duration_ms,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class GraphNode(Base):
    """A provenance-bearing graph node with a real source span when one exists."""

    __tablename__ = "graph_nodes"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "kind", "key", name="uq_graph_nodes_snapshot_kind_key"),
        Index("ix_graph_nodes_snapshot_kind", "snapshot_id", "kind"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("graph_snapshots.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    key: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    file: Mapped[str] = mapped_column(Text, default="")
    line: Mapped[int] = mapped_column(Integer, default=0)
    end_line: Mapped[int] = mapped_column(Integer, default=0)
    language: Mapped[str] = mapped_column(String(24), default="")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    provenance: Mapped[dict] = mapped_column(JSON, default=dict)
    properties: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    content_hash: Mapped[str] = mapped_column(String(64), default="")

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "snapshot_id": self.snapshot_id,
            "kind": self.kind,
            "key": self.key,
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "language": self.language,
            "confidence": self.confidence,
            "provenance": self.provenance or {},
            "properties": self.properties or {},
            "evidence_ids": list(self.evidence_ids or []),
            "content_hash": self.content_hash,
        }


class GraphEdge(Base):
    """A typed, provenance-bearing relation between two graph nodes."""

    __tablename__ = "graph_edges"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "key", name="uq_graph_edges_snapshot_key"),
        Index("ix_graph_edges_snapshot_kind", "snapshot_id", "kind"),
        Index("ix_graph_edges_source", "snapshot_id", "source_id"),
        Index("ix_graph_edges_target", "snapshot_id", "target_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("graph_snapshots.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    key: Mapped[str] = mapped_column(Text, nullable=False)
    source_id: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    file: Mapped[str] = mapped_column(Text, default="")
    line: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    provenance: Mapped[dict] = mapped_column(JSON, default=dict)
    properties: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    content_hash: Mapped[str] = mapped_column(String(64), default="")

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "snapshot_id": self.snapshot_id,
            "kind": self.kind,
            "key": self.key,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "file": self.file,
            "line": self.line,
            "confidence": self.confidence,
            "provenance": self.provenance or {},
            "properties": self.properties or {},
            "evidence_ids": list(self.evidence_ids or []),
            "content_hash": self.content_hash,
        }


class AdapterCertification(Base):
    """The measured result of running an adapter contract.

    A row is evidence of what a specific server and tool surface did during one
    contract run. It is not a badge for every version of an agent that might
    speak the protocol; callers should check the timestamp and tool count.
    """

    __tablename__ = "adapter_certifications"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    adapter: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    transport: Mapped[str] = mapped_column(String(32), nullable=False)
    server_name: Mapped[str] = mapped_column(String(64), default="")
    server_version: Mapped[str] = mapped_column(String(32), default="")
    tool_count: Mapped[int] = mapped_column(Integer, default=0)
    certified: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    checks: Mapped[list] = mapped_column(JSON, default=list)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    certified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "adapter": self.adapter,
            "protocol": self.protocol,
            "transport": self.transport,
            "server_name": self.server_name,
            "server_version": self.server_version,
            "tool_count": self.tool_count,
            "certified": self.certified,
            "checks": list(self.checks or []),
            "details": self.details or {},
            "duration_ms": self.duration_ms,
            "certified_at": self.certified_at.isoformat() if self.certified_at else None,
        }


class EvidenceRecord(Base):
    """One link in a campaign's tamper-evident evidence chain.

    The ``grade`` is not decoration. E0/E1/E2 are hypotheses or observations;
    only E3/E4 are reportable findings. The ledger refuses an E3/E4 record that
    does not carry an execution id, an observable, a reproduction command and an
    environment digest.
    """

    __tablename__ = "evidence_records"
    __table_args__ = (
        UniqueConstraint("campaign_id", "seq", name="uq_evidence_records_campaign_seq"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    grade: Mapped[str] = mapped_column(String(2), nullable=False)
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    claim: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    artifacts: Mapped[list] = mapped_column(JSON, default=list)
    reproduce_command: Mapped[str] = mapped_column(Text, default="")
    environment_digest: Mapped[str] = mapped_column(String(128), default="")
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    @property
    def reportable(self) -> bool:
        return self.grade in {"E3", "E4"}

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "campaign_id": self.campaign_id,
            "seq": self.seq,
            "finding_id": self.finding_id,
            "grade": self.grade,
            "kind": self.kind,
            "claim": self.claim,
            "payload": self.payload or {},
            "artifacts": list(self.artifacts or []),
            "reproduce_command": self.reproduce_command,
            "environment_digest": self.environment_digest,
            "previous_hash": self.previous_hash,
            "content_hash": self.content_hash,
            "reportable": self.reportable,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AgentToken(Base):
    """An agent credential for the HTTP/A2A gateway.

    The plaintext token is shown once when it is created; only its SHA-256
    digest is stored. Scopes are an explicit allow-list, quotas are enforced per
    rolling hour from the audit trail, and revocation is a timestamp — a
    credential manager for the gateway, not a note in a config file.
    """

    __tablename__ = "agent_tokens"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # The tenant this credential acts for, and the principal it acts as. Both
    # are resolved at authentication and neither is ever read from the request.
    tenant_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    principal_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    token_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    quota_per_hour: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "principal_id": self.principal_id,
            "name": self.name,
            "scopes": list(self.scopes or []),
            "quota_per_hour": self.quota_per_hour,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked": self.revoked_at is not None,
        }


class InteropAudit(Base):
    """One authenticated gateway call: who, what, with which outcome.

    Denials are recorded too (with ``ok`` false), because an audit trail that
    only shows successes cannot answer "who tried to widen their scope".
    """

    __tablename__ = "interop_audit"
    __table_args__ = (
        Index("ix_interop_audit_token_created", "token_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    agent: Mapped[str] = mapped_column(String(64), default="", index=True)
    token_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool: Mapped[str] = mapped_column(String(64), default="", index=True)
    campaign_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    input_hash: Mapped[str] = mapped_column(String(64), default="")
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str] = mapped_column(Text, default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "protocol": self.protocol,
            "agent": self.agent,
            "token_id": self.token_id,
            "tool": self.tool,
            "campaign_id": self.campaign_id,
            "input_hash": self.input_hash,
            "ok": self.ok,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class InteropTask(Base):
    """An A2A task: one tool call with a durable lifecycle.

    The row is the source of truth for ``GetTask``/``ListTasks``/streaming.
    ``state`` uses the A2A v1.0 ProtoJSON enum names (``TASK_STATE_*``).
    """

    __tablename__ = "interop_tasks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    context_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    agent: Mapped[str] = mapped_column(String(64), default="", index=True)
    token_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool: Mapped[str] = mapped_column(String(64), default="")
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    state: Mapped[str] = mapped_column(String(24), default="TASK_STATE_SUBMITTED", index=True)
    status_message: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    artifacts: Mapped[list] = mapped_column(JSON, default=list)
    history: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str] = mapped_column(Text, default="")
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    push_configs: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_wire(
        self,
        *,
        history_length: int | None = None,
        include_artifacts: bool = True,
    ) -> dict[str, object]:
        history = list(self.history or [])
        if history_length is not None:
            history = history[-history_length:] if history_length > 0 else []
        out: dict[str, object] = {
            "id": self.id,
            "contextId": self.context_id,
            "status": {
                "state": self.state,
                "timestamp": (self.updated_at or self.created_at).isoformat()
                if (self.updated_at or self.created_at)
                else None,
            },
        }
        if self.status_message:
            out["status"]["message"] = self.status_message  # type: ignore[index]
        if history:
            out["history"] = history
        if include_artifacts:
            out["artifacts"] = list(self.artifacts or [])
        return out


class InteropArtifact(Base):
    """A stored tool result behind a signed URL.

    A2A artifacts inline the result for small payloads; the stored copy is what
    signed URLs serve, so a follow-up fetch does not have to re-run the tool.
    """

    __tablename__ = "interop_artifacts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    task_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    tool: Mapped[str] = mapped_column(String(64), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InteropSetting(Base):
    """Small durable key/value store for gateway-level secrets (e.g. HMAC keys)."""

    __tablename__ = "interop_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WebhookSubscription(Base):
    """An operator-configured webhook endpoint for campaign events."""

    __tablename__ = "webhook_subscriptions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    events: Mapped[list] = mapped_column(JSON, default=list)
    secret: Mapped[str] = mapped_column(String(64), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "url": self.url,
            "events": list(self.events or []),
            "active": self.active,
            "has_secret": bool(self.secret),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class WebhookDelivery(Base):
    """One pending or attempted delivery of one campaign event.

    ``(subscription_id, event_id)`` is unique: enqueueing is idempotent, so a
    server restart or a repeated drain cannot double-deliver a campaign event.
    """

    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        UniqueConstraint(
            "subscription_id", "event_id", name="uq_webhook_deliveries_subscription_event"
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    subscription_id: Mapped[str] = mapped_column(
        ForeignKey("webhook_subscriptions.id"), nullable=False, index=True
    )
    event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    campaign_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_kind: Mapped[str] = mapped_column(String(48), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "subscription_id": self.subscription_id,
            "event_id": self.event_id,
            "campaign_id": self.campaign_id,
            "event_kind": self.event_kind,
            "payload": self.payload or {},
            "status": self.status,
            "attempts": self.attempts,
            "last_status_code": self.last_status_code,
            "last_error": self.last_error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
