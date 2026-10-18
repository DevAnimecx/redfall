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
    Integer,
    String,
    Text,
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
