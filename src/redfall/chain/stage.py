"""The chain stage: propose over reproduced findings, replay, link, report.

Order matters here. The model sees only findings that already reproduced on
their own, including the responses the harness observed, so an extraction path
is read off real output. Each proposal is then reviewed structurally, replayed
in the sandbox as one composite PoC, and only the steps whose predicates held
become edges. The attack graph is rebuilt from the persisted rows afterwards,
so the report's paths come from the database and not from this function's
memory of what it just did.

A proposal that review refuses is still recorded: the report should be able to
show that a chain was considered and why it was not run.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agent.agent import Agent
from ..chain.cvss_compound import severity_score
from ..llm import BudgetExceeded, LLMError
from ..sandbox.docker_gvisor import SandboxUnavailable
from ..store.models import ChainRow, EdgeRow
from .executor import ChainExecutor
from .graph import build_graph
from .plan import review_plan

# How many findings the model is shown in one proposal call, and how much of
# each finding's runtime evidence. The observed response is what the extraction
# paths are read from, so the tail of the evidence matters more than the head.
MAX_FINDINGS_IN_PROMPT = 40
EVIDENCE_EXCERPT = 1600


@dataclass
class ChainStageOutcome:
    """Everything the report and the scan row need to know about the stage."""

    proposed: int = 0
    reviewed_out: int = 0
    reproduced: int = 0
    partial: int = 0
    refused: int = 0
    chains: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    refusals: list[dict[str, Any]] = field(default_factory=list)
    graph: dict[str, Any] = field(default_factory=dict)
    strongest: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def run_chain_stage(
    *,
    agent: Agent,
    executor: ChainExecutor,
    session: Session,
    scan_id: str,
    findings: Sequence[Mapping[str, Any]],
    max_chains: int,
    emit: Callable[[str, dict[str, Any]], None] | None = None,
) -> ChainStageOutcome:
    """Run the whole stage and return its outcome. Never invents an edge."""
    outcome = ChainStageOutcome()

    def announce(kind: str, payload: dict[str, Any]) -> None:
        if emit is not None:
            emit(kind, payload)

    reproduced = [finding for finding in findings if finding.get("reproduced")]
    if len(reproduced) < 2:
        announce("chain:skip", {"reason": "fewer than two reproduced findings", "findings": len(reproduced)})
        return outcome

    findings_by_id: dict[str, Mapping[str, Any]] = {str(f["id"]): f for f in reproduced}

    try:
        proposals = agent.propose_chains(
            findings=_prompt_findings(reproduced),
            max_chains=max_chains,
        )
    except (LLMError, BudgetExceeded) as err:
        outcome.errors.append(f"chain proposal failed: {err}")
        announce("chain:llm-error", {"error": str(err)})
        return outcome

    outcome.proposed = len(proposals)
    announce("chain:proposed", {"proposals": len(proposals)})

    for index, proposal in enumerate(proposals[:max_chains]):
        title = str(proposal.get("title") or f"chain-{index + 1}") if isinstance(proposal, Mapping) else f"chain-{index + 1}"
        plan, problems = review_plan(proposal if isinstance(proposal, Mapping) else {}, findings_by_id)
        if plan is None:
            outcome.reviewed_out += 1
            _record_review_refusal(session, scan_id, title, proposal, problems)
            outcome.refusals.append({"title": title, "problems": problems, "run": False})
            announce("chain:review-refused", {"title": title, "problems": problems})
            continue

        try:
            result = executor.execute(plan)
        except SandboxUnavailable:
            raise
        except Exception as err:  # noqa: BLE001 - one bad chain must not kill the scan
            outcome.errors.append(f"chain {title!r} failed: {err}")
            announce("chain:error", {"title": title, "error": str(err)})
            continue

        if result.reproduced:
            outcome.reproduced += 1
        elif result.status == "partial":
            outcome.partial += 1
        else:
            outcome.refused += 1
        announce(
            "chain:replayed",
            {
                "title": plan.title,
                "status": result.status,
                "steps": len(plan.steps),
                "steps_passed": result.steps_passed,
                "reason": result.reason,
                "cvss_compound": result.cvss_compound,
            },
        )

    _summarise(session, scan_id, findings, outcome)
    announce(
        "chain:done",
        {
            "proposed": outcome.proposed,
            "reproduced": outcome.reproduced,
            "partial": outcome.partial,
            "refused": outcome.refused,
            "edges": len(outcome.edges),
        },
    )
    return outcome


# ------------------------------------------------------------------- helpers
def _prompt_findings(findings: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The subset of each finding the model needs, worst first."""
    ranked = sorted(
        findings,
        key=lambda f: (-(severity_score(str(f.get("severity") or "")) or 0.0), str(f.get("id"))),
    )
    out: list[dict[str, Any]] = []
    for finding in ranked[:MAX_FINDINGS_IN_PROMPT]:
        poc = finding.get("poc") if isinstance(finding.get("poc"), dict) else {}
        out.append(
            {
                "id": str(finding.get("id")),
                "category": finding.get("category"),
                "severity": finding.get("severity"),
                "title": finding.get("title"),
                "description": str(finding.get("description") or "")[:1200],
                "location": finding.get("location"),
                "poc": {
                    "request": poc.get("request"),
                    "expect_expr": poc.get("expect_expr"),
                    "has_setup": bool(isinstance(poc.get("setup"), dict) and poc["setup"].get("request")),
                    "has_followup": bool(isinstance(poc.get("followup"), dict) and poc["followup"].get("request")),
                },
                "observed": _evidence_excerpt(str(finding.get("evidence") or "")),
            }
        )
    return out


def _evidence_excerpt(evidence: str) -> str:
    if len(evidence) <= EVIDENCE_EXCERPT:
        return evidence
    return "…[clipped]\n" + evidence[-EVIDENCE_EXCERPT:]


def _record_review_refusal(
    session: Session,
    scan_id: str,
    title: str,
    proposal: Any,
    problems: Sequence[str],
) -> None:
    raw_steps = proposal.get("steps") if isinstance(proposal, Mapping) else None
    steps = []
    if isinstance(raw_steps, list):
        for step in raw_steps:
            if not isinstance(step, Mapping):
                continue
            steps.append(
                {
                    "n": len(steps) + 1,
                    "finding_id": str(step.get("finding_id") or ""),
                    "description": str(step.get("description") or ""),
                    "state_before": str(step.get("state_before") or ""),
                    "state_after": str(step.get("state_after") or ""),
                    "ran": False,
                    "ok": False,
                    "status": None,
                    "body": "",
                    "extract": sorted((step.get("extract") or {}).keys()) if isinstance(step.get("extract"), Mapping) else [],
                }
            )
    finding_ids = [step["finding_id"] for step in steps if step["finding_id"]]
    chain_id = hashlib.sha256(
        f"{scan_id}:{title}:{','.join(finding_ids)}:review".encode()
    ).hexdigest()[:16]
    session.add(
        ChainRow(
            id=chain_id,
            scan_id=scan_id,
            title=title,
            rationale=str(proposal.get("rationale") or "") if isinstance(proposal, Mapping) else "",
            status="refused",
            reason="review-refused",
            finding_ids=[],
            states=[],
            steps=steps,
            steps_passed=0,
            edges=[],
            narrative="",
            cvss_compound=None,
            severity="unknown",
            poc={},
            run_id=None,
        )
    )
    session.flush()


def _summarise(
    session: Session,
    scan_id: str,
    findings: Sequence[Mapping[str, Any]],
    outcome: ChainStageOutcome,
) -> None:
    """Read the stage's rows back and rebuild the graph from them alone."""
    chain_rows = session.execute(
        select(ChainRow).where(ChainRow.scan_id == scan_id).order_by(ChainRow.created_at, ChainRow.id)
    ).scalars().all()
    edge_rows = session.execute(
        select(EdgeRow).where(EdgeRow.scan_id == scan_id).order_by(EdgeRow.discovered_at, EdgeRow.id)
    ).scalars().all()

    outcome.chains = [row.to_wire() for row in chain_rows if row.status in ("reproduced", "partial")]
    outcome.edges = [row.to_wire() for row in edge_rows]
    outcome.refusals = [
        {"title": row.title, "problems": [row.reason or "refused"], "run": True, "steps_passed": row.steps_passed}
        for row in chain_rows
        if row.status == "refused"
    ]

    graph = build_graph(findings, outcome.edges)
    outcome.graph = graph.stats()
    outcome.strongest = [
        {
            "steps": chain["steps"],
            "finding_ids": chain["finding_ids"],
            "states": chain["states"],
            "cvss_compound": chain["cvss_compound"],
            "severity": chain["severity"],
        }
        for chain in graph.strongest_chains(limit=5)
    ]
