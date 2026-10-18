"""Replaying a reviewed chain inside the sandbox and admitting what held.

The composite PoC is built from the findings' own reproduced PoCs, stitched in
the order the proposal names and wired together by the extraction maps the
proposal wrote. It is then executed by the same validator that runs a single
finding: a real gVisor container, a real target, a real verdict.

Two rules decide what lands in the database:

* a hop is admitted only when its step's predicate held against the live
  application — `steps_passed` from the verdict, never the proposal's word;
* an admitted hop joins two independently reproduced findings, because a chain
  step is a claim about two findings, not one.

A chain that stops halfway keeps the hops it proved and the record of where it
stopped. A chain that never got past step one keeps nothing but the refusal.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from sqlalchemy.orm import Session

from ..store.models import ChainRow, EdgeRow
from .cvss_compound import chain_severity, compound_cvss, severity_score
from .graph import STATE_NONE, AttackGraph, Edge, State
from .narrative import narrate
from .plan import ChainPlan


def compose_poc(plan: ChainPlan, findings: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Assemble the one PoC that replays the whole chain in order.

    Each step keeps its finding's own predicate and preconditions: a chain does
    not weaken what a single step has to prove, it only adds the data flow.
    """
    steps: list[dict[str, Any]] = []
    for step in plan.steps:
        poc = (findings[step.finding_id].get("poc") or {}) if isinstance(findings[step.finding_id].get("poc"), dict) else {}
        entry: dict[str, Any] = {
            "id": step.finding_id,
            "finding_id": step.finding_id,
            "request": poc["request"],
            "expect_expr": step.expect_expr or poc["expect_expr"],
            "extract": {name: dict(selector) for name, selector in step.extract.items()},
        }
        setup = step.setup if step.setup is not None else poc.get("setup")
        followup = step.followup if step.followup is not None else poc.get("followup")
        if isinstance(setup, dict) and setup.get("request"):
            entry["setup"] = setup
        if isinstance(followup, dict) and followup.get("request"):
            entry["followup"] = followup
        steps.append(entry)

    return {
        "type": "chain",
        "steps": steps,
        "expect_expr": f"steps.length === {len(steps)} && steps.every((s) => s.ok === true)",
    }


@dataclass
class ChainOutcome:
    """What one composite replay produced, in report order."""

    chain_id: str
    status: str  # reproduced | partial | refused
    reason: str
    steps_passed: int
    linked_finding_ids: list[str]
    edge_rows: list[EdgeRow] = field(default_factory=list)
    narrative: str = ""
    cvss_compound: float | None = None
    severity: str = "unknown"

    @property
    def reproduced(self) -> bool:
        return self.status == "reproduced"


class ChainExecutor:
    """Runs proposals and writes the hops that reproduced."""

    def __init__(
        self,
        *,
        validator: Any,
        session: Session,
        scan_id: str,
        findings: Mapping[str, Mapping[str, Any]],
    ) -> None:
        self.validator = validator
        self.session = session
        self.scan_id = scan_id
        self.findings = findings

    # -- public ------------------------------------------------------------
    def execute(self, plan: ChainPlan) -> ChainOutcome:
        chain_id = self._chain_id(plan)
        poc = compose_poc(plan, self.findings)
        first_file = str(self.findings[plan.steps[0].finding_id].get("location", {}).get("file") or "")

        verdict = self.validator.validate(
            branch_id=None,
            poc=poc,
            finding_category="chain",
            target_file=first_file,
        )

        steps_passed = verdict.steps_passed
        if steps_passed is None:
            steps_passed = len(plan.steps) if verdict.reproduced else 0
        steps_passed = max(0, min(int(steps_passed), len(plan.steps)))

        rows = self._admit_hops(plan, chain_id, steps_passed)
        graph, chain_edges = self._sub_graph(plan, rows)
        base, modifiers = graph.chain_scores(chain_edges) if chain_edges else ([], [])
        score = compound_cvss(base, modifiers) if chain_edges else None
        narrative = narrate(graph, chain_edges, self.findings) if chain_edges else ""

        if verdict.reproduced:
            status = "reproduced"
        elif steps_passed > 0:
            status = "partial"
        else:
            status = "refused"

        step_records = self._step_records(plan, verdict, steps_passed)
        linked_ids = list(plan.finding_ids[:steps_passed])

        row = ChainRow(
            id=chain_id,
            scan_id=self.scan_id,
            title=plan.title,
            rationale=plan.rationale,
            status=status,
            reason=str(verdict.reason or ""),
            finding_ids=linked_ids,
            states=list(plan.states[: steps_passed + 1]) if steps_passed else [],
            steps=step_records,
            steps_passed=steps_passed,
            edges=[edge.id for edge in rows],
            narrative=narrative,
            cvss_compound=score,
            severity=chain_severity(score),
            poc=poc,
            run_id=verdict.run_id,
            created_at=datetime.now(timezone.utc),
        )
        self.session.add(row)
        self.session.flush()

        return ChainOutcome(
            chain_id=chain_id,
            status=status,
            reason=str(verdict.reason or ""),
            steps_passed=steps_passed,
            linked_finding_ids=linked_ids,
            edge_rows=rows,
            narrative=narrative,
            cvss_compound=score,
            severity=chain_severity(score),
        )

    # -- hops --------------------------------------------------------------
    def _admit_hops(self, plan: ChainPlan, chain_id: str, steps_passed: int) -> list[EdgeRow]:
        """One edge per step that held, in path order.

        The edge for step j covers the transition step j performed
        (`states[j-1]` → `states[j]`). It cites step j and the step it feeds:
        for the last step in a chain, the step that fed it instead. Both
        findings reproduced on their own, which is what rule 13 asks for, and
        the transition itself was just watched happening end to end.
        """
        rows: list[EdgeRow] = []
        total = len(plan.steps)
        for j in range(1, steps_passed + 1):
            if j < total:
                pair = (plan.finding_ids[j - 1], plan.finding_ids[j])
            else:
                pair = (plan.finding_ids[j - 2], plan.finding_ids[j - 1])
            source = plan.states[j - 1]
            target = plan.states[j]
            description = (
                f"step {j} of {total}: {plan.steps[j - 1].description or plan.steps[j - 1].finding_id} "
                f"({source} -> {target})"
            )
            row = EdgeRow(
                id=hashlib.sha256(f"{self.scan_id}:{chain_id}:{j}".encode()).hexdigest()[:16],
                scan_id=self.scan_id,
                chain_id=chain_id,
                source=source,
                target=target,
                finding_ids=[str(pair[0]), str(pair[1])],
                description=description,
                source_kind="exploit_repro",
                reproduced=True,
                branch_id=str(self.findings[plan.steps[j - 1].finding_id].get("branch_id") or ""),
                discovered_at=datetime.now(timezone.utc),
            )
            self.session.add(row)
            rows.append(row)
        self.session.flush()
        return rows

    def _sub_graph(self, plan: ChainPlan, rows: Sequence[EdgeRow]) -> tuple[AttackGraph, list[Edge]]:
        """The chain's own slice of the attack graph, rebuilt from its rows."""
        graph = AttackGraph()
        graph.add_state(STATE_NONE)
        for fid in plan.finding_ids:
            finding = self.findings[fid]
            score = severity_score(str(finding.get("severity") or ""))
            if score is not None:
                graph.register_finding(fid, score)
        for key in plan.states:
            kind, _, resource = key.partition(":")
            graph.add_state(State(kind, resource))
        chain_edges: list[Edge] = []
        for row in rows:
            edge = Edge(
                id=row.id,
                source=row.source,
                target=row.target,
                finding_ids=tuple(str(fid) for fid in row.finding_ids),
                description=row.description,
                source_kind=row.source_kind,
                reproduced=row.reproduced,
                branch_id=row.branch_id,
                discovered_at=row.discovered_at,
            )
            graph.add_edge(edge)
            chain_edges.append(edge)
        return graph, chain_edges

    # -- records -----------------------------------------------------------
    @staticmethod
    def _step_records(plan: ChainPlan, verdict: Any, steps_passed: int) -> list[dict[str, Any]]:
        observed = {int(step.get("n", 0)): step for step in verdict.steps}
        records: list[dict[str, Any]] = []
        for index, step in enumerate(plan.steps, start=1):
            seen = observed.get(index, {})
            records.append(
                {
                    "n": index,
                    "finding_id": step.finding_id,
                    "description": step.description,
                    "state_before": step.state_before,
                    "state_after": step.state_after,
                    "ran": index <= steps_passed,
                    "ok": bool(seen.get("ok")) and index <= steps_passed,
                    "status": seen.get("status"),
                    "body": str(seen.get("body") or "")[:600],
                    "extract": sorted(step.extract.keys()),
                }
            )
        return records

    def _chain_id(self, plan: ChainPlan) -> str:
        payload = f"{self.scan_id}:{plan.title}:" + ",".join(plan.finding_ids)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]
