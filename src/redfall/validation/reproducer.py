"""Re-run one stored finding in the gVisor sandbox and record what happened.

A reproduction is not a status flag. It is a new execution with its own sandbox
run, observable, environment digest and, when a campaign is supplied, an
append-only evidence record. A failed re-run never erases an earlier verified
finding; it records the failed observation separately.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.orm import Session

from ..evidence.ledger import EvidenceLedger
from ..ingestion.git_repo import inspect as inspect_git
from ..sandbox.docker_gvisor import RUNTIME, SandboxUnavailable
from ..store.models import Campaign, Finding, Scan
from .validator import Validator, Verdict


class ReproductionError(RuntimeError):
    """The finding cannot be reproduced without inventing a result."""


class ReproductionBlocked(ReproductionError):
    """A required runtime or persisted input is unavailable."""

    def __init__(self, reason: str, *, details: list[str] | None = None) -> None:
        self.reason = reason
        self.details = list(details or [])
        super().__init__(reason)


@dataclass(frozen=True)
class ReproductionOutcome:
    finding_id: str
    reproduced: bool
    reason: str
    run_id: str = ""
    status: int | None = None
    body: str = ""
    evidence: str = ""
    duration_ms: int = 0
    target: str = ""
    command: str = ""
    environment_digest: str = ""
    evidence_id: str | None = None
    evidence_grade: str = ""
    reportable: bool = False

    def to_wire(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "reproduced": self.reproduced,
            "reason": self.reason,
            "run_id": self.run_id,
            "status": self.status,
            "body": self.body,
            "evidence": self.evidence,
            "duration_ms": self.duration_ms,
            "target": self.target,
            "command": self.command,
            "environment_digest": self.environment_digest,
            "evidence_id": self.evidence_id,
            "evidence_grade": self.evidence_grade,
            "reportable": self.reportable,
        }


def _digest(facts: dict[str, Any]) -> str:
    payload = json.dumps(facts, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _observable(verdict: Verdict) -> str:
    for candidate in (verdict.evidence, verdict.body, verdict.reason):
        text = str(candidate or "").strip()
        if text:
            return text[:2000]
    if verdict.status is not None:
        return f"HTTP {verdict.status}"
    return ""


class Reproducer:
    def __init__(
        self,
        session: Session,
        *,
        validator_factory: Callable[..., Validator] = Validator,
        workdir: Path | None = None,
        timeout_s: int = 300,
    ) -> None:
        self.session = session
        self._validator_factory = validator_factory
        self.workdir = workdir
        self.timeout_s = timeout_s

    def reproduce(
        self,
        finding_id: str,
        *,
        campaign_id: str | None = None,
        target: str | Path | None = None,
        branch_id: str | None = None,
    ) -> ReproductionOutcome:
        finding = self.session.get(Finding, finding_id)
        if finding is None:
            raise ReproductionError(f"finding not found: {finding_id}")
        scan = self.session.get(Scan, finding.scan_id)
        if scan is None:
            raise ReproductionBlocked(
                f"finding {finding_id} has no scan row; its target cannot be resolved"
            )
        target_path = Path(target or scan.repo).expanduser().resolve()
        if not target_path.exists():
            raise ReproductionBlocked(f"target does not exist: {target_path}")
        if not target_path.is_dir():
            raise ReproductionBlocked(f"target is not a directory: {target_path}")
        poc = finding.poc if isinstance(finding.poc, dict) else {}
        if not poc:
            raise ReproductionBlocked(
                f"finding {finding_id} has no stored PoC request; nothing can be replayed"
            )
        campaign: Campaign | None = None
        if campaign_id:
            campaign = self.session.get(Campaign, campaign_id)
            if campaign is None:
                raise ReproductionError(f"campaign not found: {campaign_id}")

        try:
            validator = self._validator_factory(
                target=target_path,
                session=self.session,
                scan_id=finding.scan_id,
                workdir=self.workdir,
                timeout_s=self.timeout_s,
            )
        except SandboxUnavailable as exc:
            raise ReproductionBlocked(str(exc), details=list(exc.reasons)) from exc

        try:
            verdict = validator.validate(
                branch_id=branch_id or finding.branch_id,
                poc=poc,
                finding_category=finding.category,
                target_file=finding.location_file,
            )
        except SandboxUnavailable as exc:
            raise ReproductionBlocked(str(exc), details=list(exc.reasons)) from exc

        git = inspect_git(target_path)
        sandbox = getattr(validator, "sandbox", None)
        image = str(getattr(sandbox, "image", "unknown"))
        environment_digest = _digest(
            {
                "runtime": RUNTIME,
                "image": image,
                "target_commit": git.commit,
                "target_branch": git.branch,
                "target_dirty": git.dirty,
                "finding_category": finding.category,
                "target_file": finding.location_file,
            }
        )
        command = (
            f"redfall reproduce {finding.id} --target {target_path}"
            + (f" --campaign-id {campaign_id}" if campaign_id else "")
        )
        observable = _observable(verdict)
        evidence_id: str | None = None
        grade = ""
        reportable = False
        if campaign is not None:
            ledger = EvidenceLedger(self.session)
            if verdict.reproduced:
                grade = "E3"
                reportable = True
                record = ledger.append(
                    campaign.id,
                    grade=grade,
                    kind="execution",
                    claim=f"Reproduced {finding.category}: {finding.title}",
                    finding_id=finding.id,
                    payload={
                        "execution_id": verdict.run_id,
                        "observable": observable,
                        "expected_observable": finding.evidence or finding.title,
                        "status_code": verdict.status,
                        "finding_category": finding.category,
                        "target_file": finding.location_file,
                        "target_line": finding.location_line,
                        "reproduced": True,
                        "container_id": verdict.container_id,
                        "duration_ms": verdict.duration_ms,
                    },
                    reproduce_command=command,
                    environment_digest=environment_digest,
                )
                evidence_id = record.id
            else:
                grade = "E2"
                record = ledger.append(
                    campaign.id,
                    grade=grade,
                    kind="dynamic",
                    claim=f"Reproduction attempt did not hold: {finding.title}",
                    finding_id=finding.id,
                    payload={
                        "observation": observable or verdict.reason,
                        "reproduced": False,
                        "reason": verdict.reason,
                        "status_code": verdict.status,
                        "execution_id": verdict.run_id,
                        "duration_ms": verdict.duration_ms,
                    },
                    reproduce_command=command,
                    environment_digest=environment_digest,
                )
                evidence_id = record.id

        if verdict.reproduced:
            finding.reproduced = True
            finding.reproduction_run_id = verdict.run_id
            if finding.status == "open":
                finding.status = "verified"
        self.session.flush()
        return ReproductionOutcome(
            finding_id=finding.id,
            reproduced=verdict.reproduced,
            reason=verdict.reason,
            run_id=verdict.run_id,
            status=verdict.status,
            body=verdict.body,
            evidence=verdict.evidence,
            duration_ms=verdict.duration_ms,
            target=str(target_path),
            command=command,
            environment_digest=environment_digest,
            evidence_id=evidence_id,
            evidence_grade=grade,
            reportable=reportable,
        )
