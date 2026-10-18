"""Fix generation, application and verification (§6.1).

A fix is only `verified` when both of these hold, measured by real execution:

  (a) the target's own test suite passes with the patch applied, and
  (b) the original PoC no longer succeeds.

Either one failing sends the finding back to the model with the failure text
attached, up to `MAX_ATTEMPTS` times. After that the fix is left for a human
with the full transcript — never marked verified.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ..agent.agent import Agent, AnalysisFinding
from ..fix.applier import ApplyResult, PatchRejected, apply_patch_with_stdin, current_branch, revert
from ..llm import LLMError
from ..store.models import Finding, Fix
from ..validation.validator import Validator

MAX_ATTEMPTS = 3


@dataclass
class FixOutcome:
    fix_id: str
    finding_id: str
    status: str
    verified: bool
    test_result: str
    poc_neutralized: bool
    attempts: int
    patch: str = ""
    strategy: str = ""
    verify_log: str = ""
    blocker: str | None = None
    history: list[dict[str, Any]] = field(default_factory=list)


class Fixer:
    """Runs the fix loop for one finding against a real repository."""

    def __init__(
        self,
        *,
        agent: Agent,
        validator: Validator,
        session: Session,
        scan_id: str,
        target: Path,
        tests: dict[str, str] | None = None,
        dependencies: list[dict[str, Any]] | None = None,
    ) -> None:
        self.agent = agent
        self.validator = validator
        self.session = session
        self.scan_id = scan_id
        self.target = Path(target).resolve()
        self.tests = tests or {}
        self.dependencies = dependencies or []

    def run(self, finding: Finding) -> FixOutcome:
        """Attempt to fix one finding, verifying each attempt for real."""
        base_branch = current_branch(self.target)
        history: list[dict[str, Any]] = []
        verify_feedback: str | None = None
        applied: ApplyResult | None = None
        test_result = "not_run"
        poc_neutralized = False
        verified = False
        patch_text = ""
        strategy = ""
        blocker: str | None = None
        verify_log = ""

        candidate = AnalysisFinding(
            category=finding.category,
            severity=finding.severity,
            title=finding.title,
            description=finding.description,
            file=finding.location_file,
            line=finding.location_line,
            symbol=finding.location_symbol,
            poc=finding.poc,
            evidence=finding.evidence,
            remediation=finding.remediation,
        )

        for attempt in range(1, MAX_ATTEMPTS + 1):
            if applied is not None:
                revert(self.target, applied.branch, base_branch)
                applied = None

            try:
                proposal = self.agent.propose_fix(
                    finding=candidate,
                    file_source=self._read_source(finding.location_file),
                    tests=self.tests,
                    dependencies=self.dependencies,
                    verify_feedback=verify_feedback,
                )
            except LLMError as err:
                history.append({"attempt": attempt, "stage": "propose", "error": str(err)})
                break

            blocker = proposal.get("blocker")
            patch_text = proposal.get("patch") or ""
            strategy = proposal.get("strategy") or ""
            if blocker:
                history.append({"attempt": attempt, "stage": "propose", "blocker": blocker})
                break
            if not patch_text.strip():
                verify_feedback = "The previous attempt returned an empty patch. Return a real unified diff."
                history.append({"attempt": attempt, "stage": "propose", "error": "empty patch"})
                continue

            try:
                applied = apply_patch_with_stdin(
                    self.target,
                    patch_text,
                    branch=f"redfall/{finding.id[:12]}",
                    message=f"redfall: fix {finding.category} at {finding.location_file}:{finding.location_line}",
                )
            except PatchRejected as err:
                verify_feedback = f"The patch did not apply: {err}. Regenerate it against the current file contents."
                history.append({"attempt": attempt, "stage": "apply", "error": str(err)})
                continue

            tests_passed, test_log = self._run_tests()
            test_result = "passed" if tests_passed else "failed"
            if not tests_passed:
                verify_feedback = f"The test suite failed with the patch applied:\n{test_log[-3000:]}"
                history.append({"attempt": attempt, "stage": "tests", "error": verify_feedback})
                continue

            neutralized, poc_log = self._replay_poc(finding)
            poc_neutralized = neutralized
            verify_log = f"[tests]\n{test_log[-3000:]}\n\n[poc]\n{poc_log[-3000:]}"
            if neutralized:
                verified = True
                history.append({"attempt": attempt, "stage": "verified", "log": poc_log[-800:]})
                break

            verify_feedback = (
                "The test suite passed, but the original PoC still succeeds:\n"
                f"{poc_log[-2500:]}\n"
                "The vulnerability is not actually removed. Fix the root cause, not the symptom."
            )
            history.append({"attempt": attempt, "stage": "poc-still-works", "log": poc_log[-800:]})

        if applied is not None and not verified:
            revert(self.target, applied.branch, base_branch)
            applied = None

        status = self._status(verified, test_result, poc_neutralized, blocker)
        fix_id = f"fix-{finding.id[:12]}"
        self.session.add(
            Fix(
                id=fix_id,
                finding_id=finding.id,
                patch=patch_text,
                strategy=strategy,
                attempts=len(history),
                verified=verified,
                verify_log=verify_log + ("\n\n[history]\n" + _format_history(history) if history else ""),
                test_result=test_result,
                poc_neutralized=poc_neutralized,
                rescan_result="not_run",
                status=status,
                applied_at=_now() if (applied is not None and verified) else None,
            )
        )
        finding.status = "fixed" if verified else "needs_human_review"
        self.session.flush()

        return FixOutcome(
            fix_id=fix_id,
            finding_id=finding.id,
            status=status,
            verified=verified,
            test_result=test_result,
            poc_neutralized=poc_neutralized,
            attempts=len(history),
            patch=patch_text,
            strategy=strategy,
            verify_log=verify_log,
            blocker=blocker,
            history=history,
        )

    # -- execution ---------------------------------------------------------
    def _run_tests(self) -> tuple[bool, str]:
        """Run the target's own suite inside the sandbox with the patch applied."""
        from ..sandbox.docker_gvisor import SandboxRequest, ensure_runtime

        ensure_runtime()
        result = self.validator.sandbox.run(
            SandboxRequest(
                workdir=self.target,
                command=["bash", "-lc", "npm install --no-audit --no-fund --loglevel=error && npm test"],
                env={
                    "NODE_ENV": "test",
                    "JWT_SECRET": "redfall-verify-secret",
                    "DB_PASSWORD": "Sup3rS3cretBankPwd!",
                    "STRIPE_WEBHOOK_SECRET": "whsec_redfall_verify_secret",
                },
                timeout_s=900,
                labels={"stage": "tests"},
            )
        )
        log = (result.stdout + "\n" + result.stderr).strip()
        return result.ok, log

    def _replay_poc(self, finding: Finding) -> tuple[bool, str]:
        """Replay the original PoC. Verified requires it to stop working."""
        verdict = self.validator.validate(
            branch_id=finding.branch_id,
            poc=finding.poc,
            finding_category=finding.category,
            target_file=finding.location_file,
        )
        log = f"reproduced={verdict.reproduced} reason={verdict.reason}\n{verdict.evidence}"
        return (not verdict.reproduced), log

    def _read_source(self, rel_path: str) -> str:
        path = self.target / rel_path
        if not path.exists():
            return ""
        return path.read_text(errors="replace")

    @staticmethod
    def _status(verified: bool, test_result: str, poc_neutralized: bool, blocker: str | None) -> str:
        if verified:
            return "verified"
        if blocker:
            return "blocked"
        if test_result == "failed":
            return "tests_failed"
        if not poc_neutralized:
            return "poc_still_works"
        return "needs_human_review"


def _format_history(history: list[dict[str, Any]]) -> str:
    lines = []
    for entry in history:
        parts = [f"attempt {entry.get('attempt')} [{entry.get('stage')}"]
        for key in ("error", "blocker", "log"):
            if entry.get(key):
                parts.append(f"{key}: {str(entry[key])[:600]}")
        lines.append("] ".join(parts))
    return "\n".join(lines)


def fix_record(outcome: FixOutcome) -> dict[str, Any]:
    """The wire record `range_runner --fixes` reads back for one finding.

    `finding_id` is the scan finding id — the same id the scan report's findings
    carry — so the gate can line the fix up with the finding it matched. Only
    `verified` counts toward fix_rate there; the rest is for the reader.
    """
    return {
        "finding_id": outcome.finding_id,
        "fix_id": outcome.fix_id,
        "status": outcome.status,
        "verified": bool(outcome.verified),
        "test_result": outcome.test_result,
        "poc_neutralized": bool(outcome.poc_neutralized),
        "attempts": outcome.attempts,
        "strategy": outcome.strategy,
    }


def write_fixes_file(path: str | Path, record: dict[str, Any]) -> Path:
    """Append or replace one finding's record in a fixes JSON file.

    Repeated `redfall fix --out` runs build one file: a record for a finding_id
    already present is replaced, every other record is kept. The result is the
    list form `range_runner --fixes` accepts (it also accepts `{"fixes": []}`).
    """
    out = Path(path)
    records: list[Any] = []
    if out.exists():
        loaded = json.loads(out.read_text())
        records = loaded if isinstance(loaded, list) else list(loaded.get("fixes") or [])
    finding_id = str(record.get("finding_id") or "")
    records = [
        existing
        for existing in records
        if not (
            isinstance(existing, dict)
            and str(existing.get("finding_id") or "") == finding_id
        )
    ]
    records.append(record)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(records, indent=2))
    return out


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)
