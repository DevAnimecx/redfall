"""PoC execution and verdict recording.

A finding counts as real only when the harness reports `reproduced: true` from
inside a gVisor container that was running the target application. There is no
static-analysis-only acceptance path, and no host-side execution path.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ..config import default_workdir
from ..sandbox.docker_gvisor import (
    DockerGVisorSandbox,
    SandboxExecutionError,
    SandboxRequest,
    SandboxUnavailable,
    ensure_runtime,
)
from ..store.models import SandboxRun

HARNESS = Path(__file__).parent / "harness.mjs"
VERDICT_MARKER = "REDFALL_VERDICT "

# Files the target needs at runtime but which are not application source.
RUNTIME_GLOBS = ("package.json", "package-lock.json", "tsconfig.json", "jest.config.js", ".env.example")
RUNTIME_DIRS = ("src", "migrations", "public", "views", "templates")


@dataclass(frozen=True)
class Verdict:
    run_id: str
    reproduced: bool
    reason: str
    status: int | None
    body: str
    evidence: str
    detail: str = ""
    container_id: str = ""
    runtime: str = "runsc"
    duration_ms: int = 0
    # Multi-step chain PoCs report how many steps held before the run stopped;
    # a single-request PoC leaves both empty. Only the steps that actually held
    # may be credited, so the count travels with the verdict.
    steps_passed: int | None = None
    steps: tuple[dict[str, Any], ...] = ()


class Validator:
    """Builds a sandbox workspace per PoC and executes it."""

    def __init__(
        self,
        *,
        target: Path,
        session: Session,
        scan_id: str,
        sandbox: DockerGVisorSandbox | None = None,
        workdir: Path | None = None,
        timeout_s: int = 300,
    ) -> None:
        ensure_runtime()
        self.target = Path(target).resolve()
        self.session = session
        self.scan_id = scan_id
        self.sandbox = sandbox or DockerGVisorSandbox()
        self.workdir = Path(workdir or (default_workdir() / "workspaces"))
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.timeout_s = timeout_s
        self._template: Path | None = None

    # -- public ------------------------------------------------------------
    def validate(
        self,
        *,
        branch_id: str | None,
        poc: dict[str, Any],
        finding_category: str,
        target_file: str,
    ) -> Verdict:
        """Run one PoC in a fresh gVisor container and return the verdict."""
        ensure_runtime()
        run_id = self._run_id(poc)
        workspace = self._prepare_workspace(run_id, poc)

        request = SandboxRequest(
            workdir=workspace,
            command=["node", "harness.mjs"],
            env={
                "REDFALL_WORK": "/work",
                "REDFALL_TARGET_DIR": "target",
                "REDFALL_POC_FILE": "poc.json",
                "REDFALL_APP_PORT": "4000",
            },
            timeout_s=self.timeout_s,
            labels={"category": finding_category, "run": run_id},
        )

        started = time.time()
        try:
            result = self.sandbox.run(request)
        except SandboxUnavailable:
            raise
        except SandboxExecutionError as err:
            return self._record_failure(run_id, branch_id, f"sandbox: {err}", started)

        verdict = self._parse_verdict(result.stdout, run_id)
        self._record(
            run_id=run_id,
            branch_id=branch_id,
            container_id=result.container_id,
            runtime=result.runtime,
            exit_code=result.exit_code,
            ok=verdict.reproduced,
            stdout=result.stdout[-8000:],
            stderr=result.stderr[-4000:],
            error="" if result.ok else (result.stderr[-1000:] or f"exit {result.exit_code}"),
            duration_ms=result.duration_ms,
        )
        return Verdict(
            run_id=run_id,
            reproduced=verdict.reproduced,
            reason=verdict.reason,
            status=verdict.status,
            body=verdict.body,
            evidence=verdict.evidence or result.stdout[-1500:],
            detail=result.stderr[-2000:],
            container_id=result.container_id,
            runtime=result.runtime,
            duration_ms=result.duration_ms,
        )

    # -- workspace ---------------------------------------------------------
    def _prepare_workspace(self, run_id: str, poc: dict[str, Any]) -> Path:
        """Copy the target into a throwaway workspace and drop the PoC beside it.

        The target is copied rather than mounted so an exploit that writes to
        disk cannot damage the repository being scanned.
        """
        workspace = self.workdir / run_id
        if workspace.exists():
            shutil.rmtree(workspace)
        workspace.mkdir(parents=True)

        target_copy = workspace / "target"
        self._copy_target(target_copy)
        (workspace / "harness.mjs").write_text(HARNESS.read_text())
        (workspace / "poc.json").write_text(json.dumps(poc, indent=2))
        return workspace

    def _copy_target(self, dest: Path) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        for pattern in RUNTIME_GLOBS:
            src = self.target / pattern
            if src.exists():
                shutil.copy2(src, dest / pattern)
        for dirname in RUNTIME_DIRS:
            src = self.target / dirname
            if src.exists():
                shutil.copytree(src, dest / dirname, dirs_exist_ok=True)
        # node_modules is large, so link it instead of copying when the host can.
        # A link that cannot be created (or cannot be resolved inside the
        # container) is not an error: the harness runs `npm install` itself, and
        # copying a host-built tree across operating systems would be worse than
        # reinstalling because the binaries would not match the container.
        node_modules = self.target / "node_modules"
        if node_modules.exists():
            try:
                (dest / "node_modules").symlink_to(node_modules, target_is_directory=True)
            except OSError:
                pass

    # -- verdict -----------------------------------------------------------
    @staticmethod
    def _parse_verdict(stdout: str, run_id: str) -> Verdict:
        """Read the last verdict line the harness emitted."""
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if not line.startswith(VERDICT_MARKER):
                continue
            try:
                data = json.loads(line[len(VERDICT_MARKER) :])
            except json.JSONDecodeError:
                continue
            return Verdict(
                run_id=run_id,
                reproduced=bool(data.get("reproduced")),
                reason=str(data.get("reason") or ""),
                status=data.get("status") if isinstance(data.get("status"), int) else None,
                body=str(data.get("body") or ""),
                evidence=str(data.get("evidence") or ""),
                detail=str(data.get("detail") or ""),
                steps_passed=data.get("steps_passed") if isinstance(data.get("steps_passed"), int) else None,
                steps=tuple(step for step in (data.get("steps") or []) if isinstance(step, dict)),
            )
        return Verdict(
            run_id=run_id,
            reproduced=False,
            reason="no-verdict",
            status=None,
            body="",
            evidence="",
            detail="the harness did not emit a verdict line",
        )

    def _record_failure(self, run_id: str, branch_id: str | None, error: str, started: float) -> Verdict:
        self._record(
            run_id=run_id,
            branch_id=branch_id,
            container_id="",
            runtime="runsc",
            exit_code=None,
            ok=False,
            stdout="",
            stderr="",
            error=error,
            duration_ms=int((time.time() - started) * 1000),
        )
        return Verdict(
            run_id=run_id,
            reproduced=False,
            reason="sandbox-error",
            status=None,
            body="",
            evidence="",
            detail=error,
        )

    def _record(
        self,
        *,
        run_id: str,
        branch_id: str | None,
        container_id: str,
        runtime: str,
        exit_code: int | None,
        ok: bool,
        stdout: str,
        stderr: str,
        error: str,
        duration_ms: int,
    ) -> None:
        from datetime import datetime, timezone

        self.session.add(
            SandboxRun(
                id=run_id,
                scan_id=self.scan_id,
                branch_id=branch_id,
                container_id=container_id,
                runtime=runtime,
                finished_at=datetime.now(timezone.utc),
                exit_code=exit_code,
                ok=ok,
                stdout_tail=stdout[-8000:],
                error=(error + "\n" + stderr[-2000:]).strip()[:4000],
            )
        )
        self.session.flush()

    @staticmethod
    def _run_id(poc: dict[str, Any]) -> str:
        payload = json.dumps(poc, sort_keys=True) + str(time.time_ns())
        return hashlib.sha256(payload.encode()).hexdigest()[:16]
