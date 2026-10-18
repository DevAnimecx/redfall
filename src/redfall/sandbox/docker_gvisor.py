"""gVisor-isolated execution of exploit and verification payloads (§1 rule 5).

Every exploit Redfall reports is executed inside a Docker container started with
`--runtime=runsc`. There is deliberately no alternative execution path in this
module: no `subprocess`, no host process, no in-process eval. If `runsc` is not
available, `SandboxUnavailable` is raised and the scan fails. A finding that was
not really executed is worse than no finding.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from ..config import default_workdir

RUNTIME = "runsc"


class SandboxUnavailable(RuntimeError):
    """Docker or the gVisor runtime is missing. Nothing will be faked instead."""

    def __init__(self, reasons: Sequence[str]) -> None:
        self.reasons = list(reasons)
        super().__init__(
            "gVisor sandbox unavailable:\n  - "
            + "\n  - ".join(self.reasons)
            + "\nRedfall has no fallback execution path; see BLOCKED.md."
        )


class SandboxExecutionError(RuntimeError):
    """The container could not be started or did not behave."""


@dataclass(frozen=True)
class SandboxRequest:
    """What to run. `workdir` is copied into the container at /work."""

    workdir: Path
    command: list[str]
    env: dict[str, str] = field(default_factory=dict)
    timeout_s: int = 120
    network: str = "bridge"
    memory: str = "1g"
    cpus: str = "1.0"
    read_only_rootfs: bool = False
    labels: dict[str, str] = field(default_factory=dict)
    # Exposed so a target app inside the container is reachable from the harness.
    publish: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SandboxResult:
    container_id: str
    runtime: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool
    image: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def tail(self, n: int = 2000) -> str:
        return self.stdout[-n:]


def check_runtime() -> list[str]:
    """Return the list of reasons the gVisor sandbox cannot run here. Empty == ready."""
    reasons: list[str] = []
    docker = shutil.which("docker")
    if docker is None:
        reasons.append("the `docker` CLI is not on PATH")
        return reasons

    try:
        info = subprocess.run(
            [docker, "info", "--format", "{{json .Runtimes}}"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as err:
        reasons.append(f"`docker info` failed: {type(err).__name__}: {err}")
        return reasons

    if info.returncode != 0:
        detail = (info.stderr or info.stdout or "").strip().splitlines()
        reasons.append(f"`docker info` exited {info.returncode}: {detail[-1] if detail else 'no output'}")
        return reasons

    try:
        runtimes = sorted(json.loads(info.stdout.strip() or "{}").keys())
    except json.JSONDecodeError:
        reasons.append(f"`docker info` returned unparsable runtime list: {info.stdout[:120]!r}")
        return reasons

    if RUNTIME not in runtimes:
        reasons.append(
            f"runtime {RUNTIME!r} is not registered with the Docker daemon "
            f"(registered: {runtimes or 'none'}); install gVisor and add it to daemon.json"
        )
    return reasons


def ensure_runtime() -> None:
    """Raise SandboxUnavailable unless a real gVisor runtime is present."""
    reasons = check_runtime()
    if reasons:
        raise SandboxUnavailable(reasons)


class DockerGVisorSandbox:
    """Runs commands in throwaway gVisor containers and always cleans up."""

    def __init__(self, image: str = "redfall-sandbox:latest", run_dir: Path | None = None) -> None:
        self.image = image
        self.run_dir = run_dir or (default_workdir() / "sandbox")
        self.run_dir.mkdir(parents=True, exist_ok=True)
        ensure_runtime()

    def run(self, request: SandboxRequest) -> SandboxResult:
        """Execute one request in a fresh container and return its real output."""
        ensure_runtime()
        container_name = f"redfall-{uuid.uuid4().hex[:12]}"
        cmd = self._docker_command(request, container_name)

        started = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=request.timeout_s + 30,
            )
        except subprocess.TimeoutExpired as err:
            duration_ms = int((time.time() - started) * 1000)
            stdout = (err.stdout or b"").decode("utf-8", errors="replace") if isinstance(err.stdout, bytes) else (err.stdout or "")
            stderr = (err.stderr or b"").decode("utf-8", errors="replace") if isinstance(err.stderr, bytes) else (err.stderr or "")
            return SandboxResult(
                container_id=container_name,
                runtime=RUNTIME,
                exit_code=-1,
                stdout=stdout,
                stderr=stderr + f"\n[redfall] execution exceeded {request.timeout_s}s and was killed",
                duration_ms=duration_ms,
                timed_out=True,
                image=self.image,
            )
        except (OSError, subprocess.SubprocessError) as err:
            raise SandboxExecutionError(f"could not start container: {type(err).__name__}: {err}") from err
        finally:
            self._cleanup(container_name)

        duration_ms = int((time.time() - started) * 1000)
        return SandboxResult(
            container_id=container_name,
            runtime=RUNTIME,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_ms=duration_ms,
            timed_out=False,
            image=self.image,
        )

    # -- internals ---------------------------------------------------------
    def _docker_command(self, request: SandboxRequest, name: str) -> list[str]:
        cmd = [
            "docker",
            "run",
            "--rm",
            "--name",
            name,
            f"--runtime={RUNTIME}",
            f"--memory={request.memory}",
            f"--cpus={request.cpus}",
            f"--network={request.network}",
            "--pids-limit=256",
            "--security-opt=no-new-privileges",
            "--cap-drop=ALL",
            "--workdir=/work",
        ]
        if request.read_only_rootfs:
            cmd.append("--read-only")
        for mapping in request.publish:
            cmd += ["--publish", mapping]
        for key, value in sorted(request.env.items()):
            cmd += ["--env", f"{key}={value}"]
        for key, value in sorted(request.labels.items()):
            cmd += ["--label", f"redfall.{key}={value}"]
        cmd += ["--label", f"redfall.run={name}"]
        cmd += ["--volume", f"{request.workdir.resolve()}:/work"]
        cmd.append(self.image)
        cmd += request.command
        return cmd

    def _cleanup(self, name: str) -> None:
        """Best-effort removal; `--rm` handles the normal path."""
        try:
            subprocess.run(
                ["docker", "rm", "--force", name],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            pass


def build_image(dockerfile_dir: Path, tag: str = "redfall-sandbox:latest") -> str:
    """Build the sandbox image from the checked-in Dockerfile."""
    ensure_runtime()
    dockerfile = dockerfile_dir / "Dockerfile"
    if not dockerfile.exists():
        raise SandboxExecutionError(f"no Dockerfile at {dockerfile}")
    proc = subprocess.run(
        ["docker", "build", "--tag", tag, str(dockerfile_dir.resolve())],
        capture_output=True,
        text=True,
        timeout=1800,
    )
    if proc.returncode != 0:
        raise SandboxExecutionError(f"image build failed: {proc.stderr[-2000:]}")
    return tag


def workspace_hash(workdir: Path) -> str:
    """Content hash of a workspace, for recording what was actually executed."""
    digest = hashlib.sha256()
    for path in sorted(p for p in workdir.rglob("*") if p.is_file()):
        try:
            digest.update(str(path.relative_to(workdir)).encode())
            digest.update(path.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()


def describe() -> dict[str, Any]:
    """Factual sandbox capability report for the report and for BLOCKED.md."""
    reasons = check_runtime()
    return {
        "runtime": RUNTIME,
        "ready": not reasons,
        "reasons_unavailable": reasons,
        "docker_cli": shutil.which("docker") is not None,
    }
