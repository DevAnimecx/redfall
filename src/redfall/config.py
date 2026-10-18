"""Runtime configuration and the startup prerequisite assertions from §12.

Nothing here invents a fallback. When a prerequisite is missing the caller gets a
`PrerequisiteError` naming exactly what is absent, because a scan that silently
degrades produces findings nobody can trust.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


class PrerequisiteError(RuntimeError):
    """A §12 prerequisite is missing. Carries every failure, not just the first."""

    def __init__(self, failures: list[str]) -> None:
        self.failures = failures
        super().__init__("unmet prerequisites:\n  - " + "\n  - ".join(failures))


def default_workdir() -> Path:
    """The platform temp directory, not a POSIX literal.

    `/tmp/redfall` is the documented default on Linux; on a host without `/tmp`
    the same path silently resolves to a drive-relative directory, so the
    platform temp root is used unless the operator overrides it.
    """
    return Path(tempfile.gettempdir()) / "redfall"


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value


@dataclass(frozen=True)
class Config:
    """Everything Redfall needs at runtime, read once from the environment."""

    database_url: str
    redis_url: str

    openai_api_key: str | None
    anthropic_api_key: str | None

    sandbox_runtime: str
    sandbox_pool_size: int
    sandbox_timeout_s: int

    max_tokens_per_scan: int
    max_cost_per_scan_usd: float
    branch_max_depth: int
    chain_max_candidates: int

    workdir: Path = field(default_factory=default_workdir)

    @property
    def has_llm_provider(self) -> bool:
        """True when at least one real provider credential is present."""
        return bool(self.openai_api_key or self.anthropic_api_key)

    @property
    def providers(self) -> list[str]:
        found: list[str] = []
        if self.openai_api_key:
            found.append("openai")
        if self.anthropic_api_key:
            found.append("anthropic")
        return found


def load_config() -> Config:
    """Read configuration from the environment, applying §12 defaults."""
    workdir = Path(_env("REDFALL_WORKDIR") or default_workdir())
    return Config(
        # SQLAlchemy resolves `postgresql://` to psycopg2, which is not a
        # dependency of this project; the driver is named explicitly so a clean
        # install connects with the psycopg v3 driver it actually ships.
        database_url=_env("DATABASE_URL", "postgresql+psycopg://redfall:redfall@localhost:5432/redfall")
        or "postgresql+psycopg://redfall:redfall@localhost:5432/redfall",
        redis_url=_env("REDIS_URL", "redis://localhost:6379/0") or "redis://localhost:6379/0",
        openai_api_key=_env("OPENAI_API_KEY"),
        anthropic_api_key=_env("ANTHROPIC_API_KEY"),
        sandbox_runtime=_env("REDFALL_SANDBOX_RUNTIME", "runsc") or "runsc",
        sandbox_pool_size=int(_env("REDFALL_SANDBOX_POOL_SIZE", "3") or 3),
        sandbox_timeout_s=int(_env("REDFALL_SANDBOX_TIMEOUT_S", "120") or 120),
        max_tokens_per_scan=int(_env("REDFALL_MAX_TOKENS_PER_SCAN", "500000") or 500000),
        max_cost_per_scan_usd=float(_env("REDFALL_MAX_COST_PER_SCAN_USD", "10") or 10),
        branch_max_depth=int(_env("REDFALL_BRANCH_MAX_DEPTH", "3") or 3),
        chain_max_candidates=int(_env("REDFALL_MAX_CHAINS", "4") or 4),
        workdir=workdir,
    )


def _docker_runtimes() -> tuple[bool, list[str]]:
    """Return (docker_available, registered_runtime_names)."""
    if shutil.which("docker") is None:
        return False, []
    try:
        out = subprocess.run(
            ["docker", "info", "--format", "{{json .Runtimes}}"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return False, []
    if out.returncode != 0:
        return False, []
    import json

    try:
        runtimes = json.loads(out.stdout.strip() or "{}")
    except json.JSONDecodeError:
        return True, []
    # `docker info` prints the literal `null` when the daemon is reachable but
    # the caller cannot read its configuration, and an empty dict when it can.
    # Either way Docker is available; only the runtime list is unknown. Crashing
    # here would turn a permissions problem into an AttributeError.
    if not isinstance(runtimes, dict):
        return True, []
    return True, sorted(runtimes.keys())


def check_prerequisites(config: Config, *, require_llm: bool = True, require_sandbox: bool = True) -> None:
    """Assert the §12 prerequisites, collecting every failure before raising.

    `require_llm` / `require_sandbox` let read-only commands (report, findings)
    run on a host that cannot scan, without weakening the scan path: `redfall
    scan` always passes both as True.
    """
    failures: list[str] = []

    docker_ok, runtimes = _docker_runtimes()
    if require_sandbox:
        if not docker_ok:
            failures.append(
                "Docker is not available (`docker info` did not succeed); "
                "Redfall executes every finding in a gVisor container and has no fallback"
            )
        elif config.sandbox_runtime not in runtimes:
            failures.append(
                f"sandbox runtime {config.sandbox_runtime!r} is not registered with Docker; "
                f"available runtimes: {runtimes or 'none'}"
            )

    if require_llm and not config.has_llm_provider:
        failures.append(
            "no LLM provider credential found; set OPENAI_API_KEY or ANTHROPIC_API_KEY. "
            "Redfall makes live provider calls only — see BLOCKED.md"
        )

    for tool in ("node", "npm"):
        if shutil.which(tool) is None:
            failures.append(f"{tool} is required to build and test TypeScript targets")

    if failures:
        raise PrerequisiteError(failures)


def describe_environment(config: Config) -> dict[str, object]:
    """A factual snapshot of the host, for the report and for diagnostics."""
    docker_ok, runtimes = _docker_runtimes()
    return {
        "docker_cli": shutil.which("docker") is not None,
        "docker_available": docker_ok,
        "docker_runtimes": runtimes,
        "sandbox_runtime_configured": config.sandbox_runtime,
        "sandbox_runtime_present": config.sandbox_runtime in runtimes,
        "llm_providers": config.providers,
        "node": shutil.which("node") is not None,
        "npm": shutil.which("npm") is not None,
    }
