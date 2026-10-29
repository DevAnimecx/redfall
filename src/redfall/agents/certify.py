"""The executable agent contract (0.2.2).

`redfall agent certify <name>` runs a real agent, for real, and records what
happened. It is the same discipline as `redfall mcp certify`: no simulation, no
"should work", and a result that names exactly which checks passed.

The checks, in order:

1. **installed** — the executable is present and reports a version;
2. **answers** — one real prompt returns non-empty output;
3. **json** — one real prompt asking for JSON returns a parseable object;
4. **exit code** — the run exits cleanly (a non-zero exit with output is
   recorded as a warning, not a pass, because RedFall cannot rely on an agent
   that reports failure while producing an answer).

A certification covers this agent, this version, on this host, at this time —
the same narrow claim the interop certifier makes.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .driver import AgentDriver, AgentError

#: A tiny, unambiguous task. An agent that cannot echo JSON cannot be trusted to
#: produce the engine's finding, chain and fix schemas.
_JSON_PROMPT = (
    "Reply with exactly this JSON object and nothing else, no prose and no "
    'markdown fences: {"ok": true, "value": 42}'
)
_TEXT_PROMPT = "Reply with the single word: ready"


@dataclass
class CertificationCheck:
    name: str
    passed: bool
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class CertificationReport:
    agent: str
    version: str | None
    checks: list[CertificationCheck] = field(default_factory=list)
    duration_ms: int = 0
    timestamp: str = ""

    @property
    def certified(self) -> bool:
        """Certified only when every check passed. There is no partial pass."""
        return bool(self.checks) and all(c.passed for c in self.checks)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "version": self.version,
            "certified": self.certified,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
            "checks": [c.as_dict() for c in self.checks],
        }


def certify_driver(driver: AgentDriver, *, timeout_s: int = 180) -> CertificationReport:
    """Run the contract against one driver. Raises only when it is not installed."""
    started = time.time()
    report = CertificationReport(
        agent=driver.name,
        version=None,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    # 1. installed
    if not driver.available():
        report.checks.append(CertificationCheck("installed", False, driver.install_hint()))
        report.duration_ms = int((time.time() - started) * 1000)
        return report
    version = driver.version()
    report.version = version
    report.checks.append(
        CertificationCheck("installed", True, f"{driver.executable()} {version or ''}".strip())
    )

    # 2. answers
    try:
        invocation = driver.invoke(_TEXT_PROMPT, timeout_s=timeout_s)
    except AgentError as err:
        report.checks.append(CertificationCheck("answers", False, str(err)))
        report.duration_ms = int((time.time() - started) * 1000)
        return report
    text = (invocation.text or "").strip()
    report.checks.append(
        CertificationCheck("answers", bool(text), f"{len(text)} bytes in {invocation.duration_ms}ms")
    )
    if not text:
        report.duration_ms = int((time.time() - started) * 1000)
        return report

    # 3. json
    try:
        json_invocation = driver.invoke(_JSON_PROMPT, timeout_s=timeout_s)
        parsed = _parse_json(json_invocation.text)
        passed = isinstance(parsed, dict)
        detail = json.dumps(parsed)[:120] if passed else f"not a JSON object: {json_invocation.text[:120]!r}"
    except (AgentError, ValueError) as err:
        passed = False
        detail = str(err)
    report.checks.append(CertificationCheck("json", passed, detail))

    # 4. exit code
    report.checks.append(
        CertificationCheck(
            "exit_code",
            invocation.exit_code == 0,
            f"exit {invocation.exit_code}" + (f"; stderr: {invocation.stderr[:120]}" if invocation.stderr else ""),
        )
    )

    report.duration_ms = int((time.time() - started) * 1000)
    return report


def _parse_json(text: str) -> Any:
    from ..llm import extract_json

    return extract_json(text)


__all__ = ["CertificationCheck", "CertificationReport", "certify_driver"]
