"""The agent driver contract (0.2.2).

A driver knows three things about one agent: how to tell whether it is
installed, how to run it once with a prompt, and what it can do. Everything the
engine needs from an agent — plan, analyse, propose a chain, propose a fix —
is one prompt that must come back as JSON, so the driver surface is small.

Two rules every driver obeys, because they are what makes an agent's answer as
trustworthy as a provider's:

1. **A real subprocess or a real socket.** No driver simulates an agent. If the
   agent is not installed the driver refuses; it never fabricates a reply.
2. **The prompt is data, not shell.** Prompts are long, contain source code and
   are attacker-influenced (the target's source is untrusted). A driver passes
   the prompt on stdin or as an argv element, never string-interpolated into a
   shell command line.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class AgentNotInstalled(RuntimeError):
    """The agent this driver wraps is not present on this host."""

    def __init__(self, name: str, hint: str) -> None:
        self.name = name
        self.hint = hint
        super().__init__(f"agent {name!r} is not installed. {hint}")


class AgentError(RuntimeError):
    """The agent ran but did not produce a usable answer."""


@dataclass
class AgentCapabilities:
    """What a driver can rely on when it hands work to this agent."""

    #: Does the agent accept a long prompt (whole-file context)?
    long_context: bool = True
    #: Can the agent be told to emit a specific JSON shape reliably?
    structured_output: bool = False
    #: Approximate context window in tokens, when known.
    context_tokens: int | None = None
    #: Does invoking it start a fresh conversation each time?
    stateless: bool = True


@dataclass
class AgentInvocation:
    """The result of one real run of an agent."""

    text: str
    exit_code: int
    duration_ms: int
    argv: list[str] = field(default_factory=list)
    stderr: str = ""
    #: Tokens are unknown for most CLI agents; None means "not reported".
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    cost_usd: float | None = None


class AgentDriver(ABC):
    """Base class for every agent RedFall can borrow reasoning from."""

    #: Stable key used in config, on the CLI and in the report.
    name: str = "agent"
    #: What the operator sees in `redfall agent list`.
    title: str = "Agent"
    #: Homepage or docs, for the install hint.
    homepage: str = ""
    capabilities: AgentCapabilities = AgentCapabilities()

    # -- detection ---------------------------------------------------------
    @abstractmethod
    def executable(self) -> str | None:
        """The command to run, or None when the agent is not installed."""

    def version(self) -> str | None:
        """Best-effort version string, for the certification record."""
        exe = self.executable()
        if exe is None:
            return None
        try:
            out = subprocess.run(
                [exe, *self.version_argv()],
                capture_output=True,
                text=True,
                timeout=20,
                encoding="utf-8",
                errors="replace",
            )
        except (OSError, subprocess.SubprocessError):
            return None
        text = (out.stdout or out.stderr or "").strip().splitlines()
        return text[0].strip() if text else None

    def version_argv(self) -> list[str]:
        return ["--version"]

    def available(self) -> bool:
        return self.executable() is not None

    def install_hint(self) -> str:
        where = f" See {self.homepage}." if self.homepage else ""
        return f"Install it and put it on PATH, then re-run `redfall agent list`.{where}"

    def require(self) -> str:
        exe = self.executable()
        if exe is None:
            raise AgentNotInstalled(self.name, self.install_hint())
        return exe

    # -- invocation --------------------------------------------------------
    @abstractmethod
    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        """Return (argv, stdin).

        The prompt is never interpolated into a shell string. Either it goes on
        stdin (preferred, uncapped by argv limits) or it is a single argv
        element passed to the process directly.
        """

    def invoke(self, prompt: str, *, model: str | None = None, timeout_s: int = 300) -> AgentInvocation:
        exe = self.require()
        argv, stdin = self.command(prompt, model=model)
        argv = [exe, *argv]
        started = time.time()
        try:
            proc = subprocess.run(
                argv,
                input=stdin,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_s,
                env=self.env(),
            )
        except subprocess.TimeoutExpired as err:
            raise AgentError(
                f"agent {self.name!r} exceeded {timeout_s}s; raise the timeout or use a "
                f"faster model"
            ) from err
        except OSError as err:
            raise AgentError(f"could not run agent {self.name!r}: {err}") from err

        duration_ms = int((time.time() - started) * 1000)
        if proc.returncode != 0 and not (proc.stdout or "").strip():
            raise AgentError(
                f"agent {self.name!r} exited {proc.returncode} with no output: "
                f"{(proc.stderr or '').strip()[:400]}"
            )
        return AgentInvocation(
            text=proc.stdout or "",
            exit_code=proc.returncode,
            duration_ms=duration_ms,
            argv=argv,
            stderr=proc.stderr or "",
            **self.parse_usage(proc.stdout or "", proc.stderr or ""),
        )

    def env(self) -> dict[str, str]:
        """Environment for the subprocess. Overridden to add keys."""
        import os

        return dict(os.environ)

    def parse_usage(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Extract token/cost accounting when the agent reports it."""
        return {}

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "installed": self.available(),
            "executable": self.executable(),
            "version": self.version() if self.available() else None,
            "homepage": self.homepage,
            "capabilities": {
                "long_context": self.capabilities.long_context,
                "structured_output": self.capabilities.structured_output,
                "context_tokens": self.capabilities.context_tokens,
                "stateless": self.capabilities.stateless,
            },
        }


def which(name: str) -> str | None:
    """PATH lookup that also accepts an absolute path from env overrides."""
    return shutil.which(name)


__all__ = [
    "AgentCapabilities",
    "AgentDriver",
    "AgentError",
    "AgentInvocation",
    "AgentNotInstalled",
    "which",
]
