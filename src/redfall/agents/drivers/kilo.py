"""Kilo Code driver (0.2.5, wave 3).

Kilo Code (a fork of Cline/Roo) exposes a headless `kilocode -p` entry point.
"""

from __future__ import annotations

from ..driver import AgentCapabilities, AgentDriver, which


class KiloDriver(AgentDriver):
    name = "kilo"
    title = "Kilo Code"
    homepage = "https://kilocode.ai"
    capabilities = AgentCapabilities(
        long_context=True,
        structured_output=False,
        context_tokens=128_000,
        stateless=True,
    )

    def executable(self) -> str | None:
        import os

        return os.getenv("REDFALL_KILO_BIN") or which("kilocode") or which("kilo")

    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        argv = ["-p", prompt]
        if model:
            argv += ["--model", model]
        return argv, None
