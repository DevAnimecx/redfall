"""Crush driver (0.2.5, wave 3).

Charm's Crush runs headless with `crush run -p "<prompt>"`.
"""

from __future__ import annotations

from ..driver import AgentCapabilities, AgentDriver, which


class CrushDriver(AgentDriver):
    name = "crush"
    title = "Crush (Charm)"
    homepage = "https://github.com/charmbracelet/crush"
    capabilities = AgentCapabilities(
        long_context=True,
        structured_output=False,
        context_tokens=128_000,
        stateless=True,
    )

    def executable(self) -> str | None:
        import os

        return os.getenv("REDFALL_CRUSH_BIN") or which("crush")

    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        argv = ["run", "-q", "-p", prompt]
        return argv, None
