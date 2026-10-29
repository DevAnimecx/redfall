"""Cline driver (0.2.5, wave 3).

Cline's headless mode is `cline -p "<prompt>"`. It is a VS Code extension
first, but ships a CLI entry point.
"""

from __future__ import annotations

from ..driver import AgentCapabilities, AgentDriver, which


class ClineDriver(AgentDriver):
    name = "cline"
    title = "Cline"
    homepage = "https://cline.bot"
    capabilities = AgentCapabilities(
        long_context=True,
        structured_output=False,
        context_tokens=128_000,
        stateless=True,
    )

    def executable(self) -> str | None:
        import os

        return os.getenv("REDFALL_CLINE_BIN") or which("cline")

    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        argv = ["-p", prompt, "--auto-approve", "false"]
        if model:
            argv += ["--model", model]
        return argv, None
