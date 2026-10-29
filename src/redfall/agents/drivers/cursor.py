"""Cursor Agent CLI driver (0.2.4, wave 2).

`cursor-agent -p "<prompt>"` runs one non-interactive turn.
"""

from __future__ import annotations

from ..driver import AgentCapabilities, AgentDriver, which


class CursorDriver(AgentDriver):
    name = "cursor"
    title = "Cursor Agent CLI"
    homepage = "https://cursor.com/cli"
    capabilities = AgentCapabilities(
        long_context=True,
        structured_output=False,
        context_tokens=200_000,
        stateless=True,
    )

    def executable(self) -> str | None:
        import os

        return os.getenv("REDFALL_CURSOR_BIN") or which("cursor-agent") or which("cursor")

    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        argv = ["-p", prompt, "--output-format", "text"]
        if model:
            argv += ["--model", model]
        return argv, None
