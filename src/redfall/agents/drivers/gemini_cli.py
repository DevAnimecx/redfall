"""Gemini CLI driver (0.2.3, wave 1).

`gemini -p "<prompt>"` runs one non-interactive turn. Prompts are passed as a
single argv element.
"""

from __future__ import annotations

from ..driver import AgentCapabilities, AgentDriver, which


class GeminiCliDriver(AgentDriver):
    name = "gemini-cli"
    title = "Google Gemini CLI"
    homepage = "https://github.com/google-gemini/gemini-cli"
    capabilities = AgentCapabilities(
        long_context=True,
        structured_output=False,
        context_tokens=1_000_000,
        stateless=True,
    )

    def executable(self) -> str | None:
        import os

        return os.getenv("REDFALL_GEMINI_BIN") or which("gemini")

    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        argv = ["-p", prompt]
        if model:
            argv += ["-m", model]
        return argv, None
