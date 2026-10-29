"""OpenAI Codex CLI driver (0.2.3, wave 1).

`codex exec "<prompt>"` is Codex's non-interactive mode. It reads the prompt as
a single argv element and prints the final message to stdout.
"""

from __future__ import annotations

from ..driver import AgentCapabilities, AgentDriver, which


class CodexDriver(AgentDriver):
    name = "codex"
    title = "OpenAI Codex CLI"
    homepage = "https://github.com/openai/codex"
    capabilities = AgentCapabilities(
        long_context=True,
        structured_output=False,
        context_tokens=200_000,
        stateless=True,
    )

    def executable(self) -> str | None:
        import os

        return os.getenv("REDFALL_CODEX_BIN") or which("codex")

    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        argv = ["exec", "--skip-git-repo-check", prompt]
        if model:
            argv = ["exec", "--skip-git-repo-check", "--model", model, prompt]
        return argv, None
