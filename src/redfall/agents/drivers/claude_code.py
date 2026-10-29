"""Claude Code driver (0.2.3, wave 1).

`claude -p "<prompt>"` runs one non-interactive turn and prints the reply to
stdout. The prompt is passed as a single argv element — it is never interpolated
into a shell string.
"""

from __future__ import annotations

from ..driver import AgentCapabilities, AgentDriver


class ClaudeCodeDriver(AgentDriver):
    name = "claude-code"
    title = "Claude Code"
    homepage = "https://claude.com/claude-code"
    capabilities = AgentCapabilities(
        long_context=True,
        structured_output=True,
        context_tokens=200_000,
        stateless=True,
    )

    def executable(self) -> str | None:
        import os

        return os.getenv("REDFALL_CLAUDE_BIN") or ("claude" if _which("claude") else None)

    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        argv = ["-p", prompt, "--output-format", "text"]
        if model:
            argv += ["--model", model]
        return argv, None


def _which(name: str) -> str | None:
    from ..driver import which

    return which(name)
