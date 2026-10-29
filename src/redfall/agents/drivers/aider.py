"""Aider driver (0.2.3, wave 1).

`aider --message "<prompt>" --no-auto-commits --yes ...` runs one non-interactive
turn. Aider normally edits files in the repo it is pointed at; RedFall runs it in
a scratch directory and only reads the reply, so it must be told not to commit
and to answer in chat.
"""

from __future__ import annotations

from ..driver import AgentCapabilities, AgentDriver, which


class AiderDriver(AgentDriver):
    name = "aider"
    title = "Aider"
    homepage = "https://aider.chat"
    capabilities = AgentCapabilities(
        long_context=True,
        structured_output=False,
        context_tokens=128_000,
        stateless=True,
    )

    def executable(self) -> str | None:
        import os

        return os.getenv("REDFALL_AIDER_BIN") or which("aider")

    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        argv = [
            "--message",
            prompt,
            "--no-auto-commits",
            "--no-git",
            "--yes-always",
            "--no-pretty",
            "--no-stream",
            "--exit",
        ]
        if model:
            argv += ["--model", model]
        return argv, None
