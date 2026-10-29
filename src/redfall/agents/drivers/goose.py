"""Goose driver (0.2.4, wave 2).

Block's Goose runs headless with `goose run -t "<prompt>"`.
"""

from __future__ import annotations

from ..driver import AgentCapabilities, AgentDriver, which


class GooseDriver(AgentDriver):
    name = "goose"
    title = "Goose (Block)"
    homepage = "https://block.github.io/goose/"
    capabilities = AgentCapabilities(
        long_context=True,
        structured_output=False,
        context_tokens=128_000,
        stateless=True,
    )

    def executable(self) -> str | None:
        import os

        return os.getenv("REDFALL_GOOSE_BIN") or which("goose")

    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        argv = ["run", "-t", prompt, "--quiet"]
        return argv, None
