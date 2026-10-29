"""OpenHands driver (0.2.4, wave 2).

The OpenHands CLI runs headless with `openhands --headless -t "<prompt>"`.
"""

from __future__ import annotations

from ..driver import AgentCapabilities, AgentDriver, which


class OpenHandsDriver(AgentDriver):
    name = "openhands"
    title = "OpenHands"
    homepage = "https://github.com/All-Hands-AI/OpenHands"
    capabilities = AgentCapabilities(
        long_context=True,
        structured_output=False,
        context_tokens=128_000,
        stateless=True,
    )

    def executable(self) -> str | None:
        import os

        return os.getenv("REDFALL_OPENHANDS_BIN") or which("openhands")

    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        argv = ["--headless", "-t", prompt, "--override-cli-mode", "true"]
        if model:
            argv += ["--llm-model", model]
        return argv, None
