"""Continue CLI driver (0.2.4, wave 2).

Continue ships a headless CLI (`cn`) that runs one turn with `cn -p`.
"""

from __future__ import annotations

from ..driver import AgentCapabilities, AgentDriver, which


class ContinueDriver(AgentDriver):
    name = "continue"
    title = "Continue"
    homepage = "https://docs.continue.dev/cli"
    capabilities = AgentCapabilities(
        long_context=True,
        structured_output=False,
        context_tokens=128_000,
        stateless=True,
    )

    def executable(self) -> str | None:
        import os

        return os.getenv("REDFALL_CONTINUE_BIN") or which("cn") or which("continue")

    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        argv = ["-p", prompt]
        if model:
            argv += ["--model", model]
        return argv, None
