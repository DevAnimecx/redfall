"""Qwen Code driver (0.2.5, wave 3).

Qwen Code is a Gemini-CLI fork; its non-interactive entry point is `qwen -p`.
"""

from __future__ import annotations

from ..driver import AgentCapabilities, AgentDriver, which


class QwenCodeDriver(AgentDriver):
    name = "qwen-code"
    title = "Qwen Code"
    homepage = "https://github.com/QwenLM/qwen-code"
    capabilities = AgentCapabilities(
        long_context=True,
        structured_output=False,
        context_tokens=1_000_000,
        stateless=True,
    )

    def executable(self) -> str | None:
        import os

        return os.getenv("REDFALL_QWEN_BIN") or which("qwen")

    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        argv = ["-p", prompt]
        if model:
            argv += ["-m", model]
        return argv, None
