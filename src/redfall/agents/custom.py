"""The custom driver (0.2.6).

Everything else is a named agent. This is the escape hatch: an operator
describes an agent RedFall has never heard of in config, and it works like any
shipped driver.

    [[backend.options.agents]]
    name = "my-agent"
    command = "my-agent-cli"
    args = ["--prompt", "{prompt}"]      # or omit args to pass the prompt on stdin
    env = { MY_AGENT_KEY = "MY_AGENT_KEY" }  # subprocess env NAME = host env NAME
    json_path = "result.content"          # optional: where the reply lives in stdout
    output = "text"                       # text | json
    version_args = ["--version"]

`command` is a program name resolved on PATH (or an absolute path). It is run
directly — never through a shell — so `args` cannot inject a shell command.
"""

from __future__ import annotations

import json
import shutil
from typing import Any

from .driver import AgentCapabilities, AgentDriver

_PROMPT_PLACEHOLDER = "{prompt}"


class CustomAgentDriver(AgentDriver):
    """An operator-defined agent, built from a dict spec."""

    homepage = ""

    def __init__(self, spec: dict[str, Any]) -> None:
        super().__init__()
        name = str(spec.get("name") or "").strip()
        command = str(spec.get("command") or "").strip()
        if not name:
            raise ValueError("custom agent spec needs a non-empty `name`")
        if not command:
            raise ValueError(f"custom agent {name!r} needs a non-empty `command`")

        self.name = name
        self.title = str(spec.get("title") or name)
        self.homepage = str(spec.get("homepage") or "")
        self._command = command
        self._args: list[str] = [str(a) for a in (spec.get("args") or [])]
        self._env_map: dict[str, str] = {
            str(k): str(v) for k, v in (spec.get("env") or {}).items()
        }
        self._json_path = spec.get("json_path")
        self._version_args = [str(a) for a in (spec.get("version_args") or ["--version"])]
        self._model_flag = spec.get("model_flag")
        self.capabilities = AgentCapabilities(
            long_context=bool(spec.get("long_context", True)),
            structured_output=bool(spec.get("structured_output", False)),
            context_tokens=spec.get("context_tokens"),
            stateless=bool(spec.get("stateless", True)),
        )

    @classmethod
    def from_spec(cls, spec: dict[str, Any]) -> "CustomAgentDriver":
        if not isinstance(spec, dict):
            raise ValueError("custom agent spec must be a table/dict")
        return cls(spec)

    # -- detection ---------------------------------------------------------
    def executable(self) -> str | None:
        if shutil.which(self._command):
            return self._command
        # Allow an absolute path that exists on disk but is not on PATH.
        import os

        if os.path.isabs(self._command) and os.path.exists(self._command):
            return self._command
        return None

    def version_argv(self) -> list[str]:
        return list(self._version_args)

    def install_hint(self) -> str:
        return f"Install {self._command!r} and put it on PATH."

    # -- invocation --------------------------------------------------------
    def command(self, prompt: str, *, model: str | None) -> tuple[list[str], str | None]:
        args = list(self._args)
        if model and self._model_flag:
            args += [str(self._model_flag), model]

        if any(_PROMPT_PLACEHOLDER in a for a in args):
            rendered = [a.replace(_PROMPT_PLACEHOLDER, prompt) for a in args]
            return rendered, None
        # No placeholder: pass the prompt on stdin, which is not limited by argv.
        return args, prompt

    def env(self) -> dict[str, str]:
        import os

        env = dict(os.environ)
        for sub_env, host_env in self._env_map.items():
            value = os.getenv(host_env)
            if value is not None:
                env[sub_env] = value
        return env

    def parse_usage(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Pull a reply out of JSON output when the spec says where it lives."""
        if not self._json_path:
            return {}
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return {}
        value: Any = data
        for part in str(self._json_path).split("."):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return {}
        if isinstance(value, str):
            # A JSON envelope: replace the text the backend will parse.
            return {"_extracted": value}
        return {}

    def invoke(self, prompt: str, *, model: str | None = None, timeout_s: int = 300):
        invocation = super().invoke(prompt, model=model, timeout_s=timeout_s)
        extracted = self.parse_usage(invocation.text, invocation.stderr).get("_extracted")
        if extracted:
            invocation.text = extracted
        return invocation


__all__ = ["CustomAgentDriver"]
