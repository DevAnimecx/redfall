"""Which backend to reason with, and how it is configured (0.2.7).

Precedence, highest first:

1. a `redfall.toml` in the target directory or the current directory;
2. `$REDFALL_CONFIG` if it names a file;
3. `~/.config/redfall/config.toml`;
4. environment variables — the 0.1.x path, kept so nothing that worked breaks.

With nothing configured at all the default is `auto`: use a provider key if one
is present, otherwise use the first detected agent. `auto` is a choice, not a
fallback — if neither exists it raises with both options named.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - the project requires 3.12
    tomllib = None  # type: ignore[assignment]


CONFIG_FILENAME = "redfall.toml"


@dataclass
class BackendConfig:
    """A resolved description of the reasoning backend."""

    kind: str = "auto"  # auto | litellm | agent | openai_compat | custom | router
    #: For kind="agent"/"custom": the driver name.
    agent: str | None = None
    #: For kind="openai_compat"/"custom": base URL and model handle.
    base_url: str | None = None
    model: str | None = None
    #: Env var holding the key for openai_compat. Defaults to OPENAI_API_KEY.
    api_key_env: str | None = None
    #: Free-form extras (custom driver command, prompt template, ...).
    options: dict[str, Any] = field(default_factory=dict)
    #: For kind="router": tier -> backend spec mapping, and a fallback.
    routes: dict[str, Any] = field(default_factory=dict)
    #: For kind="router": consensus settings.
    consensus: dict[str, Any] = field(default_factory=dict)
    #: Where this config was read from, for diagnostics. None when from env.
    source: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "agent": self.agent,
            "model": self.model,
            "base_url": self.base_url,
            "has_options": bool(self.options),
            "routes": sorted(self.routes),
            "source": self.source,
        }


def _candidate_paths(target: Path | None) -> list[Path]:
    out: list[Path] = []
    env = os.getenv("REDFALL_CONFIG")
    if env:
        out.append(Path(env))
    if target is not None:
        out.append(Path(target) / CONFIG_FILENAME)
    out.append(Path.cwd() / CONFIG_FILENAME)
    out.append(Path.home() / ".config" / "redfall" / CONFIG_FILENAME)
    return out


def load_backend_config(target: Path | None = None) -> BackendConfig:
    """Resolve a BackendConfig from the first config file found, else env."""
    if tomllib is not None:
        for path in _candidate_paths(target):
            if path.is_file():
                try:
                    data = tomllib.loads(path.read_text(encoding="utf-8"))
                except (OSError, tomllib.TOMLDecodeError):
                    continue
                cfg = _from_toml(data)
                cfg.source = str(path)
                return cfg
    return _from_env()


def _from_toml(data: dict[str, Any]) -> BackendConfig:
    backend = data.get("backend") or {}
    cfg = BackendConfig(
        kind=str(backend.get("kind") or "auto"),
        agent=backend.get("agent"),
        base_url=backend.get("base_url"),
        model=backend.get("model"),
        api_key_env=backend.get("api_key_env"),
        options=dict(backend.get("options") or {}),
        routes=dict(data.get("routes") or {}),
        consensus=dict(data.get("consensus") or {}),
    )
    # A config that names an agent without a kind means kind="agent".
    if cfg.kind == "auto" and cfg.agent:
        cfg.kind = "agent"
    return cfg


def _from_env() -> BackendConfig:
    kind = os.getenv("REDFALL_BACKEND")
    agent = os.getenv("REDFALL_AGENT")
    if not kind and agent:
        kind = "agent"
    return BackendConfig(
        kind=kind or "auto",
        agent=agent,
        base_url=os.getenv("REDFALL_BASE_URL"),
        model=os.getenv("REDFALL_MODEL"),
        api_key_env=os.getenv("REDFALL_API_KEY_ENV"),
    )


RENDER_TEMPLATE = """# RedFall configuration. Every key is optional; uncomment to use.

[backend]
# kind = "auto"            # auto | litellm | agent | openai_compat | custom | router
# agent = "claude-code"    # used when kind = "agent"
# base_url = "http://localhost:11434/v1"  # used when kind = "openai_compat"
# model = "qwen2.5-coder:32b"
# api_key_env = "OPENAI_API_KEY"

# --- multi-agent routing (kind = "router") -------------------------------
# [routes]
# fast = { kind = "agent", agent = "gemini-cli" }
# deep = { kind = "agent", agent = "claude-code" }

# [consensus]
# agents = ["claude-code", "codex"]
# min_agree = 2
"""


def render_default_config() -> str:
    return RENDER_TEMPLATE
