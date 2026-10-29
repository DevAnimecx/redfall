"""The driver registry (0.2.2).

One place that knows every agent RedFall can drive. The registry is built from
the shipped driver classes plus any custom drivers the operator registered in
config, so `redfall agent list` and the backend factory see the same set.
"""

from __future__ import annotations

from .driver import AgentDriver


def _builtin_classes() -> list[type[AgentDriver]]:
    from .drivers.aider import AiderDriver
    from .drivers.claude_code import ClaudeCodeDriver
    from .drivers.cline import ClineDriver
    from .drivers.codex import CodexDriver
    from .drivers.continue_agent import ContinueDriver
    from .drivers.crush import CrushDriver
    from .drivers.cursor import CursorDriver
    from .drivers.gemini_cli import GeminiCliDriver
    from .drivers.goose import GooseDriver
    from .drivers.kilo import KiloDriver
    from .drivers.openhands import OpenHandsDriver
    from .drivers.qwen_code import QwenCodeDriver

    return [
        ClaudeCodeDriver,
        CodexDriver,
        GeminiCliDriver,
        AiderDriver,
        CursorDriver,
        GooseDriver,
        OpenHandsDriver,
        ContinueDriver,
        ClineDriver,
        KiloDriver,
        QwenCodeDriver,
        CrushDriver,
    ]


class DriverRegistry:
    def __init__(self, drivers: list[AgentDriver] | None = None) -> None:
        self._drivers: dict[str, AgentDriver] = {}
        for cls in _builtin_classes():
            instance = cls()
            self._drivers[instance.name] = instance
        for driver in drivers or []:
            self._drivers[driver.name] = driver

    def get(self, name: str) -> AgentDriver | None:
        return self._drivers.get(name)

    def names(self) -> list[str]:
        return sorted(self._drivers)

    def all(self) -> list[AgentDriver]:
        return [self._drivers[n] for n in self.names()]

    def detected(self) -> list[str]:
        """Names of drivers whose agent is actually installed, in registry order."""
        return [d.name for d in self.all() if d.available()]

    def describe_all(self) -> list[dict]:
        return [d.describe() for d in self.all()]


_REGISTRY: DriverRegistry | None = None


def driver_registry() -> DriverRegistry:
    """The process-wide registry, including custom drivers from config."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = DriverRegistry(_custom_drivers())
    return _REGISTRY


def reset_registry() -> None:
    """Drop the cached registry (tests and config reloads)."""
    global _REGISTRY
    _REGISTRY = None


def _custom_drivers() -> list[AgentDriver]:
    """Custom drivers declared in config, if any and if loadable."""
    try:
        from ..reasoning.config import load_backend_config
        from .custom import CustomAgentDriver
    except Exception:  # noqa: BLE001 - a broken custom spec must not break `list`
        return []
    out: list[AgentDriver] = []
    for item in (load_backend_config().options or {}).get("agents") or []:
        if not isinstance(item, dict):
            continue
        try:
            out.append(CustomAgentDriver.from_spec(item))
        except ValueError:
            continue
    return out


__all__ = ["DriverRegistry", "driver_registry", "reset_registry"]
