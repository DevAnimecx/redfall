"""Build a live backend from a BackendConfig (0.2.1 / 0.2.7).

`make_backend` is the only constructor the rest of the engine uses. It never
returns a degraded object: when it cannot build what was asked for it raises
`BackendError` naming every option that would have worked.
"""

from __future__ import annotations

from typing import Any

from .backend import BackendError, ReasoningBackend
from .config import BackendConfig


def _agent_registry():
    from ..agents import driver_registry

    return driver_registry()


def _provider_key_present() -> bool:
    import os

    return bool(os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"))


def make_backend(config: BackendConfig, *, session_factory, budget) -> ReasoningBackend:
    kind = (config.kind or "auto").lower()

    if kind == "auto":
        if _provider_key_present():
            kind = "litellm"
        else:
            detected = _agent_registry().detected()
            if detected:
                return _build_agent(detected[0], config, session_factory=session_factory, budget=budget)
            raise BackendError(
                "no reasoning backend is configured and none was detected. Either set an "
                "OPENAI_API_KEY / ANTHROPIC_API_KEY, or install an agent RedFall can drive "
                "(run `redfall agent list` to see the 12 supported agents), or set "
                "`[backend] kind = ...` in redfall.toml."
            )

    if kind == "litellm":
        from .litellm_backend import LiteLLMBackend

        if not _provider_key_present():
            raise BackendError(
                "backend kind is 'litellm' but no provider key is present; set "
                "OPENAI_API_KEY or ANTHROPIC_API_KEY, or choose another backend"
            )
        return LiteLLMBackend(session_factory=session_factory, budget=budget)

    if kind == "agent":
        name = config.agent
        if not name:
            raise BackendError("backend kind is 'agent' but no agent name was given")
        return _build_agent(name, config, session_factory=session_factory, budget=budget)

    if kind == "openai_compat":
        from .openai_compat import OpenAICompatBackend

        return OpenAICompatBackend(
            base_url=config.base_url, model=config.model, api_key_env=config.api_key_env,
            session_factory=session_factory, budget=budget,
        )

    if kind == "custom":
        return _build_custom(config, session_factory=session_factory, budget=budget)

    if kind == "router":
        from .router import RouterBackend

        return RouterBackend(
            config, session_factory=session_factory, budget=budget, build=make_backend
        )

    raise BackendError(
        f"unknown backend kind {config.kind!r}; expected one of "
        "auto, litellm, agent, openai_compat, custom, router"
    )


def _build_agent(name: str, config: BackendConfig, *, session_factory, budget) -> ReasoningBackend:
    from .agent_backend import AgentBackend

    registry = _agent_registry()
    driver = registry.get(name)
    if driver is None:
        raise BackendError(
            f"unknown agent {name!r}; known agents: {', '.join(registry.names()) or 'none'}"
        )
    if not driver.available():
        raise BackendError(
            f"agent {name!r} is configured but not installed on this host. {driver.install_hint()}"
        )
    return AgentBackend(driver, session_factory=session_factory, budget=budget)


def _build_custom(config: BackendConfig, *, session_factory, budget) -> ReasoningBackend:
    from ..agents.custom import CustomAgentDriver
    from .agent_backend import AgentBackend

    spec: dict[str, Any] = dict(config.options or {})
    if config.agent and "command" not in spec:
        spec["command"] = config.agent
    try:
        driver = CustomAgentDriver.from_spec(spec)
    except ValueError as err:
        raise BackendError(f"invalid custom backend spec: {err}") from err
    return AgentBackend(driver, session_factory=session_factory, budget=budget)
