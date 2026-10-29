"""The reasoning layer.

One interface (`ReasoningBackend`), several answers to it:

* `LiteLLMBackend` — a provider API key.
* `AgentDriver` — an agent the operator already runs, with no key of RedFall's.
* `RouterBackend` — dispatches stages across a set of the above.

The factory `make_backend` reads a `BackendConfig` and returns a live backend, or
raises `BackendError` naming exactly what is missing. There is no fallback: a
scan whose backend cannot answer fails rather than degrading.
"""

from __future__ import annotations

from .backend import BackendError, BackendResult, ReasoningBackend, request_digest
from .config import BackendConfig, ConfigError, load_backend_config
from .litellm_backend import LiteLLMBackend

__all__ = [
    "BackendConfig",
    "BackendError",
    "BackendResult",
    "ConfigError",
    "LiteLLMBackend",
    "ReasoningBackend",
    "load_backend_config",
    "make_backend",
    "request_digest",
]


def make_backend(config: BackendConfig, *, session_factory, budget) -> ReasoningBackend:
    """Build the backend a config names. Never returns a fallback."""
    from .factory import make_backend as _make

    return _make(config, session_factory=session_factory, budget=budget)
