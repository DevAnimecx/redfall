"""Borrowing an agent's reasoning instead of holding an API key (0.2.x).

Twelve shipped drivers, a custom escape hatch, and a registry that knows which
of them are actually installed on this host.
"""

from __future__ import annotations

from .custom import CustomAgentDriver
from .driver import (
    AgentCapabilities,
    AgentDriver,
    AgentError,
    AgentInvocation,
    AgentNotInstalled,
)
from .registry import DriverRegistry, driver_registry, reset_registry

__all__ = [
    "AgentCapabilities",
    "AgentDriver",
    "AgentError",
    "AgentInvocation",
    "AgentNotInstalled",
    "CustomAgentDriver",
    "DriverRegistry",
    "driver_registry",
    "reset_registry",
]
