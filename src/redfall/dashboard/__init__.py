"""The live control-plane API (0.3.0).

The dashboard talks to one HTTP surface that reuses the same `ToolRegistry` the
MCP, HTTP and A2A gateways already expose. There is no parallel implementation
of any operation: a scan started from the dashboard runs the same handler as a
scan started from `redfall campaign run`, and a finding shown in the UI is the
row that handler read.

Two things this module adds that the agent gateways do not have:

* **Server-Sent Events** — a running scan streams its branch, finding and spend
  events to the browser, so the UI is live rather than a poll of a saved file.
* **A browser-shaped error** — every failure is a JSON body with a `kind`, so
  the UI can say what went wrong instead of rendering a blank pane.
"""

from __future__ import annotations

from .events import EventBus, EventBusError
from .server import ApiError, Dashboard, DashboardServer, serve_dashboard

__all__ = ["ApiError", "Dashboard", "DashboardServer", "EventBus", "EventBusError", "serve_dashboard"]
