"""The dashboard HTTP API (0.3.1).

One stdlib `ThreadingHTTPServer`, no framework, no second source of truth. Every
route delegates to the shipped `ToolRegistry`, so an operation is implemented
exactly once and the dashboard cannot drift from the CLI, MCP or A2A surfaces.

Routes
------
    GET  /healthz                       liveness and database state
    GET  /api/version                   server + tool count
    GET  /api/agents                    reasoning backends and detection
    GET  /api/projects                  repositories the server may scan
    GET  /api/scans                     recent scans, newest first
    GET  /api/scans/{id}                one scan with branches and findings
    GET  /api/scans/{id}/events         Server-Sent Events for that scan
    POST /api/scans                     start a scan (blocking; see note)
    POST /api/scans/{id}/cancel         cancel a running campaign
    GET  /api/findings                  findings, filterable
    GET  /api/findings/{id}             one finding with its evidence
    POST /api/findings/{id}/reproduce   re-run the PoC in the sandbox
    POST /api/findings/{id}/fix         propose a fix (never auto-applies)
    GET  /api/reports/{id}              the report bundle for a scan

Note on `POST /api/scans`: a scan is long. The server starts it on a worker
thread and returns `202` with the scan id immediately, so the UI stays
responsive and follows progress over the events stream. The scan is real: it
runs the same handler as the CLI, and it fails the same way when a prerequisite
is missing.

Auth: when `REDFALL_DASHBOARD_TOKEN` is set, every `/api` route requires
`Authorization: Bearer <token>`. Unset, the server binds loopback and says so.
This is a single-operator console, not a multi-tenant service — that is 0.5.0.
"""

from __future__ import annotations

import json
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from ..interop.tools import ToolError, ToolRegistry
from ..version import __version__
from .events import EventBus, EventBusError

#: Tools the dashboard is allowed to call, mapped from route to tool name.
READ_ROUTES = {
    "agents": "redfall_agents_list",
    "reasoning": "redfall_reasoning_describe",
}


class ApiError(RuntimeError):
    """A request the dashboard refused, with an HTTP status and a stable kind."""

    def __init__(self, status: int, kind: str, message: str) -> None:
        self.status = status
        self.kind = kind
        self.message = message
        super().__init__(message)


class Dashboard:
    """The request-handling core, independent of the socket layer.

    Keeping this separate from `BaseHTTPRequestHandler` means the routes can be
    tested by calling `handle()` directly — no socket needed for the unit tests,
    while the contract tests still exercise a real server.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        bus: EventBus | None = None,
        token: str | None = None,
        projects: list[str] | None = None,
    ) -> None:
        self.registry = registry
        self.bus = bus or EventBus()
        self.token = token
        self.projects = list(projects or [])
        self._workers: dict[str, threading.Thread] = {}
        self._lock = threading.Lock()

    # -- auth --------------------------------------------------------------
    def check_auth(self, header: str | None) -> None:
        if not self.token:
            return
        if not header or not header.startswith("Bearer "):
            raise ApiError(401, "unauthorized", "a bearer token is required")
        if header.removeprefix("Bearer ").strip() != self.token:
            raise ApiError(403, "forbidden", "the bearer token is not valid")

    # -- routing -----------------------------------------------------------
    def handle(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, list[str]] | None = None,
        body: dict[str, Any] | None = None,
        auth_header: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """Return (status, json-body). Raises ApiError for a refusal."""
        query = query or {}
        self.check_auth(auth_header)
        parts = [p for p in path.split("/") if p]
        try:
            return self._route(method, parts, query, body or {})
        except ApiError:
            raise
        except ToolError as exc:
            raise ApiError(400, "tool_error", str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 - a 500 must still be JSON
            raise ApiError(500, "internal", f"{type(exc).__name__}: {exc}") from exc

    def _route(
        self,
        method: str,
        parts: list[str],
        query: dict[str, list[str]],
        body: dict[str, Any],
    ) -> tuple[int, dict[str, Any]]:
        if not parts:
            return 200, {"name": "redfall dashboard", "version": __version__}

        head = parts[0]

        if head == "healthz":
            return 200, self.registry.call("redfall_health", {})

        if head == "api":
            if len(parts) == 1:
                return 200, {"version": __version__, "tools": len(self.registry.specs())}
            return self._api(method, parts[1:], query, body)

        raise ApiError(404, "not_found", f"no route for /{'/'.join(parts)}")

    def _api(
        self,
        method: str,
        parts: list[str],
        query: dict[str, list[str]],
        body: dict[str, Any],
    ) -> tuple[int, dict[str, Any]]:
        resource = parts[0]

        if resource == "version":
            return 200, {"version": __version__, "tools": len(self.registry.specs())}

        if resource == "agents":
            return 200, self.registry.call("redfall_agents_list", {})

        if resource == "reasoning":
            return 200, self.registry.call("redfall_reasoning_describe", {})

        if resource == "projects":
            return 200, {"projects": self.projects, "roots": self._project_roots()}

        if resource == "scans":
            return self._scans(method, parts[1:], query, body)

        if resource == "findings":
            return self._findings(method, parts[1:], query, body)

        if resource == "reports":
            if len(parts) < 2:
                raise ApiError(400, "bad_request", "a scan id is required")
            return 200, self.registry.call("redfall_report", {"scan_id": parts[1]})

        raise ApiError(404, "not_found", f"no API resource {resource!r}")

    # -- scans -------------------------------------------------------------
    def _scans(
        self,
        method: str,
        rest: list[str],
        query: dict[str, list[str]],
        body: dict[str, Any],
    ) -> tuple[int, dict[str, Any]]:
        if not rest:
            if method == "GET":
                limit = _int(query.get("limit", ["50"])[0], 50)
                return 200, self.registry.call("redfall_campaign_list", {"limit": limit})
            if method == "POST":
                return self._start_scan(body)
            raise ApiError(405, "method_not_allowed", f"{method} is not allowed here")

        scan_id = rest[0]

        if len(rest) == 1:
            if method == "GET":
                # A live scan is identified by an id the bus minted before the
                # scan started. It has no database row yet, so its status comes
                # from the stream rather than the store: answer with what the
                # bus knows and let the client keep streaming.
                if scan_id.startswith("live-"):
                    return 200, {
                        "id": scan_id,
                        "status": "running",
                        "live": True,
                        "queued": self.bus.has_subscribers(scan_id),
                    }
                return 200, self._scan_detail(scan_id)
            raise ApiError(405, "method_not_allowed", f"{method} is not allowed here")

        action = rest[1]
        if action == "events":
            # The socket layer handles SSE; reaching here means a direct call.
            raise ApiError(400, "use_stream", "open /api/scans/{id}/events as an event stream")
        if action == "cancel" and method == "POST":
            return 200, self.registry.call("redfall_campaign_cancel", {"campaign_id": scan_id})
        if action == "pause" and method == "POST":
            return 200, self.registry.call("redfall_campaign_pause", {"campaign_id": scan_id})
        if action == "resume" and method == "POST":
            return 200, self.registry.call("redfall_campaign_resume", {"campaign_id": scan_id})

        raise ApiError(404, "not_found", f"no scan action {action!r}")

    def _scan_detail(self, scan_id: str) -> dict[str, Any]:
        detail = self.registry.call("redfall_campaign_status", {"campaign_id": scan_id})
        findings = self.registry.call("redfall_findings", {"scan_id": scan_id, "limit": 500})
        detail = dict(detail)
        detail["findings"] = findings.get("findings", [])
        return detail

    def _start_scan(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        target = body.get("target") or body.get("repo")
        if not isinstance(target, str) or not target.strip():
            raise ApiError(400, "bad_request", "`target` must be a non-empty path")

        # Refuse a target outside the configured project roots, the same way the
        # agent gateways do, so the dashboard cannot be pointed anywhere.
        self._check_project(target)

        args: dict[str, Any] = {"target": target}
        for key in ("objective", "budget_usd", "budget_tokens", "commit"):
            if key in body and body[key] is not None:
                args[key] = body[key]

        # A long scan runs on a worker thread; the request returns at once.
        #
        # The scan id is minted here, before the scan starts, so a browser can
        # subscribe to `/api/scans/{id}/events` and be listening *before* the
        # first event is published. Without that, a client that subscribes only
        # after reading the response races the start of the scan.
        scan_id = self.bus.new_scan_id()
        args["scan_id"] = scan_id
        result_holder: dict[str, Any] = {}

        def run() -> None:
            try:
                self.bus.publish("scan:start", {"target": target}, scan_id)
                result = self.registry.call("redfall_scan_run", args)
                result_holder.update(result)
                self.bus.publish(
                    "scan:done",
                    {
                        "findings": len(result.get("findings", [])),
                        "status": result.get("status", ""),
                        "scan_id": result.get("scan_id", scan_id),
                    },
                    scan_id,
                )
            except Exception as exc:  # noqa: BLE001 - the stream reports the failure
                self.bus.publish("scan:error", {"error": str(exc)}, scan_id)

        thread = threading.Thread(target=run, name=f"scan-{scan_id}", daemon=True)
        with self._lock:
            self._workers[scan_id] = thread
        thread.start()
        return 202, {
            "accepted": True,
            "target": target,
            "scan_id": scan_id,
            "events": f"/api/scans/{scan_id}/events",
        }

    def _project_roots(self) -> list[str]:
        return list(self.projects)

    def _check_project(self, target: str) -> None:
        if not self.projects:
            return
        import os

        resolved = os.path.realpath(target)
        for root in self.projects:
            root_real = os.path.realpath(root)
            if resolved == root_real or resolved.startswith(root_real + os.sep):
                return
        raise ApiError(
            403,
            "out_of_scope",
            f"{target} is outside the configured project roots: {self.projects}",
        )

    # -- findings ----------------------------------------------------------
    def _findings(
        self,
        method: str,
        rest: list[str],
        query: dict[str, list[str]],
        body: dict[str, Any],
    ) -> tuple[int, dict[str, Any]]:
        if not rest:
            args: dict[str, Any] = {"limit": _int(query.get("limit", ["200"])[0], 200)}
            for key in ("scan_id", "severity", "category", "reproduced"):
                if key in query:
                    args[key] = query[key][0]
            return 200, self.registry.call("redfall_findings", args)

        finding_id = rest[0]
        if len(rest) == 1:
            return 200, self.registry.call("redfall_finding", {"finding_id": finding_id})

        action = rest[1]
        if action == "reproduce" and method == "POST":
            return 200, self.registry.call("redfall_reproduce", {"finding_id": finding_id})
        if action == "fix" and method == "POST":
            # Never applies: the handler attempts the fix inside a throwaway
            # git worktree and returns the patch, so the operator's checkout is
            # untouched. A dashboard that silently patched a repo would be the
            # opposite of what this project is for.
            args: dict[str, Any] = {"finding_id": finding_id}
            for key in ("target", "campaign_id", "require_reproduced"):
                if key in body and body[key] is not None:
                    args[key] = body[key]
            return 200, self.registry.call("redfall_fix_propose", args)
        raise ApiError(404, "not_found", f"no finding action {action!r}")


def _int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # Injected by the server factory.
    dashboard: Dashboard

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        # One line per request on stderr, the same shape the interop gateway uses.
        import sys

        sys.stderr.write("[dashboard] " + (fmt % args) + "\n")

    # -- plumbing ----------------------------------------------------------
    def _cors(self) -> None:
        # The Next.js dev server is a different origin during development.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _json(self, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self._cors()
        self.end_headers()
        self.wfile.write(data)

    def _error(self, err: ApiError) -> None:
        self._json(err.status, {"error": {"kind": err.kind, "message": err.message}})

    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(400, "bad_json", f"request body is not JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ApiError(400, "bad_json", "request body must be a JSON object")
        return parsed

    def _split(self) -> tuple[str, dict[str, list[str]]]:
        parsed = urlparse(self.path)
        return parsed.path, parse_qs(parsed.query)

    # -- verbs -------------------------------------------------------------
    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path, query = self._split()
        if path.startswith("/api/scans/") and path.endswith("/events"):
            self._sse(path)
            return
        try:
            status, body = self.dashboard.handle(
                "GET", path, query=query, auth_header=self.headers.get("Authorization")
            )
        except ApiError as err:
            self._error(err)
            return
        self._json(status, body)

    def do_POST(self) -> None:  # noqa: N802
        path, query = self._split()
        try:
            body = self._read_body()
            status, payload = self.dashboard.handle(
                "POST", path, query=query, body=body,
                auth_header=self.headers.get("Authorization"),
            )
        except ApiError as err:
            self._error(err)
            return
        self._json(status, payload)

    def _note_disconnect(self, exc: OSError) -> None:
        """Record a client disconnect so the log shows why a stream ended."""
        self.log_message("stream closed by client: %s", type(exc).__name__)

    # -- Server-Sent Events ------------------------------------------------
    def _sse(self, path: str) -> None:
        parts = [p for p in path.split("/") if p]
        # /api/scans/{id}/events
        scan_id = parts[2] if len(parts) >= 4 else None
        try:
            self.dashboard.check_auth(self.headers.get("Authorization"))
            sub = self.dashboard.bus.subscribe(scan_id)
        except ApiError as err:
            self._error(err)
            return
        except EventBusError as err:
            self._error(ApiError(503, "bus_closed", str(err)))
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            for event in sub.events(heartbeat_s=15.0):
                if event is None:
                    self.wfile.write(b": heartbeat\n\n")
                else:
                    self.wfile.write(event.sse().encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError) as exc:
            # The browser navigated away; the stream simply ends.
            self._note_disconnect(exc)
        except Exception:  # noqa: BLE001 - a stream failure must close cleanly
            traceback.print_exc()
        finally:
            sub.close()


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        dashboard: Dashboard,
    ) -> None:
        handler = type("_BoundHandler", (_Handler,), {"dashboard": dashboard})
        super().__init__(address, handler)
        self.dashboard = dashboard

    def server_close(self) -> None:
        self.dashboard.bus.close()
        super().server_close()


def serve_dashboard(
    *,
    host: str,
    port: int,
    registry: ToolRegistry,
    token: str | None = None,
    projects: list[str] | None = None,
    on_ready: Callable[[DashboardServer], None] | None = None,
) -> DashboardServer:
    """Start the dashboard and return the running server.

    The caller owns the lifecycle: `server.serve_forever()` to run it, or
    `server.shutdown()` to stop it. `on_ready` is called with the live server
    once the socket is bound, so a caller can read the real port when `port=0`.
    """
    dashboard = Dashboard(registry, token=token, projects=projects)
    server = DashboardServer((host, port), dashboard)
    if on_ready is not None:
        on_ready(server)
    return server


__all__ = ["ApiError", "Dashboard", "DashboardServer", "serve_dashboard"]
