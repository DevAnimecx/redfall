"""Executable adapter contracts.

A certification is a measured fact: a real server process started, completed the
MCP handshake, exposed the expected tools, persisted a campaign through those
tools, denied an out-of-scope path, and returned a protocol-visible error for an
unknown tool. A server that cannot do all of that is not certified, even if it
advertises the MCP transport.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.engine import make_url

from ..version import __version__
from .mcp_client import (
    MCPClientError,
    MCPStdioClient,
    default_server_command,
    source_environment,
)

CORE_TOOLS = frozenset(
    {
        "redfall_health",
        "redfall_campaign_create",
        "redfall_campaign_status",
        "redfall_campaign_run",
        "redfall_campaign_reserve",
        "redfall_campaign_settle_reservation",
        "redfall_task_enqueue",
        "redfall_evidence_append",
        "redfall_evidence_verify",
        "redfall_report_readiness",
        "redfall_graph_index",
        "redfall_graph_latest",
        "redfall_graph_stats",
        "redfall_graph_search",
        "redfall_graph_node",
        "redfall_graph_neighbors",
        "redfall_graph_paths",
        "redfall_graph_routes",
        "redfall_graph_diff",
        "redfall_graph_sources",
        "redfall_graph_inventory",
        "redfall_scan_run",
        "redfall_findings",
        "redfall_finding",
        "redfall_reproduce",
        "redfall_report",
        "redfall_policy_check",
    }
)


@dataclass
class ContractCheck:
    name: str
    passed: bool
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_wire(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
            "data": self.data,
        }


@dataclass
class AdapterContractReport:
    adapter: str
    protocol: str
    transport: str
    database_url: str
    certified: bool
    checks: list[ContractCheck]
    server_name: str = ""
    server_version: str = ""
    protocol_version: str = ""
    tool_count: int = 0
    duration_ms: int = 0
    error: str = ""

    def to_wire(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "protocol": self.protocol,
            "transport": self.transport,
            "database_url": self.database_url,
            "certified": self.certified,
            "server_name": self.server_name,
            "server_version": self.server_version,
            "protocol_version": self.protocol_version,
            "tool_count": self.tool_count,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "checks": [check.to_wire() for check in self.checks],
        }


def _sqlite_url(path: Path) -> str:
    return f"sqlite+pysqlite:///{path.as_posix()}"


def _redact_url(url: str) -> str:
    try:
        return make_url(url).render_as_string(hide_password=True)
    except Exception:  # noqa: BLE001 - an unparseable URL is still a secret risk
        return "<database-url-redacted>"


def run_mcp_stdio_contract(
    database_url: str | None = None,
    *,
    command: list[str] | None = None,
    timeout: float = 60.0,
) -> AdapterContractReport:
    started = time.monotonic()
    temporary: Path | None = None
    if database_url is None:
        temporary = Path(tempfile.mkdtemp(prefix="redfall-contract-"))
        database_url = _sqlite_url(temporary / "contract.db")
    target_directory = Path(tempfile.mkdtemp(prefix="redfall-contract-target-"))
    (target_directory / "app.py").write_text(
        "def ping():\n    return 'pong'\n",
        encoding="utf-8",
    )
    checks: list[ContractCheck] = []
    report = AdapterContractReport(
        adapter="mcp-stdio",
        protocol="mcp",
        transport="stdio",
        database_url=_redact_url(database_url),
        certified=False,
        checks=checks,
    )
    client: MCPStdioClient | None = None

    def check(name: str, action: Callable[[], tuple[str, dict[str, Any]]]) -> None:
        try:
            detail, data = action()
            checks.append(ContractCheck(name=name, passed=True, detail=detail, data=data))
        except Exception as exc:  # noqa: BLE001 - a failed check is the report
            checks.append(
                ContractCheck(
                    name=name,
                    passed=False,
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )

    try:
        client = MCPStdioClient(
            command or default_server_command(database_url),
            env={
                **source_environment(),
                "REDFALL_ALLOWED_ROOTS": str(target_directory),
            },
            timeout=timeout,
        )
        client.start()
        initialized = client.initialize()
        server_info = initialized.get("serverInfo") or {}
        report.server_name = str(server_info.get("name") or "")
        report.server_version = str(server_info.get("version") or "")
        report.protocol_version = str(initialized.get("protocolVersion") or "")
        check(
            "initialize",
            lambda: (
                "server completed MCP initialize",
                {
                    "server_name": report.server_name,
                    "server_version": report.server_version,
                    "protocol_version": report.protocol_version,
                },
            ),
        )
        if report.server_name != "redfall":
            checks.append(
                ContractCheck(
                    name="server-identity",
                    passed=False,
                    detail=f"expected server name redfall, got {report.server_name!r}",
                )
            )
        else:
            checks.append(ContractCheck(name="server-identity", passed=True))

        tools = client.list_tools()
        report.tool_count = len(tools)
        names = [str(tool.get("name") or "") for tool in tools]
        duplicate = sorted({name for name in names if names.count(name) > 1})

        def validate_tools() -> tuple[str, dict[str, Any]]:
            missing = sorted(CORE_TOOLS - set(names))
            if missing:
                raise AssertionError(f"missing tools: {', '.join(missing)}")
            if duplicate:
                raise AssertionError(f"duplicate tool names: {', '.join(duplicate)}")
            for tool in tools:
                schema = tool.get("inputSchema")
                if not isinstance(schema, dict) or schema.get("type") != "object":
                    raise AssertionError(f"tool {tool.get('name')} has no object inputSchema")
            return f"{len(tools)} tools with object schemas", {"tool_count": len(tools)}

        check("tools-list", validate_tools)

        def health() -> tuple[str, dict[str, Any]]:
            result = client.call_tool("redfall_health")
            if not isinstance(result, dict) or result.get("ok") is not True:
                raise AssertionError(f"health returned {result!r}")
            return "health reports ok", {"database": result.get("database", "")}

        check("health", health)

        campaign_id = ""

        def create_campaign() -> tuple[str, dict[str, Any]]:
            nonlocal campaign_id
            result = client.call_tool(
                "redfall_campaign_create",
                {
                    "repo": "contract/redfall-adapter",
                    "objective": "discovery",
                    "budget_usd": 1,
                },
            )
            campaign_id = str(result.get("id") or "")
            if not campaign_id:
                raise AssertionError("campaign create returned no id")
            return "campaign persisted through MCP", {"campaign_id": campaign_id}

        check("campaign-create", create_campaign)

        def campaign_status() -> tuple[str, dict[str, Any]]:
            if not campaign_id:
                raise AssertionError("no campaign id from previous check")
            result = client.call_tool("redfall_campaign_status", {"campaign_id": campaign_id})
            campaign = result.get("campaign") or {}
            if campaign.get("status") != "draft":
                raise AssertionError(f"expected draft campaign, got {campaign.get('status')!r}")
            return "campaign status is durable", {"campaign_id": campaign_id}

        check("campaign-status", campaign_status)

        def task_enqueue() -> tuple[str, dict[str, Any]]:
            if not campaign_id:
                raise AssertionError("no campaign id from previous check")
            result = client.call_tool(
                "redfall_task_enqueue",
                {
                    "campaign_id": campaign_id,
                    "kind": "graph.index",
                    "payload": {"target": "contract/not-a-local-repository"},
                },
            )
            if result.get("kind") != "graph.index" or result.get("status") != "pending":
                raise AssertionError(f"unexpected task: {result!r}")
            return "task queued and durable", {"task_id": result.get("id")}

        check("task-enqueue", task_enqueue)

        def graph_index() -> tuple[str, dict[str, Any]]:
            result = client.call_tool(
                "redfall_graph_index",
                {"target": str(target_directory), "label": "contract"},
            )
            snapshot = result.get("snapshot") or {}
            if snapshot.get("status") != "complete":
                raise AssertionError(f"unexpected snapshot: {snapshot!r}")
            if int(snapshot.get("nodes") or 0) < 1:
                raise AssertionError("graph snapshot contains no nodes")
            return (
                "real source indexed with provenance",
                {
                    "snapshot_id": snapshot.get("id", ""),
                    "nodes": snapshot.get("nodes", 0),
                },
            )

        check("graph-index", graph_index)

        def graph_latest() -> tuple[str, dict[str, Any]]:
            result = client.call_tool("redfall_graph_latest", {"limit": 1})
            snapshot = result.get("snapshot") or {}
            if not snapshot.get("id"):
                raise AssertionError(f"no latest snapshot: {result!r}")
            return "latest snapshot is queryable", {"snapshot_id": snapshot["id"]}

        check("graph-latest", graph_latest)

        def policy_denial() -> tuple[str, dict[str, Any]]:
            result = client.call_tool(
                "redfall_policy_check",
                {"action": "index", "target": str(Path.home())},
            )
            if result.get("allowed") is not False:
                raise AssertionError(f"expected denial, got {result!r}")
            return "out-of-scope path denied", {"reason": result.get("reason", "")}

        check("policy-denial", policy_denial)

        def unknown_tool() -> tuple[str, dict[str, Any]]:
            result = client.call_tool_raw("redfall_this_tool_does_not_exist", {})
            if not result.get("isError"):
                raise AssertionError("unknown tool did not return isError")
            content = result.get("content") or []
            text = " ".join(
                str(item.get("text") or "")
                for item in content
                if isinstance(item, dict)
            )
            if "unknown tool" not in text:
                raise AssertionError(f"unexpected tool error text: {text!r}")
            return "unknown tool is a protocol-visible error", {}

        check("unknown-tool", unknown_tool)

        report.certified = bool(checks) and all(item.passed for item in checks)
    except (MCPClientError, OSError) as exc:
        report.error = f"{type(exc).__name__}: {exc}"
        if not checks:
            checks.append(ContractCheck(name="server-start", passed=False, detail=report.error))
    finally:
        if client is not None:
            client.close()
        report.duration_ms = int((time.monotonic() - started) * 1000)
        shutil.rmtree(target_directory, ignore_errors=True)
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
    return report


def report_json(report: AdapterContractReport) -> str:
    return json.dumps(report.to_wire(), indent=2, default=str)


# ---------------------------------------------------------------------------
# HTTP/OpenAPI and A2A contracts
# ---------------------------------------------------------------------------


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _request(
    method: str,
    url: str,
    *,
    body: dict[str, Any] | None = None,
    token: str = "",
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    """One real HTTP request. Returns status, parsed JSON body and headers."""

    from urllib.error import HTTPError, URLError
    from urllib.request import Request, urlopen

    headers: dict[str, str] = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
            parsed = json.loads(raw) if raw else {}
            return int(response.status), parsed, {k.lower(): v for k, v in response.headers.items()}
    except HTTPError as exc:
        raw = exc.read()
        parsed = json.loads(raw) if raw else {}
        return int(exc.code), parsed, {k.lower(): v for k, v in exc.headers.items()}
    except URLError as exc:
        raise RuntimeError(f"request failed: {type(exc).__name__}: {exc}") from exc


def _rpc(
    base_url: str,
    token: str,
    method: str,
    params: dict[str, Any],
    *,
    timeout: float = 15.0,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    return _request(
        "POST",
        f"{base_url}/a2a/v1",
        body={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        token=token,
        timeout=timeout,
    )


class _GatewayHarness:
    """A real gateway subprocess on a temporary SQLite database."""

    def __init__(self, database_url: str | None = None, *, timeout: float) -> None:
        import subprocess

        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        from ..store.models import Base

        self.timeout = timeout
        self.temporary = Path(tempfile.mkdtemp(prefix="redfall-contract-"))
        self.target = Path(tempfile.mkdtemp(prefix="redfall-contract-target-"))
        (self.target / "app.py").write_text(
            "def ping():\n    return 'pong'\n", encoding="utf-8"
        )
        self.database_url = database_url or _sqlite_url(self.temporary / "contract.db")
        self.engine = create_engine(self.database_url, future=True)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(
            bind=self.engine, expire_on_commit=False, future=True
        )
        self.port = _free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._stderr_path = self.temporary / "gateway.stderr"
        self._stderr = open(self._stderr_path, "w+b")
        self.process = None
        self._stopped = False
        environment = {
            **os.environ,
            **source_environment(),
            "REDFALL_ALLOWED_ROOTS": str(self.target),
        }
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "redfall.interop.http_server",
                "--database-url",
                self.database_url,
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
            ],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=self._stderr,
        )
        try:
            self._wait_healthy()
        except Exception:
            self.stop()
            raise

    def _stderr_tail(self) -> str:
        try:
            self._stderr.flush()
            self._stderr.seek(0)
            text = self._stderr.read().decode("utf-8", errors="replace")
        except OSError:
            return ""
        return text[-4000:].strip()

    def _wait_healthy(self) -> None:
        from threading import Event

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"gateway exited with {self.process.returncode}: {self._stderr_tail()}"
                )
            try:
                status, body, _headers = _request(
                    "GET", f"{self.base_url}/healthz", timeout=2.0
                )
            except RuntimeError:
                Event().wait(0.1)
                continue
            if status == 200 and body.get("ok") is True:
                return
            Event().wait(0.1)
        raise RuntimeError(
            f"gateway did not become healthy in {self.timeout}s: {self._stderr_tail()}"
        )

    def token(self, name: str, scopes: list[str], *, quota_per_hour: int = 0) -> str:
        from .auth import create_token

        with self.Session() as session:
            _row, plaintext = create_token(
                session, name=name, scopes=scopes, quota_per_hour=quota_per_hour
            )
            session.commit()
            return plaintext

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        process = self.process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:
                process.kill()
                process.wait(timeout=10)
        try:
            self._stderr.close()
        finally:
            self.engine.dispose()
            shutil.rmtree(self.temporary, ignore_errors=True)
            shutil.rmtree(self.target, ignore_errors=True)


def _poll_task(
    base_url: str,
    token: str,
    task_id: str,
    *,
    timeout: float,
) -> dict[str, Any]:
    from threading import Event

    terminal = {
        "TASK_STATE_COMPLETED",
        "TASK_STATE_FAILED",
        "TASK_STATE_CANCELED",
        "TASK_STATE_REJECTED",
    }
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        status, body, _headers = _rpc(base_url, token, "GetTask", {"id": task_id})
        if status != 200:
            raise RuntimeError(f"GetTask returned HTTP {status}: {body!r}")
        if "error" in body:
            raise RuntimeError(f"GetTask error: {body['error']!r}")
        last = body.get("result") or {}
        state = (last.get("status") or {}).get("state")
        if state in terminal:
            return last
        Event().wait(0.1)
    raise RuntimeError(f"task {task_id} did not finish: {last!r}")


def _sse_events(
    base_url: str,
    token: str,
    method: str,
    params: dict[str, Any],
    *,
    timeout: float,
) -> list[dict[str, Any]]:
    """Read a real SSE stream until the task reaches a terminal state."""

    import http.client

    from urllib.parse import urlsplit

    parts = urlsplit(base_url)
    connection = http.client.HTTPConnection(
        parts.hostname or "127.0.0.1", parts.port or 80, timeout=timeout
    )
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    )
    try:
        connection.request(
            "POST",
            "/a2a/v1",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            detail = response.read(2000).decode("utf-8", errors="replace")
            raise RuntimeError(f"SSE request returned HTTP {response.status}: {detail}")
        content_type = response.getheader("Content-Type") or ""
        if "text/event-stream" not in content_type:
            raise RuntimeError(f"expected text/event-stream, got {content_type!r}")
        events: list[dict[str, Any]] = []
        while True:
            line = response.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            if not text.startswith("data: "):
                continue
            envelope = json.loads(text[len("data: ") :])
            result = envelope.get("result") or {}
            events.append(result)
            if "statusUpdate" in result:
                state = (result["statusUpdate"].get("status") or {}).get("state")
                if state in {
                    "TASK_STATE_COMPLETED",
                    "TASK_STATE_FAILED",
                    "TASK_STATE_CANCELED",
                    "TASK_STATE_REJECTED",
                }:
                    break
        return events
    finally:
        connection.close()


def run_http_contract(
    database_url: str | None = None,
    *,
    timeout: float = 60.0,
) -> AdapterContractReport:
    """Certify the OpenAPI/HTTP surface against a real gateway subprocess."""

    started = time.monotonic()
    checks: list[ContractCheck] = []
    report = AdapterContractReport(
        adapter="http-openapi",
        protocol="openapi",
        transport="http",
        database_url=_redact_url(database_url or "<temporary-sqlite>"),
        certified=False,
        checks=checks,
        server_name="redfall",
        server_version="",
        protocol_version="3.1.0",
    )
    harness: _GatewayHarness | None = None

    def check(name: str, action: Callable[[], tuple[str, dict[str, Any]]]) -> None:
        try:
            detail, data = action()
            checks.append(ContractCheck(name=name, passed=True, detail=detail, data=data))
        except Exception as exc:  # noqa: BLE001 - a failed check is the report
            checks.append(
                ContractCheck(
                    name=name,
                    passed=False,
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )

    try:
        harness = _GatewayHarness(database_url, timeout=timeout)
        report.database_url = _redact_url(harness.database_url)
        reader = harness.token("contract-reader", ["read"])
        admin = harness.token("contract-admin", ["read", "execute", "admin"])
        quota = harness.token("contract-quota", ["read"], quota_per_hour=1)
        specs = {"count": 0}
        tool_names: set[str] = set()

        def health() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _request("GET", f"{harness.base_url}/healthz")
            if status != 200 or body.get("ok") is not True:
                raise AssertionError(f"health returned HTTP {status}: {body!r}")
            return "health reports ok", {"database": body.get("database", "")}

        check("health", health)

        def openapi() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _request(
                "GET", f"{harness.base_url}/v1/openapi.json"
            )
            if status != 200:
                raise AssertionError(f"openapi returned HTTP {status}")
            if not str(body.get("openapi", "")).startswith("3.1"):
                raise AssertionError(f"unexpected openapi version: {body.get('openapi')!r}")
            paths = body.get("paths") or {}
            if "/v1/tools/redfall_health" not in paths:
                raise AssertionError("openapi is missing the health tool path")
            count = int(body.get("x-redfall-tool-count") or 0)
            if count < len(CORE_TOOLS):
                raise AssertionError(f"openapi advertises only {count} tools")
            return f"OpenAPI 3.1 with {count} tool paths", {"tool_count": count}

        check("openapi", openapi)

        def unauthenticated() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _request(
                "GET", f"{harness.base_url}/v1/tools"
            )
            if status != 401:
                raise AssertionError(f"expected 401, got HTTP {status}: {body!r}")
            return "unauthenticated tool listing is denied", {"code": body.get("error", {}).get("code", "")}

        check("unauthenticated-denial", unauthenticated)

        def tools_list() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _request(
                "GET", f"{harness.base_url}/v1/tools", token=admin
            )
            if status != 200:
                raise AssertionError(f"tools returned HTTP {status}: {body!r}")
            names = {str(tool.get("name")) for tool in body.get("tools") or []}
            missing = sorted(CORE_TOOLS - names)
            if missing:
                raise AssertionError(f"missing tools: {', '.join(missing)}")
            specs["count"] = len(names)
            tool_names.update(names)
            return f"{len(names)} tools advertised", {"tool_count": len(names)}

        check("tools-list", tools_list)

        def health_tool() -> tuple[str, dict[str, Any]]:
            status, body, headers = _request(
                "POST",
                f"{harness.base_url}/v1/tools/redfall_health",
                body={},
                token=admin,
            )
            if status != 200:
                raise AssertionError(f"tool call returned HTTP {status}: {body!r}")
            result = body.get("result") or {}
            if result.get("ok") is not True:
                raise AssertionError(f"unexpected result: {body!r}")
            if body.get("trust") != "untrusted-repository-data":
                raise AssertionError("result is not trust-labelled")
            if headers.get("x-redfall-trust") != "untrusted-repository-data":
                raise AssertionError("missing X-Redfall-Trust header")
            return "tool result is executed and trust-labelled", {}

        check("tool-call", health_tool)

        def graph_index() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _request(
                "POST",
                f"{harness.base_url}/v1/tools/redfall_graph_index",
                body={"target": str(harness.target), "label": "contract"},
                token=admin,
                timeout=30.0,
            )
            if status != 200:
                raise AssertionError(f"graph index returned HTTP {status}: {body!r}")
            snapshot = (body.get("result") or {}).get("snapshot") or {}
            if snapshot.get("status") != "complete" or int(snapshot.get("nodes") or 0) < 1:
                raise AssertionError(f"unexpected snapshot: {snapshot!r}")
            return "real source indexed over HTTP", {"snapshot_id": snapshot.get("id", "")}

        check("graph-index", graph_index)

        def scope_denial() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _request(
                "POST",
                f"{harness.base_url}/v1/tools/redfall_graph_index",
                body={"target": str(harness.target)},
                token=reader,
            )
            if status != 403:
                raise AssertionError(f"expected 403, got HTTP {status}: {body!r}")
            if (body.get("error") or {}).get("code") != "forbidden":
                raise AssertionError(f"unexpected error body: {body!r}")
            return "read scope cannot execute", {}

        check("scope-denial", scope_denial)

        def unknown_tool() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _request(
                "POST",
                f"{harness.base_url}/v1/tools/redfall_this_tool_does_not_exist",
                body={},
                token=admin,
            )
            if status != 404:
                raise AssertionError(f"expected 404, got HTTP {status}: {body!r}")
            return "unknown tool is a protocol-visible 404", {}

        check("unknown-tool", unknown_tool)

        def quota_denial() -> tuple[str, dict[str, Any]]:
            first_status, first_body, _headers = _request(
                "POST",
                f"{harness.base_url}/v1/tools/redfall_health",
                body={},
                token=quota,
            )
            if first_status != 200:
                raise AssertionError(f"first call returned HTTP {first_status}: {first_body!r}")
            second_status, second_body, _headers = _request(
                "POST",
                f"{harness.base_url}/v1/tools/redfall_health",
                body={},
                token=quota,
            )
            if second_status != 429:
                raise AssertionError(
                    f"expected 429 on the second call, got HTTP {second_status}: {second_body!r}"
                )
            return "hourly quota is enforced", {"quota": 1}

        check("quota", quota_denial)

        def audit_trail() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _request(
                "GET", f"{harness.base_url}/v1/audit?limit=100", token=admin
            )
            if status != 200:
                raise AssertionError(f"audit returned HTTP {status}: {body!r}")
            calls = body.get("calls") or []
            tools = {str(call.get("tool")) for call in calls}
            if "redfall_graph_index" not in tools:
                raise AssertionError(f"graph.index is not audited: {sorted(tools)}")
            if not any(
                call.get("agent") == "contract-reader" and call.get("ok") is False
                for call in calls
            ):
                raise AssertionError("the scope denial was not audited")
            return f"{len(calls)} audit rows persisted", {"calls": len(calls)}

        check("audit", audit_trail)

        report.server_version = __version__
        report.tool_count = specs["count"]
        report.certified = bool(checks) and all(item.passed for item in checks)
    except Exception as exc:  # noqa: BLE001 - the report records the real failure
        report.error = f"{type(exc).__name__}: {exc}"
        if not checks:
            checks.append(ContractCheck(name="server-start", passed=False, detail=report.error))
    finally:
        if harness is not None:
            harness.stop()
        report.duration_ms = int((time.monotonic() - started) * 1000)
    return report


def run_a2a_contract(
    database_url: str | None = None,
    *,
    timeout: float = 60.0,
) -> AdapterContractReport:
    """Certify the A2A v1.0 JSON-RPC surface against a real gateway subprocess."""

    started = time.monotonic()
    checks: list[ContractCheck] = []
    report = AdapterContractReport(
        adapter="a2a",
        protocol="a2a",
        transport="http",
        database_url=_redact_url(database_url or "<temporary-sqlite>"),
        certified=False,
        checks=checks,
        server_name="redfall",
        server_version="",
        protocol_version="1.0",
    )
    harness: _GatewayHarness | None = None

    def check(name: str, action: Callable[[], tuple[str, dict[str, Any]]]) -> None:
        try:
            detail, data = action()
            checks.append(ContractCheck(name=name, passed=True, detail=detail, data=data))
        except Exception as exc:  # noqa: BLE001 - a failed check is the report
            checks.append(
                ContractCheck(
                    name=name,
                    passed=False,
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )

    try:
        harness = _GatewayHarness(database_url, timeout=timeout)
        report.database_url = _redact_url(harness.database_url)
        reader = harness.token("contract-reader", ["read"])
        admin = harness.token("contract-admin", ["read", "execute", "admin"])

        def agent_card() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _request(
                "GET", f"{harness.base_url}/.well-known/agent-card.json"
            )
            if status != 200:
                raise AssertionError(f"agent card returned HTTP {status}")
            if body.get("name") != "RedFall":
                raise AssertionError(f"unexpected agent name: {body.get('name')!r}")
            interfaces = body.get("supportedInterfaces") or []
            if not interfaces or interfaces[0].get("protocolBinding") != "JSONRPC":
                raise AssertionError(f"unexpected interfaces: {interfaces!r}")
            if interfaces[0].get("protocolVersion") != "1.0":
                raise AssertionError(f"unexpected protocol version: {interfaces[0]!r}")
            if "bearer" not in (body.get("securitySchemes") or {}):
                raise AssertionError("agent card does not declare bearer auth")
            if not body.get("skills"):
                raise AssertionError("agent card has no skills")
            capabilities = body.get("capabilities") or {}
            if capabilities.get("streaming") is not True:
                raise AssertionError("streaming is not advertised")
            if capabilities.get("pushNotifications") is not False:
                raise AssertionError("push notifications must not be advertised")
            return "Agent Card is A2A v1.0 JSONRPC with bearer auth", {
                "skills": len(body.get("skills") or [])
            }

        check("agent-card", agent_card)

        def unauthenticated() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _rpc(
                harness.base_url,
                "",
                "SendMessage",
                {
                    "message": {
                        "messageId": "msg-contract-unauth",
                        "role": "ROLE_USER",
                        "parts": [{"data": {"tool": "redfall_health", "arguments": {}}}],
                    }
                },
            )
            if status != 401:
                raise AssertionError(f"expected 401, got HTTP {status}: {body!r}")
            return "unauthenticated A2A call is denied", {}

        check("unauthenticated-denial", unauthenticated)

        task_state: dict[str, Any] = {}

        def send_message() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _rpc(
                harness.base_url,
                admin,
                "SendMessage",
                {
                    "message": {
                        "messageId": "msg-contract-graph",
                        "role": "ROLE_USER",
                        "parts": [
                            {
                                "data": {
                                    "tool": "redfall_graph_index",
                                    "arguments": {
                                        "target": str(harness.target),
                                        "label": "contract",
                                    },
                                }
                            }
                        ],
                    },
                    "configuration": {"returnImmediately": True},
                },
            )
            if status != 200 or "error" in body:
                raise AssertionError(f"SendMessage failed: HTTP {status} {body!r}")
            task = (body.get("result") or {}).get("task") or {}
            task_id = str(task.get("id") or "")
            if not task_id:
                raise AssertionError(f"SendMessage returned no task: {body!r}")
            task_state["id"] = task_id
            return "task created through SendMessage", {"task_id": task_id}

        check("send-message", send_message)

        def get_task() -> tuple[str, dict[str, Any]]:
            task_id = str(task_state.get("id") or "")
            if not task_id:
                raise AssertionError("no task id from send-message")
            task = _poll_task(harness.base_url, admin, task_id, timeout=timeout)
            task_state["task"] = task
            if task.get("status", {}).get("state") != "TASK_STATE_COMPLETED":
                raise AssertionError(f"task did not complete: {task!r}")
            artifacts = task.get("artifacts") or []
            if not artifacts:
                raise AssertionError("completed task has no artifacts")
            part = (artifacts[0].get("parts") or [{}])[0]
            if not isinstance(part.get("data"), dict):
                raise AssertionError(f"artifact has no data part: {part!r}")
            if part["data"].get("snapshot", {}).get("status") != "complete":
                raise AssertionError(f"artifact does not contain the graph: {part!r}")
            task_state["artifact_url"] = (
                (artifacts[0].get("metadata") or {}).get("redfall", {}).get("url", "")
            )
            return "task completed with a real artifact", {"task_id": task_id}

        check("get-task", get_task)

        def list_tasks() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _rpc(
                harness.base_url, admin, "ListTasks", {"pageSize": 10}
            )
            if status != 200 or "error" in body:
                raise AssertionError(f"ListTasks failed: HTTP {status} {body!r}")
            result = body.get("result") or {}
            ids = {str(task.get("id")) for task in result.get("tasks") or []}
            if str(task_state.get("id")) not in ids:
                raise AssertionError(f"task missing from ListTasks: {result!r}")
            if not isinstance(result.get("nextPageToken"), str):
                raise AssertionError("nextPageToken is missing")
            if not isinstance(result.get("pageSize"), int):
                raise AssertionError("pageSize is missing")
            return "task is listed with pagination fields", {
                "tasks": len(result.get("tasks") or [])
            }

        check("list-tasks", list_tasks)

        def artifact_url() -> tuple[str, dict[str, Any]]:
            url = str(task_state.get("artifact_url") or "")
            if not url:
                raise AssertionError("artifact has no signed URL")
            status, body, _headers = _request("GET", url)
            if status != 200:
                raise AssertionError(f"signed artifact returned HTTP {status}: {body!r}")
            artifact = body.get("artifact") or {}
            if not artifact.get("payload"):
                raise AssertionError(f"artifact payload is empty: {body!r}")
            if body.get("trust") != "untrusted-repository-data":
                raise AssertionError("artifact is not trust-labelled")
            tampered = url[:-1] + ("0" if url[-1] != "0" else "1")
            bad_status, _bad_body, _headers = _request("GET", tampered)
            if bad_status != 403:
                raise AssertionError(f"tampered signature returned HTTP {bad_status}")
            return "signed artifact URL works and tampering is denied", {}

        check("artifact-url", artifact_url)

        def cancel_terminal() -> tuple[str, dict[str, Any]]:
            task_id = str(task_state.get("id") or "")
            status, body, _headers = _rpc(
                harness.base_url, admin, "CancelTask", {"id": task_id}
            )
            if status != 200 or "error" not in body:
                raise AssertionError(f"cancel of a terminal task succeeded: {body!r}")
            if int(body["error"].get("code") or 0) != -32002:
                raise AssertionError(f"unexpected cancel error: {body['error']!r}")
            return "terminal task cancellation is refused with -32002", {}

        check("cancel-terminal", cancel_terminal)

        def unknown_method() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _rpc(
                harness.base_url, admin, "ThisMethodDoesNotExist", {}
            )
            if status != 200 or "error" not in body:
                raise AssertionError(f"unknown method returned: HTTP {status} {body!r}")
            if int(body["error"].get("code") or 0) != -32601:
                raise AssertionError(f"unexpected method error: {body['error']!r}")
            return "unknown method is a JSON-RPC error", {}

        check("unknown-method", unknown_method)

        def push_unsupported() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _rpc(
                harness.base_url,
                admin,
                "CreateTaskPushNotificationConfig",
                {"taskId": str(task_state.get("id") or ""), "url": "http://127.0.0.1:9/hook"},
            )
            if status != 200 or "error" not in body:
                raise AssertionError(f"push config was accepted: {body!r}")
            if int(body["error"].get("code") or 0) != -32003:
                raise AssertionError(f"unexpected push error: {body['error']!r}")
            return "undeclared push notifications return -32003", {}

        check("push-unsupported", push_unsupported)

        def scope_denial() -> tuple[str, dict[str, Any]]:
            status, body, _headers = _rpc(
                harness.base_url,
                reader,
                "SendMessage",
                {
                    "message": {
                        "messageId": "msg-contract-scope",
                        "role": "ROLE_USER",
                        "parts": [
                            {
                                "data": {
                                    "tool": "redfall_graph_index",
                                    "arguments": {"target": str(harness.target)},
                                }
                            }
                        ],
                    },
                    "configuration": {"returnImmediately": True},
                },
            )
            if status != 200 or "error" not in body:
                raise AssertionError(f"read token executed a write tool: {body!r}")
            message_text = str((body.get("error") or {}).get("message") or "")
            if "insufficient scope" not in message_text:
                raise AssertionError(f"unexpected scope error: {body['error']!r}")
            return "read scope cannot execute tools", {}

        check("scope-denial", scope_denial)

        def streaming() -> tuple[str, dict[str, Any]]:
            events = _sse_events(
                harness.base_url,
                admin,
                "SendStreamingMessage",
                {
                    "message": {
                        "messageId": "msg-contract-stream",
                        "role": "ROLE_USER",
                        "parts": [{"data": {"tool": "redfall_health", "arguments": {}}}],
                    }
                },
                timeout=min(timeout, 30.0),
            )
            if not events or "task" not in events[0]:
                raise AssertionError(f"stream did not begin with a Task: {events[:2]!r}")
            completed = any(
                (event.get("statusUpdate", {}).get("status", {}) or {}).get("state")
                == "TASK_STATE_COMPLETED"
                for event in events
            )
            if not completed:
                raise AssertionError(f"stream never reported completion: {events!r}")
            return f"SSE streamed {len(events)} events to completion", {
                "events": len(events)
            }

        check("streaming", streaming)

        status, document, _headers = _request(
            "GET", f"{harness.base_url}/v1/openapi.json"
        )
        report.tool_count = (
            int((document or {}).get("x-redfall-tool-count") or 0) if status == 200 else 0
        )
        report.server_version = __version__
        report.certified = bool(checks) and all(item.passed for item in checks)
    except Exception as exc:  # noqa: BLE001 - the report records the real failure
        report.error = f"{type(exc).__name__}: {exc}"
        if not checks:
            checks.append(ContractCheck(name="server-start", passed=False, detail=report.error))
    finally:
        if harness is not None:
            harness.stop()
        report.duration_ms = int((time.monotonic() - started) * 1000)
    return report
