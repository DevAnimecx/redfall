"""Executable adapter contracts.

A certification is a measured fact: a real server process started, completed the
MCP handshake, exposed the expected tools, persisted a campaign through those
tools, denied an out-of-scope path, and returned a protocol-visible error for an
unknown tool. A server that cannot do all of that is not certified, even if it
advertises the MCP transport.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.engine import make_url

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
