"""MCP stdio conformance for the campaign/evidence tool surface.

The in-process test exercises request handling and the real tool registry. The
subprocess test starts the actual module, writes newline-delimited JSON-RPC to
its stdin and reads the responses from stdout, so a transport regression cannot
hide behind a direct method call.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from redfall.interop.mcp_stdio import MCPServer
from redfall.interop.tools import ToolRegistry
from redfall.store.models import Base

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def registry(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'mcp.db'}", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    yield ToolRegistry(Session)
    engine.dispose()


def rpc(server: MCPServer, request_id, method, params=None):
    return server.handle(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
    )


def payload(response):
    assert response is not None
    assert "result" in response, response
    assert response["result"]["isError"] is False, response
    return json.loads(response["result"]["content"][0]["text"])


def test_initialize_and_tool_discovery(registry):
    server = MCPServer(registry)
    response = rpc(
        server,
        1,
        "initialize",
        {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test"}},
    )
    assert response is not None
    assert response["result"]["protocolVersion"] == "2025-06-18"
    assert response["result"]["serverInfo"]["name"] == "redfall"

    names = {tool["name"] for tool in rpc(server, 2, "tools/list")["result"]["tools"]}
    assert {
        "redfall_health",
        "redfall_campaign_create",
        "redfall_campaign_status",
        "redfall_task_enqueue",
        "redfall_task_claim",
        "redfall_evidence_append",
        "redfall_evidence_verify",
        "redfall_report_readiness",
    } <= names

    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) is None


def test_campaign_workflow_through_the_tools(registry):
    server = MCPServer(registry)
    campaign = payload(
        rpc(
            server,
            10,
            "tools/call",
            {
                "name": "redfall_campaign_create",
                "arguments": {
                    "repo": "acme/api",
                    "objective": "discovery",
                    "scope": {"repos": ["acme/api"]},
                    "budget_usd": 2.0,
                },
            },
        )
    )
    campaign_id = campaign["id"]
    assert campaign["status"] == "draft"
    assert campaign["budget"]["usd"] == 2.0

    scoped = payload(
        rpc(
            server,
            11,
            "tools/call",
            {
                "name": "redfall_campaign_scope",
                "arguments": {"campaign_id": campaign_id, "scope": {"repos": ["acme/api"]}},
            },
        )
    )
    assert scoped["status"] == "scoped"
    started = payload(
        rpc(server, 12, "tools/call", {"name": "redfall_campaign_start", "arguments": {"campaign_id": campaign_id}})
    )
    assert started["status"] == "indexing"

    task = payload(
        rpc(
            server,
            13,
            "tools/call",
            {
                "name": "redfall_task_enqueue",
                "arguments": {"campaign_id": campaign_id, "kind": "index", "payload": {"path": "."}},
            },
        )
    )
    claimed = payload(
        rpc(
            server,
            14,
            "tools/call",
            {
                "name": "redfall_task_claim",
                "arguments": {"campaign_id": campaign_id, "worker": "agent-1", "lease_seconds": 60},
            },
        )
    )
    assert claimed["task"]["id"] == task["id"]
    completed = payload(
        rpc(
            server,
            15,
            "tools/call",
            {
                "name": "redfall_task_complete",
                "arguments": {"task_id": task["id"], "worker": "agent-1", "result": {"files": 4}},
            },
        )
    )
    assert completed["status"] == "completed"
    assert completed["result"]["files"] == 4

    evidence = payload(
        rpc(
            server,
            16,
            "tools/call",
            {
                "name": "redfall_evidence_append",
                "arguments": {
                    "campaign_id": campaign_id,
                    "grade": "E3",
                    "kind": "execution",
                    "claim": "The replay reaches the marker",
                    "payload": {"execution_id": "exe-1", "observable": "marker"},
                    "reproduce_command": "redfall reproduce exe-1",
                    "environment_digest": "sha256:test-image",
                },
            },
        )
    )
    assert evidence["reportable"] is True

    verification = payload(
        rpc(
            server,
            17,
            "tools/call",
            {"name": "redfall_evidence_verify", "arguments": {"campaign_id": campaign_id}},
        )
    )
    assert verification["ok"] is True
    readiness = payload(
        rpc(
            server,
            18,
            "tools/call",
            {"name": "redfall_report_readiness", "arguments": {"campaign_id": campaign_id}},
        )
    )
    assert readiness["ready"] is True
    assert readiness["evidence_ids"] == [evidence["id"]]

    status = payload(
        rpc(
            server,
            19,
            "tools/call",
            {"name": "redfall_campaign_status", "arguments": {"campaign_id": campaign_id}},
        )
    )
    assert status["tasks"]["by_status"]["completed"] == 1
    assert status["evidence"]["reportable"] == 1
    assert status["chain"]["ok"] is True


def test_tool_errors_are_returned_as_mcp_errors(registry):
    server = MCPServer(registry)
    response = rpc(
        server,
        20,
        "tools/call",
        {"name": "redfall_campaign_status", "arguments": {"campaign_id": "cmp-missing"}},
    )
    assert response["result"]["isError"] is True
    assert "no such campaign" in response["result"]["content"][0]["text"]

    response = rpc(server, 21, "tools/call", {"name": "redfall_unknown", "arguments": {}})
    assert response["result"]["isError"] is True
    assert "unknown tool" in response["result"]["content"][0]["text"]

    response = rpc(server, 22, "tools/call", {"name": "redfall_campaign_create", "arguments": {}})
    assert response["result"]["isError"] is True
    assert "repo" in response["result"]["content"][0]["text"]


def test_stdio_module_starts_and_answers_real_requests(tmp_path):
    database = tmp_path / "stdio.db"
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite+pysqlite:///{database.as_posix()}"
    src = str(ROOT / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")

    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "stdio-test"}},
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "redfall_campaign_create",
                "arguments": {"repo": "acme/stdio", "scope": {"repos": ["acme/stdio"]}},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "redfall_campaign_list", "arguments": {}},
        },
    ]
    completed = subprocess.run(
        [sys.executable, "-m", "redfall.interop.mcp_stdio"],
        input="\n".join(json.dumps(request) for request in requests) + "\n",
        text=True,
        capture_output=True,
        cwd=ROOT,
        env=env,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    lines = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    assert len(lines) == 4, completed.stdout
    assert lines[0]["result"]["protocolVersion"] == "2025-06-18"
    assert any(tool["name"] == "redfall_campaign_create" for tool in lines[1]["result"]["tools"])
    created = json.loads(lines[2]["result"]["content"][0]["text"])
    assert created["repo"] == "acme/stdio"
    listed = json.loads(lines[3]["result"]["content"][0]["text"])
    assert [campaign["id"] for campaign in listed["campaigns"]] == [created["id"]]
