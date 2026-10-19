"""Phase 2 tool surface: graph, scan/finding access, reports and contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from redfall.campaign.service import CampaignService
from redfall.evidence.ledger import EvidenceLedger
from redfall.interop.contract import run_mcp_stdio_contract
from redfall.interop.mcp_stdio import MCPServer
from redfall.interop.tools import ToolRegistry
from redfall.store.models import Base, Finding, Scan

ROOT = Path(__file__).resolve().parents[1]
VULNBANK = ROOT / "range" / "vulnbank"


@pytest.fixture()
def registry(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'phase2.db'}", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    yield ToolRegistry(Session)
    engine.dispose()


def call(server: MCPServer, request_id: int, name: str, arguments: dict | None = None):
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )
    return response["result"]


def payload(server: MCPServer, request_id: int, name: str, arguments: dict | None = None):
    result = call(server, request_id, name, arguments)
    assert result["isError"] is False, result
    return json.loads(result["content"][0]["text"])


def active_campaign(server: MCPServer) -> str:
    campaign = payload(
        server,
        1,
        "redfall_campaign_create",
        {"repo": str(VULNBANK), "objective": "discovery", "budget_usd": 5},
    )
    campaign_id = campaign["id"]
    payload(
        server,
        2,
        "redfall_campaign_scope",
        {"campaign_id": campaign_id, "scope": {"repos": [str(VULNBANK)]}},
    )
    payload(server, 3, "redfall_campaign_start", {"campaign_id": campaign_id})
    return campaign_id


def test_phase2_tools_are_advertised(registry):
    names = {tool["name"] for tool in registry.specs()}
    assert {
        "redfall_campaign_run",
        "redfall_graph_index",
        "redfall_graph_latest",
        "redfall_graph_stats",
        "redfall_graph_search",
        "redfall_graph_node",
        "redfall_graph_neighbors",
        "redfall_graph_paths",
        "redfall_graph_routes",
        "redfall_graph_diff",
        "redfall_scan_run",
        "redfall_findings",
        "redfall_finding",
        "redfall_reproduce",
        "redfall_report",
        "redfall_policy_check",
        "redfall_adapter_certifications",
    } <= names
    assert len(names) >= 42


def test_graph_tools_persist_and_query_a_real_snapshot(registry):
    server = MCPServer(registry)
    campaign_id = active_campaign(server)
    indexed = payload(
        server,
        10,
        "redfall_graph_index",
        {"campaign_id": campaign_id, "target": str(VULNBANK)},
    )
    snapshot_id = indexed["snapshot"]["id"]
    assert indexed["snapshot"]["status"] == "complete"
    assert indexed["snapshot"]["nodes"] > 0
    assert indexed["snapshot"]["routes"] > 0

    latest = payload(server, 11, "redfall_graph_latest", {"campaign_id": campaign_id})
    assert latest["snapshot"]["id"] == snapshot_id

    stats = payload(server, 12, "redfall_graph_stats", {"snapshot_id": snapshot_id})
    assert stats["coverage"]["files"] == indexed["snapshot"]["files"]
    assert stats["nodes_by_kind"]["Route"] == indexed["snapshot"]["routes"]

    routes = payload(
        server,
        13,
        "redfall_graph_routes",
        {"snapshot_id": snapshot_id, "path_contains": "/api/auth", "limit": 5},
    )
    assert routes["returned"] >= 1
    assert all("/api/auth" in item["properties"]["path"] for item in routes["routes"])
    route_id = routes["routes"][0]["id"]

    node = payload(server, 14, "redfall_graph_node", {"snapshot_id": snapshot_id, "node": route_id})
    assert node["node"]["id"] == route_id
    assert isinstance(node["outgoing"], list)

    search = payload(
        server,
        15,
        "redfall_graph_search",
        {"snapshot_id": snapshot_id, "query": "login", "kind": "Route"},
    )
    assert search["returned"] >= 1

    sources = payload(server, 16, "redfall_graph_sources", {"snapshot_id": snapshot_id})
    assert sources["sources"]
    sinks = payload(server, 17, "redfall_graph_sources", {"snapshot_id": snapshot_id, "role": "sink"})
    assert sinks["sinks"]

    inventory = payload(server, 18, "redfall_graph_inventory", {"snapshot_id": snapshot_id})
    assert inventory["routes"]


def test_findings_tool_does_not_borrow_another_campaigns_evidence(registry):
    with registry._session_factory() as session:
        service = CampaignService(session)
        evidence_campaign = service.create(str(VULNBANK), budget_usd=1)
        query_campaign = service.create(str(VULNBANK), budget_usd=1)
        scan = Scan(
            id="scan-mcp-findings",
            repo=str(VULNBANK),
            commit="abc123",
            status="completed",
            findings_total=1,
        )
        finding = Finding(
            id="finding-mcp-scope",
            scan_id=scan.id,
            branch_id="branch-1",
            category="sql_injection",
            severity="high",
            title="Scoped evidence check",
            location_file="src/routes/users.ts",
            location_line=12,
            poc={"method": "GET", "path": "/api/users/1"},
            evidence="SQLITE_ERROR",
            status="open",
        )
        query_campaign.scan_id = scan.id
        session.add_all([scan, finding])
        session.flush()
        EvidenceLedger(session).append(
            evidence_campaign.id,
            grade="E3",
            kind="execution",
            claim="Reproduced in another campaign",
            payload={"execution_id": "exe-scope", "observable": "SQLITE_ERROR"},
            finding_id=finding.id,
            reproduce_command="redfall reproduce finding-mcp-scope",
            environment_digest="sha256:scope-image",
        )
        session.commit()
        query_campaign_id = query_campaign.id

    server = MCPServer(registry)
    result = payload(
        server,
        19,
        "redfall_findings",
        {"campaign_id": query_campaign_id},
    )
    assert result["returned"] == 1
    assert result["findings"][0]["evidence_ids"] == []
    assert result["findings"][0]["verified_by_evidence"] is False


def test_policy_tool_denies_paths_without_allowed_roots(registry, monkeypatch):
    monkeypatch.delenv("REDFALL_ALLOWED_ROOTS", raising=False)
    server = MCPServer(registry)
    result = payload(
        server,
        20,
        "redfall_policy_check",
        {"action": "index", "target": str(Path.home())},
    )
    assert result["allowed"] is False
    assert result["roots"] == []


def test_report_tool_refuses_an_empty_campaign(registry):
    server = MCPServer(registry)
    campaign_id = active_campaign(server)
    result = call(server, 30, "redfall_report", {"campaign_id": campaign_id})
    assert result["isError"] is True
    assert "no E3/E4 evidence" in result["content"][0]["text"]


def test_campaign_run_tool_executes_graph_task(registry):
    server = MCPServer(registry)
    campaign_id = active_campaign(server)
    payload(
        server,
        40,
        "redfall_task_enqueue",
        {
            "campaign_id": campaign_id,
            "kind": "graph.index",
            "payload": {"target": str(VULNBANK)},
        },
    )
    run = payload(
        server,
        41,
        "redfall_campaign_run",
        {"campaign_id": campaign_id, "max_tasks": 2, "worker": "mcp-test"},
    )
    assert run["completed"] == 1
    assert run["results"][0]["status"] == "completed"
    latest = payload(server, 42, "redfall_graph_latest", {"campaign_id": campaign_id})
    assert latest["snapshot"]["status"] == "complete"


def test_mcp_stdio_adapter_contract_certifies_the_shipped_server():
    report = run_mcp_stdio_contract(timeout=60)
    assert report.certified is True, report.to_wire()
    assert report.server_name == "redfall"
    assert report.tool_count >= 42
    assert {check.name for check in report.checks} >= {
        "initialize",
        "tools-list",
        "health",
        "campaign-create",
        "campaign-status",
        "task-enqueue",
        "graph-index",
        "graph-latest",
        "policy-denial",
        "unknown-tool",
    }
    assert all(check.passed for check in report.checks)
