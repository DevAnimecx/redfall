"""CLI commands added in phase 2 execute the same graph and runner code."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from redfall.cli import main

ROOT = Path(__file__).resolve().parents[1]
VULNBANK = ROOT / "range" / "vulnbank"


def invoke_json(runner: CliRunner, args: list[str]):
    result = runner.invoke(main, args)
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_graph_commands_build_and_query_a_snapshot(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'graph-cli.db'}")
    monkeypatch.setenv("REDFALL_ALLOWED_ROOTS", str(VULNBANK))
    runner = CliRunner()

    indexed = invoke_json(runner, ["graph", "index", str(VULNBANK)])
    snapshot_id = indexed["snapshot"]["id"]
    assert indexed["snapshot"]["status"] == "complete"
    assert indexed["stats"]["nodes_by_kind"]["Route"] > 0

    stats = invoke_json(runner, ["graph", "stats", "--snapshot-id", snapshot_id])
    assert stats["coverage"]["files"] == indexed["snapshot"]["files"]

    routes = invoke_json(
        runner,
        [
            "graph",
            "routes",
            "--snapshot-id",
            snapshot_id,
            "--path-contains",
            "/api/auth",
            "--limit",
            "5",
        ],
    )
    assert routes["returned"] >= 1
    assert all("/api/auth" in item["properties"]["path"] for item in routes["routes"])

    sources = invoke_json(
        runner, ["graph", "sources", "--snapshot-id", snapshot_id, "--role", "source"]
    )
    assert sources["sources"]
    assert "sinks" not in sources

    inventory = invoke_json(runner, ["graph", "inventory", "--snapshot-id", snapshot_id])
    assert inventory["routes"]

    node = invoke_json(
        runner, ["graph", "node", routes["routes"][0]["id"], "--snapshot-id", snapshot_id]
    )
    assert node["node"]["kind"] == "Route"


def test_campaign_run_cli_executes_graph_task(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'runner-cli.db'}")
    runner = CliRunner()

    created = invoke_json(runner, ["campaign", "create", str(VULNBANK), "--budget-usd", "5"])
    campaign_id = created["id"]
    invoke_json(
        runner,
        ["campaign", "scope", campaign_id, "--scope-json", json.dumps({"repos": [str(VULNBANK)]})],
    )
    invoke_json(runner, ["campaign", "start", campaign_id])
    invoke_json(
        runner,
        [
            "campaign",
            "task",
            "add",
            campaign_id,
            "graph.index",
            "--payload-json",
            json.dumps({"target": str(VULNBANK)}),
        ],
    )
    run = invoke_json(
        runner, ["campaign", "run", campaign_id, "--max-tasks", "2", "--worker", "cli-test"]
    )
    assert run["completed"] == 1
    assert run["results"][0]["kind"] == "graph.index"

    latest = invoke_json(runner, ["graph", "latest", "--campaign-id", campaign_id])
    assert latest["snapshot"]["status"] == "complete"

    reservations = invoke_json(runner, ["campaign", "reservations", campaign_id])
    assert reservations["reservations"] == []

    refused = runner.invoke(main, ["campaign", "export", campaign_id])
    assert refused.exit_code == 1
    assert "refusing to report" in refused.output


def test_adapters_list_does_not_claim_unimplemented_transports(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'adapters.db'}")
    data = invoke_json(CliRunner(), ["adapters", "list"])
    by_name = {item["name"]: item for item in data["adapters"]}
    assert by_name["mcp-stdio"]["status"] == "supported"
    assert by_name["a2a"]["status"] == "planned"
    assert by_name["http-openapi"]["status"] == "planned"
    assert "not implemented" in by_name["a2a"]["certification"]


def test_mcp_certify_persists_measured_contract_result(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'cert.db'}")
    runner = CliRunner()
    certified = invoke_json(runner, ["mcp", "certify", "--timeout", "60"])
    assert certified["certified"] is True
    assert certified["server_name"] == "redfall"
    assert certified["tool_count"] >= 42

    rows = invoke_json(runner, ["adapters", "certifications"])
    assert len(rows["certifications"]) == 1
    row = rows["certifications"][0]
    assert row["adapter"] == "mcp-stdio"
    assert row["certified"] is True
    assert all(check["passed"] for check in row["checks"])
