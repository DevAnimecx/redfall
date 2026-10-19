"""The campaign CLI drives the same durable state as the MCP tools."""

from __future__ import annotations

import json

from click.testing import CliRunner

from redfall.cli import main


def invoke_json(runner: CliRunner, args: list[str]):
    result = runner.invoke(main, args)
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_cli_campaign_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'cli.db'}")
    runner = CliRunner()

    created = invoke_json(runner, ["campaign", "create", "acme/api"])
    campaign_id = created["id"]
    assert created["status"] == "draft"

    scoped = invoke_json(
        runner,
        ["campaign", "scope", campaign_id, "--scope-json", json.dumps({"repos": ["acme/api"]})],
    )
    assert scoped["status"] == "scoped"

    started = invoke_json(runner, ["campaign", "start", campaign_id])
    assert started["status"] == "indexing"

    task = invoke_json(
        runner,
        ["campaign", "task", "add", campaign_id, "index", "--payload-json", json.dumps({"path": "."})],
    )
    claimed = invoke_json(runner, ["campaign", "task", "claim", campaign_id, "--worker", "cli-worker"])
    assert claimed["task"]["id"] == task["id"]
    completed = invoke_json(
        runner,
        [
            "campaign",
            "task",
            "complete",
            task["id"],
            "--worker",
            "cli-worker",
            "--result-json",
            json.dumps({"files": 2}),
        ],
    )
    assert completed["status"] == "completed"

    evidence = invoke_json(
        runner,
        [
            "campaign",
            "evidence",
            "add",
            campaign_id,
            "--grade",
            "E3",
            "--kind",
            "execution",
            "--claim",
            "The replay reaches the marker",
            "--payload-json",
            json.dumps({"execution_id": "exe-cli", "observable": "marker"}),
            "--reproduce-command",
            "redfall reproduce exe-cli",
            "--environment-digest",
            "sha256:cli-image",
        ],
    )
    assert evidence["reportable"] is True

    verified = invoke_json(runner, ["campaign", "evidence", "verify", campaign_id])
    assert verified["ok"] is True

    status = invoke_json(runner, ["campaign", "status", campaign_id])
    assert status["campaign"]["id"] == campaign_id
    assert status["tasks"]["by_status"]["completed"] == 1
    assert status["evidence"]["reportable"] == 1
    assert status["chain"]["ok"] is True

    recon = invoke_json(runner, ["campaign", "transition", campaign_id, "recon"])
    assert recon["status"] == "recon"
    reported = invoke_json(runner, ["campaign", "report", campaign_id])
    assert reported["status"] == "reported"
