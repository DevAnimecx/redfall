"""Phase 3 CLI: token lifecycle, webhooks, audit and measured certification."""

from __future__ import annotations

import json

from click.testing import CliRunner

from redfall.cli import main


def invoke_json(runner: CliRunner, args: list[str]):
    result = runner.invoke(main, args)
    assert result.exit_code == 0, result.output + result.stderr
    value, _end = json.JSONDecoder().raw_decode(result.output.lstrip())
    return value


def test_token_create_list_and_revoke(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'tokens.db'}")
    runner = CliRunner()

    created = invoke_json(
        runner,
        [
            "interop",
            "token",
            "create",
            "--name",
            "ci-reader",
            "--scopes",
            "read,execute",
            "--quota-per-hour",
            "5",
        ],
    )
    assert created["name"] == "ci-reader"
    assert created["scopes"] == ["execute", "read"]
    assert created["quota_per_hour"] == 5
    assert created["token"].startswith("rfl_")
    assert created["revoked"] is False

    listed = invoke_json(runner, ["interop", "token", "list"])
    assert len(listed["tokens"]) == 1
    assert "token" not in listed["tokens"][0]
    assert listed["tokens"][0]["id"] == created["id"]

    revoked = invoke_json(
        runner, ["interop", "token", "revoke", "--id", created["id"]]
    )
    assert revoked["revoked"] is True
    listed = invoke_json(runner, ["interop", "token", "list"])
    assert listed["tokens"][0]["revoked"] is True


def test_token_creation_rejects_unknown_scopes(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'bad.db'}")
    result = CliRunner().invoke(
        main,
        ["interop", "token", "create", "--name", "bad", "--scopes", "root"],
    )
    assert result.exit_code == 1
    assert "unknown scope" in result.stderr


def test_webhook_create_list_and_remove(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'hooks.db'}")
    runner = CliRunner()

    added = invoke_json(
        runner,
        [
            "interop",
            "webhook",
            "add",
            "--url",
            "https://example.com/redfall",
            "--events",
            "campaign.*,task.*",
            "--secret",
            "test-secret",
        ],
    )
    assert added["secret"] == "test-secret"
    assert added["events"] == ["campaign.*", "task.*"]
    assert added["has_secret"] is True

    listed = invoke_json(runner, ["interop", "webhook", "list"])
    assert len(listed["webhooks"]) == 1
    assert "secret" not in listed["webhooks"][0]

    removed = invoke_json(
        runner, ["interop", "webhook", "remove", "--id", added["id"]]
    )
    assert removed["removed"] == added["id"]
    assert invoke_json(runner, ["interop", "webhook", "list"]) == {"webhooks": []}


def test_webhook_loopback_requires_the_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'hooks.db'}")
    runner = CliRunner()
    denied = runner.invoke(
        main,
        [
            "interop",
            "webhook",
            "add",
            "--url",
            "http://127.0.0.1:9999/hook",
            "--event",
            "campaign.*",
        ],
    )
    assert denied.exit_code == 1
    assert "loopback" in denied.stderr
    allowed = invoke_json(
        runner,
        [
            "interop",
            "webhook",
            "add",
            "--url",
            "http://127.0.0.1:9999/hook",
            "--event",
            "campaign.*",
            "--allow-loopback",
        ],
    )
    assert allowed["url"] == "http://127.0.0.1:9999/hook"


def test_audit_and_deliver_commands(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'audit.db'}")
    runner = CliRunner()
    assert invoke_json(runner, ["interop", "audit"]) == {"calls": []}
    delivery = invoke_json(runner, ["interop", "webhook", "deliver"])
    assert delivery["enqueued"] == 0
    assert delivery["delivered"] == 0


def test_http_certification_is_persisted(tmp_path, monkeypatch):
    database_url = f"sqlite+pysqlite:///{tmp_path / 'certify.db'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    runner = CliRunner()

    report = invoke_json(
        runner,
        [
            "interop",
            "certify",
            "--protocol",
            "http",
            "--database-url",
            database_url,
            "--timeout",
            "60",
        ],
    )
    assert report["adapter"] == "http-openapi"
    assert report["certified"] is True
    assert report["error"] == ""
    assert all(check["passed"] for check in report["checks"])

    certifications = invoke_json(runner, ["adapters", "certifications"])
    rows = certifications["certifications"]
    assert len(rows) == 1
    assert rows[0]["adapter"] == "http-openapi"
    assert rows[0]["certified"] is True


def test_adapters_list_marks_gateways_supported():
    listed = invoke_json(CliRunner(), ["adapters", "list"])
    by_name = {item["name"]: item for item in listed["adapters"]}
    assert by_name["http-openapi"]["status"] == "supported"
    assert by_name["a2a"]["status"] == "supported"
    assert "redfall interop certify" in by_name["a2a"]["certification"]


def test_interop_serve_help_is_available():
    result = CliRunner().invoke(main, ["interop", "serve", "--help"])
    assert result.exit_code == 0
    assert "OpenAPI" in result.output
