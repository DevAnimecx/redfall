"""The `redfall tenant` command surface, driven end to end.

These run the real Click commands against a real SQLite database, because the
property worth checking is that the CLI and the library agree. A command that
printed success while writing nothing, or that created a rule the engine then
ignored, would pass a unit test on either half alone.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    """A runner with the database pointed at a throwaway file.

    The CLI builds its engine from `load_config()`, which reads `DATABASE_URL`,
    so setting it here routes every command at the temporary database without
    changing a production default.
    """
    db_path = tmp_path / "cli.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    from redfall.store import db

    db.init_engine(f"sqlite:///{db_path}")
    return CliRunner()


def _run(runner, *args: str):
    from redfall.cli import main

    result = runner.invoke(main, ["tenant", *args], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    return result


def _json(result) -> dict:
    """The JSON object a command printed, ignoring any trailing status line."""
    text = result.output.strip()
    start = text.index("{")
    return json.loads(text[start:])


def test_create_then_list_shows_the_tenant(runner):
    created = _json(_run(runner, "create", "acme", "--name", "Acme Corp"))
    assert created["slug"] == "acme"
    asked = _json(_run(runner, "list"))
    assert [t["slug"] for t in asked["tenants"]] == ["acme"]


def test_create_refuses_a_duplicate_slug_with_a_nonzero_exit(runner):
    from redfall.cli import main

    _run(runner, "create", "acme")
    result = runner.invoke(main, ["tenant", "create", "acme"], catch_exceptions=False)
    assert result.exit_code != 0
    assert "already exists" in result.output


def test_a_reserved_slug_is_refused_by_the_command(runner):
    from redfall.cli import main

    result = runner.invoke(main, ["tenant", "create", "self"], catch_exceptions=False)
    assert result.exit_code != 0
    assert "reserved" in result.output


def test_roles_prints_the_whole_table(runner):
    payload = _json(_run(runner, "roles"))
    names = {entry["role"] for entry in payload["roles"]}
    assert names == {"viewer", "analyst", "engineer", "owner", "auditor"}
    owner = next(e for e in payload["roles"] if e["role"] == "owner")
    assert "tenant:admin" in owner["permissions"]


def test_add_member_then_list_shows_the_role_and_its_permissions(runner):
    _run(runner, "create", "acme")
    _run(runner, "add-member", "acme", "Dev@Example.com", "--role", "engineer")
    payload = _json(_run(runner, "members", "acme"))
    member = payload["members"][0]
    assert member["email"] == "dev@example.com"
    assert member["role"] == "engineer"
    assert "campaign:run" in member["permissions"]


def test_set_role_changes_what_a_member_may_do(runner):
    _run(runner, "create", "acme")
    _run(runner, "add-member", "acme", "a@b.com", "--role", "viewer")
    changed = _json(_run(runner, "set-role", "acme", "a@b.com", "auditor"))
    assert changed["role"] == "auditor"
    payload = _json(_run(runner, "members", "acme"))
    assert "audit:export" in payload["members"][0]["permissions"]


def test_set_role_refuses_an_unknown_role(runner):
    from redfall.cli import main

    _run(runner, "create", "acme")
    _run(runner, "add-member", "acme", "a@b.com")
    result = runner.invoke(
        main, ["tenant", "set-role", "acme", "a@b.com", "root"], catch_exceptions=False
    )
    assert result.exit_code != 0
    assert "unknown role" in result.output


def test_suspend_then_resume_changes_the_reported_status(runner):
    _run(runner, "create", "acme")
    suspended = _json(_run(runner, "suspend", "acme", "--reason", "review"))
    assert suspended["status"] == "suspended"
    assert suspended["suspended_at"] is not None
    resumed = _json(_run(runner, "resume", "acme"))
    assert resumed["status"] == "active"
    assert resumed["suspended_at"] is None


def test_policy_load_writes_rules_and_policy_list_reads_them(runner, tmp_path):
    _run(runner, "create", "acme")
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "effect": "deny",
                        "action": "redfall_fix_apply*",
                        "name": "no-auto-fix",
                        "priority": 3,
                    },
                    {"effect": "allow", "action": "redfall_scan_*", "name": "scan-ok"},
                ]
            }
        ),
        encoding="utf-8",
    )
    loaded = _json(_run(runner, "policy-load", "acme", str(policy)))
    assert loaded["loaded"] == 2
    listed = _json(_run(runner, "policy-list", "acme"))
    names = {r["name"] for r in listed["rules"]}
    assert names == {"no-auto-fix", "scan-ok"}
    # Highest priority first.
    assert listed["rules"][0]["name"] == "no-auto-fix"


def test_a_bad_policy_file_leaves_the_existing_policy_intact(runner, tmp_path):
    from redfall.cli import main

    _run(runner, "create", "acme")
    good = tmp_path / "good.json"
    good.write_text(
        json.dumps({"rules": [{"effect": "deny", "action": "keep-me", "name": "kept"}]}),
        encoding="utf-8",
    )
    _run(runner, "policy-load", "acme", str(good))

    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "rules": [
                    {"effect": "deny", "action": "fine", "name": "fine"},
                    {"effect": "deny", "action": "x", "condition": {"f": {"bogus": 1}}},
                ]
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        main, ["tenant", "policy-load", "acme", str(bad), "--replace"], catch_exceptions=False
    )
    assert result.exit_code != 0
    # The replace must not have happened: a failed load changes nothing.
    listed = _json(_run(runner, "policy-list", "acme"))
    assert [r["name"] for r in listed["rules"]] == ["kept"]


def test_policy_check_explains_a_denial(runner, tmp_path):
    _run(runner, "create", "acme")
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "effect": "deny",
                        "action": "redfall_scan_run",
                        "name": "classified-frozen",
                        "condition": {"arg.target": {"prefix": "/srv/classified"}},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    _run(runner, "policy-load", "acme", str(policy))

    blocked = _json(
        _run(runner, "policy-check", "acme", "redfall_scan_run", "--context-json", '{"target": "/srv/classified/app"}')
    )
    assert blocked["decision"]["allowed"] is False
    assert blocked["decision"]["rule_name"] == "classified-frozen"

    allowed = _json(
        _run(runner, "policy-check", "acme", "redfall_scan_run", "--context-json", '{"target": "/srv/public"}')
    )
    assert allowed["decision"]["allowed"] is True


def test_policy_check_rejects_malformed_context(runner):
    from redfall.cli import main

    _run(runner, "create", "acme")
    result = runner.invoke(
        main,
        ["tenant", "policy-check", "acme", "x", "--context-json", "not json"],
        catch_exceptions=False,
    )
    assert result.exit_code != 0
    assert "not valid JSON" in result.output


def test_adopt_reports_nothing_to_do_on_a_fresh_database(runner):
    payload = _json(_run(runner, "adopt"))
    assert payload["note"] == "nothing predates tenancy"


def test_adopt_check_reports_counts_without_claiming_them(runner):
    from redfall.enterprise.tenancy import orphan_counts
    from redfall.store import db
    from redfall.store.models import Campaign

    with db.session_scope() as session:
        session.add(Campaign(id="cmp-old", repo="/srv/app", tenant_id=""))
    payload = _json(_run(runner, "adopt", "--check"))
    assert payload["unclaimed"]["campaigns"] == 1

    with db.session_scope() as session:
        assert orphan_counts(session)["campaigns"] == 1  # still unmoved
    _run(runner, "adopt")
    with db.session_scope() as session:
        assert orphan_counts(session)["campaigns"] == 0


def test_audit_export_writes_records_and_reports_a_resume_point(runner, tmp_path):
    from datetime import datetime, timezone

    from redfall.enterprise.tenancy import activate
    from redfall.store import db
    from redfall.store.models import AgentToken, InteropAudit
    from redfall.interop.auth import hash_token

    _run(runner, "create", "acme")
    with db.session_scope() as session:
        tenant = activate(session, slug="acme")
        session.add(
            AgentToken(
                id="tok-1",
                name="ci",
                tenant_id=tenant.id,
                token_sha256=hash_token("rfl_ci"),
                scopes=["read"],
            )
        )
        session.add(
            InteropAudit(
                id="aud-1",
                protocol="http",
                agent="ci",
                token_id="tok-1",
                tool="redfall_scan_run",
                ok=True,
                created_at=datetime.now(timezone.utc),
            )
        )

    out = tmp_path / "audit.jsonl"
    result = _run(runner, "audit-export", "acme", "--out", str(out))
    assert out.exists()
    assert json.loads(out.read_text(encoding="utf-8").splitlines()[0])["tool"] == "redfall_scan_run"

    payload = _json(result)
    assert payload["export"]["record_count"] == 1
    assert payload["resume_with_since"] is not None


def test_audit_export_redacts_a_credential_by_default(runner, tmp_path):
    from datetime import datetime, timezone

    from redfall.enterprise.tenancy import activate
    from redfall.store import db
    from redfall.store.models import AgentToken, InteropAudit
    from redfall.interop.auth import hash_token

    _run(runner, "create", "acme")
    with db.session_scope() as session:
        tenant = activate(session, slug="acme")
        session.add(
            AgentToken(
                id="tok-1",
                name="ci",
                tenant_id=tenant.id,
                token_sha256=hash_token("rfl_ci"),
                scopes=["read"],
            )
        )
        session.add(
            InteropAudit(
                id="aud-1",
                protocol="http",
                agent="ci",
                token_id="tok-1",
                tool="redfall_scan_run",
                ok=False,
                error="rejected token rfl_supersecret999",
                created_at=datetime.now(timezone.utc),
            )
        )

    out = tmp_path / "audit.jsonl"
    _run(runner, "audit-export", "acme", "--out", str(out))
    text = out.read_text(encoding="utf-8")
    assert "rfl_supersecret999" not in text
    assert "[redacted]" in text
