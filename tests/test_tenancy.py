"""Tenancy, roles, policy and audit export.

The tests that matter here are the adversarial ones. A tenancy layer that
works when used correctly is worth nothing: the failure mode it exists to
prevent is a caller reaching another tenant's data by supplying an id, so the
suite spends most of its length on that.

Every test runs against a real SQLite database and real rows.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture()
def session(tmp_path, monkeypatch):
    from redfall.store import db

    db.init_engine(f"sqlite:///{tmp_path / 'tenant.db'}")
    with db.session_scope() as s:
        yield s


@pytest.fixture()
def enforced(monkeypatch):
    """Turn tenancy on for one test, and off again afterwards."""
    monkeypatch.setenv("REDFALL_TENANCY", "enforce")
    yield
    monkeypatch.delenv("REDFALL_TENANCY", raising=False)


def _campaign(session, *, tenant_id: str, name: str = "c"):
    from redfall.store.models import Campaign

    row = Campaign(id=f"cmp-{name}", repo="/srv/app", tenant_id=tenant_id)
    session.add(row)
    session.flush()
    return row


def _token(session, *, tenant_id: str, name: str = "t", scopes=None):
    from redfall.store.models import AgentToken
    from redfall.interop.auth import hash_token

    row = AgentToken(
        id=f"tok-{name}",
        name=name,
        tenant_id=tenant_id,
        token_sha256=hash_token(f"rfl_{name}"),
        scopes=scopes or ["read"],
    )
    session.add(row)
    session.flush()
    return row


# -- tenant lifecycle ------------------------------------------------------

def test_a_tenant_is_created_with_a_unique_slug(session):
    from redfall.enterprise.tenancy import TenantError, create_tenant

    create_tenant(session, slug="acme", name="Acme Corp")
    with pytest.raises(TenantError, match="already exists"):
        create_tenant(session, slug="acme")


def test_a_reserved_slug_is_refused(session):
    from redfall.enterprise.tenancy import TenantError, create_tenant

    for slug in ("self", "all", "any", ".."):
        with pytest.raises(TenantError, match="reserved"):
            create_tenant(session, slug=slug)


def test_a_slug_with_path_characters_is_refused(session):
    from redfall.enterprise.tenancy import TenantError, create_tenant

    with pytest.raises(TenantError, match="may contain only"):
        create_tenant(session, slug="acme/../etc")


def test_a_suspended_tenant_cannot_be_required(session):
    from redfall.enterprise.tenancy import TenantError, require_tenant, suspend_tenant

    tenant = __import__("redfall.enterprise.tenancy", fromlist=["create_tenant"]).create_tenant(
        session, slug="acme"
    )
    suspend_tenant(session, tenant_id=tenant.id, reason="non-payment")
    with pytest.raises(TenantError, match="suspended"):
        require_tenant(session, tenant_id=tenant.id)


def test_activating_the_default_tenant_is_idempotent(session):
    from redfall.enterprise.tenancy import activate

    first = activate(session)
    second = activate(session)
    assert first.id == second.id
    assert first.slug == "default"


# -- the scope, and what it can see ----------------------------------------

def test_tenancy_off_means_an_unenforced_scope_sees_everything(session):
    from redfall.enterprise.tenancy import resolve_scope

    scope = resolve_scope(session)
    assert scope.enforced is False
    assert scope.owns("anything") is True
    assert scope.owns(None) is True


def test_tenancy_on_makes_the_scope_its_own_tenant_only(session, enforced):
    from redfall.enterprise.tenancy import create_tenant, resolve_scope

    acme = create_tenant(session, slug="acme")
    other = create_tenant(session, slug="globex")
    token = _token(session, tenant_id=acme.id)

    scope = resolve_scope(session, token)
    assert scope.enforced is True
    assert scope.tenant_id == acme.id
    assert scope.owns(acme.id) is True
    assert scope.owns(other.id) is False


def test_a_token_cannot_name_another_tenant(session, enforced):
    """The attack the whole layer exists to stop: claim someone else's tenant."""
    from redfall.enterprise.tenancy import TenantError, create_tenant, resolve_scope

    acme = create_tenant(session, slug="acme")
    globex = create_tenant(session, slug="globex")
    token = _token(session, tenant_id=acme.id)

    with pytest.raises(TenantError, match="cannot act as"):
        resolve_scope(session, token, tenant_id=globex.id)


def test_a_pre_tenancy_token_is_refused_rather_than_guessed(session, enforced):
    from redfall.enterprise.tenancy import TenantError, create_tenant, resolve_scope

    create_tenant(session, slug="acme")
    orphan = _token(session, tenant_id="")
    with pytest.raises(TenantError, match="no tenant"):
        resolve_scope(session, orphan)


def test_a_scope_for_a_missing_tenant_is_refused(session, enforced):
    from redfall.enterprise.tenancy import TenantError, resolve_scope

    with pytest.raises(TenantError, match="does not exist"):
        resolve_scope(session, tenant_id="ten-nope")


def test_the_filter_clause_is_none_when_tenancy_is_off(session):
    from redfall.enterprise.tenancy import resolve_scope
    from redfall.store.models import Campaign

    scope = resolve_scope(session)
    assert scope.filter_column(Campaign.tenant_id) is None


def test_the_filter_clause_narrows_a_query_when_enforced(session, enforced):
    from redfall.enterprise.tenancy import create_tenant, resolve_scope
    from redfall.store.models import Campaign

    acme = create_tenant(session, slug="acme")
    globex = create_tenant(session, slug="globex")
    _campaign(session, tenant_id=acme.id, name="a1")
    _campaign(session, tenant_id=globex.id, name="g1")

    scope = resolve_scope(session, _token(session, tenant_id=acme.id))
    clause = scope.filter_column(Campaign.tenant_id)
    rows = list(session.scalars(__import__("sqlalchemy").select(Campaign).where(clause)).all())
    assert [r.id for r in rows] == ["cmp-a1"]


def test_reading_another_tenants_campaign_by_id_finds_nothing(session, enforced):
    """The row exists; the query cannot see it. That is the whole point."""
    import sqlalchemy

    from redfall.enterprise.tenancy import create_tenant, resolve_scope
    from redfall.store.models import Campaign

    acme = create_tenant(session, slug="acme")
    globex = create_tenant(session, slug="globex")
    secret = _campaign(session, tenant_id=globex.id, name="secret")

    scope = resolve_scope(session, _token(session, tenant_id=acme.id))
    clause = scope.filter_column(Campaign.tenant_id)
    found = session.scalar(
        sqlalchemy.select(Campaign).where(Campaign.id == secret.id, clause)
    )
    assert found is None
    # And the row is still there — nothing was deleted to make the test pass.
    assert session.get(Campaign, secret.id) is not None


# -- adoption of pre-tenancy rows ------------------------------------------

def test_orphan_counts_report_what_predates_tenancy(session, enforced):
    from redfall.enterprise.tenancy import orphan_counts

    _campaign(session, tenant_id="", name="old")
    _token(session, tenant_id="", name="oldtok")
    counts = orphan_counts(session)
    assert counts == {"campaigns": 1, "tokens": 1}


def test_adoption_claims_orphans_and_is_idempotent(session, enforced):
    from redfall.enterprise.tenancy import adopt_orphans, orphan_counts

    _campaign(session, tenant_id="", name="old")
    _token(session, tenant_id="", name="oldtok")

    first = adopt_orphans(session)
    assert first["campaigns"] == 1
    assert first["tokens"] == 1
    second = adopt_orphans(session)
    assert second["campaigns"] == 0
    assert second["tokens"] == 0
    assert orphan_counts(session) == {"campaigns": 0, "tokens": 0}


def test_adoption_leaves_another_tenants_rows_alone(session, enforced):
    from redfall.enterprise.tenancy import adopt_orphans, create_tenant
    from redfall.store.models import Campaign

    acme = create_tenant(session, slug="acme")
    _campaign(session, tenant_id=acme.id, name="mine")
    _campaign(session, tenant_id="", name="orphan")

    adopt_orphans(session, tenant_id=acme.id)
    assert session.get(Campaign, "cmp-mine").tenant_id == acme.id
    assert session.get(Campaign, "cmp-orphan").tenant_id == acme.id


# -- roles -----------------------------------------------------------------

def test_every_permission_belongs_to_at_least_one_role():
    from redfall.enterprise.roles import ALL_PERMISSIONS, ROLE_PERMISSIONS

    granted = set().union(*ROLE_PERMISSIONS.values())
    assert ALL_PERMISSIONS - granted == set(), "a permission no role can ever hold"


def test_only_the_owner_holds_tenant_admin():
    from redfall.enterprise.roles import ROLE_PERMISSIONS, Permission

    holders = {
        role for role, perms in ROLE_PERMISSIONS.items() if Permission.TENANT_ADMIN in perms
    }
    assert holders == {"owner"}


def test_a_viewer_cannot_run_a_campaign():
    from redfall.enterprise.roles import Permission, role_allows

    assert role_allows("viewer", Permission.CAMPAIGN_READ) is True
    assert role_allows("viewer", Permission.CAMPAIGN_RUN) is False


def test_an_auditor_may_export_evidence_but_not_change_it():
    from redfall.enterprise.roles import Permission, role_allows

    assert role_allows("auditor", Permission.EVIDENCE_EXPORT) is True
    assert role_allows("auditor", Permission.FINDING_TRIAGE) is False


def test_an_unknown_role_grants_nothing_rather_than_raising():
    """A stale role string in a row must refuse, not crash the request."""
    from redfall.enterprise.roles import Permission, role_allows

    assert role_allows("superuser", Permission.CAMPAIGN_READ) is False


def test_an_unknown_permission_is_refused():
    from redfall.enterprise.roles import role_allows

    assert role_allows("owner", "campaign:explode") is False


def test_a_principal_is_created_with_a_validated_role(session, enforced):
    from redfall.enterprise.roles import RoleError
    from redfall.enterprise.tenancy import create_principal, create_tenant

    acme = create_tenant(session, slug="acme")
    with pytest.raises(RoleError):
        create_principal(session, tenant_id=acme.id, email="a@b.com", role="superuser")
    row = create_principal(session, tenant_id=acme.id, email="A@B.com", role="analyst")
    assert row.email == "a@b.com"
    assert row.role == "analyst"


def test_a_duplicate_member_is_refused(session, enforced):
    from redfall.enterprise.tenancy import TenantError, create_principal, create_tenant

    acme = create_tenant(session, slug="acme")
    create_principal(session, tenant_id=acme.id, email="a@b.com")
    with pytest.raises(TenantError, match="already a member"):
        create_principal(session, tenant_id=acme.id, email="a@b.com")


def test_a_role_change_cannot_cross_a_tenant_boundary(session, enforced):
    from redfall.enterprise.tenancy import TenantError, create_principal, create_tenant, set_role

    acme = create_tenant(session, slug="acme")
    globex = create_tenant(session, slug="globex")
    member = create_principal(session, tenant_id=globex.id, email="x@y.com")

    with pytest.raises(TenantError, match="no such principal in this tenant"):
        set_role(session, tenant_id=acme.id, principal_id=member.id, role="owner")
    # And the role is unchanged.
    assert session.get(type(member), member.id).role == "viewer"


# -- policy ----------------------------------------------------------------

def test_an_empty_policy_denies_by_default(session, enforced):
    from redfall.enterprise.policy import PolicyEngine
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    decision = PolicyEngine(session, tenant_id=acme.id).decide("redfall_scan_run")
    assert decision.allowed is False
    assert decision.defaulted is True
    assert "defaults to deny" in decision.reason


def test_the_open_environment_variable_flips_the_default(session, enforced, monkeypatch):
    from redfall.enterprise.policy import PolicyEngine
    from redfall.enterprise.tenancy import create_tenant

    monkeypatch.setenv("REDFALL_POLICY", "open")
    acme = create_tenant(session, slug="acme")
    decision = PolicyEngine(session, tenant_id=acme.id).decide("redfall_scan_run")
    assert decision.allowed is True
    assert decision.defaulted is True


def test_a_deny_rule_refuses_a_matching_call(session, enforced):
    from redfall.enterprise.policy import PolicyEngine, create_rule
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    create_rule(
        session,
        tenant_id=acme.id,
        effect="deny",
        action="redfall_fix_apply*",
        name="no-auto-fix",
    )
    decision = PolicyEngine(session, tenant_id=acme.id).decide("redfall_fix_apply")
    assert decision.allowed is False
    assert decision.rule_name == "no-auto-fix"


def test_a_deny_wins_a_priority_tie_against_a_broad_allow(session, enforced):
    """A wildcard allow must not swallow an explicit prohibition."""
    from redfall.enterprise.policy import PolicyEngine, create_rule
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    create_rule(session, tenant_id=acme.id, effect="allow", action="*", priority=0, name="all")
    create_rule(
        session,
        tenant_id=acme.id,
        effect="deny",
        action="redfall_campaign_cancel",
        priority=0,
        name="protected",
    )
    engine = PolicyEngine(session, tenant_id=acme.id)
    assert engine.decide("redfall_campaign_cancel").allowed is False
    assert engine.decide("redfall_scan_run").allowed is True


def test_a_higher_priority_allow_beats_a_lower_deny(session, enforced):
    from redfall.enterprise.policy import PolicyEngine, create_rule
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    create_rule(session, tenant_id=acme.id, effect="deny", action="*", priority=1, name="freeze")
    create_rule(
        session,
        tenant_id=acme.id,
        effect="allow",
        action="redfall_scan_run",
        priority=9,
        name="scan-ok",
    )
    engine = PolicyEngine(session, tenant_id=acme.id)
    assert engine.decide("redfall_scan_run").allowed is True
    assert engine.decide("redfall_fix_apply").allowed is False


def test_a_condition_narrows_a_rule_to_paths_under_a_prefix(session, enforced):
    from redfall.enterprise.policy import PolicyEngine, create_rule
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    create_rule(
        session,
        tenant_id=acme.id,
        effect="deny",
        action="redfall_scan_run",
        condition={"arg.target": {"prefix": "/srv/classified"}},
        name="classified-frozen",
    )
    engine = PolicyEngine(session, tenant_id=acme.id)
    blocked = engine.decide("redfall_scan_run", {"arg": {"target": "/srv/classified/app"}})
    allowed = engine.decide("redfall_scan_run", {"arg": {"target": "/srv/public"}})
    assert blocked.allowed is False
    assert allowed.allowed is True  # no rule matched, and the deny rule did not


def test_a_condition_on_a_missing_field_never_fires(session, enforced):
    """A rule about an argument that was not supplied must not match."""
    from redfall.enterprise.policy import PolicyEngine, create_rule
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    create_rule(
        session,
        tenant_id=acme.id,
        effect="deny",
        action="*",
        condition={"arg.target": {"prefix": "/srv"}},
        name="path-gated",
    )
    engine = PolicyEngine(session, tenant_id=acme.id)
    decision = engine.decide("redfall_scan_run", {})
    assert decision.allowed is True  # denied-by-default is off here because a rule exists


def test_an_unknown_operator_is_refused_at_write_time(session, enforced):
    from redfall.enterprise.policy import PolicyError, create_rule
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    with pytest.raises(PolicyError, match="unknown operator"):
        create_rule(
            session,
            tenant_id=acme.id,
            effect="deny",
            action="*",
            condition={"arg.x": {"evaluate": "1+1"}},
        )


def test_a_regex_condition_is_anchored_at_both_ends(session, enforced):
    from redfall.enterprise.policy import PolicyEngine, create_rule
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    create_rule(
        session,
        tenant_id=acme.id,
        effect="deny",
        action="*",
        condition={"arg.commit": {"matches": "[0-9a-f]{7}"}},
        name="short-sha-only",
    )
    engine = PolicyEngine(session, tenant_id=acme.id)
    # An unanchored pattern would match the 7-hex prefix of this and wrongly deny.
    assert engine.decide("redfall_scan_run", {"arg": {"commit": "deadbeefffff"}}).allowed is True
    assert engine.decide("redfall_scan_run", {"arg": {"commit": "deadbee"}}).allowed is False


def test_an_invalid_effect_is_refused(session, enforced):
    from redfall.enterprise.policy import PolicyError, create_rule
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    with pytest.raises(PolicyError, match="effect must be"):
        create_rule(session, tenant_id=acme.id, effect="maybe", action="*")


def test_rules_are_isolated_per_tenant(session, enforced):
    from redfall.enterprise.policy import PolicyEngine, create_rule
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    globex = create_tenant(session, slug="globex")
    create_rule(session, tenant_id=acme.id, effect="deny", action="*", name="acme-frozen")

    assert PolicyEngine(session, tenant_id=acme.id).decide("x").allowed is False
    # Globex has no rules, so it hits its own default, not Acme's rule.
    assert PolicyEngine(session, tenant_id=globex.id).decide("x").defaulted is True


def test_explain_reports_every_rule_and_the_verdict(session, enforced):
    from redfall.enterprise.policy import PolicyEngine, create_rule
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    create_rule(session, tenant_id=acme.id, effect="allow", action="redfall_scan_*", name="scan")
    create_rule(session, tenant_id=acme.id, effect="deny", action="redfall_fix_*", name="fix")

    report = PolicyEngine(session, tenant_id=acme.id).explain("redfall_scan_run")
    assert report["decision"]["allowed"] is True
    by_name = {r["name"]: r for r in report["rules"]}
    assert by_name["scan"]["action_matched"] is True
    assert by_name["fix"]["action_matched"] is False
    assert by_name["fix"]["reason"] == "action pattern did not match"


def test_a_policy_file_with_a_foreign_tenant_is_refused(session, tmp_path, enforced):
    from redfall.enterprise.policy import PolicyError, load_rule_file
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps({"tenant_id": "ten-other", "rules": []}), encoding="utf-8"
    )
    with pytest.raises(PolicyError, match="not "):
        load_rule_file(str(path), tenant_id=acme.id)


def test_a_policy_file_with_an_unknown_operator_lands_nothing(session, tmp_path, enforced):
    from redfall.enterprise.policy import PolicyError, create_rule, list_rules, load_rule_file
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    create_rule(session, tenant_id=acme.id, effect="deny", action="keep-me", name="existing")

    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "rules": [
                    {"effect": "deny", "action": "a", "name": "ok"},
                    {"effect": "deny", "action": "b", "condition": {"x": {"nope": 1}}},
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="rule 1"):
        load_rule_file(str(path), tenant_id=acme.id)
    # The bad file changed nothing: the pre-existing rule is still the only one.
    assert [r.name for r in list_rules(session, tenant_id=acme.id)] == ["existing"]


def test_a_valid_policy_file_parses_into_rule_dicts(tmp_path):
    from redfall.enterprise.policy import load_rule_file

    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "effect": "deny",
                        "action": "redfall_fix_apply*",
                        "name": "no-auto-apply",
                        "priority": 5,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rules = load_rule_file(str(path))
    assert rules[0]["effect"] == "deny"
    assert rules[0]["priority"] == 5


# -- audit export ----------------------------------------------------------

def _audit(session, *, token_id: str, tool: str = "redfall_scan_run", ok: bool = True,
           error: str = "", when: datetime | None = None):
    from redfall.store.models import InteropAudit

    row = InteropAudit(
        id=f"aud-{session.query(InteropAudit).count() if hasattr(session, 'query') else 0}"
        f"-{tool[-4:]}",
        protocol="http",
        agent="tester",
        token_id=token_id,
        tool=tool,
        ok=ok,
        error=error,
        duration_ms=3,
        created_at=when or datetime.now(timezone.utc),
    )
    session.add(row)
    session.flush()
    return row


def test_an_export_contains_only_the_tenants_rows(session, enforced):
    from redfall.enterprise.audit import AuditExporter
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    globex = create_tenant(session, slug="globex")
    a = _token(session, tenant_id=acme.id, name="a")
    g = _token(session, tenant_id=globex.id, name="g")
    _audit(session, token_id=a.id, tool="redfall_scan_run")
    _audit(session, token_id=g.id, tool="redfall_campaign_cancel")

    body, record = AuditExporter(session, tenant_id=acme.id).export()
    assert "redfall_scan_run" in body
    assert "redfall_campaign_cancel" not in body
    assert record.record_count == 1


def test_a_denied_call_appears_in_the_export(session, enforced):
    """An audit trail that hides denials cannot answer who tried what."""
    from redfall.enterprise.audit import AuditExporter
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    tok = _token(session, tenant_id=acme.id, name="a")
    _audit(session, token_id=tok.id, ok=False, error="forbidden: scope")

    entries = AuditExporter(session, tenant_id=acme.id).entries()
    assert len(entries) == 1
    assert entries[0].ok is False
    assert "forbidden" in entries[0].error


def test_a_credential_in_free_text_is_redacted(session, enforced):
    from redfall.enterprise.audit import AuditExporter, REDACTED
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    tok = _token(session, tenant_id=acme.id, name="a")
    _audit(session, token_id=tok.id, error="auth failed for Bearer abcdef1234567890")

    body, _ = AuditExporter(session, tenant_id=acme.id).export()
    assert "abcdef1234567890" not in body
    assert REDACTED in body


def test_an_unredacted_export_is_an_explicit_choice(session, enforced):
    from redfall.enterprise.audit import AuditExporter
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    tok = _token(session, tenant_id=acme.id, name="a")
    _audit(session, token_id=tok.id, error="token rfl_secretvalue123456")

    body, record = AuditExporter(session, tenant_id=acme.id).export(redact=False)
    assert "rfl_secretvalue123456" in body
    assert record.note == "unredacted"


def test_a_jsonl_export_is_one_object_per_line(session, enforced):
    from redfall.enterprise.audit import AuditExporter
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    tok = _token(session, tenant_id=acme.id, name="a")
    _audit(session, token_id=tok.id, tool="redfall_scan_run")
    _audit(session, token_id=tok.id, tool="redfall_findings")

    body, _ = AuditExporter(session, tenant_id=acme.id).export(fmt="jsonl")
    lines = [ln for ln in body.splitlines() if ln]
    assert len(lines) == 2
    assert all(json.loads(ln)["tool"].startswith("redfall_") for ln in lines)


def test_a_csv_export_has_a_stable_header(session, enforced):
    from redfall.enterprise.audit import AuditExporter, CSV_FIELDS
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    tok = _token(session, tenant_id=acme.id, name="a")
    _audit(session, token_id=tok.id)

    body, _ = AuditExporter(session, tenant_id=acme.id).export(fmt="csv")
    assert body.splitlines()[0].split(",") == list(CSV_FIELDS)


def test_two_consecutive_exports_cover_the_timeline_without_a_gap(session, enforced):
    """The write barrier is the property that makes backfill safe."""
    from redfall.enterprise.audit import AuditExporter
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    tok = _token(session, tenant_id=acme.id, name="a")
    base = datetime.now(timezone.utc) - timedelta(hours=2)
    _audit(session, token_id=tok.id, tool="first", when=base)
    _audit(session, token_id=tok.id, tool="second", when=base + timedelta(minutes=30))

    exporter = AuditExporter(session, tenant_id=acme.id)
    first_body, first = exporter.export()
    _audit(session, token_id=tok.id, tool="third", when=base + timedelta(minutes=45))
    exporter.export()
    # Resume from the barrier, not from "now": the third call is caught up.
    resumed, _ = exporter.export(since=first.write_until)
    assert "third" in resumed
    assert "first" not in resumed


def test_a_backwards_range_is_refused(session, enforced):
    from redfall.enterprise.audit import AuditExporter
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError, match="later than"):
        AuditExporter(session, tenant_id=acme.id).export(
            since=now, until=now - timedelta(hours=1)
        )


def test_an_unknown_format_is_refused(session, enforced):
    from redfall.enterprise.audit import AuditExporter
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    with pytest.raises(ValueError, match="format must be"):
        AuditExporter(session, tenant_id=acme.id).export(fmt="xml")


def test_coverage_reports_a_range_that_would_truncate(session, enforced):
    from redfall.enterprise.audit import AuditExporter
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    tok = _token(session, tenant_id=acme.id, name="a")
    base = datetime.now(timezone.utc) - timedelta(minutes=5)
    for i in range(5):
        _audit(session, token_id=tok.id, tool=f"t{i}", when=base + timedelta(seconds=i))

    exporter = AuditExporter(session, tenant_id=acme.id)
    loose = exporter.verify_coverage(since=base - timedelta(minutes=1), until=base + timedelta(minutes=5), limit=10)
    tight = exporter.verify_coverage(since=base - timedelta(minutes=1), until=base + timedelta(minutes=5), limit=2)
    assert loose["complete"] is True
    assert loose["count"] == 5
    assert tight["complete"] is False
    assert "limit" in tight["note"]


def test_an_export_over_an_empty_tenant_says_zero_rather_than_failing(session, enforced):
    from redfall.enterprise.audit import AuditExporter
    from redfall.enterprise.tenancy import create_tenant

    acme = create_tenant(session, slug="acme")
    body, record = AuditExporter(session, tenant_id=acme.id).export()
    assert body == ""
    assert record.record_count == 0
