"""`redfall tenant` — the enterprise control plane from the command line.

Four groups under one command: tenants, members and roles, policy rules, and
audit export. Every subcommand writes through the same functions the HTTP
surface uses, so the CLI cannot drift from what the gateway enforces.

Two design notes an operator will notice:

* Commands report what they changed, not just that they succeeded. ``adopt``
  prints how many rows it claimed; ``policy load`` prints how many rules it
  wrote. A security tool that silently does nothing is worse than one that
  fails.
* Nothing deletes. A tenant is suspended, a rule is disabled, a member's role
  changes. The audit trail has to keep resolving its own references.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from .store.db import init_engine, session_scope


def _emit(payload: object, out: Path | None) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True)
    if out is not None:
        out.write_text(text + "\n", encoding="utf-8")
        click.echo(f"wrote {out}")
    else:
        click.echo(text)


@click.group()
def tenant() -> None:
    """Create tenants, manage members, set policy and export audit."""


# -- tenants ---------------------------------------------------------------

@tenant.command("create")
@click.argument("slug")
@click.option("--name", default="", help="Human name. Defaults to the slug.")
@click.option("--max-campaigns", type=int, default=None, help="Ceiling on campaigns. Omit for no ceiling.")
@click.option("--budget-usd", type=float, default=None, help="Spend ceiling in USD. Omit for no ceiling.")
def tenant_create(slug: str, name: str, max_campaigns: int | None, budget_usd: float | None) -> None:
    """Create an isolation boundary."""
    from .config import load_config
    from .enterprise.tenancy import TenantError, create_tenant

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            row = create_tenant(
                session,
                slug=slug,
                name=name,
                max_campaigns=max_campaigns,
                budget_usd=budget_usd,
            )
            _emit(row.to_wire(), None)
    except TenantError as err:
        raise click.ClickException(str(err)) from err


@tenant.command("list")
def tenant_list() -> None:
    """List every tenant and whether tenancy is enforced."""
    from .config import load_config
    from .enterprise.tenancy import list_tenants, tenancy_enabled

    config = load_config()
    init_engine(config.database_url)
    with session_scope() as session:
        rows = list_tenants(session)
        _emit(
            {
                "enforced": tenancy_enabled(),
                "tenants": [row.to_wire() for row in rows],
            },
            None,
        )


@tenant.command("suspend")
@click.argument("slug")
@click.option("--reason", default="", help="Recorded on the row and in the response.")
def tenant_suspend(slug: str, reason: str) -> None:
    """Stop a tenant's members from acting. Nothing is deleted."""
    from .config import load_config
    from .enterprise.tenancy import TenantError, suspend_tenant

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            row = suspend_tenant(session, slug=slug, reason=reason)
            _emit(row.to_wire(), None)
    except TenantError as err:
        raise click.ClickException(str(err)) from err


@tenant.command("resume")
@click.argument("slug")
def tenant_resume(slug: str) -> None:
    """Lift a suspension."""
    from .config import load_config
    from .enterprise.tenancy import TenantError, resume_tenant

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            _emit(resume_tenant(session, slug=slug).to_wire(), None)
    except TenantError as err:
        raise click.ClickException(str(err)) from err


@tenant.command("adopt")
@click.option("--slug", default="default", show_default=True, help="Tenant to claim pre-tenancy rows into.")
@click.option("--check", "check_only", is_flag=True, help="Report what predates tenancy without claiming it.")
def tenant_adopt(slug: str, check_only: bool) -> None:
    """Claim campaigns and tokens written before tenancy existed."""
    from .config import load_config
    from .enterprise.tenancy import TenantError, activate, adopt_orphans, orphan_counts

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            counts = orphan_counts(session)
            if check_only:
                _emit({"unclaimed": counts, "checked_only": True}, None)
                return
            if counts["campaigns"] == 0 and counts["tokens"] == 0:
                _emit({"adopted": {"campaigns": 0, "tokens": 0}, "note": "nothing predates tenancy"}, None)
                return
            target = activate(session, slug=slug)
            adopted = adopt_orphans(session, tenant_id=target.id)
            _emit({"adopted": adopted, "tenant": target.to_wire()}, None)
    except TenantError as err:
        raise click.ClickException(str(err)) from err


# -- members ---------------------------------------------------------------

@tenant.command("add-member")
@click.argument("slug")
@click.argument("email")
@click.option("--role", default="viewer", show_default=True, help="One of viewer, analyst, engineer, owner, auditor.")
@click.option("--display-name", default="", help="Defaults to the local part of the email.")
def tenant_add_member(slug: str, email: str, role: str, display_name: str) -> None:
    """Add a person to a tenant with a role."""
    from .config import load_config
    from .enterprise.roles import RoleError
    from .enterprise.tenancy import TenantError, create_principal, require_tenant

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            target = require_tenant(session, slug=slug)
            row = create_principal(
                session,
                tenant_id=target.id,
                email=email,
                role=role,
                display_name=display_name,
            )
            _emit(row.to_wire(), None)
    except (TenantError, RoleError) as err:
        raise click.ClickException(str(err)) from err


@tenant.command("members")
@click.argument("slug")
def tenant_members(slug: str) -> None:
    """List a tenant's members and their roles."""
    from .config import load_config
    from .enterprise.roles import permissions_for
    from .enterprise.tenancy import TenantError, list_principals, require_tenant

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            target = require_tenant(session, slug=slug)
            rows = list_principals(session, tenant_id=target.id)
            _emit(
                {
                    "tenant": target.to_wire(),
                    "members": [
                        {**row.to_wire(), "permissions": sorted(p.value for p in permissions_for(row.role))}
                        for row in rows
                    ],
                },
                None,
            )
    except TenantError as err:
        raise click.ClickException(str(err)) from err


@tenant.command("set-role")
@click.argument("slug")
@click.argument("email")
@click.argument("role")
def tenant_set_role(slug: str, email: str, role: str) -> None:
    """Change a member's role."""
    from .config import load_config
    from .enterprise.roles import RoleError
    from .enterprise.tenancy import TenantError, require_tenant, set_role

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            target = require_tenant(session, slug=slug)
            row = set_role(session, tenant_id=target.id, email=email, role=role)
            _emit(row.to_wire(), None)
    except (TenantError, RoleError) as err:
        raise click.ClickException(str(err)) from err


@tenant.command("roles")
def tenant_roles() -> None:
    """Print the role table: what each role may do."""
    from .enterprise.roles import describe_roles

    _emit({"roles": describe_roles()}, None)


# -- policy ----------------------------------------------------------------

@tenant.command("policy-list")
@click.argument("slug")
def tenant_policy_list(slug: str) -> None:
    """List a tenant's policy rules, highest priority first."""
    from .config import load_config
    from .enterprise.policy import list_rules
    from .enterprise.tenancy import TenantError, require_tenant

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            target = require_tenant(session, slug=slug)
            rows = list_rules(session, tenant_id=target.id)
            _emit({"tenant": target.slug, "rules": [row.to_wire() for row in rows]}, None)
    except TenantError as err:
        raise click.ClickException(str(err)) from err


@tenant.command("policy-load")
@click.argument("slug")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--replace", is_flag=True, help="Delete this tenant's existing rules first.")
def tenant_policy_load(slug: str, path: Path, replace: bool) -> None:
    """Load rules from a JSON policy file. A bad file changes nothing."""
    from .config import load_config
    from .enterprise.policy import PolicyError, create_rule, delete_rule, list_rules, load_rule_file
    from .enterprise.tenancy import TenantError, require_tenant

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            target = require_tenant(session, slug=slug)
            # Parse and validate the whole file before deleting anything, so a
            # typo on line 20 cannot leave the tenant with no policy at all.
            entries = load_rule_file(str(path), tenant_id=target.id)
            removed = 0
            if replace:
                for existing in list_rules(session, tenant_id=target.id):
                    if delete_rule(session, tenant_id=target.id, rule_id=existing.id):
                        removed += 1
            written = [
                create_rule(
                    session,
                    tenant_id=target.id,
                    effect=entry["effect"],
                    action=entry["action"],
                    name=entry["name"],
                    condition=entry["condition"],
                    priority=entry["priority"],
                )
                for entry in entries
            ]
            _emit(
                {
                    "tenant": target.slug,
                    "loaded": len(written),
                    "replaced": removed,
                    "rules": [row.to_wire() for row in written],
                },
                None,
            )
    except (TenantError, PolicyError) as err:
        raise click.ClickException(str(err)) from err


@tenant.command("policy-check")
@click.argument("slug")
@click.argument("action")
@click.option("--context-json", default="", help="JSON object the conditions are evaluated against.")
def tenant_policy_check(slug: str, action: str, context_json: str) -> None:
    """Explain the decision for one action, naming every rule considered."""
    from .config import load_config
    from .enterprise.policy import PolicyEngine, PolicyError
    from .enterprise.tenancy import TenantError, require_tenant

    context: dict = {}
    if context_json:
        try:
            parsed = json.loads(context_json)
        except json.JSONDecodeError as err:
            raise click.ClickException(f"--context-json is not valid JSON: {err}") from err
        if not isinstance(parsed, dict):
            raise click.ClickException("--context-json must be a JSON object")
        context = parsed
    # Nest under `arg` so a rule can say `arg.target` for a tool argument,
    # matching how the gateway builds the context.
    if context and "arg" not in context:
        context = {"arg": context}

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            target = require_tenant(session, slug=slug)
            report = PolicyEngine(session, tenant_id=target.id).explain(action, context)
            _emit(report, None)
    except (TenantError, PolicyError) as err:
        raise click.ClickException(str(err)) from err


# -- audit -----------------------------------------------------------------

@tenant.command("audit-export")
@click.argument("slug")
@click.option("--format", "fmt", type=click.Choice(["jsonl", "csv"]), default="jsonl", show_default=True)
@click.option("--since", default="", help="ISO-8601 lower bound, inclusive.")
@click.option("--until", default="", help="ISO-8601 upper bound, inclusive.")
@click.option("--limit", type=int, default=10_000, show_default=True)
@click.option("--redact/--no-redact", default=True, show_default=True, help="Scrub credential-shaped text.")
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None, help="Write the records here.")
def tenant_audit_export(
    slug: str,
    fmt: str,
    since: str,
    until: str,
    limit: int,
    redact: bool,
    out_path: Path | None,
) -> None:
    """Export a tenant's audit trail for a SIEM or an auditor.

    The recorded barrier is the last exported record's timestamp, so
    ``--since`` with it on the next run covers the timeline with no gap.
    """
    from datetime import datetime

    from .config import load_config
    from .enterprise.audit import AuditExporter
    from .enterprise.tenancy import TenantError, require_tenant

    def parse(value: str, label: str):
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError as err:
            raise click.ClickException(f"--{label} is not ISO-8601: {err}") from err

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            target = require_tenant(session, slug=slug)
            body, record = AuditExporter(session, tenant_id=target.id).export(
                fmt=fmt,
                since=parse(since, "since"),
                until=parse(until, "until"),
                limit=limit,
                redact=redact,
            )
            if out_path is not None:
                out_path.write_text(body, encoding="utf-8")
                click.echo(f"wrote {record.record_count} record(s) to {out_path}")
            elif body:
                click.echo(body, nl=False)
            _emit(
                {
                    "export": record.to_wire(),
                    "resume_with_since": record.write_until.isoformat() if record.write_until else None,
                },
                None,
            )
    except TenantError as err:
        raise click.ClickException(str(err)) from err
