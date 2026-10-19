"""Redfall command line. Every command does real work; there is no dry run."""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import click
from rich.console import Console
from rich.table import Table

from .config import PrerequisiteError, check_prerequisites, describe_environment, load_config
from .store.db import init_engine, ping

console = Console()
err_console = Console(stderr=True, style="bold red")


def _fail(message: str, code: int = 1) -> None:
    err_console.print(message)
    raise SystemExit(code)


@click.group()
@click.version_option(package_name="redfall")
def main() -> None:
    """Redfall — autonomous vulnerability discovery and verified repair."""


@main.command()
def doctor() -> None:
    """Report exactly which prerequisites this host satisfies."""
    config = load_config()
    env = describe_environment(config)
    table = Table(title="Redfall prerequisites")
    table.add_column("Requirement")
    table.add_column("State")
    table.add_column("Detail")

    db_ok, db_detail = ping(config.database_url)
    table.add_row("Postgres", "OK" if db_ok else "MISSING", db_detail[:80])

    from .store.state import StateStore

    redis_ok, redis_detail = StateStore(config.redis_url).ping()
    table.add_row("Redis", "OK" if redis_ok else "MISSING", redis_detail[:80])

    table.add_row(
        f"Sandbox runtime ({config.sandbox_runtime})",
        "OK" if env["sandbox_runtime_present"] else "MISSING",
        f"docker cli: {env['docker_cli']}; runtimes: {env['docker_runtimes'] or 'none'}",
    )
    table.add_row(
        "LLM provider",
        "OK" if config.providers else "MISSING",
        ", ".join(config.providers) or "set OPENAI_API_KEY or ANTHROPIC_API_KEY",
    )
    table.add_row("Node", "OK" if env["node"] else "MISSING", "")
    table.add_row("npm", "OK" if env["npm"] else "MISSING", "")

    console.print(table)
    try:
        check_prerequisites(config)
        console.print("[green]all prerequisites satisfied — scans can run[/green]")
    except PrerequisiteError as exc:
        console.print("[red]scans cannot run:[/red]\n  - " + "\n  - ".join(exc.failures))
        raise SystemExit(1) from None


@main.command()
@click.argument("target", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None, help="Write the scan report JSON here.")
@click.option("--quiet", is_flag=True, help="Only print the final summary.")
def scan(target: Path, out_path: Path | None, quiet: bool) -> None:
    """Scan a repository. Executes every finding in a gVisor sandbox."""
    config = load_config()
    try:
        check_prerequisites(config)
    except PrerequisiteError as exc:
        _fail("refusing to scan:\n  - " + "\n  - ".join(exc.failures) + "\n\nSee BLOCKED.md.")

    from .orchestrator import run_scan

    def on_event(kind: str, payload: dict) -> None:
        if quiet:
            return
        detail = json.dumps(payload, default=str)
        if len(detail) > 200:
            detail = detail[:200] + "…"
        console.print(f"[cyan]{kind}[/cyan] {detail}")

    report = run_scan(config, target, out_path=out_path, on_event=on_event)

    table = Table(title=f"Scan {report.scan_id}")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("status", report.status)
    table.add_row("duration_ms", str(report.duration_ms))
    table.add_row("branches", str(len(report.branches)))
    table.add_row("findings", str(len(report.findings)))
    for severity, count in sorted(_severity_counts(report.findings).items()):
        table.add_row(f"  {severity}", str(count))
    table.add_row("sandbox runs", str(report.sandbox_runs))
    table.add_row("llm calls", str(report.llm.get("calls", 0)))
    table.add_row("tokens", str(report.llm.get("tokens_used", 0)))
    table.add_row("cost (USD)", f"{report.llm.get('cost_usd', 0):.4f}")
    console.print(table)
    for error in report.errors:
        err_console.print(f"error: {error}")
    if out_path:
        console.print(f"report written to {out_path}")


@main.command()
@click.argument("scan_id", required=False)
@click.option("--campaign", "campaign_id", default="", help="List findings linked to a campaign instead.")
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None)
def findings(scan_id: str | None, campaign_id: str, out_path: Path | None) -> None:
    """List the findings recorded for a scan or campaign."""
    from sqlalchemy import or_, select
    from sqlalchemy.orm import sessionmaker

    from .store.models import Campaign, EvidenceRecord, Finding

    if not scan_id and not campaign_id:
        _fail("pass a scan id or --campaign")
    config = load_config()
    engine = init_engine(config.database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with SessionLocal() as session:
        statement = select(Finding)
        title = f"Findings for scan {scan_id}"
        if campaign_id:
            campaign = session.get(Campaign, campaign_id)
            if campaign is None:
                _fail(f"no such campaign: {campaign_id}")
            linked = session.scalars(
                select(EvidenceRecord.finding_id).where(
                    EvidenceRecord.campaign_id == campaign_id,
                    EvidenceRecord.finding_id.is_not(None),
                )
            ).all()
            ids = {str(item) for item in linked if item}
            if campaign.scan_id:
                statement = statement.where(
                    or_(Finding.scan_id == campaign.scan_id, Finding.id.in_(ids) if ids else Finding.id == "")
                )
            elif ids:
                statement = statement.where(Finding.id.in_(ids))
            else:
                statement = statement.where(Finding.id == "")
            title = f"Findings for campaign {campaign_id}"
        elif scan_id:
            statement = statement.where(Finding.scan_id == scan_id)
        rows = session.execute(statement.order_by(Finding.discovered_at)).scalars().all()
        if not rows:
            _fail("no findings recorded")
        table = Table(title=title)
        for column in ("id", "category", "severity", "location", "status", "evidence"):
            table.add_column(column)
        for row in rows:
            evidence = session.scalars(
                select(EvidenceRecord).where(EvidenceRecord.finding_id == row.id)
            ).all()
            reportable = any(record.grade in {"E3", "E4"} for record in evidence)
            table.add_row(
                row.id,
                row.category,
                row.severity,
                f"{row.location_file}:{row.location_line}",
                row.status,
                "E3/E4" if reportable else "unverified",
            )
        console.print(table)
        if out_path:
            out_path.write_text(
                json.dumps([r.to_wire() for r in rows], indent=2, default=str),
                encoding="utf-8",
            )
            console.print(f"written to {out_path}")


@main.command()
@click.argument("finding_id")
@click.option("--target", "target_path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=None)
@click.option("--campaign-id", default="", help="Append a hash-chained evidence record to this campaign.")
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None, help="Write the outcome JSON here.")
def reproduce(finding_id: str, target_path: Path | None, campaign_id: str, out_path: Path | None) -> None:
    """Replay a stored finding's PoC inside the gVisor sandbox."""
    from sqlalchemy.orm import sessionmaker

    from .campaign.policy import (
        PolicyError,
        require_campaign_path,
        require_os_path,
    )
    from .store.models import Campaign, Finding, Scan
    from .validation.reproducer import ReproductionBlocked, ReproductionError, Reproducer

    config = load_config()
    engine = init_engine(config.database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with SessionLocal() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            _fail(f"no such finding: {finding_id}")
        scan = session.get(Scan, finding.scan_id)
        if scan is None:
            _fail(f"finding {finding_id} has no scan target")
        resolved_target = target_path or Path(scan.repo)
        try:
            if campaign_id:
                campaign = session.get(Campaign, campaign_id)
                if campaign is None:
                    _fail(f"no such campaign: {campaign_id}")
                resolved_target = require_campaign_path(
                    campaign, resolved_target, action="reproduce"
                )
            else:
                resolved_target = require_os_path(resolved_target, action="reproduce")
        except PolicyError as exc:
            _fail(f"target is outside allowed scope: {exc}")
        try:
            outcome = Reproducer(
                session,
                workdir=config.workdir / "workspaces",
                timeout_s=config.sandbox_timeout_s,
            ).reproduce(finding_id, campaign_id=campaign_id or None, target=resolved_target)
        except ReproductionBlocked as exc:
            err_console.print(f"blocked: {exc.reason}")
            for detail in exc.details:
                err_console.print(f"  - {detail}")
            raise SystemExit(2) from None
        except ReproductionError as exc:
            _fail(str(exc))
        data = outcome.to_wire()
        if out_path:
            out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            console.print(f"outcome written to {out_path}")
        console.print_json(data=data)
    if not outcome.reproduced:
        raise SystemExit(2)


@main.command()
@click.argument("finding_id")
@click.option("--target", "target_path", type=click.Path(exists=True, file_okay=False, path_type=Path), required=True)
@click.option(
    "--out",
    "out_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Append this finding's fix record to a fixes JSON that `range_runner --fixes` reads.",
)
def fix(finding_id: str, target_path: Path, out_path: Path | None) -> None:
    """Generate, apply and verify a patch for one finding."""
    from sqlalchemy.orm import sessionmaker

    from .agent.agent import Agent
    from .fix.fixer import Fixer, fix_record, write_fixes_file
    from .llm import new_budget
    from .store.models import Finding
    from .validation.validator import Validator

    config = load_config()
    try:
        check_prerequisites(config)
    except PrerequisiteError as exc:
        _fail("refusing to fix:\n  - " + "\n  - ".join(exc.failures))

    engine = init_engine(config.database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with SessionLocal() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            _fail(f"no such finding: {finding_id}")

        budget = new_budget(config.max_tokens_per_scan, config.max_cost_per_scan_usd)
        agent = Agent(llm=_make_llm(SessionLocal, budget), scan_id=finding.scan_id)
        validator = Validator(
            target=target_path,
            session=session,
            scan_id=finding.scan_id,
            workdir=config.workdir / "workspaces",
            timeout_s=config.sandbox_timeout_s,
        )
        fixer = Fixer(
            agent=agent,
            validator=validator,
            session=session,
            scan_id=finding.scan_id,
            target=target_path,
            tests=_read_tests(target_path),
            dependencies=_read_deps(target_path),
        )
        outcome = fixer.run(finding)

    console.print(f"fix {outcome.fix_id} for {outcome.finding_id}")
    console.print(f"  status:          {outcome.status}")
    console.print(f"  verified:        {outcome.verified}")
    console.print(f"  tests:           {outcome.test_result}")
    console.print(f"  poc neutralized: {outcome.poc_neutralized}")
    console.print(f"  attempts:        {outcome.attempts}")
    if outcome.blocker:
        console.print(f"  blocker:         {outcome.blocker}")
    if out_path:
        write_fixes_file(out_path, fix_record(outcome))
        console.print(f"fix record written to {out_path}")
    if outcome.verified:
        console.print("[green]VERIFIED[/green]")
    else:
        console.print("[yellow]NOT VERIFIED[/yellow]")
        raise SystemExit(2)


@main.command()
@click.argument("scan_id")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "sarif"]),
    default="json",
    show_default=True,
    help="Output format. `sarif` emits SARIF 2.1.0 for code-scanning consumers.",
)
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None, help="Write the report here instead of stdout.")
def report(scan_id: str, fmt: str, out_path: Path | None) -> None:
    """Print the stored report for a scan."""
    from sqlalchemy import func, select
    from sqlalchemy.orm import sessionmaker

    from .store.models import Branch, Finding, LLMCall, Scan

    config = load_config()
    engine = init_engine(config.database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            _fail(f"no such scan: {scan_id}")
        branch_rows = session.execute(select(Branch).where(Branch.scan_id == scan_id)).scalars().all()
        finding_rows = session.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all()
        calls = session.execute(
            select(func.count(), func.sum(LLMCall.prompt_tokens + LLMCall.completion_tokens), func.sum(LLMCall.cost_usd))
            .where(LLMCall.scan_id == scan_id)
        ).one()

    data = {
        "scan": scan.to_wire() if hasattr(scan, "to_wire") else {
            "id": scan.id,
            "repo": scan.repo,
            "commit": scan.commit,
            "status": scan.status,
            "duration_ms": scan.duration_ms,
            "findings_total": scan.findings_total,
            "findings_by_severity": scan.findings_by_severity,
            "tokens_total": scan.tokens_total,
            "cost_estimate_usd": scan.cost_estimate_usd,
        },
        "branches": [
            {
                "name": b.name,
                "status": b.status,
                "type": b.type,
                "priority": b.priority,
                "scope_files": b.scope_files,
            }
            for b in branch_rows
        ],
        "findings": [f.to_wire() for f in finding_rows],
        "llm": {"calls": calls[0], "tokens": int(calls[1] or 0), "cost_usd": float(calls[2] or 0.0)},
        "environment": describe_environment(config),
    }

    if fmt == "sarif":
        from .sarif import build_sarif

        payload = build_sarif(data["scan"], data["findings"])
        rendered = json.dumps(payload, indent=2)
        if out_path:
            out_path.write_text(rendered + "\n", encoding="utf-8")
            console.print(f"sarif written to {out_path}")
        else:
            print(rendered)
        return

    console.print_json(data=data)


@main.command()
def environment() -> None:
    """Print the factual host capability report as JSON."""
    console.print_json(data=describe_environment(load_config()))


# --------------------------------------------------------------- campaign
@main.group()
def campaign() -> None:
    """Create and inspect durable security campaigns."""


@campaign.command("create")
@click.argument("repo")
@click.option("--objective", type=click.Choice(["discovery", "reproduction", "fix", "regression", "chain", "compliance"]), default="discovery", show_default=True)
@click.option("--commit", default="", help="Source commit or revision label.")
@click.option("--scope-json", default="", help="JSON object describing allowed repositories, branches and hosts.")
@click.option("--policy-json", default="", help="JSON object describing authorised techniques and gates.")
@click.option("--budget-usd", type=float, default=10.0, show_default=True)
@click.option("--budget-tokens", type=int, default=500_000, show_default=True)
@click.option("--budget-sandbox-minutes", type=float, default=60.0, show_default=True)
@click.option("--budget-wall-clock-s", type=int, default=3_600, show_default=True)
def campaign_create(
    repo: str,
    objective: str,
    commit: str,
    scope_json: str,
    policy_json: str,
    budget_usd: float,
    budget_tokens: int,
    budget_sandbox_minutes: float,
    budget_wall_clock_s: int,
) -> None:
    """Create a draft campaign. Nothing is executed until it is scoped and started."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        row = CampaignService(session).create(
            repo,
            objective=objective,
            commit=commit,
            scope=_json_object(scope_json, "scope"),
            policy=_json_object(policy_json, "policy"),
            budget_usd=budget_usd,
            budget_tokens=budget_tokens,
            budget_sandbox_minutes=budget_sandbox_minutes,
            budget_wall_clock_s=budget_wall_clock_s,
        )
        data = row.to_wire()
    console.print_json(data=data)


@campaign.command("scope")
@click.argument("campaign_id")
@click.option("--scope-json", required=True, help="JSON object describing allowed repositories, branches and hosts.")
def campaign_scope(campaign_id: str, scope_json: str) -> None:
    """Set the scope and move a draft campaign to scoped."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).scope(campaign_id, _json_object(scope_json, "scope")).to_wire()
    console.print_json(data=data)


@campaign.command("start")
@click.argument("campaign_id")
def campaign_start(campaign_id: str) -> None:
    """Start a scoped campaign by moving it to indexing."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).start(campaign_id).to_wire()
    console.print_json(data=data)


@campaign.command("list")
@click.option("--limit", type=int, default=50, show_default=True)
def campaign_list(limit: int) -> None:
    """List recent campaigns."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = [row.to_wire() for row in CampaignService(session).list_campaigns(limit=limit)]
    console.print_json(data={"campaigns": data})


@campaign.command("status")
@click.argument("campaign_id")
def campaign_status(campaign_id: str) -> None:
    """Show campaign state, tasks, evidence, budget and chain integrity."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).status(campaign_id)
    console.print_json(data=data)


@campaign.command("transition")
@click.argument("campaign_id")
@click.argument("state")
@click.option("--reason", default="", help="Why the state changed.")
def campaign_transition(campaign_id: str, state: str, reason: str) -> None:
    """Move a campaign to an explicit legal state."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).transition(campaign_id, state, reason=reason).to_wire()
    console.print_json(data=data)


@campaign.command("pause")
@click.argument("campaign_id")
@click.option("--reason", default="", help="Why the campaign is paused.")
def campaign_pause(campaign_id: str, reason: str) -> None:
    """Pause a campaign."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).pause(campaign_id, reason=reason).to_wire()
    console.print_json(data=data)


@campaign.command("resume")
@click.argument("campaign_id")
@click.option("--reason", default="", help="Why the campaign is resumed.")
def campaign_resume(campaign_id: str, reason: str) -> None:
    """Resume a paused or blocked campaign into its recorded state."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).resume(campaign_id, reason=reason).to_wire()
    console.print_json(data=data)


@campaign.command("cancel")
@click.argument("campaign_id")
@click.option("--reason", default="", help="Why the campaign is cancelled.")
def campaign_cancel(campaign_id: str, reason: str) -> None:
    """Cancel a campaign."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).cancel(campaign_id, reason=reason).to_wire()
    console.print_json(data=data)


@campaign.command("report")
@click.argument("campaign_id")
@click.option("--reason", default="", help="Why the campaign is being reported.")
def campaign_report(campaign_id: str, reason: str) -> None:
    """Move a campaign to reported. Run `campaign evidence verify` first."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).report(campaign_id, reason=reason).to_wire()
    console.print_json(data=data)


@campaign.command("spend")
@click.argument("campaign_id")
@click.option("--usd", type=float, default=0.0, show_default=True)
@click.option("--tokens", type=int, default=0, show_default=True)
@click.option("--sandbox-minutes", type=float, default=0.0, show_default=True)
@click.option("--source", default="", help="What incurred the spend.")
def campaign_spend(campaign_id: str, usd: float, tokens: int, sandbox_minutes: float, source: str) -> None:
    """Record spend and enforce the campaign budget."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).record_spend(
            campaign_id,
            usd=usd,
            tokens=tokens,
            sandbox_minutes=sandbox_minutes,
            source=source,
        )
    console.print_json(data=data)


@campaign.command("run")
@click.argument("campaign_id")
@click.option("--worker", default="cli-worker", show_default=True)
@click.option("--max-tasks", type=int, default=10, show_default=True)
@click.option("--lease-seconds", type=int, default=300, show_default=True)
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None)
def campaign_run(campaign_id: str, worker: str, max_tasks: int, lease_seconds: int, out_path: Path | None) -> None:
    """Claim and execute ready tasks with the real resumable runner."""
    from sqlalchemy.orm import sessionmaker

    from .campaign.runner import CampaignRunner

    config = load_config()
    engine = init_engine(config.database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    result = CampaignRunner(
        SessionLocal,
        worker=worker,
        config=config,
        lease_seconds=lease_seconds,
        max_tasks=max_tasks,
    ).run(campaign_id, max_tasks=max_tasks)
    if out_path:
        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        console.print(f"run summary written to {out_path}")
    console.print_json(data=result)


@campaign.command("reserve")
@click.argument("campaign_id")
@click.option("--task-id", default="")
@click.option("--usd", type=float, default=0.0)
@click.option("--tokens", type=int, default=0)
@click.option("--sandbox-minutes", type=float, default=0.0)
@click.option("--source", default="")
def campaign_reserve(campaign_id: str, task_id: str, usd: float, tokens: int, sandbox_minutes: float, source: str) -> None:
    """Hold budget before an execution."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).reserve_spend(
            campaign_id,
            task_id=task_id or None,
            usd=usd,
            tokens=tokens,
            sandbox_minutes=sandbox_minutes,
            source=source,
        ).to_wire()
    console.print_json(data=data)


@campaign.command("reservations")
@click.argument("campaign_id")
@click.option("--status", default="held", help="Filter by reservation status; empty shows all.")
def campaign_reservations(campaign_id: str, status: str) -> None:
    """List budget reservations."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = [
            item.to_wire()
            for item in CampaignService(session).reservations(campaign_id, status=status or None)
        ]
    console.print_json(data={"reservations": data})


@campaign.command("release-reservation")
@click.argument("reservation_id")
@click.option("--reason", default="")
def campaign_release_reservation(reservation_id: str, reason: str) -> None:
    """Release a held reservation without spend."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).release_reservation(reservation_id, reason=reason).to_wire()
    console.print_json(data=data)


@campaign.command("settle-reservation")
@click.argument("reservation_id")
@click.option("--usd", type=float, default=0.0)
@click.option("--tokens", type=int, default=0)
@click.option("--sandbox-minutes", type=float, default=0.0)
@click.option("--source", default="")
@click.option(
    "--allow-overage",
    is_flag=True,
    help="Accept measured spend above the estimate while the campaign ceiling still holds.",
)
def campaign_settle_reservation(
    reservation_id: str,
    usd: float,
    tokens: int,
    sandbox_minutes: float,
    source: str,
    allow_overage: bool,
) -> None:
    """Replace a reservation with measured spend."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).settle_reservation(
            reservation_id,
            usd=usd,
            tokens=tokens,
            sandbox_minutes=sandbox_minutes,
            source=source,
            allow_overage=allow_overage,
        )
    console.print_json(data=data)


@campaign.command("readiness")
@click.argument("campaign_id")
def campaign_readiness(campaign_id: str) -> None:
    """Check chain integrity and the reportable-evidence gate."""
    from .evidence.ledger import EvidenceLedger

    with _db_session() as session:
        ledger = EvidenceLedger(session)
        chain = ledger.verify(campaign_id)
        reportable = ledger.reportable(campaign_id)
        ready = chain.ok and bool(reportable)
        data = {
            "ready": ready,
            "reason": "" if ready else ("evidence chain is broken" if not chain.ok else "no E3/E4 evidence"),
            "chain": chain.to_wire(),
            "evidence_ids": [record.id for record in reportable],
        }
    console.print_json(data=data)
    if not ready:
        raise SystemExit(2)


@campaign.command("export")
@click.argument("campaign_id")
@click.option("--format", "fmt", type=click.Choice(["json", "sarif"]), default="json", show_default=True)
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None)
def campaign_export(campaign_id: str, fmt: str, out_path: Path | None) -> None:
    """Emit an evidence-gated campaign report. Refuses when the gate fails."""
    from sqlalchemy.orm import sessionmaker

    from .reporting.campaign_report import ReportError, build_campaign_report

    config = load_config()
    engine = init_engine(config.database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with SessionLocal() as session:
        try:
            data = build_campaign_report(session, campaign_id, report_format=fmt)
        except ReportError as exc:
            _fail(f"refusing to report: {exc}")
        payload = data["report"]
        rendered = json.dumps(payload, indent=2, default=str)
        if out_path:
            out_path.write_text(rendered + "\n", encoding="utf-8")
            console.print(f"{fmt} report written to {out_path}")
        else:
            print(rendered)


@campaign.group("task")
def campaign_task() -> None:
    """Durable task graph operations."""


@campaign_task.command("add")
@click.argument("campaign_id")
@click.argument("kind")
@click.option("--payload-json", default="", help="Task payload as a JSON object.")
@click.option("--priority", type=int, default=0, show_default=True)
@click.option("--depends-on", multiple=True, help="Task id that must complete first. Repeatable.")
@click.option("--max-attempts", type=int, default=3, show_default=True)
def campaign_task_add(
    campaign_id: str,
    kind: str,
    payload_json: str,
    priority: int,
    depends_on: tuple[str, ...],
    max_attempts: int,
) -> None:
    """Add a task to a campaign."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).enqueue_task(
            campaign_id,
            kind,
            payload=_json_object(payload_json, "payload"),
            priority=priority,
            depends_on=list(depends_on),
            max_attempts=max_attempts,
        ).to_wire()
    console.print_json(data=data)


@campaign_task.command("claim")
@click.argument("campaign_id")
@click.option("--worker", required=True, help="Worker identity that owns the lease.")
@click.option("--lease-seconds", type=int, default=300, show_default=True)
def campaign_task_claim(campaign_id: str, worker: str, lease_seconds: int) -> None:
    """Lease the highest-priority ready task."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        task = CampaignService(session).claim_task(campaign_id, worker=worker, lease_seconds=lease_seconds)
        data = task.to_wire() if task is not None else None
    console.print_json(data={"task": data})


@campaign_task.command("complete")
@click.argument("task_id")
@click.option("--worker", required=True)
@click.option("--result-json", default="", help="Task result as a JSON object.")
def campaign_task_complete(task_id: str, worker: str, result_json: str) -> None:
    """Complete a task owned by the worker."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).complete_task(
            task_id, worker=worker, result=_json_object(result_json, "result")
        ).to_wire()
    console.print_json(data=data)


@campaign_task.command("fail")
@click.argument("task_id")
@click.option("--worker", required=True)
@click.option("--error", required=True)
@click.option("--no-retry", is_flag=True, help="Fail immediately instead of retrying up to max_attempts.")
def campaign_task_fail(task_id: str, worker: str, error: str, no_retry: bool) -> None:
    """Fail a task, retrying until max_attempts unless --no-retry is set."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = CampaignService(session).fail_task(task_id, worker=worker, error=error, retry=not no_retry).to_wire()
    console.print_json(data=data)


@campaign_task.command("list")
@click.argument("campaign_id")
@click.option("--status", default="", help="Filter by task status.")
def campaign_task_list(campaign_id: str, status: str) -> None:
    """List campaign tasks."""
    from .campaign.service import CampaignService

    with _db_session() as session:
        data = [task.to_wire() for task in CampaignService(session).list_tasks(campaign_id, status=status or None)]
    console.print_json(data={"tasks": data})


@campaign.group("evidence")
def campaign_evidence() -> None:
    """Append-only evidence ledger operations."""


@campaign_evidence.command("add")
@click.argument("campaign_id")
@click.option("--grade", type=click.Choice(["E0", "E1", "E2", "E3", "E4"]), required=True)
@click.option("--kind", type=click.Choice(["static", "dynamic", "execution", "artifact", "human", "environment", "tool", "test", "review"]), required=True)
@click.option("--claim", required=True, help="What this record supports.")
@click.option("--payload-json", default="", help="Structured evidence as a JSON object.")
@click.option("--finding-id", default="", help="Optional finding id.")
@click.option("--artifact", "artifacts", multiple=True, help="Artifact path or URI. Repeatable.")
@click.option("--reproduce-command", default="", help="Exact command that replays the evidence.")
@click.option("--environment-digest", default="", help="Immutable environment/image digest.")
def campaign_evidence_add(
    campaign_id: str,
    grade: str,
    kind: str,
    claim: str,
    payload_json: str,
    finding_id: str,
    artifacts: tuple[str, ...],
    reproduce_command: str,
    environment_digest: str,
) -> None:
    """Append a hash-chained evidence record."""
    from .evidence.ledger import EvidenceLedger

    with _db_session() as session:
        data = EvidenceLedger(session).append(
            campaign_id,
            grade=grade,
            kind=kind,
            claim=claim,
            payload=_json_object(payload_json, "payload"),
            finding_id=finding_id or None,
            artifacts=list(artifacts),
            reproduce_command=reproduce_command,
            environment_digest=environment_digest,
        ).to_wire()
    console.print_json(data=data)


@campaign_evidence.command("list")
@click.argument("campaign_id")
@click.option("--reportable-only", is_flag=True, help="Only E3/E4 records.")
def campaign_evidence_list(campaign_id: str, reportable_only: bool) -> None:
    """List evidence in chain order."""
    from .evidence.ledger import EvidenceLedger

    with _db_session() as session:
        data = [record.to_wire() for record in EvidenceLedger(session).list(campaign_id, reportable_only=reportable_only)]
    console.print_json(data={"evidence": data})


@campaign_evidence.command("verify")
@click.argument("campaign_id")
def campaign_evidence_verify(campaign_id: str) -> None:
    """Recompute the evidence hash chain."""
    from .evidence.ledger import EvidenceLedger

    with _db_session() as session:
        data = EvidenceLedger(session).verify(campaign_id).to_wire()
    console.print_json(data=data)


# ------------------------------------------------------------------- graph
@main.group()
def graph() -> None:
    """Build and query persisted code-graph snapshots."""


@graph.command("index")
@click.argument("target", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--campaign-id", default="")
@click.option("--label", default="")
def graph_index(target: Path, campaign_id: str, label: str) -> None:
    """Parse real source and persist an immutable graph snapshot."""
    from .campaign.policy import PolicyError, require_campaign_path, require_os_path
    from .graph.indexer import GraphIndexer
    from .graph.query import GraphQuery
    from .store.models import Campaign

    with _db_session() as session:
        resolved = target
        try:
            if campaign_id:
                campaign = session.get(Campaign, campaign_id)
                if campaign is None:
                    _fail(f"no such campaign: {campaign_id}")
                resolved = require_campaign_path(campaign, target, action="index")
            else:
                resolved = require_os_path(target, action="index")
        except PolicyError as exc:
            _fail(f"target is outside allowed scope: {exc}")
        snapshot = GraphIndexer(session).index(resolved, campaign_id=campaign_id or None, label=label)
        data = {
            "snapshot": snapshot.to_wire(),
            "stats": GraphQuery(session).stats(snapshot.id),
        }
    console.print_json(data=data)


@graph.command("stats")
@click.option("--snapshot-id", default="")
@click.option("--campaign-id", default="")
def graph_stats(snapshot_id: str, campaign_id: str) -> None:
    """Show graph counts by node and edge kind."""
    from .graph.query import GraphQuery

    with _db_session() as session:
        data = GraphQuery(session).stats(snapshot_id or None, campaign_id=campaign_id or None)
    console.print_json(data=data)


@graph.command("latest")
@click.option("--campaign-id", default="")
@click.option("--root", default="")
@click.option("--limit", type=int, default=1, show_default=True)
def graph_latest(campaign_id: str, root: str, limit: int) -> None:
    """Show the most recent persisted snapshot."""
    from .graph.query import GraphQuery

    with _db_session() as session:
        snapshots = GraphQuery(session).list_snapshots(
            campaign_id=campaign_id or None,
            root=root or None,
            limit=limit,
        )
    console.print_json(
        data={"snapshots": snapshots, "snapshot": snapshots[0] if snapshots else None}
    )


@graph.command("search")
@click.argument("query", required=False, default="")
@click.option("--snapshot-id", default="")
@click.option("--kind", default="")
@click.option("--file", "file_filter", default="")
@click.option("--limit", type=int, default=50, show_default=True)
def graph_search(query: str, snapshot_id: str, kind: str, file_filter: str, limit: int) -> None:
    """Search graph nodes without inventing absent records."""
    from .graph.query import GraphQuery

    with _db_session() as session:
        data = GraphQuery(session).search(
            snapshot_id=snapshot_id or None,
            query=query,
            kind=kind,
            file=file_filter,
            limit=limit,
        )
    console.print_json(data=data)


@graph.command("node")
@click.argument("node")
@click.option("--snapshot-id", default="")
def graph_node(node: str, snapshot_id: str) -> None:
    """Show a node and its incoming/outgoing edges."""
    from .graph.query import GraphQuery

    with _db_session() as session:
        query = GraphQuery(session)
        data = query.node_detail(query.snapshot(snapshot_id or None).id, node)
    console.print_json(data=data)


@graph.command("neighbors")
@click.argument("node")
@click.option("--snapshot-id", default="")
@click.option("--direction", type=click.Choice(["out", "in", "both"]), default="both", show_default=True)
@click.option("--edge-kind", "edge_kinds", multiple=True)
@click.option("--depth", type=int, default=1, show_default=True)
@click.option("--limit", type=int, default=200, show_default=True)
def graph_neighbors(node: str, snapshot_id: str, direction: str, edge_kinds: tuple[str, ...], depth: int, limit: int) -> None:
    """Traverse stored edges with a hard node budget."""
    from .graph.query import GraphQuery

    with _db_session() as session:
        query = GraphQuery(session)
        data = query.neighbors(
            query.snapshot(snapshot_id or None).id,
            node,
            direction=direction,
            edge_kinds=list(edge_kinds) or None,
            depth=depth,
            limit=limit,
        )
    console.print_json(data=data)


@graph.command("paths")
@click.argument("source")
@click.argument("target")
@click.option("--snapshot-id", default="")
@click.option("--edge-kind", "edge_kinds", multiple=True)
@click.option("--max-depth", type=int, default=5, show_default=True)
@click.option("--limit", type=int, default=10, show_default=True)
def graph_paths(source: str, target: str, snapshot_id: str, edge_kinds: tuple[str, ...], max_depth: int, limit: int) -> None:
    """Find bounded directed paths and return full provenance."""
    from .graph.query import GraphQuery

    with _db_session() as session:
        query = GraphQuery(session)
        data = query.paths(
            query.snapshot(snapshot_id or None).id,
            source,
            target,
            edge_kinds=list(edge_kinds) or None,
            max_depth=max_depth,
            limit=limit,
        )
    console.print_json(data=data)


@graph.command("routes")
@click.option("--snapshot-id", default="")
@click.option("--campaign-id", default="")
@click.option("--method", default="")
@click.option("--path-contains", default="")
@click.option("--limit", type=int, default=200, show_default=True)
def graph_routes(snapshot_id: str, campaign_id: str, method: str, path_contains: str, limit: int) -> None:
    """List resolved HTTP routes with their source locations."""
    from .graph.query import GraphQuery

    with _db_session() as session:
        data = GraphQuery(session).routes(
            snapshot_id or None,
            campaign_id=campaign_id or None,
            method=method,
            path_contains=path_contains,
            limit=limit,
        )
    console.print_json(data=data)


@graph.command("sources")
@click.option("--snapshot-id", default="")
@click.option("--campaign-id", default="")
@click.option("--role", type=click.Choice(["both", "source", "sink"]), default="both", show_default=True)
@click.option("--limit", type=int, default=200, show_default=True)
def graph_sources(snapshot_id: str, campaign_id: str, role: str, limit: int) -> None:
    """List stored taint sources, sinks and flows."""
    from .graph.query import GraphQuery

    with _db_session() as session:
        data = GraphQuery(session).sources_sinks(
            snapshot_id or None,
            campaign_id=campaign_id or None,
            limit=limit,
        )
    if role == "source":
        data = {
            "snapshot_id": data["snapshot_id"],
            "sources": data["sources"],
            "truncated": data["truncated"],
        }
    elif role == "sink":
        data = {
            "snapshot_id": data["snapshot_id"],
            "sinks": data["sinks"],
            "truncated": data["truncated"],
        }
    console.print_json(data=data)


@graph.command("inventory")
@click.option("--snapshot-id", default="")
@click.option("--campaign-id", default="")
@click.option("--limit", type=int, default=200, show_default=True)
def graph_inventory(snapshot_id: str, campaign_id: str, limit: int) -> None:
    """Return the route, dependency and surface inventory of a snapshot."""
    from .graph.query import GraphQuery

    with _db_session() as session:
        data = GraphQuery(session).inventory(
            snapshot_id or None,
            campaign_id=campaign_id or None,
            limit=limit,
        )
    console.print_json(data=data)


@graph.command("diff")
@click.argument("base_snapshot")
@click.argument("head_snapshot")
@click.option("--limit", type=int, default=200, show_default=True)
def graph_diff(base_snapshot: str, head_snapshot: str, limit: int) -> None:
    """Compare two persisted snapshots by stable key and content hash."""
    from .graph.query import GraphQuery

    with _db_session() as session:
        data = GraphQuery(session).diff(base_snapshot, head_snapshot, limit=limit)
    console.print_json(data=data)


@main.command("policy-check")
@click.argument("action", type=click.Choice(["index", "scan", "reproduce", "report", "fix"]))
@click.option("--target", default="")
@click.option("--campaign-id", default="")
def policy_check(action: str, target: str, campaign_id: str) -> None:
    """Check a filesystem action against campaign scope or allowed roots."""
    from .campaign.policy import check_campaign_path, check_os_path
    from .store.models import Campaign

    if not target:
        console.print_json(
            data={
                "allowed": action == "report",
                "action": action,
                "target": "",
                "roots": [],
                "reason": "no filesystem path requested",
            }
        )
        return
    with _db_session() as session:
        if campaign_id:
            campaign = session.get(Campaign, campaign_id)
            if campaign is None:
                _fail(f"no such campaign: {campaign_id}")
            decision = check_campaign_path(campaign, target, action=action)
        else:
            decision = check_os_path(target, action=action)
    console.print_json(data=decision.to_wire())
    if not decision.allowed:
        raise SystemExit(2)


# -------------------------------------------------------------------- MCP
@main.group()
def mcp() -> None:
    """Agent interoperability servers."""


@mcp.command("serve")
@click.option("--database-url", default="", help="Override the database URL for the MCP process.")
def mcp_serve(database_url: str) -> None:
    """Serve campaign/evidence tools over MCP stdio."""
    from .interop.mcp_stdio import build_registry, run_stdio

    config = load_config()
    url = database_url or config.database_url
    import os

    os.environ["DATABASE_URL"] = url
    try:
        registry = build_registry(url)
    except Exception as exc:  # noqa: BLE001 - startup must report the real failure
        _fail(f"MCP database unavailable: {type(exc).__name__}: {exc}")
    run_stdio(registry)


@mcp.command("certify")
@click.option("--timeout", type=float, default=60.0, show_default=True)
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None)
def mcp_certify(timeout: float, out_path: Path | None) -> None:
    """Run the MCP stdio adapter contract against a fresh real server."""
    import uuid

    from .interop.contract import run_mcp_stdio_contract
    from .store.models import AdapterCertification

    report = run_mcp_stdio_contract(timeout=timeout)
    data = report.to_wire()
    with _db_session() as session:
        session.add(
            AdapterCertification(
                id=f"adapter-{uuid.uuid4().hex}",
                adapter=report.adapter,
                protocol=report.protocol,
                transport=report.transport,
                server_name=report.server_name,
                server_version=report.server_version,
                tool_count=report.tool_count,
                certified=report.certified,
                checks=[check.to_wire() for check in report.checks],
                details={
                    "protocol_version": report.protocol_version,
                    "error": report.error,
                    "contract_database": report.database_url,
                },
                duration_ms=report.duration_ms,
            )
        )
    if out_path:
        out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        console.print(f"contract report written to {out_path}")
    console.print_json(data=data)
    if not report.certified:
        raise SystemExit(2)


@main.group()
def adapters() -> None:
    """Protocol adapter availability and measured certifications."""


@adapters.command("list")
def adapters_list() -> None:
    """List implemented transports without claiming unimplemented ones."""
    console.print_json(
        data={
            "adapters": [
                {
                    "name": "mcp-stdio",
                    "protocol": "mcp",
                    "transport": "stdio",
                    "status": "supported",
                    "certification": "run `redfall mcp certify`",
                },
                {
                    "name": "cli",
                    "protocol": "process",
                    "transport": "cli",
                    "status": "supported",
                    "certification": "not contract-certified",
                },
                {
                    "name": "http-openapi",
                    "protocol": "openapi",
                    "transport": "http",
                    "status": "planned",
                    "certification": "not implemented",
                },
                {
                    "name": "a2a",
                    "protocol": "a2a",
                    "transport": "http",
                    "status": "planned",
                    "certification": "not implemented",
                },
            ]
        }
    )


@adapters.command("certifications")
@click.option("--limit", type=int, default=20, show_default=True)
def adapters_certifications(limit: int) -> None:
    """List persisted adapter contract results."""
    from sqlalchemy import select
    from sqlalchemy.orm import sessionmaker

    from .store.models import AdapterCertification

    config = load_config()
    engine = init_engine(config.database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with SessionLocal() as session:
        rows = session.scalars(
            select(AdapterCertification)
            .order_by(AdapterCertification.certified_at.desc())
            .limit(limit)
        ).all()
        data = [row.to_wire() for row in rows]
    console.print_json(data={"certifications": data})


@contextmanager
def _db_session() -> Iterator:
    from sqlalchemy.orm import sessionmaker

    config = load_config()
    engine = init_engine(config.database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _json_object(text: str, label: str) -> dict:
    if not text.strip():
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        _fail(f"--{label}-json is not valid JSON: {exc.msg}")
    if not isinstance(value, dict):
        _fail(f"--{label}-json must be a JSON object")
    return value


def _make_llm(session_factory, budget):
    from .llm import LLM

    return LLM(session_factory=session_factory, budget=budget)


def _read_tests(target: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    tests_dir = target / "tests"
    if not tests_dir.exists():
        return out
    for path in sorted(tests_dir.rglob("*.test.ts")):
        out[path.relative_to(target).as_posix()] = path.read_text(errors="replace")
    return out


def _read_deps(target: Path) -> list[dict]:
    from .ingestion.dependencies import read_dependencies

    deps, _ = read_dependencies(target)
    return [{"name": d.name, "declared": d.declared, "resolved": d.resolved} for d in deps if not d.is_dev]


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


if __name__ == "__main__":
    main()
