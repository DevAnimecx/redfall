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
@click.argument("scan_id")
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None)
def findings(scan_id: str, out_path: Path | None) -> None:
    """List the findings recorded for a scan."""
    from sqlalchemy import select
    from sqlalchemy.orm import sessionmaker

    from .store.models import Finding

    config = load_config()
    engine = init_engine(config.database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with SessionLocal() as session:
        rows = (
            session.execute(
                select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.discovered_at)
            )
            .scalars()
            .all()
        )
        if not rows:
            _fail(f"no findings recorded for scan {scan_id}")
        table = Table(title=f"Findings for {scan_id}")
        for column in ("id", "category", "severity", "location", "status"):
            table.add_column(column)
        for row in rows:
            table.add_row(
                row.id,
                row.category,
                row.severity,
                f"{row.location_file}:{row.location_line}",
                row.status,
            )
        console.print(table)
        if out_path:
            out_path.write_text(json.dumps([r.to_wire() for r in rows], indent=2, default=str))
            console.print(f"written to {out_path}")


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
    try:
        registry = build_registry(url)
    except Exception as exc:  # noqa: BLE001 - startup must report the real failure
        _fail(f"MCP database unavailable: {type(exc).__name__}: {exc}")
    run_stdio(registry)


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
