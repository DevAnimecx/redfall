"""Redfall command line. Every command does real work; there is no dry run."""

from __future__ import annotations

import json
import sys
from pathlib import Path

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
        console.print(f"[red]scans cannot run:[/red]\n  - " + "\n  - ".join(exc.failures))
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
    from sqlalchemy import select
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
def report(scan_id: str) -> None:
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

    console.print_json(
        data={
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
    )


@main.command()
def environment() -> None:
    """Print the factual host capability report as JSON."""
    console.print_json(data=describe_environment(load_config()))


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
