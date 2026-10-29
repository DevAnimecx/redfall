"""The `redfall agent` command group (0.2.2 / 0.2.7).

Three verbs: `list` what RedFall can drive, `detect` which are actually on this
host, and `certify` one by running it for real. Certification is the same idea as
`redfall mcp certify`: a fresh process, one real task, one refusal case, and a
stored result that names exactly what was proven.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from .agents import AgentError, driver_registry
from .agents.certify import certify_driver
from .reasoning.config import load_backend_config, render_default_config


@click.group()
def agent() -> None:
    """Drive an installed agent as RedFall's reasoning backend."""


@agent.command("list")
def agent_list() -> None:
    """List the supported agents and whether each is installed here."""
    registry = driver_registry()
    rows = []
    for driver in registry.all():
        described = driver.describe()
        rows.append(
            {
                "name": described["name"],
                "title": described["title"],
                "installed": described["installed"],
                "executable": described["executable"],
                "version": described["version"],
                "homepage": described["homepage"],
            }
        )
    installed = [r["name"] for r in rows if r["installed"]]
    click.echo(
        json.dumps(
            {
                "supported": len(rows),
                "installed": installed,
                "agents": rows,
            },
            indent=2,
        )
    )


@agent.command("detect")
def agent_detect() -> None:
    """Print the agents installed on this host and the backend that would be used."""
    registry = driver_registry()
    detected = registry.detected()
    config = load_backend_config()
    result: dict[str, object] = {
        "detected": detected,
        "config": config.as_dict(),
    }
    try:
        from .reasoning import make_backend

        backend = make_backend(config, session_factory=None, budget=None)
        result["would_use"] = backend.describe()
    except Exception as exc:  # noqa: BLE001 - detect reports, it does not crash
        result["would_use"] = None
        result["error"] = str(exc)
    click.echo(json.dumps(result, indent=2, default=str))


@agent.command("certify")
@click.argument("name")
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None, help="Write the certification JSON here.")
@click.option("--timeout", "timeout_s", type=int, default=180, help="Per-invocation timeout in seconds.")
def agent_certify(name: str, out_path: Path | None, timeout_s: int) -> None:
    """Run one agent for real and record what it proved."""
    registry = driver_registry()
    driver = registry.get(name)
    if driver is None:
        click.echo(
            json.dumps(
                {"certified": False, "error": f"unknown agent {name!r}", "known": registry.names()},
                indent=2,
            )
        )
        raise SystemExit(2)

    try:
        report = certify_driver(driver, timeout_s=timeout_s)
    except AgentError as exc:
        click.echo(json.dumps({"certified": False, "agent": name, "error": str(exc)}, indent=2))
        raise SystemExit(2) from None

    data = report.as_dict()
    if out_path:
        out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        click.echo(f"certification written to {out_path}")
    click.echo(json.dumps(data, indent=2, default=str))
    if not report.certified:
        raise SystemExit(2)


@agent.command("config")
@click.option("--write", "write_path", type=click.Path(path_type=Path), default=None, help="Write a starter redfall.toml here.")
def agent_config(write_path: Path | None) -> None:
    """Show the effective backend config, or write a starter file."""
    if write_path is not None:
        write_path.write_text(render_default_config(), encoding="utf-8")
        click.echo(f"wrote {write_path}")
        return
    config = load_backend_config()
    click.echo(json.dumps(config.as_dict(), indent=2, default=str))


__all__ = ["agent"]
