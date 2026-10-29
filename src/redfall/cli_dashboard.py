"""`redfall dashboard` (0.3.0).

Starts the live control-plane API the Next.js console talks to. Binds loopback
by default: this is a single-operator console, and the safe default is that it
is not reachable from the network unless the operator says so. Setting a token
is required to bind a non-loopback address, so an exposed dashboard is never
unauthenticated by accident.
"""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path

import click

from .store.db import init_engine


@click.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Address to bind.")
@click.option("--port", default=8787, show_default=True, type=int, help="Port to bind (0 picks a free one).")
@click.option("--token", default=None, help="Bearer token. Defaults to $REDFALL_DASHBOARD_TOKEN.")
@click.option(
    "--project",
    "projects",
    multiple=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="A directory the dashboard may scan. Repeatable. Without it, any target is allowed.",
)
def dashboard(host: str, port: int, token: str | None, projects: tuple[Path, ...]) -> None:
    """Serve the live dashboard API and event stream."""
    from .config import load_config
    from .dashboard import serve_dashboard
    from .interop.tools import ToolRegistry

    token = token or os.getenv("REDFALL_DASHBOARD_TOKEN")

    # Refuse an exposed, unauthenticated dashboard rather than silently binding.
    if not _is_loopback(host) and not token:
        raise click.ClickException(
            f"refusing to bind {host} without a token: set --token or "
            "REDFALL_DASHBOARD_TOKEN, or bind loopback (the default)"
        )

    config = load_config()
    engine = init_engine(config.database_url)
    from sqlalchemy.orm import sessionmaker

    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    registry = ToolRegistry(SessionLocal)

    roots = [str(p.resolve()) for p in projects] or None
    server = serve_dashboard(
        host=host,
        port=port,
        registry=registry,
        token=token,
        projects=roots,
    )
    bound_host, bound_port = server.server_address[:2]
    click.echo(
        json.dumps(
            {
                "dashboard": f"http://{bound_host}:{bound_port}",
                "auth": "bearer" if token else "none (loopback)",
                "projects": roots or "any (no --project given)",
                "events": "/api/scans/{id}/events",
            },
            indent=2,
        )
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        click.echo("\nstopping dashboard")
    finally:
        server.server_close()


def _is_loopback(host: str) -> bool:
    if host in {"localhost", ""}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


__all__ = ["dashboard"]
