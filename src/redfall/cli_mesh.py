"""`redfall mesh` — inspect the agent mesh and check a binding before using it.

`redfall mesh check` is the command worth having: it takes the same config the
engine would read and reports what topology it produces, which roles share an
agent, and which separation constraints are only satisfied by luck. An operator
can run it before a campaign instead of discovering after one that the critic
was the author.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from .mesh.binding import BindingError, bind_from_config, mesh_summary, plan_for
from .mesh.roles import MeshError, describe_roles


def _emit(payload: object, out: Path | None) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True)
    if out is not None:
        out.write_text(text + "\n", encoding="utf-8")
        click.echo(f"wrote {out}")
    else:
        click.echo(text)


@click.group()
def mesh() -> None:
    """The agent mesh: roles, their tools, and which agent plays each."""


@mesh.command("roles")
def mesh_roles() -> None:
    """Print every role, what it does and which tools it may call."""
    _emit({"roles": describe_roles()}, None)


@mesh.command("check")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None, help="A redfall.toml to read the [mesh] section from.")
@click.option("--default", "default_backend", default="claude-code", show_default=True, help="Backend for unbound roles.")
@click.option("--role", "role_bindings", multiple=True, help="Bind one role: --role exploit=codex. Repeatable.")
@click.option("--allow-shared", is_flag=True, help="Accept an author/critic collapse, recording the weaker guarantee.")
@click.option("--strict", is_flag=True, help="Treat an unassigned-role collapse as an error too.")
def mesh_check(
    config_path: Path | None,
    default_backend: str,
    role_bindings: tuple[str, ...],
    allow_shared: bool,
    strict: bool,
) -> None:
    """Build the plan from a config and report the topology it produces.

    Exits nonzero when the binding contradicts itself, so a scripted preflight
    fails loudly instead of producing a report nobody read the warnings of.
    """
    assignments: dict[str, str] = {}
    for item in role_bindings:
        if "=" not in item:
            raise click.ClickException(f"--role expects role=backend, got {item!r}")
        role, backend = item.split("=", 1)
        assignments[role.strip()] = backend.strip()

    try:
        if config_path is not None:
            try:
                import tomllib
            except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
                raise click.ClickException("reading a config requires Python 3.11+") from None
            document = tomllib.loads(config_path.read_text(encoding="utf-8"))
            section = document.get("mesh")
            if not isinstance(section, dict):
                raise click.ClickException(f"{config_path}: no [mesh] section")
            if default_backend == "claude-code":
                default_backend = str(section.get("default") or default_backend)
            plan = bind_from_config({**section, "allow_shared": allow_shared or section.get("allow_shared", False)})
        else:
            if not assignments:
                raise click.ClickException("name at least one --role, or pass --config")
            plan = plan_for(
                assignments,
                default_backend=default_backend,
                allow_shared=allow_shared,
                check_unassigned=strict,
            )
    except (BindingError, MeshError) as err:
        raise click.ClickException(str(err)) from err

    _emit(mesh_summary(plan), None)


@mesh.command("can")
@click.argument("role")
@click.argument("tool")
def mesh_can(role: str, tool: str) -> None:
    """Whether a role may call a tool, and the reason either way."""
    from .mesh.roles import check_tool

    try:
        check_tool(role, tool)
    except MeshError as err:
        # The refusal *is* the answer, so it goes out once as the error rather
        # than twice — a JSON body followed by a duplicate message is not
        # machine-readable, and this command is meant to be scripted.
        raise click.ClickException(str(err)) from err
    _emit({"role": role, "tool": tool, "allowed": True, "reason": "within the role's allowlist"}, None)
