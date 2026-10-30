"""The `redfall mesh` commands, driven end to end.

The command worth testing is `check`: it must exit nonzero on a binding that
contradicts itself, so a preflight catches "the critic is the author" before a
campaign runs rather than after a report is written.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from click.testing import CliRunner

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _run(*args):
    from redfall.cli import main

    return CliRunner().invoke(main, ["mesh", *args], catch_exceptions=False)


def _json(output: str) -> dict:
    return json.loads(output[output.index("{") :])


def test_roles_lists_every_role_with_its_tools():
    payload = _json(_run("roles").output)
    roles = {entry["role"]: entry for entry in payload["roles"]}
    assert len(roles) == 8
    assert "redfall_fix_propose" in roles["fixer"]["tools"]
    assert "redfall_fix_propose" not in roles["verifier"]["tools"]


def test_check_accepts_a_separated_binding():
    result = _run("check", "--role", "exploit=codex", "--role", "critic=gemini")
    assert result.exit_code == 0
    payload = _json(result.output)
    assert payload["plan"]["default_backend"] == "claude-code"


def test_check_exits_nonzero_when_author_and_critic_share_an_agent():
    result = _run("check", "--role", "exploit=codex", "--role", "critic=codex")
    assert result.exit_code != 0
    assert "critic" in result.output


def test_check_accepts_a_collapse_when_shared_is_allowed():
    result = _run(
        "check", "--role", "exploit=codex", "--role", "critic=codex", "--allow-shared"
    )
    assert result.exit_code == 0
    payload = _json(result.output)
    assert payload["plan"]["shared_acknowledged"] is True
    assert any("critic is not independent" in w for w in payload["plan"]["warnings"])


def test_strict_refuses_an_unassigned_collapse():
    result = _run("check", "--role", "exploit=codex", "--strict")
    assert result.exit_code != 0
    assert "fall back" in result.output


def test_check_without_any_binding_is_refused():
    result = _run("check")
    assert result.exit_code != 0
    assert "at least one" in result.output


def test_a_malformed_role_flag_is_refused():
    result = _run("check", "--role", "exploit")
    assert result.exit_code != 0
    assert "role=backend" in result.output


def test_check_reads_a_config_file(tmp_path):
    config = tmp_path / "redfall.toml"
    config.write_text(
        "[mesh]\n"
        'default = "claude-code"\n'
        "\n"
        "[mesh.roles]\n"
        'exploit = "codex"\n'
        'critic = "gemini"\n',
        encoding="utf-8",
    )
    result = _run("check", "--config", str(config))
    assert result.exit_code == 0
    payload = _json(result.output)
    assert payload["plan"]["default_backend"] == "claude-code"
    exploit = next(r for r in payload["roles"] if r["role"] == "exploit")
    assert exploit["backend"] == "codex"


def test_a_config_without_a_mesh_section_is_refused(tmp_path):
    config = tmp_path / "redfall.toml"
    config.write_text("[other]\nx = 1\n", encoding="utf-8")
    result = _run("check", "--config", str(config))
    assert result.exit_code != 0
    assert "no [mesh] section" in result.output


def test_can_answers_for_a_permitted_tool():
    result = _run("can", "critic", "redfall_reproduce")
    assert result.exit_code == 0
    assert _json(result.output)["allowed"] is True


def test_can_exits_nonzero_for_a_forbidden_tool():
    result = _run("can", "verifier", "redfall_fix_propose")
    assert result.exit_code != 0
    assert "may not call" in result.output
