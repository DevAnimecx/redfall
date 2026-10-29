"""0.2.x: the `redfall agent` command group."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

SELF_AGENT = ROOT / "tests" / "harness" / "self_agent.py"


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def self_agent_config(tmp_path, monkeypatch):
    """A config that registers the real self-agent as a custom driver."""
    monkeypatch.setenv("REDFALL_CONFIG", str(tmp_path / "redfall.toml"))
    (tmp_path / "redfall.toml").write_text(
        "[backend]\nkind = \"agent\"\nagent = \"self-agent\"\n"
        "\n[[backend.options.agents]]\n"
        'name = "self-agent"\n'
        f'command = "{sys.executable.replace(chr(92), "/")}"\n'
        f'args = ["{SELF_AGENT.as_posix()}", "{{prompt}}"]\n',
        encoding="utf-8",
    )
    import redfall.agents.registry as reg

    reg.reset_registry()
    yield
    reg.reset_registry()


def _main():
    from redfall.cli import main

    return main


def test_agent_list_reports_twelve_supported(runner):
    out = runner.invoke(_main(), ["agent", "list"])
    assert out.exit_code == 0, out.output
    data = json.loads(out.output)
    assert data["supported"] == 12
    assert len(data["agents"]) == 12


def test_agent_list_shows_install_state_for_each(runner):
    data = json.loads(runner.invoke(_main(), ["agent", "list"]).output)
    for agent in data["agents"]:
        assert isinstance(agent["installed"], bool)
        assert "executable" in agent
        assert "homepage" in agent


def test_agent_detect_reports_would_use(runner, self_agent_config):
    out = runner.invoke(_main(), ["agent", "detect"])
    assert out.exit_code == 0, out.output
    data = json.loads(out.output)
    assert "self-agent" in data["detected"]
    assert data["would_use"]["name"] == "agent:self-agent"


def test_agent_certify_certifies_a_real_agent(runner, self_agent_config):
    out = runner.invoke(_main(), ["agent", "certify", "self-agent"])
    assert out.exit_code == 0, out.output
    data = json.loads(out.output)
    assert data["certified"] is True
    assert [c["name"] for c in data["checks"]] == ["installed", "answers", "json", "exit_code"]


def test_agent_certify_rejects_an_unknown_name(runner):
    out = runner.invoke(_main(), ["agent", "certify", "no-such-agent"])
    assert out.exit_code == 2
    data = json.loads(out.output)
    assert data["certified"] is False
    assert "known" in data


def test_agent_certify_writes_the_report_when_asked(runner, self_agent_config, tmp_path):
    out_file = tmp_path / "cert.json"
    out = runner.invoke(_main(), ["agent", "certify", "self-agent", "--out", str(out_file)])
    assert out.exit_code == 0
    assert json.loads(out_file.read_text(encoding="utf-8"))["certified"] is True


def test_agent_config_prints_effective_config(runner, self_agent_config):
    out = runner.invoke(_main(), ["agent", "config"])
    assert out.exit_code == 0
    data = json.loads(out.output)
    assert data["kind"] == "agent"
    assert data["agent"] == "self-agent"


def test_agent_config_write_emits_a_starter_file(runner, tmp_path):
    target = tmp_path / "starter.toml"
    out = runner.invoke(_main(), ["agent", "config", "--write", str(target)])
    assert out.exit_code == 0
    assert target.is_file()
    import tomllib

    parsed = tomllib.loads(target.read_text(encoding="utf-8"))
    assert "backend" in parsed
