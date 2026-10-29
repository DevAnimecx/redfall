"""0.2.x: the shape of each shipped driver's command.

These do not run the agents (they are not installed in CI). They assert on what
each driver would run, which is where the two guarantees live: the prompt is a
single argv element or on stdin, and a model flag only appears when a model is
given.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from redfall.agents import driver_registry  # noqa: E402

PROMPT = "analyse this: res.send(req.query.q); rm -rf / # not a command"

#: driver name -> the argv[0] token that must follow the executable.
EXPECTED_HEAD = {
    "claude-code": "-p",
    "codex": "exec",
    "gemini-cli": "-p",
    "aider": "--message",
    "cursor": "-p",
    "goose": "run",
    "openhands": "--headless",
    "continue": "-p",
    "cline": "-p",
    "kilo": "-p",
    "qwen-code": "-p",
    "crush": "run",
}


def test_every_driver_is_in_the_head_map():
    assert set(driver_registry().names()) == set(EXPECTED_HEAD)


@pytest.mark.parametrize("name", sorted(EXPECTED_HEAD))
def test_driver_command_head_is_its_real_entry_point(name):
    driver = driver_registry().get(name)
    argv, _stdin = driver.command(PROMPT, model=None)
    assert argv, f"{name} produced no argv"
    assert argv[0] == EXPECTED_HEAD[name], f"{name}: {argv}"


@pytest.mark.parametrize("name", sorted(EXPECTED_HEAD))
def test_prompt_reaches_the_agent_intact_or_on_stdin(name):
    """The prompt is never shell-split: it is one argv element or stdin."""
    driver = driver_registry().get(name)
    argv, stdin = driver.command(PROMPT, model=None)
    if stdin is not None:
        assert stdin == PROMPT
        # Nothing in argv should carry the prompt when it goes on stdin.
        assert not any(PROMPT in part for part in argv)
    else:
        assert any(PROMPT in part for part in argv), f"{name} dropped the prompt"


@pytest.mark.parametrize("name", sorted(EXPECTED_HEAD))
def test_model_flag_is_absent_without_a_model(name):
    driver = driver_registry().get(name)
    argv, _ = driver.command(PROMPT, model=None)
    assert "claude-sonnet-4-5" not in argv


@pytest.mark.parametrize("name", sorted(EXPECTED_HEAD))
def test_driver_reports_capabilities(name):
    described = driver_registry().get(name).describe()
    caps = described["capabilities"]
    assert isinstance(caps["long_context"], bool)
    assert isinstance(caps["stateless"], bool)


def test_bin_override_is_honoured(monkeypatch):
    """A non-PATH install can be pointed at with REDFALL_*_BIN."""
    monkeypatch.setenv("REDFALL_CODEX_BIN", "/opt/custom/codex")
    import importlib

    import redfall.agents.drivers.codex as codex_mod

    importlib.reload(codex_mod)
    assert codex_mod.CodexDriver().executable() == "/opt/custom/codex"
    importlib.reload(codex_mod)
