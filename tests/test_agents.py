"""0.2.x: the agent driver layer.

These point real drivers at a real (tiny) agent program and assert on what
comes back. Nothing here simulates an agent; `harness/fake_agent.py` is an
actual subprocess.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

FAKE_AGENT = ROOT / "tests" / "harness" / "fake_agent.py"


def _custom_spec(**over):
    spec = {
        "name": "fake",
        "command": sys.executable,
        "args": [str(FAKE_AGENT), "--prompt", "{prompt}"],
        "json_path": None,
    }
    spec.update(over)
    return spec


def test_registry_has_twelve_drivers():
    from redfall.agents import driver_registry

    registry = driver_registry()
    assert len(registry.names()) == 12
    assert registry.names() == sorted(registry.names())


def test_registry_names_are_stable():
    from redfall.agents import driver_registry

    expected = {
        "claude-code", "codex", "gemini-cli", "aider", "cursor", "goose",
        "openhands", "continue", "cline", "kilo", "qwen-code", "crush",
    }
    assert set(driver_registry().names()) == expected


def test_every_driver_describes_itself():
    from redfall.agents import driver_registry

    for driver in driver_registry().all():
        described = driver.describe()
        assert described["name"] == driver.name
        assert isinstance(described["installed"], bool)
        assert "capabilities" in described


def test_custom_driver_runs_a_real_subprocess_and_reads_stdout():
    from redfall.agents.custom import CustomAgentDriver

    driver = CustomAgentDriver.from_spec(_custom_spec())
    assert driver.available()
    result = driver.invoke("say hello")
    assert result.exit_code == 0
    assert result.text.strip() == "ready"


def test_custom_driver_passes_prompt_on_stdin_without_placeholder():
    from redfall.agents.custom import CustomAgentDriver

    driver = CustomAgentDriver.from_spec(
        {"name": "stdin-agent", "command": sys.executable, "args": [str(FAKE_AGENT)]}
    )
    result = driver.invoke("json please")
    assert json.loads(result.text) == {"ok": True, "value": 42}


def test_custom_driver_extracts_reply_from_json_envelope():
    from redfall.agents.custom import CustomAgentDriver

    driver = CustomAgentDriver.from_spec(
        _custom_spec(json_path="result.content")
    )
    # The fake agent prints a bare object; json_path therefore does not match,
    # which must leave the text untouched rather than emptying it.
    result = driver.invoke("json please")
    assert json.loads(result.text) == {"ok": True, "value": 42}


def test_custom_driver_rejects_spec_without_command():
    from redfall.agents.custom import CustomAgentDriver

    with pytest.raises(ValueError):
        CustomAgentDriver.from_spec({"name": "broken"})


def test_custom_driver_rejects_spec_without_name():
    from redfall.agents.custom import CustomAgentDriver

    with pytest.raises(ValueError):
        CustomAgentDriver.from_spec({"command": "x"})


def test_missing_agent_reports_install_hint_not_a_crash():
    from redfall.agents.driver import AgentNotInstalled, AgentDriver

    class Missing(AgentDriver):
        name = "does-not-exist"
        title = "Missing"

        def executable(self):
            return None

        def command(self, prompt, *, model):
            return [], None

    driver = Missing()
    assert driver.available() is False
    with pytest.raises(AgentNotInstalled) as caught:
        driver.require()
    assert "install" in str(caught.value).lower()


def test_prompt_is_never_shell_interpolated():
    """A prompt containing shell metacharacters must reach the agent intact."""
    from redfall.agents.custom import CustomAgentDriver

    driver = CustomAgentDriver.from_spec(_custom_spec())
    hostile = "hello; rm -rf / && echo $(whoami) `id` | cat /etc/passwd"
    argv, stdin = driver.command(hostile, model=None)
    # The metacharacters survive as literal characters inside one argv element.
    assert any(hostile in part for part in argv)
    assert stdin is None


def test_certify_passes_against_a_real_conforming_agent():
    from redfall.agents.certify import certify_driver
    from redfall.agents.custom import CustomAgentDriver

    # The fake agent answers text and, when asked for JSON, emits JSON.
    driver = CustomAgentDriver.from_spec(_custom_spec())
    report = certify_driver(driver, timeout_s=60)
    assert report.certified, report.as_dict()
    names = [c.name for c in report.checks]
    assert names == ["installed", "answers", "json", "exit_code"]


def test_certify_refuses_when_agent_is_not_installed():
    from redfall.agents.certify import certify_driver
    from redfall.agents.driver import AgentDriver

    class Missing(AgentDriver):
        name = "nope"
        title = "Nope"

        def executable(self):
            return None

        def command(self, prompt, *, model):
            return [], None

    report = certify_driver(Missing(), timeout_s=10)
    assert report.certified is False
    assert report.checks[0].name == "installed"
    assert report.checks[0].passed is False


def test_agent_not_installed_is_reported_by_backend():
    from redfall.agents.driver import AgentDriver
    from redfall.reasoning.agent_backend import AgentBackend
    from redfall.llm import Budget

    class Missing(AgentDriver):
        name = "nope"
        title = "Nope"

        def executable(self):
            return None

        def command(self, prompt, *, model):
            return [], None

    backend = AgentBackend(Missing(), session_factory=None, budget=Budget(max_tokens=10, max_cost_usd=1))
    assert backend.available() is False
    assert backend.describe()["kind"] == "agent"


def test_agent_tools_are_registered():
    """An external agent can discover RedFall's reasoning layer over MCP/HTTP."""
    from redfall.interop.tools import ToolRegistry

    registry = ToolRegistry(lambda: None)
    names = [spec["name"] for spec in registry.specs()]
    assert "redfall_agents_list" in names
    assert "redfall_reasoning_describe" in names


def test_agents_list_tool_reports_supported_and_installed():
    from redfall.interop.tools import ToolRegistry

    out = ToolRegistry(lambda: None).call("redfall_agents_list", {})
    assert out["supported"] == 12
    assert isinstance(out["installed"], list)
    assert len(out["agents"]) == 12


def test_reasoning_describe_tool_reports_the_effective_backend():
    from redfall.interop.tools import ToolRegistry

    out = ToolRegistry(lambda: None).call("redfall_reasoning_describe", {})
    assert "config" in out
    # Either a backend resolved, or the reason it did not is stated.
    assert out.get("backend") is not None or out.get("error")
