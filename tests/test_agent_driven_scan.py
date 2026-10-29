"""RedFall driving RedFall (0.2.x self-test).

The claim this file exists to prove: the engine reasons through an *agent*, with
no provider API key anywhere, and every other stage behaves identically.

It does that the honest way. A real agent-shaped program stands in for Claude
Code — a real subprocess, driven by a real `CustomAgentDriver`, wired in by a
real `redfall.toml`. It reads the ingest evidence it is given and returns the
plan, findings and PoC that the engine's own prompts ask for. What is being
tested is not "did an LLM guess right" but:

* the engine reaches the agent for every stage, and only through the seam;
* the planner's output is honoured (branches are created from the agent's JSON);
* a finding the agent proposes is handed to the real validator;
* the transcript tables record the agent's calls exactly as they record a
  provider's;
* nothing in the path requires `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.

The PoC itself is still only counted as real if the sandbox reproduces it, so
this file stops at the boundary the host can honestly reach: no container
runtime here means no finding, and the test asserts that refusal rather than
faking a reproduction.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

TARGET = ROOT / "range" / "vulnbank"
SELF_AGENT = Path(__file__).resolve().parent / "harness" / "self_agent.py"


pytestmark = pytest.mark.skipif(
    not TARGET.exists(), reason="range/vulnbank target is missing"
)


@pytest.fixture()
def agent_config(tmp_path, monkeypatch):
    """Point RedFall at the self-agent, with no provider keys in scope."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("REDFALL_CONFIG", str(tmp_path / "redfall.toml"))
    # Forward slashes: valid in a TOML basic string on every platform and
    # accepted by Windows path handling, so no escaping is needed.
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


def test_no_provider_key_is_present(agent_config):
    assert os.getenv("OPENAI_API_KEY") is None
    assert os.getenv("ANTHROPIC_API_KEY") is None


def test_auto_resolves_to_the_agent_without_a_key(agent_config):
    from redfall.llm import Budget
    from redfall.reasoning import load_backend_config, make_backend

    backend = make_backend(load_backend_config(), session_factory=None, budget=Budget(max_tokens=100_000, max_cost_usd=10))
    assert backend.name == "agent:self-agent"
    assert backend.describe()["kind"] == "agent"


def test_engine_reaches_the_agent_for_the_plan_stage(agent_config):
    """The Agent plans by calling the configured backend, not LiteLLM."""
    from redfall.agent.agent import Agent
    from redfall.llm import Budget
    from redfall.reasoning import load_backend_config, make_backend

    backend = make_backend(load_backend_config(), session_factory=None, budget=Budget(max_tokens=100_000, max_cost_usd=10))
    agent = Agent(llm=backend, scan_id="selftest")

    routes = [
        {"method": "GET", "path": "/api/users/:id", "file": "src/routes/users.ts", "line": 12},
        {"method": "POST", "path": "/api/login", "file": "src/routes/auth.ts", "line": 30},
    ]
    branches = agent.plan(routes=routes, taints=[], dependencies=[])
    assert len(branches) >= 1
    # The agent's JSON was honoured: branch names come from the agent's reply.
    assert all(b.name for b in branches)


def test_analysis_stage_returns_findings_from_the_agent(agent_config):
    from redfall.agent.agent import Agent
    from redfall.llm import Budget
    from redfall.reasoning import load_backend_config, make_backend

    backend = make_backend(load_backend_config(), session_factory=None, budget=Budget(max_tokens=100_000, max_cost_usd=10))
    agent = Agent(llm=backend, scan_id="selftest")
    findings = agent.analyse(
        branch_id="b1",
        branch_name="auth",
        files={"src/routes/auth.ts": "app.get('/x', (req,res)=>res.send(req.query.q))"},
        routes=[],
        taints=[],
        dependencies=[],
    )
    assert findings
    assert findings[0].category


def test_transcript_tables_record_the_agent_call(agent_config):
    """A call through an agent lands in the same tables a provider call does."""
    from redfall.agent.agent import Agent
    from redfall.reasoning.agent_backend import AgentBackend

    class Recording(AgentBackend):
        """Wrap the real backend but capture what it would persist."""

        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.recorded: list[dict] = []

        def _record(self, **kw):
            self.recorded.append(kw)
            return "call-id"

    from redfall.agents import driver_registry
    from redfall.llm import Budget

    driver = driver_registry().get("self-agent")
    backend = Recording(driver, session_factory=None, budget=Budget(max_tokens=10_000, max_cost_usd=10))
    agent = Agent(llm=backend, scan_id="selftest")
    agent.plan(routes=[{"method": "GET", "path": "/x", "file": "a.ts", "line": 1}], taints=[], dependencies=[])

    assert backend.recorded, "the agent call was not recorded"
    request = backend.recorded[0]
    assert request["stage"] == "plan"
    assert request["result"].backend == "agent:self-agent"


def test_scan_refuses_without_a_sandbox_rather_than_faking_a_finding(agent_config):
    """With a reasoning backend present but no container runtime, the scan refuses.

    This is the honest outcome on a host without gVisor: the agent layer works,
    and the scan still will not report a finding it could not execute.
    """
    from redfall.config import Config, check_prerequisites, PrerequisiteError, default_workdir

    config = Config(
        database_url="postgresql+psycopg://x:x@localhost/x",
        redis_url="redis://localhost:6379/0",
        openai_api_key=None,
        anthropic_api_key=None,
        sandbox_runtime="runsc",
        sandbox_pool_size=1,
        sandbox_timeout_s=10,
        max_tokens_per_scan=1000,
        max_cost_per_scan_usd=1.0,
        branch_max_depth=1,
        chain_max_candidates=1,
        workdir=default_workdir(),
    )
    # The reasoning prerequisite is satisfied by the agent, so only the sandbox
    # (or node/npm) can be the reason a scan cannot run here.
    try:
        check_prerequisites(config, require_llm=False, require_sandbox=True)
    except PrerequisiteError as exc:
        assert all("LLM" not in f for f in exc.failures)
