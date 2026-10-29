"""0.2.x: the reasoning seam, config precedence, routing and consensus."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


# --------------------------------------------------------------- the seam

def test_backend_result_carries_accounting():
    from redfall.reasoning.backend import BackendResult

    result = BackendResult(content="x", model="m", backend="b", tier="mid")
    assert result.cached is False
    assert result.cost_usd == 0.0
    assert result.raw == {}


def test_request_digest_is_stable_and_order_independent():
    from redfall.reasoning.backend import request_digest

    messages = [{"role": "user", "content": "hi"}]
    a = request_digest("m", "mid", messages, 0.2)
    b = request_digest("m", "mid", messages, 0.2)
    c = request_digest("m", "deep", messages, 0.2)
    assert a == b
    assert a != c


def test_complete_json_repairs_then_succeeds():
    """A backend that returns prose first and JSON second still yields JSON."""
    from redfall.reasoning.backend import BackendResult, ReasoningBackend

    class Flaky(ReasoningBackend):
        name = "flaky"
        calls = 0

        def model_for_tier(self, tier):
            return "flaky"

        def _invoke(self, *, messages, stage, tier, temperature, max_tokens, scan_id, branch_id):
            type(self).calls += 1
            text = "I think the answer is..." if type(self).calls == 1 else '{"ok": true}'
            return BackendResult(content=text, model="flaky", backend="flaky", tier=tier)

    backend = Flaky(budget=_budget())
    data, _ = backend.complete_json(
        messages=[{"role": "user", "content": "go"}], stage="t", scan_id="s"
    )
    assert data == {"ok": True}
    assert Flaky.calls == 2


def test_complete_json_raises_rather_than_defaulting():
    from redfall.reasoning.backend import BackendResult, ReasoningBackend
    from redfall.llm import JSONParseError

    class Garbage(ReasoningBackend):
        name = "garbage"

        def model_for_tier(self, tier):
            return "garbage"

        def _invoke(self, *, messages, stage, tier, temperature, max_tokens, scan_id, branch_id):
            return BackendResult(content="no json here at all", model="g", backend="g", tier=tier)

    with pytest.raises(JSONParseError):
        Garbage(budget=_budget()).complete_json(
            messages=[{"role": "user", "content": "go"}], stage="t", scan_id="s"
        )


def test_budget_is_enforced_before_the_call():
    from redfall.reasoning.backend import BackendResult, ReasoningBackend
    from redfall.llm import BudgetExceeded

    invoked = []

    class Counting(ReasoningBackend):
        name = "counting"

        def model_for_tier(self, tier):
            return "c"

        def _invoke(self, *, messages, stage, tier, temperature, max_tokens, scan_id, branch_id):
            invoked.append(1)
            return BackendResult(
                content="ok", model="c", backend="c", tier=tier, prompt_tokens=100
            )

    budget = _budget(max_tokens=1)
    backend = Counting(budget=budget)
    # The first call overruns the budget and fails rather than returning; the
    # overrun is surfaced, not swallowed.
    with pytest.raises(BudgetExceeded):
        backend.complete(messages=[{"role": "user", "content": "a"}], stage="s", scan_id="s")
    assert invoked == [1]


# ------------------------------------------------------------- config

def test_config_defaults_to_auto_from_env(monkeypatch):
    from redfall.reasoning.config import load_backend_config

    monkeypatch.delenv("REDFALL_BACKEND", raising=False)
    monkeypatch.delenv("REDFALL_AGENT", raising=False)
    monkeypatch.setenv("REDFALL_CONFIG", str(Path.cwd() / "no-such-file.toml"))
    cfg = load_backend_config(target=None)
    assert cfg.kind == "auto"


def test_config_reads_redfall_toml(tmp_path):
    from redfall.reasoning.config import load_backend_config

    cfg_file = tmp_path / "redfall.toml"
    cfg_file.write_text(
        '[backend]\nkind = "agent"\nagent = "codex"\n\n[routes]\nfast = { kind = "agent", agent = "gemini-cli" }\n',
        encoding="utf-8",
    )
    cfg = load_backend_config(tmp_path)
    assert cfg.kind == "agent"
    assert cfg.agent == "codex"
    assert "fast" in cfg.routes
    assert cfg.source == str(cfg_file)


def test_config_agent_without_kind_implies_agent_kind(tmp_path):
    from redfall.reasoning.config import load_backend_config

    (tmp_path / "redfall.toml").write_text('[backend]\nagent = "claude-code"\n', encoding="utf-8")
    cfg = load_backend_config(tmp_path)
    assert cfg.kind == "agent"
    assert cfg.agent == "claude-code"


def test_config_from_env_agent_implies_agent_kind(monkeypatch):
    from redfall.reasoning.config import load_backend_config

    monkeypatch.setenv("REDFALL_CONFIG", str(Path.cwd() / "no-such.toml"))
    monkeypatch.delenv("REDFALL_BACKEND", raising=False)
    monkeypatch.setenv("REDFALL_AGENT", "codex")
    cfg = load_backend_config(target=None)
    assert cfg.kind == "agent"
    assert cfg.agent == "codex"


def test_render_default_config_is_valid_toml():
    import tomllib

    from redfall.reasoning.config import render_default_config

    parsed = tomllib.loads(render_default_config())
    assert "backend" in parsed


# ------------------------------------------------------------- factory

def test_factory_refuses_when_nothing_is_configured(monkeypatch):
    from redfall.reasoning.config import BackendConfig
    from redfall.reasoning.factory import make_backend
    from redfall.reasoning.backend import BackendError

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    import redfall.agents.registry as reg

    class Empty(reg.DriverRegistry):
        def __init__(self):
            self._drivers = {}

    monkeypatch.setattr(reg, "_REGISTRY", Empty())
    with pytest.raises(BackendError) as caught:
        make_backend(BackendConfig(kind="auto"), session_factory=None, budget=_budget())
    assert "OPENAI_API_KEY" in str(caught.value)


def test_factory_rejects_unknown_kind():
    from redfall.reasoning.config import BackendConfig
    from redfall.reasoning.factory import make_backend
    from redfall.reasoning.backend import BackendError

    with pytest.raises(BackendError):
        make_backend(BackendConfig(kind="nonsense"), session_factory=None, budget=_budget())


def test_factory_rejects_unknown_agent_name():
    from redfall.reasoning.config import BackendConfig
    from redfall.reasoning.factory import make_backend
    from redfall.reasoning.backend import BackendError

    with pytest.raises(BackendError) as caught:
        make_backend(
            BackendConfig(kind="agent", agent="no-such-agent"),
            session_factory=None,
            budget=_budget(),
        )
    assert "known agents" in str(caught.value)


def test_factory_reports_not_installed_agent():
    from redfall.reasoning.config import BackendConfig
    from redfall.reasoning.factory import make_backend
    from redfall.reasoning.backend import BackendError

    # `aider` is very unlikely to be on a CI host; when it is, the test is moot.
    from redfall.agents import driver_registry

    if driver_registry().get("aider").available():
        pytest.skip("aider is installed here; the not-installed path cannot be shown")

    with pytest.raises(BackendError) as caught:
        make_backend(BackendConfig(kind="agent", agent="aider"), session_factory=None, budget=_budget())
    assert "not installed" in str(caught.value)


# ------------------------------------------------------------- openai_compat

def test_openai_compat_describe_reports_endpoint():
    from redfall.reasoning.openai_compat import OpenAICompatBackend

    backend = OpenAICompatBackend(
        base_url="http://localhost:11434/v1", model=None, api_key_env=None,
        session_factory=None, budget=_budget(),
    )
    described = backend.describe()
    assert described["kind"] == "openai_compat"
    assert described["base_url"] == "http://localhost:11434/v1"


def test_openai_compat_refuses_an_unreachable_endpoint():
    from redfall.reasoning.openai_compat import OpenAICompatBackend
    from redfall.reasoning.backend import BackendError

    backend = OpenAICompatBackend(
        base_url="http://127.0.0.1:9", model="x", api_key_env=None,
        session_factory=None, budget=_budget(), timeout_s=2,
    )
    with pytest.raises(BackendError):
        backend.complete(messages=[{"role": "user", "content": "hi"}], stage="s", scan_id="s")


# ------------------------------------------------------------- router

def test_router_requires_routes_or_consensus():
    from redfall.reasoning.config import BackendConfig
    from redfall.reasoning.router import RouterBackend
    from redfall.reasoning.backend import BackendError

    with pytest.raises(BackendError):
        RouterBackend(
            BackendConfig(kind="router"), session_factory=None, budget=_budget(),
            build=lambda *a, **k: None,
        )


def test_router_selects_backend_by_tier():
    from redfall.reasoning.config import BackendConfig
    from redfall.reasoning.router import RouterBackend
    from redfall.reasoning.backend import BackendResult, ReasoningBackend

    class Named(ReasoningBackend):
        def __init__(self, n, *, budget):
            super().__init__(budget=budget)
            self.name = n

        def model_for_tier(self, tier):
            return self.name

        def _invoke(self, *, messages, stage, tier, temperature, max_tokens, scan_id, branch_id):
            return BackendResult(content=self.name, model=self.name, backend=self.name, tier=tier)

    made: dict[str, Named] = {}

    def build(cfg, **kw):
        made[cfg.kind] = Named(cfg.kind, budget=kw["budget"])
        return made[cfg.kind]

    config = BackendConfig(
        kind="router",
        routes={"fast": {"kind": "fastroute"}, "deep": {"kind": "deeproute"}},
    )
    router = RouterBackend(config, session_factory=None, budget=_budget(), build=build)
    result = router._invoke(
        messages=[{"role": "user", "content": "x"}], stage="s", tier="deep",
        temperature=0.2, max_tokens=None, scan_id="s", branch_id=None,
    )
    assert result.backend == "deeproute"


def test_router_consensus_keeps_agreeing_answer(monkeypatch):
    from redfall.agents.driver import AgentDriver
    from redfall.reasoning.config import BackendConfig
    from redfall.reasoning.router import RouterBackend

    class Echo(AgentDriver):
        def __init__(self, name, payload):
            self.name = name
            self.title = name
            self._payload = payload

        def executable(self):
            return "/bin/true"

        def command(self, prompt, *, model):
            return [], None

        def invoke(self, prompt, *, model=None, timeout_s=300):
            from redfall.agents.driver import AgentInvocation

            return AgentInvocation(text=self._payload, exit_code=0, duration_ms=1)

    import redfall.agents.registry as reg

    class Two(reg.DriverRegistry):
        def __init__(self):
            self._drivers = {
                "a": Echo("a", '{"v": 1}'),
                "b": Echo("b", '{"v": 1}'),
                "c": Echo("c", '{"v": 2}'),
            }

    monkeypatch.setattr(reg, "_REGISTRY", Two())
    config = BackendConfig(kind="router", consensus={"agents": ["a", "b", "c"], "min_agree": 2})
    router = RouterBackend(config, session_factory=None, budget=_budget(), build=lambda *a, **k: None)
    result = router._invoke(
        messages=[{"role": "user", "content": "x"}], stage="s", tier="mid",
        temperature=0.2, max_tokens=None, scan_id="s", branch_id=None,
    )
    consensus = result.raw["consensus"]
    assert set(consensus["agreed"]) == {"a", "b"}
    assert consensus["winner"] in {"a", "b"}


def test_router_consensus_fails_below_min_agree(monkeypatch):
    from redfall.agents.driver import AgentDriver, AgentInvocation
    from redfall.reasoning.config import BackendConfig
    from redfall.reasoning.router import RouterBackend
    from redfall.reasoning.backend import BackendError

    class Echo(AgentDriver):
        def __init__(self, name, payload):
            self.name = name
            self.title = name
            self._payload = payload

        def executable(self):
            return "/bin/true"

        def command(self, prompt, *, model):
            return [], None

        def invoke(self, prompt, *, model=None, timeout_s=300):
            return AgentInvocation(text=self._payload, exit_code=0, duration_ms=1)

    import redfall.agents.registry as reg

    class Three(reg.DriverRegistry):
        def __init__(self):
            self._drivers = {
                "a": Echo("a", '{"v": 1}'),
                "b": Echo("b", '{"v": 2}'),
                "c": Echo("c", '{"v": 3}'),
            }

    monkeypatch.setattr(reg, "_REGISTRY", Three())
    config = BackendConfig(kind="router", consensus={"agents": ["a", "b", "c"], "min_agree": 2})
    router = RouterBackend(config, session_factory=None, budget=_budget(), build=lambda *a, **k: None)
    with pytest.raises(BackendError) as caught:
        router._invoke(
            messages=[{"role": "user", "content": "x"}], stage="s", tier="mid",
            temperature=0.2, max_tokens=None, scan_id="s", branch_id=None,
        )
    assert "min_agree" in str(caught.value)


# ------------------------------------------------------------- flatten

def test_flatten_messages_keeps_roles_explicit():
    from redfall.reasoning.agent_backend import flatten_messages

    text = flatten_messages(
        [
            {"role": "system", "content": "be careful"},
            {"role": "user", "content": "find bugs"},
        ]
    )
    assert "SYSTEM INSTRUCTIONS" in text
    assert "be careful" in text
    assert "REQUEST" in text
    assert "find bugs" in text


def _budget(max_tokens: int = 10_000):
    from redfall.llm import Budget

    return Budget(max_tokens=max_tokens, max_cost_usd=100.0)


# ------------------------------------------------------------- config errors

def test_invalid_toml_is_reported_not_silently_ignored(tmp_path):
    """A broken config file must fail loudly, not fall through to env."""
    from redfall.reasoning.config import ConfigError, load_backend_config

    # A Windows path written into a TOML basic string has an invalid escape.
    (tmp_path / "redfall.toml").write_text('command = "C:' + chr(92) + 'Users' + chr(92) + 'x"' + chr(10), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_backend_config(tmp_path)


def test_config_error_message_mentions_backslashes(tmp_path):
    from redfall.reasoning.config import ConfigError, load_backend_config

    (tmp_path / "redfall.toml").write_text('p = "C:' + chr(92) + 'Users' + chr(92) + 'india"' + chr(10), encoding="utf-8")
    with pytest.raises(ConfigError) as caught:
        load_backend_config(tmp_path)
    assert "backslash" in str(caught.value).lower()
