"""The LLM layer must fail loudly and never substitute a default."""

from __future__ import annotations

import pytest

from redfall.llm import (
    JSONParseError,
    LLMError,
    Budget,
    BudgetExceeded,
    extract_json,
    model_for_tier,
    request_hash,
)


@pytest.mark.parametrize(
    "text,expected",
    [
        ('{"a": 1}', {"a": 1}),
        ('```json\n{"a": 1}\n```', {"a": 1}),
        ('Sure!\n{"a": 1}\nHope that helps.', {"a": 1}),
        ('[1, 2, 3]', [1, 2, 3]),
        ('{"note": "has } and { inside"}', {"note": "has } and { inside"}),
        ('{"q": "say \\"hi\\""}', {"q": 'say "hi"'}),
        ('{"a": 1} trailing', {"a": 1}),
    ],
)
def test_extract_json_handles_real_model_output(text, expected):
    assert extract_json(text) == expected


@pytest.mark.parametrize("text", ["", "   ", "no json at all", '{"unterminated": ', "{"])
def test_extract_json_refuses_to_guess(text):
    with pytest.raises(JSONParseError):
        extract_json(text)


def test_request_hash_is_stable_and_discriminating():
    messages = [{"role": "user", "content": "hi"}]
    assert request_hash("m", "mid", messages, 0.2) == request_hash("m", "mid", messages, 0.2)
    assert request_hash("m", "mid", messages, 0.2) != request_hash("m", "mid", messages, 0.3)
    assert request_hash("m", "mid", messages, 0.2) != request_hash("other", "mid", messages, 0.2)


def test_every_tier_resolves_to_a_real_model_id():
    for tier in ("fast", "mid", "deep"):
        assert model_for_tier(tier)
    with pytest.raises(ValueError):
        model_for_tier("gigantic")


def test_budget_raises_when_the_ceiling_is_passed():
    budget = Budget(max_tokens=1000, max_cost_usd=1.0)
    budget.add(600, 500, 0.10)
    with pytest.raises(BudgetExceeded):
        budget.check()


def test_budget_tracks_unknown_cost_without_faking_a_price():
    budget = Budget(max_tokens=10_000, max_cost_usd=1.0)
    budget.add(100, 100, None)
    budget.check()
    assert budget.cost_usd == 0.0
    assert budget.cost_unknown_calls == 1
    assert budget.tokens_used == 200


def test_a_call_without_a_provider_credential_raises(monkeypatch):
    """§1 rule 4: live calls only. No credential must mean no result."""
    from redfall.llm import LLM

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("REDFALL_MODEL_FAST", "gpt-4o-mini")

    import os

    from sqlalchemy.orm import sessionmaker

    from redfall.store.db import init_engine

    url = os.getenv("REDFALL_TEST_DATABASE_URL", "postgresql+psycopg://redfall:redfall@localhost:5432/redfall")
    Session = sessionmaker(bind=init_engine(url), expire_on_commit=False, future=True)

    llm = LLM(session_factory=Session, budget=Budget(max_tokens=1000, max_cost_usd=1.0))
    with pytest.raises(LLMError):
        llm.complete(
            messages=[{"role": "user", "content": "ping"}],
            stage="test",
            scan_id="test",
            tier="fast",
        )
