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


def _run_threads(fn, count: int) -> list[object]:
    """Run `fn(i)` on `count` threads released together, and collect what they return.

    Each thread's return value (or the exception it raised) lands in the result
    list, so the caller can assert on the outcomes rather than on thread state.

    A short switch interval maximises interleaving. On CPython it is not enough
    to make an unguarded `+=` lose an update — the GIL does not release inside
    one attribute update — so these tests pin the required behaviour under
    concurrency rather than reproducing a failure on this interpreter. They are
    what would catch a regression on a free-threaded build, or if the counters
    ever became a non-atomic type or the check and the write drifted apart.
    """
    import sys
    import threading

    results: list[object] = [None] * count
    barrier = threading.Barrier(count)

    def worker(index: int) -> None:
        try:
            results[index] = fn(index)
        except BaseException as err:  # noqa: BLE001 - recorded, asserted by the caller
            results[index] = err

    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        sys.setswitchinterval(previous)
    return results


def test_budget_loses_no_spend_when_branches_run_concurrently():
    """Branches share one budget, so a lost increment erases real spend.

    `+=` on a plain attribute is read-modify-write. Under the GIL this happens
    not to interleave, but the lock is what makes that a guarantee rather than
    an accident — and this is the property a parallel scan depends on.
    """
    budget = Budget(max_tokens=10_000_000, max_cost_usd=1000.0)
    per_call, threads = 3, 16

    _run_threads(lambda _i: budget.record(per_call, 0, 0.001), threads)

    assert budget.tokens_used == per_call * threads
    assert budget.calls == threads
    assert budget.cost_usd == pytest.approx(0.001 * threads)


def test_concurrent_record_cannot_let_the_scan_exceed_its_ceiling():
    """check-then-add must be indivisible, or two branches both pass it.

    Each call fits under the ceiling on its own, but they do not all fit
    together. If the spend and the check are separate steps — or if two threads
    read the total before either writes it — more calls get through than the
    budget permits.
    """
    budget = Budget(max_tokens=1000, max_cost_usd=1000.0)
    threads = 16

    outcomes = _run_threads(lambda _i: budget.record(300, 0, 0.0), threads)
    admitted = [o for o in outcomes if o is None]
    refused = [o for o in outcomes if isinstance(o, BudgetExceeded)]

    # 300 tokens a call under a 1000 ceiling: exactly three fit before the
    # fourth breaches it. Every other call must be refused — that is the
    # ceiling holding under concurrency, which is the property under test.
    assert len(admitted) == 3, f"{len(admitted)} calls passed a 1000-token ceiling"
    assert len(refused) == threads - 3
    # `record` adds before it checks, so a refused call still counts its spend:
    # the total is what was genuinely spent (16 × 300), not a clamped 900. The
    # numbers stay honest so a report can show the overshoot that a refusal
    # implies. Ordering is the lock's job; accuracy is this method's.
    assert budget.tokens_used == 300 * threads
    assert budget.calls == threads


def test_a_call_without_a_provider_credential_raises(monkeypatch, postgres_url):
    """§1 rule 4: live calls only. No credential must mean no result."""
    from redfall.llm import LLM

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("REDFALL_MODEL_FAST", "gpt-4o-mini")

    from sqlalchemy.orm import sessionmaker

    from redfall.store.db import init_engine

    Session = sessionmaker(bind=init_engine(postgres_url), expire_on_commit=False, future=True)

    llm = LLM(session_factory=Session, budget=Budget(max_tokens=1000, max_cost_usd=1.0))
    with pytest.raises(LLMError):
        llm.complete(
            messages=[{"role": "user", "content": "ping"}],
            stage="test",
            scan_id="test",
            tier="fast",
        )
