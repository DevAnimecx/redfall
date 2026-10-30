"""The normalised digest must ignore only differences the provider cannot see.

Every pair this collapses is a prompt the provider would treat as identical, so
reusing the first answer for the second is sound. Every pair it keeps apart is a
prompt that differs in a way the model could react to, so reusing would be
guessing — and a guessed answer in this engine becomes a finding.

The tests are therefore as much about what must NOT match as about what must.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from redfall.reasoning.backend import request_digest, semantic_digest


def _d(messages, *, model="m", tier="mid", temperature=0.2):
    return semantic_digest(model, tier, messages, temperature)


def _exact(messages, *, model="m", tier="mid", temperature=0.2):
    return request_digest(model, tier, messages, temperature)


# -- what must match -------------------------------------------------------

def test_json_key_order_does_not_change_the_digest():
    """Serialising the same object with different key order is not a new question."""
    a = [{"role": "user", "content": '{"b": 1, "a": 2}'}]
    b = [{"role": "user", "content": '{"a":2,"b":1}'}]
    assert _d(a) == _d(b)


def test_surrounding_whitespace_does_not_change_the_digest():
    a = [{"role": "user", "content": '{"a": 2, "b": 1}'}]
    b = [{"role": "user", "content": '  {"a": 2, "b": 1}  \n'}]
    assert _d(a) == _d(b)


def test_a_nested_json_object_is_canonicalised_at_every_level():
    a = [{"role": "user", "content": '{"outer": {"y": 1, "x": 2}}'}]
    b = [{"role": "user", "content": '{"outer":{"x":2,"y":1}}'}]
    assert _d(a) == _d(b)


def test_a_json_array_body_is_canonicalised():
    a = [{"role": "user", "content": '[{"b": 1, "a": 2}]'}]
    b = [{"role": "user", "content": '[{"a":2,"b":1}]'}]
    assert _d(a) == _d(b)


# -- what must NOT match ---------------------------------------------------

def test_different_values_do_not_match():
    """The failure that matters: two different questions, one answer."""
    a = [{"role": "user", "content": '{"a": 2, "b": 1}'}]
    b = [{"role": "user", "content": '{"a": 9, "b": 1}'}]
    assert _d(a) != _d(b)


def test_the_exact_digest_still_separates_key_order():
    """The normalised key is an addition; the exact one must not be loosened."""
    a = [{"role": "user", "content": '{"b": 1, "a": 2}'}]
    b = [{"role": "user", "content": '{"a":2,"b":1}'}]
    assert _exact(a) != _exact(b)


def test_interior_whitespace_in_prose_is_significant():
    """Only leading and trailing space is cosmetic in text the model reads."""
    a = [{"role": "user", "content": "(no json)  cve-2024-1"}]
    b = [{"role": "user", "content": "(no json) cve-2024-1"}]
    assert _d(a) != _d(b)


def test_prose_is_not_parsed_as_json_when_it_merely_starts_with_a_brace():
    """A body embedding JSON in prose must reach the model verbatim."""
    a = [{"role": "user", "content": "{not json, just text}"}]
    b = [{"role": "user", "content": "{ not json, just text }"}]
    assert _d(a) != _d(b)


def test_the_role_is_part_of_the_identity():
    a = [{"role": "user", "content": '{"a": 1}'}]
    b = [{"role": "assistant", "content": '{"a": 1}'}]
    assert _d(a) != _d(b)


def test_message_order_matters():
    a = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": '{"a": 1}'},
    ]
    b = [
        {"role": "user", "content": '{"a": 1}'},
        {"role": "system", "content": "sys"},
    ]
    assert _d(a) != _d(b)


def test_model_tier_and_temperature_are_part_of_the_identity():
    """Reusing across tiers or temperatures would be a different request."""
    messages = [{"role": "user", "content": '{"a": 1}'}]
    base = _d(messages)
    assert _d(messages, model="other") != base
    assert _d(messages, tier="deep") != base
    assert _d(messages, temperature=0.7) != base


def test_an_empty_message_list_has_a_stable_digest():
    assert _d([]) == _d([])


def test_a_missing_content_key_does_not_crash():
    """A malformed message must produce a digest, not an exception mid-scan."""
    a = [{"role": "user"}]
    b = [{"role": "user", "content": ""}]
    assert _d(a) == _d(b)
