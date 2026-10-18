from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "range"))

from redfall.agent import categories
from range_runner.ground_truth import load_manifest


def test_supported_coverage_is_exactly_25_categories():
    assert len(categories.SUPPORTED_CATEGORIES) == 25
    assert len(categories.all_keys()) == 25


def test_exclusions_are_documented_with_a_reason():
    assert len(categories.NOT_COVERED) == 4
    for entry in categories.NOT_COVERED:
        assert entry["key"]
        assert len(entry["reason"]) > 40, f"{entry['key']} has no real reason recorded"


def test_coverage_plus_exclusions_account_for_the_whole_range(vulnbank):
    manifest_categories = {v.category for v in load_manifest(vulnbank / "manifest.yaml")}
    covered = set(categories.all_keys())
    excluded = {e["key"] for e in categories.NOT_COVERED}
    assert covered & excluded == set(), "a category is both covered and excluded"
    unaccounted = manifest_categories - covered - excluded
    assert not unaccounted, f"categories with no coverage decision recorded: {sorted(unaccounted)}"


def test_every_covered_category_has_proof_and_fix_guidance():
    for cat in categories.SUPPORTED_CATEGORIES:
        assert cat.cwe.startswith("CWE-"), f"{cat.key} has no CWE"
        assert cat.severity in ("critical", "high", "medium", "low")
        assert cat.proof, f"{cat.key} states no required proof"
        assert cat.fix_strategy, f"{cat.key} states no fix strategy"
        assert cat.signals, f"{cat.key} states no static signals"


def test_aliases_resolve_but_do_not_blur_distinct_defects():
    assert categories.normalise("sql_injection") == "sqli"
    assert categories.normalise("sqli") == "sqli"
    assert categories.normalise("unknown_thing") == "unknown_thing"
    assert categories.normalise("idor") != categories.normalise("mass_assignment")


def test_prompt_block_lists_every_category():
    block = categories.prompt_block()
    for key in categories.all_keys():
        assert key in block, f"{key} missing from the prompt block"
