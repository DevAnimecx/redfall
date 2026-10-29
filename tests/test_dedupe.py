from __future__ import annotations

from dataclasses import dataclass

from redfall.branching.dedupe import dedupe_key, merge_duplicates


@dataclass
class F:
    category: str
    location_file: str
    location_line: int
    location_symbol: str = ""


def test_same_category_same_symbol_is_one_finding():
    merged = merge_duplicates([F("sqli", "a.ts", 38, "h"), F("sqli", "a.ts", 99, "h")])
    assert len(merged) == 1


def test_same_category_nearby_lines_is_one_finding():
    assert len(merge_duplicates([F("sqli", "a.ts", 38), F("sqli", "a.ts", 42)])) == 1


def test_same_category_distant_lines_are_two_findings():
    assert len(merge_duplicates([F("sqli", "a.ts", 38), F("sqli", "a.ts", 60)])) == 2


def test_different_categories_are_never_merged():
    assert len(merge_duplicates([F("sqli", "a.ts", 38), F("idor", "a.ts", 38)])) == 2


def test_different_files_are_never_merged():
    assert len(merge_duplicates([F("sqli", "a.ts", 38), F("sqli", "b.ts", 38)])) == 2


def test_first_discovery_is_kept():
    first, second = F("sqli", "a.ts", 38), F("sqli", "a.ts", 39)
    assert merge_duplicates([first, second])[0] is first


def test_dedupe_key_uses_the_symbol_when_present():
    assert dedupe_key("sqli", "a.ts", "h", 38) == dedupe_key("sqli", "a.ts", "h", 900)
    assert dedupe_key("sqli", "a.ts", "", 38) != dedupe_key("sqli", "a.ts", "", 39)
