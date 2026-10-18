"""Deduplication of findings (§6.1).

Two findings are the same when they share a category and point at the same
place. "Same place" means the same file and either the same symbol or lines
within a small window, because different analysis paths routinely land a few
lines apart on one root cause.
"""

from __future__ import annotations

from typing import Iterable, TypeVar

LINE_WINDOW = 5

T = TypeVar("T")


def dedupe_key(category: str, file: str, symbol: str, line: int) -> str:
    """A stable identity for a finding. Symbol wins when present, since it is
    the more precise anchor; the line is the fallback."""
    if symbol:
        return f"{category}|{file}|{symbol}"
    return f"{category}|{file}|L{line}"


def same_location(file_a: str, line_a: int, symbol_a: str, file_b: str, line_b: int, symbol_b: str) -> bool:
    """The §9 matching rule for locations, reused for dedupe."""
    if file_a != file_b:
        return False
    if symbol_a and symbol_b and symbol_a == symbol_b:
        return True
    return abs(line_a - line_b) <= LINE_WINDOW


def merge_duplicates(findings: Iterable[T]) -> list[T]:
    """Collapse findings that describe the same defect, keeping the first.

    The first is kept because branches run in priority order, so the earliest
    discovery came from the highest-priority analysis path.
    """
    kept: list[T] = []
    for finding in findings:
        if _conflicts(kept, finding):
            continue
        kept.append(finding)
    return kept


def _conflicts(kept: list[T], finding: T) -> bool:
    for existing in kept:
        if getattr(existing, "category", None) != getattr(finding, "category", None):
            continue
        if same_location(
            getattr(existing, "location_file", ""),
            getattr(existing, "location_line", 0),
            getattr(existing, "location_symbol", ""),
            getattr(finding, "location_file", ""),
            getattr(finding, "location_line", 0),
            getattr(finding, "location_symbol", ""),
        ):
            return True
    return False
