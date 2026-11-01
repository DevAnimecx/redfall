"""The recall scorer: measuring omission.

Every existing measure in this repository scores *what the engine produced* —
matched findings, reproduced PoCs, chained steps. None of them can see what it
failed to produce, because there is nothing there to count.

Recall measures omission. The corpus lists every flow that exists; the scorer
counts how many the engine found and how many it invented:

- **recall** — found ⊘ expected. The coverage number. The whole point.
- **invented rate** — unmatched findings ⊘ all findings. How noisy the
  generator is when it should have stayed quiet.
- Per-category and per-language recall — so "Python recall improved" is not
  allowed to hide "Java recall is zero".

The matcher is deliberately conservative in the same direction as the range
matcher: an invented finding hurts the invented rate, but a missed finding
hurts recall, and borderline matching credits the engine when the evidence is
arguable. That asymmetry is a choice, and it is stated: this scorer measures
the engine generously and still refuses to award it for flows it did not find.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# Line tolerance for matching a reported finding to an expected one. The range
# matcher uses the same value, so a flow the range accepts this scorer accepts.
LINE_TOLERANCE = 3


class _Missing:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<missing>"


@dataclass
class RecallResult:
    """One scorer run: what was found, what was missed, what was invented."""

    found_ids: tuple[str, ...] = ()
    missed_ids: tuple[str, ...] = ()
    invented: tuple[dict[str, Any], ...] = ()

    @property
    def expected_count(self) -> int:
        return len(self.found_ids) + len(self.missed_ids)

    @property
    def recall(self) -> float | None:
        """Found ⊘ expected. None when there was nothing to find."""
        if self.expected_count == 0:
            return None
        return len(self.found_ids) / self.expected_count

    @property
    def invented_rate(self) -> float | None:
        """Unmatched findings ⊘ all findings. None when nothing was reported."""
        total = len(self.found_ids) + len(self.invented)
        if total == 0:
            return None
        return len(self.invented) / total

    def recall_for(self, *, language: str = "", category: str) -> float | None:
        """Recall restricted to one language or category.

        A filter that matches nothing returns None rather than 0.0: no Java
        flows in the corpus is not evidence that Java recall is zero.
        """
        return self._subset_recall(lambda ef: (
            (not category or ef["category"] == category)
            and (not language or ef["language"] == language)
        ))

    def _subset_recall(self, predicate) -> float | None:
        # found/missed ids are matched against expected ids; the subset is the
        # set of expected ids passing the predicate, found among found_ids.
        subset = [eid for eid in self._expected_index if predicate(self._expected_index[eid])]
        if not subset:
            return None
        found = sum(1 for eid in subset if eid in self.found_ids)
        return found / len(subset)

    _expected_index: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)

    def to_wire(self) -> dict[str, Any]:
        per_category: dict[str, dict[str, float | None]] = {}
        for eid in self._expected_index:
            entry = self._expected_index[eid]
            cat = entry["category"]
            bucket = per_category.setdefault(cat, {"expected": 0, "found": 0})
            bucket["expected"] += 1
            if eid in self.found_ids:
                bucket["found"] += 1
        return {
            "expected": self.expected_count,
            "found": len(self.found_ids),
            "missed": len(self.missed_ids),
            "invented_count": len(self.invented),
            "recall": self.recall,
            "invented_rate": self.invented_rate,
            "recall_by_category": {
                cat: (b["found"] / b["expected"] if b["expected"] else None)
                for cat, b in sorted(per_category.items())
            },
        }


def recall_from_taint(
    findings: Iterable[dict[str, Any]],
    expected: Iterable[Any],
) -> RecallResult:
    """Score reported findings against the corpus's expected flows.

    ``findings`` is a list of dicts with at least ``category``, ``file`` and
    ``line`` — the shape the scan report and the taint engine both emit.
    ``expected`` is the corpus's `ExpectedFinding` records.

    Matching is one-to-one and greedy on best line agreement, mirroring the
    range matcher so the two cannot disagree about whether a flow was found.
    """
    result = RecallResult()
    expected_list = list(expected)
    result._expected_index = {
        e.id: {
            "id": e.id,
            "language": e.language,
            "category": e.category,
            "file": e.file,
            "symbol": e.symbol,
            "line": e.line,
        }
        for e in expected_list
    }

    reported = [dict(f) for f in findings]
    matched_expected: set[str] = set()
    used_findings: set[int] = set()

    # Best-agreement first, so a vague match cannot steal the expected flow a
    # precise match would have claimed. Higher agreement wins; ties break by
    # expected id then finding index, keeping the order stable across runs.
    candidates: list[tuple[int, str, int]] = []
    for idx, finding in enumerate(reported):
        f_category = str(finding.get("category") or "").strip()
        f_file = str(finding.get("file") or "").strip()
        f_line = int(finding.get("line") or 0)
        f_symbol = str(finding.get("symbol") or finding.get("enclosing_function") or "").strip()
        for e in expected_list:
            if e.id in matched_expected:
                continue
            if f_category != e.category:
                continue
            if f_file != e.file:
                continue
            line_ok = abs(f_line - e.line) <= LINE_TOLERANCE
            symbol_ok = bool(e.symbol) and f_symbol == e.symbol
            if not (line_ok or symbol_ok):
                continue
            candidates.append((int(line_ok) + int(symbol_ok), e.id, idx))
    candidates.sort(key=lambda c: (-c[0], c[1], c[2]))

    for _, eid, idx in candidates:
        if eid in matched_expected or idx in used_findings:
            continue
        matched_expected.add(eid)
        used_findings.add(idx)
        result.found_ids = (*result.found_ids, eid)

    result.missed_ids = tuple(e.id for e in expected_list if e.id not in matched_expected)
    result.invented = tuple(
        reported[idx] for idx in range(len(reported)) if idx not in used_findings
    )
    return result


def recall_summary(results: dict[str, RecallResult]) -> dict[str, Any]:
    """Per-corpus recall roll-up across a set of runs.

    Every corpus reports its own recall; the summary aggregates by weighting
    each corpus equally. A corpus with 5 expected flows counts the same as one
    with 50 — averaging per-corpus recall would otherwise let the large corpus
    dominate, and "recall" from a run that skipped the small corpus would
    silently become the small corpus's zero.
    """
    recalls = [r.recall for r in results.values() if r.recall is not None]
    total_expected = sum(r.expected_count for r in results.values())
    total_found = sum(len(r.found_ids) for r in results.values())
    total_invented = sum(len(r.invented) for r in results.values())
    return {
        "corpora": {name: r.to_wire() for name, r in results.items()},
        "macro_recall": (sum(recalls) / len(recalls)) if recalls else None,
        "micro_recall": (total_found / total_expected) if total_expected else None,
        "total_expected": total_expected,
        "total_found": total_found,
        "total_invented": total_invented,
        "corpora_scored": len(recalls),
        "corpora_total": len(results),
    }
