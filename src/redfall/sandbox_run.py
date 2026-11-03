"""Score RedFall against real, third-party vulnerable applications.

`redfall bench` measures against corpora this project wrote. That is the right
instrument for regression and the wrong one for capability: a corpus authored by
the same person who wrote the detectors shares their blind spots, and agreement
looks like accuracy.

This runner scores against applications nobody here wrote, seeded by people who
had no interest in what RedFall finds. It is the only measurement in the project
that can falsify the tuned numbers.

**Scoring is by file and category, not by line.** The ground truth for a
third-party app is drawn from its documentation and its own code comments, and
those name *where* a class of bug lives, rarely the exact line the app's authors
would have chosen. Scoring on line numbers would measure whether this project
guessed another team's formatting. The trade-off is stated rather than hidden:
file+category is a weaker match, and a detector that fires on the wrong line of
the right file still scores.

**A missing challenge is a skip, not a failure.** The trees are cloned by
`sandbox/fetch_challenges.sh` and are never committed, so a host that has not
fetched them reports `not fetched` and scores nothing rather than scoring zero.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

SANDBOX = Path(__file__).resolve().parents[2] / "sandbox"
CHALLENGES = SANDBOX / "challenges"
GROUND_TRUTH = SANDBOX / "ground_truth.json"

# Files that are not the application: vendored libraries, build output, tests.
SKIP_PARTS = ("node_modules", "vendor", "assets", "dist", "build", ".git", "coverage")
SKIP_NAMES = (".min.js", "-min.js", ".bundle.js")
SOURCE_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py"}


@dataclass
class Expected:
    id: str
    category: str
    file: str
    note: str
    line: int = 0

    def matches(self, finding: dict[str, Any]) -> bool:
        """File and category. Line is deliberately not compared — see module doc.

        The file comparison accepts a match on the path suffix, because the
        ground truth is written against the app's own layout while a finding
        carries the path relative to wherever this runner was pointed.
        """
        if finding.get("category") != self.category:
            return False
        found = str(finding.get("file") or "").replace("\\", "/")
        return found == self.file or found.endswith("/" + self.file)


@dataclass
class TargetResult:
    name: str
    files_scanned: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    found: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    fetched: bool = True

    @property
    def recall(self) -> float | None:
        total = len(self.found) + len(self.missed)
        return (len(self.found) / total) if total else None

    def to_wire(self) -> dict[str, Any]:
        return {
            "target": self.name,
            "fetched": self.fetched,
            "files_scanned": self.files_scanned,
            "findings": len(self.findings),
            "found": self.found,
            "missed": self.missed,
            "recall": self.recall,
        }


def load_ground_truth() -> dict[str, Any]:
    return json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))


def expected_for(target: str) -> list[Expected]:
    data = load_ground_truth()
    entry = (data.get("targets") or {}).get(target) or {}
    return [
        Expected(
            id=str(item["id"]),
            category=str(item["category"]),
            file=str(item["file"]).replace("\\", "/"),
            note=str(item.get("note") or ""),
            line=int(item.get("line") or 0),
        )
        for item in (entry.get("expected") or [])
    ]


def source_files(root: Path) -> Iterator[Path]:
    """Application sources, with vendored and generated files excluded."""
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        parts = {p.lower() for p in path.parts}
        if parts & set(SKIP_PARTS):
            continue
        name = path.name.lower()
        if any(skip in name for skip in SKIP_NAMES):
            continue
        yield path


def _taint_findings(path: Path, rel: str) -> list[dict[str, Any]]:
    """The flow analysis for one file, mapped to corpus categories.

    The detector suite covers the classes that are shapes rather than flows; the
    taint stage covers the ones that are flows. Scoring only the detectors
    measured half the engine, and reported a SQL injection as a miss when the
    flow analysis had already found it.
    """
    from .cli_bench import _category_for_sink
    from .ingestion.languages import support_for

    support = support_for(path)
    if support is None:
        return []
    try:
        parsed = support.parse(str(path), path.read_bytes())
        if parsed is None:
            return []
        symbols = support.symbols(parsed)
        taints = support.taint(parsed, symbols)
    except Exception:  # noqa: BLE001 - one unparsable file must not end a scan
        return []
    return [
        {
            "category": _category_for_sink(taint.sink),
            "file": rel,
            "line": int(taint.line or 0),
            "symbol": taint.symbol or "",
            "detail": f"{taint.source} reaches {taint.sink} ({taint.sink_kind})",
        }
        for taint in taints
    ]


def scan_target(name: str) -> TargetResult:
    """Run both analysis stages over one fetched challenge app."""
    from .detect import detect_file

    root = CHALLENGES / name
    result = TargetResult(name=name)
    if not root.is_dir():
        result.fetched = False
        return result

    # The tree's own library vocabulary, before any file is walked — the same
    # step `ingest()` performs. Without it the sink classifiers fall back to
    # their built-in tables, and an app that fetches with `needle` reports no
    # sinks at all: a scanner that sees nothing looks exactly like a clean
    # application, which is the most dangerous way for a measurement to fail.
    from .ingestion import symbols as symbols_mod
    from .ingestion.library_sinks import library_sinks

    symbols_mod.use_library_kinds(
        {lib: inf.kind for lib, inf in library_sinks(root).items()}
    )

    for path in source_files(root):
        rel = str(path.relative_to(root)).replace("\\", "/")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        result.files_scanned += 1
        seen: set[tuple[str, str, int]] = set()
        for hit in detect_file(rel, text):
            row = hit.to_row()
            seen.add((row["category"], row["file"], row["line"]))
            result.findings.append(row)
        for row in _taint_findings(path, rel):
            key = (row["category"], row["file"], row["line"])
            if key in seen:
                continue
            seen.add(key)
            result.findings.append(row)

    symbols_mod.clear_library_kinds()

    for expectation in expected_for(name):
        if any(expectation.matches(finding) for finding in result.findings):
            result.found.append(expectation.id)
        else:
            result.missed.append(expectation.id)
    return result


def run_all() -> dict[str, Any]:
    """Score every challenge app that has been fetched."""
    data = load_ground_truth()
    names = sorted((data.get("targets") or {}).keys())
    results = [scan_target(name) for name in names]

    scored = [r for r in results if r.fetched]
    recalls = [r.recall for r in scored if r.recall is not None]
    return {
        "targets": [r.to_wire() for r in results],
        "fetched": len(scored),
        "not_fetched": [r.name for r in results if not r.fetched],
        # Every corpus weighs the same, as in the bench: a large app must not
        # dominate a small one, or a single easy target carries the figure.
        "mean_recall": (sum(recalls) / len(recalls)) if recalls else None,
        "scoring": "file + category (line not compared; see sandbox_run docstring)",
    }
