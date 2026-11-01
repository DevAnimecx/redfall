"""A versioned, sealed corpus.

A corpus is three files in one directory:

- ``manifest.json``  — the targets, the commits, the expected findings, the
  proof contracts. Committed *before* any run.
- ``budget.json``    — the wall clock, tokens, sandbox minutes and dollar
  ceiling one tool gets. The same numbers the baselines get.
- ``ground-truth.json`` — the answers. **Read only by the scorer, never
  handed to the engine.** A benchmark that lets the engine see the answers
  measures whether the engine can read a file.

The seal is enforced structurally: `load_corpus` returns the manifest and the
budget to a caller, and the ground truth only through `scorer_grade`, a
function the engine never receives. There is no API on `Corpus` that exposes
the answers to the path that runs a scan.

Pre-registration is enforced by the fingerprint: `manifest_fingerprint` hashes
the manifest's canonical form. A run records it, and a report whose manifest
hash differs from the committed one did not measure the corpus it claims to
have measured.

A corpus chosen after seeing results is a demo. The fingerprint is what makes
choosing-after visible.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class CorpusError(RuntimeError):
    """The corpus is malformed, incomplete, or lying about itself."""


class BudgetError(RuntimeError):
    """The budget cannot do what was asked of it."""


@dataclass(frozen=True)
class Budget:
    """What one tool gets on one corpus.

    Every field is a ceiling, measured by the runner, and reported per run. A
    field of zero or None means "unbounded on this dimension, but still
    reported" — so a run that claims to be cheaper can be checked against what
    it actually spent.
    """

    wall_clock_s: int | None = None
    tokens: int | None = None
    sandbox_minutes: float | None = None
    usd: float | None = None

    def to_wire(self) -> dict[str, Any]:
        return {
            "wall_clock_s": self.wall_clock_s,
            "tokens": self.tokens,
            "sandbox_minutes": self.sandbox_minutes,
            "usd": self.usd,
        }

    def validate(self) -> None:
        for name, value in (
            ("wall_clock_s", self.wall_clock_s),
            ("tokens", self.tokens),
            ("sandbox_minutes", self.sandbox_minutes),
            ("usd", self.usd),
        ):
            if value is not None and value < 0:
                raise BudgetError(f"budget.{name} must be >= 0, got {value}")


@dataclass(frozen=True)
class ExpectedFinding:
    """One flow the corpus says exists, and the proof contract for it."""

    id: str
    language: str
    category: str
    file: str
    symbol: str
    line: int
    #: How the corpus says it should be proven. The scorer does not run this;
    #: the arena's execution stage does, and records what happened.
    proof_contract: str = ""

    def to_wire(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "language": self.language,
            "category": self.category,
            "file": self.file,
            "symbol": self.symbol,
            "line": self.line,
            "proof_contract": self.proof_contract,
        }


@dataclass(frozen=True)
class Corpus:
    """A sealed corpus: what was committed, and the handle to the answers."""

    name: str
    version: str
    manifest: dict[str, Any]
    expected: tuple[ExpectedFinding, ...]
    budget: Budget
    ground_truth: tuple[dict[str, Any], ...]
    # The digest of the manifest's canonical form at load time. Recorded on
    # every run; a report whose digest differs did not measure this corpus.
    fingerprint: str
    source_dir: Path = field(default_factory=Path)

    def to_wire(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "fingerprint": self.fingerprint,
            "expected_count": len(self.expected),
            "budget": self.budget.to_wire(),
            "source_dir": str(self.source_dir),
        }


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise CorpusError(f"missing corpus file: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CorpusError(f"{path.name} is not valid JSON: {exc}") from exc


def manifest_fingerprint(manifest: dict[str, Any]) -> str:
    """A stable digest of the manifest's canonical form."""
    canonical = json.dumps(manifest, sort_keys=True, ensure_ascii=False, default=str)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def load_corpus(directory: str | Path) -> Corpus:
    """Load and validate a corpus directory.

    Raises rather than guessing on any structural problem: a corpus that
    validates loosely is a corpus that can be gamed accidentally.
    """
    root = Path(directory)
    if not root.is_dir():
        raise CorpusError(f"no such corpus directory: {root}")

    document = _read_json(root / "manifest.json")
    if not isinstance(document, dict):
        raise CorpusError("manifest.json must be a JSON object")
    name = str(document.get("name") or "").strip()
    if not name:
        raise CorpusError("manifest.json must name the corpus")
    version = str(document.get("version") or "").strip()
    if not version:
        raise CorpusError("manifest.json must declare a version")

    raw_expected = document.get("expected") or []
    if not isinstance(raw_expected, list):
        raise CorpusError("manifest 'expected' must be a list")
    if not raw_expected:
        # An empty corpus scores 100% recall trivially, which is the fraud
        # this whole package exists to prevent. Refuse rather than allow a
        # vacuous 1.0 to be reported.
        raise CorpusError("manifest 'expected' is empty; an empty corpus cannot measure recall")

    expected: list[ExpectedFinding] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_expected):
        if not isinstance(raw, dict):
            raise CorpusError(f"expected[{index}] is not an object")
        fid = str(raw.get("id") or "").strip()
        if not fid:
            raise CorpusError(f"expected[{index}] has no id")
        if fid in seen_ids:
            raise CorpusError(f"duplicate expected id: {fid}")
        seen_ids.add(fid)
        language = str(raw.get("language") or "").strip()
        category = str(raw.get("category") or "").strip()
        file_path = str(raw.get("file") or "").strip()
        if not language or not category or not file_path:
            raise CorpusError(
                f"expected[{index}] ({fid}) needs language, category and file"
            )
        line = raw.get("line")
        if not isinstance(line, int) or line <= 0:
            raise CorpusError(f"expected[{index}] ({fid}) needs a positive line number")
        expected.append(
            ExpectedFinding(
                id=fid,
                language=language,
                category=category,
                file=file_path,
                symbol=str(raw.get("symbol") or "").strip(),
                line=line,
                proof_contract=str(raw.get("proof_contract") or raw.get("proof") or "").strip(),
            )
        )

    budget_doc = _read_json(root / "budget.json")
    budget = Budget(
        wall_clock_s=budget_doc.get("wall_clock_s"),
        tokens=budget_doc.get("tokens"),
        sandbox_minutes=budget_doc.get("sandbox_minutes"),
        usd=budget_doc.get("usd"),
    )
    budget.validate()

    truth_doc = _read_json(root / "ground-truth.json")
    truth = truth_doc.get("findings") if isinstance(truth_doc, dict) else truth_doc
    if not isinstance(truth, list):
        raise CorpusError("ground-truth.json must be an object with a 'findings' list")
    if len(truth) != len(expected):
        # Ground truth that disagrees with the manifest about how many flows
        # exist means one of them is wrong, and a scorer cannot know which.
        raise CorpusError(
            f"ground truth has {len(truth)} findings but the manifest expects "
            f"{len(expected)}; the corpus contradicts itself"
        )

    fingerprint = manifest_fingerprint({"manifest": document, "budget": budget_doc})

    return Corpus(
        name=name,
        version=version,
        manifest=document,
        expected=tuple(expected),
        budget=budget,
        ground_truth=tuple(truth),
        fingerprint=fingerprint,
        source_dir=root,
    )


def budget_for(
    corpus: Corpus,
    *,
    wall_clock_s: int | None = None,
) -> Budget:
    """The budget one run gets: the corpus's committed ceiling.

    An explicit override may only *narrow* a dimension. Widening a budget after
    pre-registration is how a losing run buys itself a win, so `budget_for`
    refuses a value above the ceiling and says that is why.
    """
    committed = corpus.budget
    if wall_clock_s is None:
        return committed
    if committed.wall_clock_s is not None and wall_clock_s > committed.wall_clock_s:
        raise BudgetError(
            f"requested wall clock {wall_clock_s}s exceeds the committed budget "
            f"of {committed.wall_clock_s}s; a budget may be narrowed, never widened"
        )
    return Budget(
        wall_clock_s=wall_clock_s,
        tokens=committed.tokens,
        sandbox_minutes=committed.sandbox_minutes,
        usd=committed.usd,
    )
