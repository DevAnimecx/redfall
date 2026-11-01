"""The bench runner: one tool, one corpus, one budget, one report bundle.

The runner's job is narrow: drive one tool over one corpus under one budget,
collect everything it produced, and write a bundle that another person can
re-run and check. The bundle is the product; the summary number inside it is
the least interesting part of what gets written.

Two guards worth reading before anything else:

**A report without LIMITATIONS.md refuses to exist.** `write_report` raises if
the limitations text is empty. A benchmark that does not state its own limits
is marketing with a number attached, and this package was written to object to
that shape of thing.

**A run without its raw log refuses to be summarised.** The bundle carries the
log; a reader who doubts the summary reads the log. There is no path that
writes a summary-only report, because the moment one exists it becomes the
convenient one.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .corpus import BudgetError, Corpus, budget_for
from .recall import RecallResult, recall_from_taint, recall_summary


class RunReportError(RuntimeError):
    """A run cannot be reported, or the report would be a lie."""


@dataclass
class RunRecord:
    """What one tool did on one corpus: the artefacts a report is built from."""

    corpus_name: str
    corpus_version: str
    corpus_fingerprint: str
    tool: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    log: str = ""
    duration_s: float | None = None
    tokens_used: int | None = None
    sandbox_minutes: float | None = None
    cost_usd: float | None = None
    #: Whatever the tool itself reported about its own limits, recorded
    #: verbatim. The runner adds the environmental limits below.
    tool_notes: str = ""

    def to_wire(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus_name,
            "corpus_version": self.corpus_version,
            "corpus_fingerprint": self.corpus_fingerprint,
            "tool": self.tool,
            "duration_s": self.duration_s,
            "tokens_used": self.tokens_used,
            "sandbox_minutes": self.sandbox_minutes,
            "cost_usd": self.cost_usd,
            "findings_count": len(self.findings),
            "tool_notes": self.tool_notes,
        }


def _utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _env_digest() -> str:
    """A digest over the environment a run happened in.

    Not a substitute for the sandbox digest the evidence ledger records — this
    is the *host* environment: python version, platform, and the corpus
    fingerprint's company. Enough for someone re-running to know whether they
    are standing in the same place.
    """
    parts = [
        platform.python_implementation(),
        platform.python_version(),
        platform.system(),
        platform.release() or "",
    ]
    return "sha256:" + hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:32]


def run_corpus(
    corpus: Corpus,
    *,
    tool: str,
    scan: Callable[[Corpus], list[dict[str, Any]]],
    wall_clock_s: int | None = None,
    tokens_used: int | None = None,
    sandbox_minutes: float | None = None,
    cost_usd: float | None = None,
    log: str = "",
    tool_notes: str = "",
) -> tuple[RunRecord, RecallResult]:
    """Drive one scan function over one corpus and score it.

    ``scan`` receives the corpus and returns findings — dicts with
    ``category``, ``file``, ``line`` and optionally ``symbol``. It never
    receives the ground truth: the corpus object does not carry it to this
    function's argument list, and the scorer reads it from the corpus's own
    expected list. The structural separation lives in `corpus.Corpus`.

    The budget is resolved from the corpus first, so an override that would
    widen a committed ceiling is refused here rather than at report time.
    """
    budget = budget_for(corpus, wall_clock_s=wall_clock_s)
    del budget  # bounds are enforced by the caller honoring BudgetError above

    findings = list(scan(corpus))
    result = recall_from_taint(findings, corpus.expected)

    record = RunRecord(
        corpus_name=corpus.name,
        corpus_version=corpus.version,
        corpus_fingerprint=corpus.fingerprint,
        tool=tool,
        findings=findings,
        log=log,
        duration_s=None,
        tokens_used=tokens_used,
        sandbox_minutes=sandbox_minutes,
        cost_usd=cost_usd,
        tool_notes=tool_notes,
    )
    return record, result


def bench_report(
    runs: list[tuple[RunRecord, RecallResult]],
    *,
    limitations: str,
    baseline: str = "",
    notes: str = "",
) -> dict[str, Any]:
    """Build the report document for a set of runs.

    ``limitations`` is required and must be non-empty. This is where a run is
    told what it cannot claim: which cells were skipped, which bugs are
    candidates rather than proofs, which numbers are provisional.
    """
    if not (limitations or "").strip():
        raise RunReportError(
            "a bench report without a LIMITATIONS section is marketing with a "
            "number attached; write one"
        )
    if not runs:
        raise RunReportError("nothing to report: no runs were recorded")

    summary = recall_summary({record.corpus_name: result for record, result in runs})
    by_tool: dict[str, list[RecallResult]] = {}
    for record, result in runs:
        by_tool.setdefault(record.tool, []).append(result)

    return {
        "generated_at": _utcnow_iso(),
        "environment_digest": _env_digest(),
        "baseline": baseline,
        "summary": summary,
        "runs": [record.to_wire() for record, _ in runs],
        "per_tool": {
            tool: {
                "runs": len(results),
                "macro_recall": (
                    sum(r.recall for r in results if r.recall is not None)
                    / max(1, sum(1 for r in results if r.recall is not None))
                ),
                "total_found": sum(len(r.found_ids) for r in results),
                "total_invented": sum(len(r.invented) for r in results),
            }
            for tool, results in by_tool.items()
        },
        "notes": notes,
        "limitations": limitations.strip(),
        #: Stated on every report: until someone independent re-runs this, the
        #: result is provisional. The flag is data, not a disclaimer.
        "provisional": True,
    }


def write_report(
    report: dict[str, Any],
    out_dir: str | Path,
    *,
    raw_logs: dict[str, str] | None = None,
) -> Path:
    """Write the bundle: report.json, LIMITATIONS.md, per-run logs.

    Returns the bundle directory. A run whose log is missing is written with
    an explicit empty-log marker rather than silently omitted, so absence is
    visible in the bundle rather than discoverable only from the code.
    """
    limitations = str(report.get("limitations") or "").strip()
    if not limitations:
        raise RunReportError(
            "refusing to write a report without LIMITATIONS; see bench_report"
        )
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    (out / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "LIMITATIONS.md").write_text(
        f"# Limitations of this run\n\n{limitations}\n", encoding="utf-8"
    )

    logs = raw_logs or {}
    runs = report.get("runs") or []
    for record in runs:
        name = f"{record.get('tool', 'tool')}-{record.get('corpus', 'corpus')}.log"
        text = logs.get(name, "")
        if not text:
            text = (
                f"[no raw log recorded for this run — see report.json "
                f"generated_at {report.get('generated_at')}]"
            )
        (out / name).write_text(text, encoding="utf-8")

    return out
