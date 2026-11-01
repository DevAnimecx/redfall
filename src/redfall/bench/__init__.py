"""The bench: measure, don't argue.

Everything here exists for one sentence in the positioning document:
"Recall, precision and cost per true finding". Three modules:

- `corpus` — a versioned, sealed corpus: manifest, budget, ground truth.
- `recall` — the scorer for the omission question: of the flows that exist,
  how many did the engine find, and how many did it invent.
- `runner` — drives one tool under one budget on one corpus, and writes a
  report bundle whose LIMITATIONS.md is a required output.

The rules the arena enforces (pre-registration, sealed ground truth, equal
budget, published raw logs, provisional-until-reproduced) are enforced by the
*shape* of these modules rather than by convention: `ground_truth.json` is read
only by the scorer and never handed to the engine; the budget is checked
against the request before it is honoured; and every report a run writes
contains a LIMITATIONS file or the run raises.
"""

from .corpus import (
    Budget,
    BudgetError,
    Corpus,
    CorpusError,
    budget_for,
    load_corpus,
    manifest_fingerprint,
)
from .recall import (
    RecallResult,
    recall_from_taint,
    recall_summary,
)
from .runner import (
    RunRecord,
    RunReportError,
    bench_report,
    run_corpus,
    write_report,
)

__all__ = [
    "Budget",
    "BudgetError",
    "Corpus",
    "CorpusError",
    "RecallResult",
    "RunRecord",
    "RunReportError",
    "bench_report",
    "budget_for",
    "load_corpus",
    "manifest_fingerprint",
    "recall_from_taint",
    "recall_summary",
    "run_corpus",
    "write_report",
]
