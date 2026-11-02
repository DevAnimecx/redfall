#!/usr/bin/env python3
"""Recall regression guard — a drop below the committed baseline fails CI.

The baseline in `bench/baselines/<corpus>.json` records the recall this engine
last measured, with the corpus fingerprint it measured against. This script
re-measures and compares.

Three outcomes, and the distinction between them matters:

* **PASS** — recall is at or above the baseline. Raising the baseline is a
  separate, deliberate commit; this script never writes it.
* **FAIL** — recall dropped. A silent recall regression is the exact failure
  the bench exists to catch: the engine finds fewer real bugs and every other
  number (precision, reproduction, the changelog) still looks fine.
* **STALE** — the corpus fingerprint changed. The baseline was measured against
  different ground truth, so comparing would be meaningless. This is not a pass
  and not a failure; it asks a human to re-baseline deliberately rather than
  letting a corpus edit silently reset the bar.

Exit codes: 0 pass, 1 regression, 2 stale.

Because a full ingest needs a database, the check runs against a throwaway
SQLite file unless REDFALL_TEST_DATABASE_URL is set. It needs no Postgres and
no container runtime, so it runs in the ordinary CI job.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

BASELINES = ROOT / "bench" / "baselines"
CORPORA = ROOT / "bench" / "corpora"

# How much recall may drift before it counts as a regression. Recall is
# deterministic for a fixed corpus and engine, so this is 0 by default: any
# drop is a real drop. The tolerance exists only so a floating-point tail does
# not trip the gate.
TOLERANCE = 1e-9


def _measure(corpus_name: str, tree: Path) -> dict:
    """Measure the engine exactly as `redfall bench recall` does.

    This function used to rebuild the finding list itself, taint stage only.
    When the CLI grew the detector stage the two silently diverged: the gate
    measured 6.2% while the command measured 18.8% on the same corpus, and the
    gate reported a regression that had not happened. Delegating to the one
    implementation is what stops that class of drift — a guard that measures
    something different from the thing it guards is worse than no guard.
    """
    from redfall.bench.corpus import load_corpus
    from redfall.bench.recall import recall_from_taint
    from redfall.cli_bench import _all_findings_for
    from redfall.store import db
    import os

    db.init_engine(
        os.getenv("REDFALL_TEST_DATABASE_URL") or "sqlite:///redfall-recall.db"
    )
    corpus = load_corpus(CORPORA / corpus_name)
    findings = _all_findings_for(tree, corpus)
    result = recall_from_taint(findings, corpus.expected)
    return {"corpus": corpus, "result": result, "findings": findings}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="", help="One corpus; default is every baseline present.")
    parser.add_argument("--tree", default="", help="Tree to scan; defaults to range/<corpus>.")
    parser.add_argument("--update", action="store_true", help="Rewrite the baseline (deliberate, reviewable).")
    args = parser.parse_args()

    names = [args.corpus] if args.corpus else sorted(p.stem for p in BASELINES.glob("*.json"))
    if not names:
        print("check_recall: no baselines to check", file=sys.stderr)
        return 1

    worst = 0
    for name in names:
        baseline_path = BASELINES / f"{name}.json"
        if not baseline_path.is_file():
            print(f"check_recall: no baseline for {name}; measure first", file=sys.stderr)
            worst = max(worst, 2)
            continue

        tree = Path(args.tree) if args.tree else ROOT / "range" / name
        if not tree.is_dir():
            print(f"check_recall: no target tree at {tree}", file=sys.stderr)
            worst = max(worst, 2)
            continue

        measured = _measure(name, tree)
        corpus = measured["corpus"]
        result = measured["result"]
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

        if baseline.get("fingerprint") != corpus.fingerprint:
            print(
                f"check_recall: STALE {name} — corpus fingerprint changed\n"
                f"  baseline: {baseline.get('fingerprint')}\n"
                f"  current:  {corpus.fingerprint}\n"
                "  re-baseline deliberately with --update after reviewing the change",
                file=sys.stderr,
            )
            worst = max(worst, 2)
            continue

        current = result.recall if result.recall is not None else 0.0
        committed = float(baseline.get("recall") or 0.0)

        if args.update:
            baseline.update(
                {
                    "recall": current,
                    "found": len(result.found_ids),
                    "expected": result.expected_count,
                    "missed": len(result.missed_ids),
                    "invented": len(result.invented),
                    "measured": __import__("datetime").date.today().isoformat(),
                }
            )
            baseline_path.write_text(
                json.dumps(baseline, indent=2) + "\n", encoding="utf-8"
            )
            print(f"check_recall: updated baseline {name} -> {current:.3f}")
            continue

        if current + TOLERANCE < committed:
            print(
                f"check_recall: FAIL {name} — recall dropped\n"
                f"  baseline: {committed:.3f} ({baseline.get('found')}/{baseline.get('expected')})\n"
                f"  current:  {current:.3f} ({len(result.found_ids)}/{result.expected_count})\n"
                f"  newly missed: {', '.join(result.missed_ids)}",
                file=sys.stderr,
            )
            worst = max(worst, 1)
        else:
            print(
                f"check_recall: PASS {name} — {current:.3f} "
                f"({len(result.found_ids)}/{result.expected_count} found, "
                f"{len(result.invented)} invented)"
            )

    return worst


if __name__ == "__main__":
    raise SystemExit(main())
