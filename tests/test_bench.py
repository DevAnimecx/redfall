"""The bench: sealed corpus, recall scoring, and a report that shows its work.

The tests that matter here are the refusals. A benchmark is easy to build in a
way that produces a number; the hard part is building one that cannot produce a
number when the number would be dishonest. Empty corpora, widened budgets,
reports without limitations, and leaked ground truth are all cases where the
convenient implementation reports something and the correct one refuses.

Everything runs against real corpora generated from the repository's own range
manifests.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _corpus_dir(tmp_path, *, expected=None, truth=None, budget=None) -> Path:
    """Write a minimal corpus directory, defaulting to a valid one."""
    expected = expected if expected is not None else [
        {
            "id": "VULN-001",
            "language": "python",
            "category": "sqli",
            "file": "src/app/routes.py",
            "symbol": "login",
            "line": 42,
        },
        {
            "id": "VULN-002",
            "language": "python",
            "category": "cmd_injection",
            "file": "src/app/tools.py",
            "symbol": "run",
            "line": 17,
        },
    ]
    truth = truth if truth is not None else [{**e, "description": "seed"} for e in expected]
    root = tmp_path / "corpus"
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(
        json.dumps({"name": "test-corpus", "version": "1", "expected": expected}),
        encoding="utf-8",
    )
    (root / "budget.json").write_text(
        json.dumps(budget or {"wall_clock_s": 600, "tokens": 1000, "sandbox_minutes": 5.0, "usd": 1.0}),
        encoding="utf-8",
    )
    (root / "ground-truth.json").write_text(
        json.dumps({"findings": truth}), encoding="utf-8"
    )
    return root


# -- corpus loading and its refusals ----------------------------------------

def test_a_valid_corpus_loads_with_a_fingerprint(tmp_path):
    from redfall.bench.corpus import load_corpus

    corpus = load_corpus(_corpus_dir(tmp_path))
    assert corpus.name == "test-corpus"
    assert len(corpus.expected) == 2
    assert corpus.fingerprint.startswith("sha256:")


def test_an_empty_corpus_is_refused(tmp_path):
    """An empty corpus scores 100% recall trivially, which is the fraud."""
    from redfall.bench.corpus import CorpusError, load_corpus

    root = _corpus_dir(tmp_path, expected=[], truth=[])
    with pytest.raises(CorpusError, match="empty corpus cannot measure recall"):
        load_corpus(root)


def test_ground_truth_that_contradicts_the_manifest_is_refused(tmp_path):
    from redfall.bench.corpus import CorpusError, load_corpus

    root = _corpus_dir(tmp_path, truth=[{"id": "ONLY-ONE"}])
    with pytest.raises(CorpusError, match="contradicts itself"):
        load_corpus(root)


def test_an_entry_without_an_anchor_is_refused(tmp_path):
    from redfall.bench.corpus import CorpusError, load_corpus

    bad = [{"id": "V1", "language": "python", "category": "sqli", "file": "a.py"}]
    root = _corpus_dir(tmp_path, expected=bad, truth=[{"id": "V1"}])
    with pytest.raises(CorpusError, match="needs a positive line number"):
        load_corpus(root)


def test_a_duplicate_id_is_refused(tmp_path):
    from redfall.bench.corpus import CorpusError, load_corpus

    dup = [
        {"id": "V1", "language": "python", "category": "sqli", "file": "a.py", "line": 1},
        {"id": "V1", "language": "python", "category": "sqli", "file": "b.py", "line": 2},
    ]
    root = _corpus_dir(tmp_path, expected=dup, truth=[{"id": "V1"}, {"id": "V1"}])
    with pytest.raises(CorpusError, match="duplicate expected id"):
        load_corpus(root)


def test_a_missing_file_is_refused(tmp_path):
    from redfall.bench.corpus import CorpusError, load_corpus

    root = _corpus_dir(tmp_path)
    (root / "ground-truth.json").unlink()
    with pytest.raises(CorpusError, match="missing corpus file"):
        load_corpus(root)


def test_a_negative_budget_is_refused(tmp_path):
    from redfall.bench.corpus import BudgetError, load_corpus

    root = _corpus_dir(tmp_path, budget={"wall_clock_s": -1})
    with pytest.raises(BudgetError, match="must be >= 0"):
        load_corpus(root)


# -- the budget ceiling -----------------------------------------------------

def test_a_budget_may_be_narrowed(tmp_path):
    from redfall.bench.corpus import budget_for, load_corpus

    corpus = load_corpus(_corpus_dir(tmp_path))
    narrowed = budget_for(corpus, wall_clock_s=60)
    assert narrowed.wall_clock_s == 60
    # The other dimensions keep the committed ceiling.
    assert narrowed.tokens == corpus.budget.tokens


def test_a_budget_may_not_be_widened(tmp_path):
    """Widening after pre-registration is how a losing run buys itself a win."""
    from redfall.bench.corpus import BudgetError, budget_for, load_corpus

    corpus = load_corpus(_corpus_dir(tmp_path))
    with pytest.raises(BudgetError, match="narrowed, never widened"):
        budget_for(corpus, wall_clock_s=999_999)


# -- recall scoring ---------------------------------------------------------

def _expected():
    from redfall.bench.corpus import ExpectedFinding

    return [
        ExpectedFinding("V1", "python", "sqli", "src/app/routes.py", "login", 42),
        ExpectedFinding("V2", "python", "cmd_injection", "src/app/tools.py", "run", 17),
        ExpectedFinding("V3", "python", "sqli", "src/app/reports.py", "render", 88),
    ]


def test_finding_every_flow_is_full_recall():
    from redfall.bench.recall import recall_from_taint

    findings = [
        {"category": "sqli", "file": "src/app/routes.py", "line": 42, "symbol": "login"},
        {"category": "cmd_injection", "file": "src/app/tools.py", "line": 17, "symbol": "run"},
        {"category": "sqli", "file": "src/app/reports.py", "line": 88, "symbol": "render"},
    ]
    result = recall_from_taint(findings, _expected())
    assert result.recall == 1.0
    assert result.missed_ids == ()
    assert result.invented == ()


def test_finding_none_is_zero_recall_and_names_the_misses():
    from redfall.bench.recall import recall_from_taint

    result = recall_from_taint([], _expected())
    assert result.recall == 0.0
    assert set(result.missed_ids) == {"V1", "V2", "V3"}


def test_a_partial_result_reports_both_halves():
    from redfall.bench.recall import recall_from_taint

    findings = [
        {"category": "sqli", "file": "src/app/routes.py", "line": 42, "symbol": "login"},
        {"category": "sqli", "file": "src/app/other.py", "line": 9, "symbol": "x"},
    ]
    result = recall_from_taint(findings, _expected())
    assert result.found_ids == ("V1",)
    assert set(result.missed_ids) == {"V2", "V3"}
    assert len(result.invented) == 1
    assert result.invented_rate == pytest.approx(0.5)


def test_a_wrong_category_does_not_count_as_found():
    from redfall.bench.recall import recall_from_taint

    findings = [{"category": "xss_reflected", "file": "src/app/routes.py", "line": 42, "symbol": "login"}]
    result = recall_from_taint(findings, _expected())
    assert result.found_ids == ()


def test_a_wrong_file_does_not_count_as_found():
    from redfall.bench.recall import recall_from_taint

    findings = [{"category": "sqli", "file": "src/app/elsewhere.py", "line": 42, "symbol": "login"}]
    result = recall_from_taint(findings, _expected())
    assert result.found_ids == ()


def test_a_line_within_tolerance_counts():
    """±3 lines, the same tolerance the range matcher uses."""
    from redfall.bench.recall import recall_from_taint

    findings = [{"category": "sqli", "file": "src/app/routes.py", "line": 45, "symbol": ""}]
    result = recall_from_taint(findings, _expected())
    assert result.found_ids == ("V1",)


def test_a_symbol_match_counts_even_when_the_line_moved():
    from redfall.bench.recall import recall_from_taint

    findings = [{"category": "sqli", "file": "src/app/routes.py", "line": 900, "symbol": "login"}]
    result = recall_from_taint(findings, _expected())
    assert result.found_ids == ("V1",)


def test_one_finding_cannot_claim_two_expected_flows():
    from redfall.bench.recall import recall_from_taint

    # One reported flow, sitting where two expected flows are within tolerance.
    expected = [
        __import__("redfall.bench.corpus", fromlist=["ExpectedFinding"]).ExpectedFinding(
            "V1", "python", "sqli", "a.py", "s", 10
        ),
        __import__("redfall.bench.corpus", fromlist=["ExpectedFinding"]).ExpectedFinding(
            "V2", "python", "sqli", "a.py", "s", 11
        ),
    ]
    findings = [{"category": "sqli", "file": "a.py", "line": 10, "symbol": "s"}]
    result = recall_from_taint(findings, expected)
    assert len(result.found_ids) == 1


def test_per_category_recall_is_reported():
    from redfall.bench.recall import recall_from_taint

    findings = [{"category": "sqli", "file": "src/app/routes.py", "line": 42, "symbol": "login"}]
    result = recall_from_taint(findings, _expected())
    wire = result.to_wire()
    assert wire["recall_by_category"]["sqli"] == pytest.approx(0.5)  # 1 of 2
    assert wire["recall_by_category"]["cmd_injection"] == 0.0


def test_a_category_with_no_expected_flows_reports_none_not_zero():
    """No Java in the corpus is not evidence that Java recall is zero."""
    from redfall.bench.recall import recall_from_taint

    result = recall_from_taint([], _expected())
    assert result.recall_for(category="java_only", language="java") is None


def test_an_empty_scoring_is_none_not_zero():
    """Nothing to find and nothing reported is not a failure — it is unmeasured."""
    from redfall.bench.recall import recall_from_taint

    result = recall_from_taint([], [])
    assert result.recall is None
    assert result.invented_rate is None


def test_recall_summary_reports_both_macro_and_micro():
    from redfall.bench.corpus import ExpectedFinding
    from redfall.bench.recall import recall_from_taint, recall_summary

    one = [ExpectedFinding("B1", "python", "sqli", "a.py", "s", 1)]
    big = recall_from_taint(
        [{"category": "sqli", "file": "a.py", "line": 1, "symbol": "s"}], one
    )
    small = recall_from_taint([], _expected())
    summary = recall_summary({"big": big, "small": small})
    # macro averages the two corpora equally; micro weights by size.
    assert summary["macro_recall"] == pytest.approx((big.recall + small.recall) / 2)
    assert summary["micro_recall"] == pytest.approx(1 / 4)


# -- report and bundle ------------------------------------------------------

def test_a_report_without_limitations_is_refused():
    from redfall.bench.runner import RunRecord, RunReportError, bench_report
    from redfall.bench.recall import recall_from_taint

    record = RunRecord("c", "1", "sha256:x", "redfall")
    result = recall_from_taint([], _expected())
    with pytest.raises(RunReportError, match="marketing with a number attached"):
        bench_report([(record, result)], limitations="")


def test_a_report_with_no_runs_is_refused():
    from redfall.bench.runner import RunReportError, bench_report

    with pytest.raises(RunReportError, match="no runs were recorded"):
        bench_report([], limitations="n/a")


def test_a_report_marks_itself_provisional():
    """Until someone independent re-runs it, the result is provisional."""
    from redfall.bench.runner import RunRecord, bench_report
    from redfall.bench.recall import recall_from_taint

    record = RunRecord("pythonbank", "1", "sha256:x", "redfall")
    result = recall_from_taint([], _expected())
    report = bench_report([(record, result)], limitations="single host, single run")
    assert report["provisional"] is True
    assert report["limitations"] == "single host, single run"


def test_writing_a_bundle_without_limitations_is_refused(tmp_path):
    from redfall.bench.runner import RunReportError, write_report

    with pytest.raises(RunReportError, match="refusing to write a report without LIMITATIONS"):
        write_report({"limitations": ""}, tmp_path / "bundle")


def test_a_bundle_contains_the_report_the_limitations_and_a_log(tmp_path):
    from redfall.bench.runner import RunRecord, bench_report, write_report
    from redfall.bench.recall import recall_from_taint

    record = RunRecord("pythonbank", "1", "sha256:x", "redfall")
    result = recall_from_taint([], _expected())
    report = bench_report([(record, result)], limitations="single host")
    bundle = write_report(report, tmp_path / "bundle")
    assert (bundle / "report.json").is_file()
    assert (bundle / "LIMITATIONS.md").is_file()
    # A missing log is written as an explicit marker, not silently omitted.
    logs = list(bundle.glob("*.log"))
    assert logs and "no raw log recorded" in logs[0].read_text(encoding="utf-8")


def test_the_bundle_limitations_file_carries_the_text(tmp_path):
    from redfall.bench.runner import RunRecord, bench_report, write_report
    from redfall.bench.recall import recall_from_taint

    record = RunRecord("c", "1", "sha256:x", "redfall")
    result = recall_from_taint([], _expected())
    report = bench_report([(record, result)], limitations="only two of five languages")
    bundle = write_report(report, tmp_path / "b")
    text = (bundle / "LIMITATIONS.md").read_text(encoding="utf-8")
    assert "only two of five languages" in text


# -- the shipped corpora ----------------------------------------------------

@pytest.mark.parametrize("name", ["pythonbank", "vulnbank", "chainbank", "vulnbank-adaptive"])
def test_the_shipped_corpora_are_valid_and_anchored(name):
    from redfall.bench.corpus import load_corpus

    root = ROOT / "bench" / "corpora" / name
    if not root.is_dir():
        pytest.skip(f"{name} corpus not generated here; run scripts/write_bench_corpus.py")
    corpus = load_corpus(root)
    assert len(corpus.expected) > 0
    for entry in corpus.expected:
        assert entry.file and entry.line > 0
        assert entry.language and entry.category


# -- the CLI ----------------------------------------------------------------

def test_bench_validate_prints_the_fingerprint(tmp_path):
    from click.testing import CliRunner

    from redfall.cli import main

    result = CliRunner().invoke(
        main, ["bench", "validate", str(_corpus_dir(tmp_path))], catch_exceptions=False
    )
    assert result.exit_code == 0
    payload = json.loads(result.output[result.output.index("{"):])
    assert payload["valid"] is True
    assert payload["corpus"]["fingerprint"].startswith("sha256:")


def test_bench_validate_refuses_an_empty_corpus(tmp_path):
    from click.testing import CliRunner

    from redfall.cli import main

    root = _corpus_dir(tmp_path, expected=[], truth=[])
    result = CliRunner().invoke(main, ["bench", "validate", str(root)], catch_exceptions=False)
    assert result.exit_code != 0
    assert "invalid corpus" in result.output
