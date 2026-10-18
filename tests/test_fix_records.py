"""The `redfall fix --out` record and the gate's reading of it.

`write_fixes_file` is what turns one fix run into the JSON `range_runner`
consumes via `--fixes`. The scoring seam is tested for real: only
`verified: true` may count toward fix_rate.
"""

from __future__ import annotations

import json

from redfall.fix.fixer import FixOutcome, fix_record, write_fixes_file
from range_runner.match import Match, MatchResult
from range_runner.run import compute_metrics


def outcome(**overrides) -> FixOutcome:
    base = dict(
        fix_id="fix-000000000001",
        finding_id="f-1",
        status="verified",
        verified=True,
        test_result="passed",
        poc_neutralized=True,
        attempts=1,
        strategy="require authentication on the lookup route",
    )
    base.update(overrides)
    return FixOutcome(**base)


# ------------------------------------------------------------------ record
def test_fix_record_carries_the_keys_the_gate_reads():
    record = fix_record(outcome())
    assert record["finding_id"] == "f-1"
    assert record["verified"] is True
    assert set(record) >= {
        "finding_id",
        "fix_id",
        "status",
        "verified",
        "test_result",
        "poc_neutralized",
        "attempts",
    }


def test_fix_record_reports_an_unverified_fix_as_such():
    record = fix_record(outcome(verified=False, status="poc_still_works", poc_neutralized=False))
    assert record["verified"] is False
    assert record["poc_neutralized"] is False


# ------------------------------------------------------------------- file
def test_write_fixes_file_builds_a_list(tmp_path):
    path = tmp_path / "fixes.json"
    write_fixes_file(path, fix_record(outcome(finding_id="f-1")))
    write_fixes_file(
        path,
        fix_record(outcome(finding_id="f-2", verified=False, status="poc_still_works")),
    )
    loaded = json.loads(path.read_text())
    assert [record["finding_id"] for record in loaded] == ["f-1", "f-2"]
    assert loaded[1]["verified"] is False


def test_write_fixes_file_replaces_a_record_for_the_same_finding(tmp_path):
    path = tmp_path / "fixes.json"
    write_fixes_file(
        path,
        fix_record(outcome(finding_id="f-1", verified=False, status="poc_still_works")),
    )
    write_fixes_file(path, fix_record(outcome(finding_id="f-1", verified=True)))
    loaded = json.loads(path.read_text())
    assert len(loaded) == 1
    assert loaded[0]["verified"] is True


def test_write_fixes_file_reads_back_the_document_form(tmp_path):
    path = tmp_path / "fixes.json"
    path.write_text(json.dumps({"fixes": [{"finding_id": "f-9", "verified": False}]}))
    write_fixes_file(path, fix_record(outcome(finding_id="f-1")))
    loaded = json.loads(path.read_text())
    assert {record["finding_id"] for record in loaded} == {"f-1", "f-9"}


# ----------------------------------------------------------- scoring seam
def compute_fix_rate(fixes: list[dict]) -> float:
    match_result = MatchResult(
        matches=[
            Match(
                vuln_id="VULN-001",
                finding_id="f-1",
                category="sqli",
                file="src/db.ts",
                manifest_line=10,
                finding_line=10,
                symbol_matched=True,
                line_matched=True,
            )
        ]
    )
    metrics, _ = compute_metrics(
        manifest=[object()],
        findings=[{"id": "f-1", "reproduced": True}],
        match_result=match_result,
        fixes=fixes,
        duration_ms=1,
    )
    return metrics.fix_rate


def test_a_verified_record_scores_the_fix(tmp_path):
    path = tmp_path / "fixes.json"
    write_fixes_file(path, fix_record(outcome(finding_id="f-1", verified=True)))
    assert compute_fix_rate(json.loads(path.read_text())) == 1.0


def test_an_unverified_record_does_not_score_the_fix(tmp_path):
    path = tmp_path / "fixes.json"
    write_fixes_file(
        path,
        fix_record(outcome(finding_id="f-1", verified=False, status="poc_still_works")),
    )
    assert compute_fix_rate(json.loads(path.read_text())) == 0.0


def test_a_record_for_a_different_finding_does_not_score(tmp_path):
    path = tmp_path / "fixes.json"
    write_fixes_file(path, fix_record(outcome(finding_id="f-other")))
    assert compute_fix_rate(json.loads(path.read_text())) == 0.0
