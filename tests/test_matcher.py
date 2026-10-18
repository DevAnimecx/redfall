"""The §9 matching rule must be exact. A near-miss is a miss."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "range"))

from range_runner.ground_truth import load_manifest
from range_runner.match import canonical_category, location_matches, match


class V:
    """Minimal stand-in for a ManifestVuln, so the rule can be probed directly."""

    def __init__(self, id, category, file, line, symbol=""):
        self.id = id
        self.category = category
        self.file = file
        self.symbol = symbol
        self.lines = [line]
        self.anchor_line = line
        self.severity = "high"


def finding(id, category, file, line, symbol="", reproduced=True):
    return {
        "id": id,
        "category": category,
        "severity": "high",
        "location": {"file": file, "line": line, "symbol": symbol},
        "reproduced": reproduced,
    }


def test_line_tolerance_is_five_and_not_six():
    assert location_matches("a.ts", 43, "", "a.ts", 38, "")[0] is True
    assert location_matches("a.ts", 44, "", "a.ts", 38, "")[0] is False


def test_symbol_match_wins_even_when_lines_are_far_apart():
    ok, line_ok, symbol_ok = location_matches("a.ts", 900, "loginHandler", "a.ts", 38, "loginHandler")
    assert ok is True
    assert line_ok is False
    assert symbol_ok is True


def test_wrong_file_never_matches():
    assert location_matches("b.ts", 38, "loginHandler", "a.ts", 38, "loginHandler")[0] is False


def test_category_must_match_or_be_a_declared_alias():
    vulns = [V("VULN-001", "sqli", "a.ts", 38, "loginHandler")]
    assert match([finding("f1", "sqli", "a.ts", 38, "loginHandler")], vulns).matches
    assert match([finding("f1", "sql_injection", "a.ts", 38, "loginHandler")], vulns).matches
    assert not match([finding("f1", "xss_reflected", "a.ts", 38, "loginHandler")], vulns).matches


def test_alias_table_does_not_invent_equivalences():
    assert canonical_category("sqli") == "sqli"
    assert canonical_category("sql_injection") == "sqli"
    # An unknown name is returned unchanged so it records as a miss.
    assert canonical_category("some_new_category") == "some_new_category"
    assert canonical_category("idor") != canonical_category("sqli")


def test_one_finding_cannot_claim_two_manifest_entries():
    vulns = [V("V1", "sqli", "a.ts", 38), V("V2", "sqli", "a.ts", 40)]
    result = match([finding("f1", "sqli", "a.ts", 38)], vulns)
    assert len(result.matches) == 1
    assert result.missed_vulns == ["V2"]


def test_two_findings_cannot_both_claim_one_entry():
    vulns = [V("V1", "sqli", "a.ts", 38)]
    result = match(
        [finding("f1", "sqli", "a.ts", 38), finding("f2", "sqli", "a.ts", 39)],
        vulns,
    )
    assert len(result.matches) == 1
    assert len(result.unmatched_findings) == 1


def test_closest_line_wins_when_two_findings_compete():
    vulns = [V("V1", "sqli", "a.ts", 38)]
    result = match(
        [finding("far", "sqli", "a.ts", 42), finding("near", "sqli", "a.ts", 38)],
        vulns,
    )
    assert result.matches[0].finding_id == "near"


def test_manifest_loads_all_32_ground_truth_entries(vulnbank):
    vulns = load_manifest(vulnbank / "manifest.yaml")
    assert len(vulns) == 32
    ids = {v.id for v in vulns}
    assert len(ids) == 32, "duplicate vuln ids in the manifest"
    for v in vulns:
        assert v.file, f"{v.id} has no location.file"
        assert v.lines, f"{v.id} has no location.lines"
        assert v.category, f"{v.id} has no category"
