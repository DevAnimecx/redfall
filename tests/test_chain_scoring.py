"""Tests for chain scoring against the real chainbank manifest.

These use the manifest on disk, not a fixture, so a change to chainbank that
breaks the scorer's assumptions fails here rather than in a scan. The last
section drives the real gate entry point with a scan whose ids are the
scanner's own — the translation the gate does before scoring is part of what is
being verified.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from range_runner.chains import load_chains, score_chains, translate_finding_ids
from range_runner.run import run as run_gate

MANIFEST = (
    Path(__file__).resolve().parents[1] / "range" / "chainbank" / "manifest.yaml"
)


@pytest.fixture(scope="module")
def manifest() -> dict:
    return yaml.safe_load(MANIFEST.read_text())


@pytest.fixture(scope="module")
def declared(manifest):
    return load_chains(manifest)


ALL_FINDINGS = [
    f"CHAINBANK-{n:03d}" for n in range(1, 13)
]


def report_with(
    findings,
    *,
    chains=None,
    edges=None,
):
    return {
        "findings": [{"finding_id": f, "id": f} for f in findings],
        "chains": chains or [],
        "edges": edges or [],
    }


# ------------------------------------------------------------- manifest shape
def test_manifest_declares_six_chains(declared):
    assert len(declared) == 6


def test_every_chain_has_at_least_two_steps(declared):
    """A one-step chain is not a chain."""
    for chain in declared:
        assert len(chain.steps) >= 2, chain.id


def test_chain_steps_connect_head_to_tail(declared):
    for chain in declared:
        assert chain.steps[0].state_before == chain.start_state, chain.id
        assert chain.steps[-1].state_after == chain.end_state, chain.id
        for i in range(len(chain.steps) - 1):
            assert chain.steps[i].state_after == chain.steps[i + 1].state_before, (
                f"{chain.id}: step {i + 1} ends at {chain.steps[i].state_after} "
                f"but step {i + 2} starts at {chain.steps[i + 1].state_before}"
            )


def test_finding_ids_are_unique_across_the_manifest(declared):
    ids = [fid for chain in declared for fid in chain.finding_ids]
    assert len(ids) == len(set(ids))


def test_every_chain_names_narrative_requirements(declared):
    for chain in declared:
        assert chain.narrative_must_contain, chain.id


def test_findings_section_covers_every_chain_step(manifest, declared):
    step_ids = {fid for chain in declared for fid in chain.finding_ids}
    finding_ids = {f["finding_id"] for f in manifest["findings"]}
    assert step_ids == finding_ids


# --------------------------------------------------------------- perfect score
def test_a_complete_linked_narrated_report_scores_one(declared):
    chains = [
        {
            "id": chain.id,
            "finding_ids": list(chain.finding_ids),
            "narrative": " ".join(chain.narrative_must_contain),
            "cvss_compound": chain.cvss_compound,
        }
        for chain in declared
    ]
    score = score_chains(
        declared,
        report_with(ALL_FINDINGS, chains=chains),
        reported_finding_ids=ALL_FINDINGS,
    )
    assert score.chain_recall == 1.0
    assert score.chain_link_rate == 1.0
    assert score.chain_narrative_rate == 1.0
    assert score.chains_recalled == 6


# ------------------------------------------------------- the failure this catches
def test_finding_everything_but_linking_nothing_is_visible(declared):
    """The exact failure chainbank exists to catch."""
    score = score_chains(
        declared,
        report_with(ALL_FINDINGS),
        reported_finding_ids=ALL_FINDINGS,
    )
    assert score.chain_recall == 1.0, "every step was reported"
    assert score.chain_link_rate == 0.0, "but nothing was connected"
    assert score.chain_narrative_rate == 0.0


def test_missing_one_step_breaks_only_that_chain(declared):
    findings = [f for f in ALL_FINDINGS if f != "CHAINBANK-004"]
    score = score_chains(declared, report_with(findings), reported_finding_ids=findings)
    assert score.chains_recalled == 5
    broken = next(r for r in score.results if not r.complete)
    assert broken.chain_id == "CHN-02"
    assert broken.missing_steps == ["CHAINBANK-004"]


def test_partial_step_credit_is_reported_per_chain(declared):
    findings = ["CHAINBANK-001"]
    score = score_chains(declared, report_with(findings), reported_finding_ids=findings)
    chn01 = next(r for r in score.results if r.chain_id == "CHN-01")
    assert chn01.steps_reported == 1
    assert chn01.steps_total == 2
    assert chn01.complete is False


def test_a_reported_chain_with_no_matching_findings_is_not_credited(declared):
    chains = [{"id": "CHN-01", "finding_ids": ["CHAINBANK-001", "CHAINBANK-002"]}]
    score = score_chains(declared, report_with([], chains=chains), reported_finding_ids=[])
    assert score.chain_recall == 0.0


def test_narrative_missing_a_required_phrase_is_reported(declared):
    chains = [
        {
            "id": "CHN-01",
            "finding_ids": ["CHAINBANK-001", "CHAINBANK-002"],
            "narrative": "the attacker takes over the account",
        }
    ]
    findings = ["CHAINBANK-001", "CHAINBANK-002"]
    score = score_chains(declared, report_with(findings, chains=chains), reported_finding_ids=findings)
    result = next(r for r in score.results if r.chain_id == "CHN-01")
    assert result.complete is True
    assert result.narrative_ok is False
    assert result.narrative_missing


def test_narrative_check_is_case_insensitive(declared):
    chains = [
        {
            "id": "CHN-01",
            "finding_ids": ["CHAINBANK-001", "CHAINBANK-002"],
            "narrative": " ".join(p.upper() for p in declared[0].narrative_must_contain),
        }
    ]
    findings = ["CHAINBANK-001", "CHAINBANK-002"]
    score = score_chains(declared, report_with(findings, chains=chains), reported_finding_ids=findings)
    assert next(r for r in score.results if r.chain_id == "CHN-01").narrative_ok is True


def test_edges_express_links_too(declared):
    edges = [
        {"from": "CHAINBANK-001", "to": "CHAINBANK-002"},
        {"source": "CHAINBANK-003", "target": "CHAINBANK-004"},
    ]
    score = score_chains(declared, report_with(ALL_FINDINGS, edges=edges), reported_finding_ids=ALL_FINDINGS)
    assert score.joins_made == 2
    assert score.chain_link_rate == round(2 / score.joins_required, 4)


def test_a_compound_score_below_the_worst_step_is_rejected(declared):
    """Rule: chaining can add risk but cannot remove it."""
    chains = [
        {
            "id": "CHN-02",
            "finding_ids": ["CHAINBANK-003", "CHAINBANK-004"],
            "narrative": " ".join(next(c for c in declared if c.id == "CHN-02").narrative_must_contain),
            "cvss_compound": 3.0,
        }
    ]
    score = score_chains(declared, report_with(ALL_FINDINGS, chains=chains), reported_finding_ids=ALL_FINDINGS)
    result = next(r for r in score.results if r.chain_id == "CHN-02")
    assert result.reported_cvss_compound == 3.0
    assert result.cvss_compound_ok is False


def test_a_compound_score_far_from_the_manifest_is_rejected(declared):
    chains = [
        {
            "id": "CHN-02",
            "finding_ids": ["CHAINBANK-003", "CHAINBANK-004"],
            "narrative": "x",
            "cvss_compound": 5.0,
        }
    ]
    score = score_chains(declared, report_with(ALL_FINDINGS, chains=chains), reported_finding_ids=ALL_FINDINGS)
    assert next(r for r in score.results if r.chain_id == "CHN-02").cvss_compound_ok is False


def test_an_empty_report_scores_zero(declared):
    score = score_chains(declared, report_with([]), reported_finding_ids=[])
    assert score.chain_recall == 0.0
    assert score.chain_link_rate == 0.0
    assert score.chain_narrative_rate == 0.0
    assert score.chains_total == 6


def test_a_manifest_with_no_chains_section_scores_nothing():
    assert load_chains({}) == []
    score = score_chains([], report_with([]), reported_finding_ids=[])
    assert score.chains_total == 0
    assert score.chain_recall == 0.0


def test_as_dict_is_json_shaped(declared):
    score = score_chains(declared, report_with(ALL_FINDINGS), reported_finding_ids=ALL_FINDINGS)
    data = score.as_dict()
    assert set(data) >= {
        "chains_total",
        "chains_recalled",
        "chain_recall",
        "joins_required",
        "joins_made",
        "chain_link_rate",
        "chain_narrative_rate",
        "results",
    }
    assert len(data["results"]) == 6


# ------------------------------------------------- id translation (scanner→manifest)
def scanner_vocabulary(manifest) -> dict[str, str]:
    """The ids a scanner would assign itself: manifest id → scanner id."""
    return {
        entry["finding_id"]: f"fnd-{index:02d}"
        for index, entry in enumerate(manifest["findings"], 1)
    }


def matcher_id_map(vocabulary) -> dict[str, str]:
    """The finding→vuln map the matcher produces, which translation consumes."""
    return {scanner: manifest for manifest, scanner in vocabulary.items()}


def scan_findings_from_manifest(manifest, vocabulary) -> list[dict]:
    """One reproducible scan finding per manifest entry, in scanner ids."""
    by_manifest_id = {entry["finding_id"]: entry for entry in manifest["findings"]}
    findings = []
    for manifest_id, scanner_id in vocabulary.items():
        entry = by_manifest_id[manifest_id]
        location = entry["location"]
        findings.append(
            {
                "id": scanner_id,
                "finding_id": scanner_id,
                "category": entry["category"],
                "severity": entry.get("severity"),
                "location": {
                    "file": location["file"],
                    "line": (location.get("lines") or [0])[0],
                    "symbol": location.get("symbol") or "",
                },
                "reproduced": True,
            }
        )
    return findings


def scanner_chains(manifest, vocabulary, *, omit=()) -> list[dict]:
    """One scan-side chain entry per declared chain, in scanner ids."""
    out = []
    for chain in manifest["chains"]:
        if chain["id"] in omit:
            continue
        out.append(
            {
                "id": f"link-{chain['id'].lower()}",
                "status": "reproduced",
                "finding_ids": [vocabulary[step["finding_id"]] for step in chain["steps"]],
                "narrative": " ".join(chain["narrative_must_contain"]),
                "cvss_compound": chain["cvss_compound"],
            }
        )
    return out


def test_translate_rewrites_ids_and_keeps_the_original(manifest):
    vocabulary = scanner_vocabulary(manifest)
    scanner_id = vocabulary["CHAINBANK-001"]
    report = {
        "findings": [{"id": scanner_id, "finding_id": scanner_id}],
        "chains": [
            {
                "id": "link-1",
                "finding_ids": [scanner_id, "fnd-unmatched"],
                "steps": [{"n": 1, "finding_id": scanner_id, "ran": True}],
                "narrative": "kept",
            }
        ],
        "edges": [
            {
                "source": "none:*",
                "target": "secret:owner_email",
                "finding_ids": [scanner_id, vocabulary["CHAINBANK-002"]],
            }
        ],
    }
    translated = translate_finding_ids(report, matcher_id_map(vocabulary))

    chain = translated["chains"][0]
    assert chain["finding_ids"] == ["CHAINBANK-001", None]
    assert chain["original_finding_ids"] == [scanner_id, "fnd-unmatched"]
    assert chain["narrative"] == "kept"
    assert "steps" not in chain
    assert chain["step_records"][0]["ran"] is True

    edge = translated["edges"][0]
    assert edge["from"] == "CHAINBANK-001"
    assert edge["to"] == "CHAINBANK-002"
    assert "source" not in edge and edge["state_source"] == "none:*"
    assert edge["state_target"] == "secret:owner_email"

    # Translation builds a new document; the scan as loaded is untouched.
    assert report["chains"][0]["finding_ids"][0] == scanner_id
    assert "from" not in report["edges"][0]


def test_translate_null_is_falsy_when_the_pair_is_incomplete(manifest):
    vocabulary = scanner_vocabulary(manifest)
    scanner_id = vocabulary["CHAINBANK-001"]
    edge = translate_finding_ids(
        {"edges": [{"finding_ids": [scanner_id, "fnd-unmatched"]}]},
        matcher_id_map(vocabulary),
    )["edges"][0]
    assert edge["finding_ids"] == ["CHAINBANK-001", None]
    # No usable pair: no `from`/`to` is invented and the states stay put.
    assert "from" not in edge and "to" not in edge
    assert "source" not in edge


def test_untranslated_scanner_ids_credit_no_joins(declared, manifest):
    """The failure translation exists to fix: the report links, the scorer sees hashes."""
    vocabulary = scanner_vocabulary(manifest)
    report = report_with(
        list(vocabulary.values()),
        chains=scanner_chains(manifest, vocabulary),
        edges=[
            {
                "source": "none:*",
                "target": "secret:owner_email",
                "finding_ids": [
                    vocabulary["CHAINBANK-001"],
                    vocabulary["CHAINBANK-002"],
                ],
            }
        ],
    )
    score = score_chains(declared, report, reported_finding_ids=list(vocabulary))
    assert score.chain_recall == 1.0, "every step was matched"
    assert score.chain_link_rate == 0.0, "but every join was stated in the wrong vocabulary"


def test_a_directly_stated_translated_join_is_credited(declared, manifest):
    vocabulary = scanner_vocabulary(manifest)
    report = {
        "findings": scan_findings_from_manifest(manifest, vocabulary),
        "chains": [
            {
                "id": "link-chn-02",
                "finding_ids": [
                    vocabulary["CHAINBANK-003"],
                    vocabulary["CHAINBANK-004"],
                ],
            }
        ],
        "edges": [],
    }
    score = score_chains(
        declared,
        translate_finding_ids(report, matcher_id_map(vocabulary)),
        reported_finding_ids=list(vocabulary),
    )
    chn02 = next(r for r in score.results if r.chain_id == "CHN-02")
    assert chn02.joins_made == 1
    assert chn02.linked is True


def test_a_join_through_an_unmatched_finding_is_never_credited(declared, manifest):
    """A sequence broken by a step outside ground truth must not bridge over it."""
    vocabulary = scanner_vocabulary(manifest)
    ghost = "fnd-not-in-ground-truth"
    report = {
        "findings": scan_findings_from_manifest(manifest, vocabulary),
        "chains": [
            {
                "id": "link-chn-02",
                "finding_ids": [
                    vocabulary["CHAINBANK-003"],
                    ghost,
                    vocabulary["CHAINBANK-004"],
                ],
            }
        ],
        "edges": [],
    }
    translated = translate_finding_ids(report, matcher_id_map(vocabulary))
    assert translated["chains"][0]["finding_ids"] == ["CHAINBANK-003", None, "CHAINBANK-004"]
    score = score_chains(declared, translated, reported_finding_ids=list(vocabulary))
    chn02 = next(r for r in score.results if r.chain_id == "CHN-02")
    assert chn02.joins_required == 1
    assert chn02.joins_made == 0, "the scanner linked through a finding that does not exist"
    assert chn02.linked is False


# --------------------------------------------------------- through the real gate
def test_the_gate_scores_a_fully_translated_scan(manifest, tmp_path):
    """End to end: scanner-vocabulary scan in, perfect chain metrics out."""
    vocabulary = scanner_vocabulary(manifest)
    scan = {
        "scan_id": "scan-under-test",
        "duration_ms": 1234,
        "findings": scan_findings_from_manifest(manifest, vocabulary),
        "chains": scanner_chains(manifest, vocabulary),
        "edges": [],
    }
    fixes = [
        {"finding_id": scanner_id, "verified": True}
        for scanner_id in vocabulary.values()
    ]
    scan_path = tmp_path / "scan.json"
    scan_path.write_text(json.dumps(scan))
    fixes_path = tmp_path / "fixes.json"
    fixes_path.write_text(json.dumps(fixes))

    report = run_gate(MANIFEST.parent, scan_path, fixes_path)

    assert report.passed, report.failures
    assert report.chain_score is not None
    assert report.chain_score.chains_total == 6
    assert report.chain_score.chain_recall == 1.0
    assert report.chain_score.chain_link_rate == 1.0
    assert report.chain_score.chain_narrative_rate == 1.0


def test_the_gate_fails_when_one_chain_is_not_linked(manifest, tmp_path):
    """Every finding is still reported; one chain is simply never connected."""
    vocabulary = scanner_vocabulary(manifest)
    scan = {
        "scan_id": "scan-under-test",
        "duration_ms": 1234,
        "findings": scan_findings_from_manifest(manifest, vocabulary),
        "chains": scanner_chains(manifest, vocabulary, omit=("CHN-06",)),
        "edges": [],
    }
    fixes = [
        {"finding_id": scanner_id, "verified": True}
        for scanner_id in vocabulary.values()
    ]
    scan_path = tmp_path / "scan.json"
    scan_path.write_text(json.dumps(scan))
    fixes_path = tmp_path / "fixes.json"
    fixes_path.write_text(json.dumps(fixes))

    report = run_gate(MANIFEST.parent, scan_path, fixes_path)

    assert not report.passed
    assert any(failure.startswith("chain_link_rate") for failure in report.failures)
    assert any(failure.startswith("chain_narrative_rate") for failure in report.failures)
