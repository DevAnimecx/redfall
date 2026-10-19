"""SARIF 2.1.0 export.

Two layers are tested: the builder's mapping rules (levels, rule dedupe,
fingerprints, the honest `verified` flag), and the real CLI reading a real
Postgres scan and emitting the log.
"""

from __future__ import annotations

import json
import uuid

import pytest
from click.testing import CliRunner

from redfall.cli import main
from redfall.sarif import build_sarif
from redfall.store.db import init_engine, session_scope
from redfall.store.models import Base, Finding, Scan


def _finding(index: int, **overrides) -> dict:
    data = {
        "id": f"fnd-{index}",
        "category": "sqli",
        "severity": "critical",
        "cvss_score": 9.0,
        "title": f"SQL injection #{index}",
        "location": {"file": "src/routes/auth.ts", "line": 41, "symbol": "loginHandler"},
        "evidence": "200 with 3 rows",
        "reproduced": True,
        "reproduction_run_id": "run-1",
        "dedupe_key": f"key-{index}",
        "status": "open",
    }
    data.update(overrides)
    return data


# --------------------------------------------------------------- pure builder
def test_builder_maps_levels_rules_and_fingerprints():
    scan = {"id": "scan-1", "repo": "acme/api", "commit": "abc123", "status": "completed"}
    findings = [
        _finding(1),
        _finding(2, category="xss", severity="low", cvss_score=0.1, reproduced=False),
        _finding(3, category="xss", severity="info", cvss_score=None, location={"file": "x.ts", "line": 0, "symbol": ""}),
        _finding(4, category="idor", severity="bizarre", cvss_score=None),
    ]
    log = build_sarif(scan, findings)

    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-schema-2.1.0.json")
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "Redfall"
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["properties"]["redfall"]["scan_id"] == "scan-1"

    # Rules are deduped by category, in first-seen order.
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["sqli", "xss", "idor"]
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.0"

    by_id = {r["properties"]["redfall"]["id"]: r for r in run["results"]}
    assert by_id["fnd-1"]["level"] == "error"
    assert by_id["fnd-2"]["level"] == "note"
    assert by_id["fnd-3"]["level"] == "note"  # info is a note, never dropped
    assert by_id["fnd-4"]["level"] == "warning"  # unknown severities fall back, never disappear

    # Verification is carried, never assumed: fnd-2 was not reproduced.
    assert by_id["fnd-1"]["properties"]["redfall"]["verified"] is True
    assert by_id["fnd-2"]["properties"]["redfall"]["verified"] is False

    # Fingerprints come from the dedupe key.
    assert by_id["fnd-2"]["partialFingerprints"]["redfall/dedupeKey"] == "key-2"

    # A finding with no known line has no region.
    physical = by_id["fnd-3"]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "x.ts"
    assert "region" not in physical


def test_builder_with_no_findings_still_emits_a_valid_run():
    log = build_sarif({"id": "scan-2", "repo": "r", "commit": "", "status": "running"}, [])
    run = log["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []
    assert run["invocations"][0]["executionSuccessful"] is False


# ---------------------------------------------------------------- real store
@pytest.fixture()
def session(monkeypatch, postgres_url):
    """A real Postgres session; DATABASE_URL is pointed at it so the CLI reads
    the same database the rows were written to."""
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    engine = init_engine(postgres_url)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with session_scope() as s:
        yield s


def test_report_sarif_from_the_real_store(session, tmp_path):
    sid = f"scan-{uuid.uuid4().hex[:10]}"
    session.add(Scan(id=sid, repo="range/vulnbank", commit="deadbeef", status="completed"))
    session.flush()
    session.add(
        Finding(
            id="fnd-001",
            scan_id=sid,
            branch_id="br-1",
            category="sqli",
            severity="critical",
            title="SQL injection in loginHandler",
            location_file="src/routes/auth.ts",
            location_line=41,
            location_symbol="loginHandler",
            poc={"request": "POST /api/auth/login"},
            evidence="status=200 rows=2",
            reproduced=True,
            reproduction_run_id="run-1",
            dedupe_key="vuln-001",
            status="open",
        )
    )
    session.add(
        Finding(
            id="fnd-002",
            scan_id=sid,
            branch_id="br-1",
            category="xss",
            severity="low",
            title="Reflected XSS candidate",
            location_file="src/views/search.ts",
            location_line=12,
            location_symbol="render",
            poc={},
            evidence="",
            reproduced=False,
            dedupe_key="cand-9",
            status="open",
        )
    )
    session.commit()  # the CLI reads through its own connection

    runner = CliRunner()
    result = runner.invoke(main, ["report", sid, "--format", "sarif"])
    assert result.exit_code == 0, result.output
    log = json.loads(result.output)
    run = log["runs"][0]
    assert len(run["results"]) == 2
    by_id = {r["properties"]["redfall"]["id"]: r for r in run["results"]}
    assert by_id["fnd-001"]["ruleId"] == "sqli"
    assert by_id["fnd-001"]["properties"]["redfall"]["verified"] is True
    assert by_id["fnd-001"]["properties"]["redfall"]["evidence"] == "status=200 rows=2"
    assert by_id["fnd-002"]["properties"]["redfall"]["verified"] is False
    assert by_id["fnd-001"]["locations"][0]["physicalLocation"]["region"]["startLine"] == 41

    out = tmp_path / "scan.sarif"
    written = runner.invoke(main, ["report", sid, "--format", "sarif", "--out", str(out)])
    assert written.exit_code == 0, written.output
    on_disk = json.loads(out.read_text(encoding="utf-8"))
    assert on_disk == log
