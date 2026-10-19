"""Reproduction outcomes become evidence; reports refuse unproven claims."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from redfall.campaign.service import CampaignService
from redfall.evidence.ledger import EvidenceLedger
from redfall.reporting.campaign_report import ReportError, build_campaign_report
from redfall.store.models import Base, EvidenceRecord, Finding, Scan
from redfall.validation.reproducer import Reproducer
from redfall.validation.validator import Verdict

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "range" / "vulnbank"


class StubSandbox:
    image = "redfall-test-image"


class ReproducedValidator:
    sandbox = StubSandbox()

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def validate(self, **kwargs):
        return Verdict(
            run_id="sandbox-run-1",
            reproduced=True,
            reason="marker matched",
            status=500,
            body="SQLITE_ERROR near SELECT",
            evidence="response body contained SQLITE_ERROR",
            detail="real verdict shape",
            container_id="container-1",
            duration_ms=1200,
        )


class NotReproducedValidator:
    sandbox = StubSandbox()

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def validate(self, **kwargs):
        return Verdict(
            run_id="sandbox-run-2",
            reproduced=False,
            reason="response was 200 without the marker",
            status=200,
            body="ok",
            evidence="response body was ok",
            duration_ms=300,
        )


@pytest.fixture()
def session(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'report.db'}", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with Session() as session:
        yield session
    engine.dispose()


def build_rows(session, *, status="indexing"):
    service = CampaignService(session)
    campaign = service.create(
        str(TARGET),
        budget_usd=5.0,
        budget_tokens=10_000,
        budget_sandbox_minutes=10.0,
    )
    service.transition(campaign.id, "scoped")
    service.transition(campaign.id, status)
    scan = Scan(
        id="scan-report",
        repo=str(TARGET),
        commit="abc123",
        status="completed",
        findings_total=2,
    )
    verified = Finding(
        id="finding-reproduced",
        scan_id=scan.id,
        branch_id="branch-1",
        category="sql_injection",
        severity="high",
        title="SQL injection reaches the marker",
        location_file="src/routes/users.ts",
        location_line=12,
        poc={"method": "GET", "path": "/api/users/1"},
        evidence="SQLITE_ERROR",
        status="open",
    )
    candidate = Finding(
        id="finding-candidate",
        scan_id=scan.id,
        branch_id="branch-1",
        category="xss",
        severity="medium",
        title="A static candidate",
        location_file="src/routes/comments.ts",
        location_line=20,
        poc={"method": "GET", "path": "/api/comments"},
        evidence="",
        status="open",
    )
    campaign.scan_id = scan.id
    session.add_all([scan, verified, candidate])
    session.commit()
    return campaign.id, scan, verified


def test_successful_reproduction_appends_e3_and_report_is_gated(session, tmp_path):
    campaign_id, scan, finding = build_rows(session)
    outcome = Reproducer(
        session,
        validator_factory=ReproducedValidator,
        workdir=tmp_path,
    ).reproduce(finding.id, campaign_id=campaign_id, target=TARGET)
    session.commit()

    assert outcome.reproduced is True
    assert outcome.evidence_grade == "E3"
    assert outcome.reportable is True
    assert finding.reproduced is True
    assert finding.status == "verified"

    records = EvidenceLedger(session).list(campaign_id)
    assert len(records) == 1
    assert records[0].grade == "E3"
    assert records[0].finding_id == finding.id
    assert records[0].reproduce_command
    assert records[0].environment_digest
    assert records[0].payload["observable"] == "response body contained SQLITE_ERROR"

    data = build_campaign_report(session, campaign_id)
    report = data["report"]
    assert data["summary"]["verified"] == 1
    assert data["summary"]["unverified"] == 1
    assert report["readiness"]["ready"] is True
    assert report["verified_findings"] == [finding.id]
    assert "finding-candidate" in report["unverified_findings"]
    assert report["evidence"][0]["reproduce_command"].startswith("redfall reproduce")

    sarif = build_campaign_report(session, campaign_id, report_format="sarif")
    assert sarif["report"]["version"] == "2.1.0"
    result = sarif["report"]["runs"][0]["results"]
    assert any(item["ruleId"] == "sql_injection" for item in result)
    assert len(result) == 1
    assert result[0]["properties"]["redfall"]["evidence_ids"]


def test_failed_reproduction_is_e2_and_not_reportable(session, tmp_path):
    campaign_id, scan, finding = build_rows(session)
    outcome = Reproducer(
        session,
        validator_factory=NotReproducedValidator,
        workdir=tmp_path,
    ).reproduce(finding.id, campaign_id=campaign_id, target=TARGET)
    session.commit()

    assert outcome.reproduced is False
    assert outcome.evidence_grade == "E2"
    assert outcome.reportable is False
    assert finding.reproduced is False
    records = EvidenceLedger(session).list(campaign_id)
    assert records[0].grade == "E2"
    assert EvidenceLedger(session).reportable(campaign_id) == []
    with pytest.raises(ReportError):
        build_campaign_report(session, campaign_id)


def test_broken_chain_blocks_report(session, tmp_path):
    campaign_id, scan, finding = build_rows(session)
    Reproducer(
        session,
        validator_factory=ReproducedValidator,
        workdir=tmp_path,
    ).reproduce(finding.id, campaign_id=campaign_id, target=TARGET)
    session.commit()
    record = session.scalars(select(EvidenceRecord)).one()
    record.claim = "tampered after the fact"
    session.commit()

    verification = EvidenceLedger(session).verify(campaign_id)
    assert verification.ok is False
    with pytest.raises(ReportError):
        build_campaign_report(session, campaign_id)
