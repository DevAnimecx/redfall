"""Evidence-gated campaign reports.

A campaign report is narrower than a scan report on purpose: it refuses to be
produced at all unless the hash chain verifies and at least one reportable
finding has E3/E4 evidence. Unverified findings that belong to the same scan are
still included, marked as unverified, so the report does not silently drop the
candidates the campaign did not prove.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..campaign.service import CampaignError, CampaignService
from ..evidence.ledger import EvidenceLedger, EvidenceError
from ..sarif import build_sarif
from ..store.models import Campaign, EvidenceRecord, Finding, Scan


class ReportError(RuntimeError):
    """The requested report would overstate the available evidence."""


def _finding_wire(finding: Finding, evidence: list[EvidenceRecord]) -> dict[str, Any]:
    wire = finding.to_wire()
    reportable = [record for record in evidence if record.grade in {"E3", "E4"}]
    wire["evidence_ids"] = [record.id for record in evidence]
    wire["verified_by_evidence"] = bool(reportable)
    wire["reproduced"] = bool(reportable)
    wire["evidence"] = finding.evidence
    return wire


def build_campaign_report(
    session: Session,
    campaign_id: str,
    *,
    report_format: str = "json",
) -> dict[str, Any]:
    campaign = session.get(Campaign, campaign_id)
    if campaign is None:
        raise ReportError(f"campaign not found: {campaign_id}")
    ledger = EvidenceLedger(session)
    try:
        verified_records = ledger.require_reportable(campaign_id)
    except EvidenceError as exc:
        raise ReportError(str(exc)) from exc
    chain = ledger.verify(campaign_id)
    linked_ids = {record.finding_id for record in verified_records if record.finding_id}
    if not linked_ids:
        raise ReportError(
            "reportable evidence exists but none is linked to a finding; "
            "a finding report would have no verified finding"
        )

    findings: list[Finding] = []
    if campaign.scan_id:
        findings = list(
            session.execute(
                select(Finding)
                .where(Finding.scan_id == campaign.scan_id)
                .order_by(Finding.severity, Finding.location_file, Finding.location_line)
            ).scalars()
        )
    known_ids = {finding.id for finding in findings}
    for finding_id in sorted(linked_ids - known_ids):
        finding = session.get(Finding, finding_id)
        if finding is not None:
            findings.append(finding)

    all_records = ledger.list(campaign_id)
    by_finding: dict[str, list[EvidenceRecord]] = {}
    for record in all_records:
        if record.finding_id:
            by_finding.setdefault(record.finding_id, []).append(record)

    finding_wires = [_finding_wire(finding, by_finding.get(finding.id, [])) for finding in findings]
    verified_findings = [item for item in finding_wires if item["verified_by_evidence"]]
    if not verified_findings:
        raise ReportError("no evidence-linked finding is reportable")

    if report_format not in {"json", "sarif"}:
        raise ReportError("format must be json or sarif")

    scan = session.get(Scan, campaign.scan_id) if campaign.scan_id else None
    scan_wire = {
        "id": scan.id if scan else campaign.id,
        "repo": campaign.repo,
        "commit": campaign.commit or (scan.commit if scan else ""),
        "status": scan.status if scan else campaign.status,
        "started_at": (scan.started_at.isoformat() if scan and scan.started_at else campaign.created_at.isoformat()),
    }
    sarif_findings = [item for item in finding_wires if item["verified_by_evidence"]]
    sarif = build_sarif(scan_wire, sarif_findings)

    try:
        status = CampaignService(session).status(campaign_id)
    except CampaignError:
        status = {}
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "campaign": campaign.to_wire(),
        "scan": scan_wire,
        "chain": chain.to_wire(),
        "readiness": {
            "ready": bool(chain.ok and verified_records),
            "reason": "" if chain.ok and verified_records else "evidence gate not met",
            "reportable_evidence": len(verified_records),
        },
        "budget": status.get("budget_remaining", {}),
        "evidence": [record.to_wire() for record in all_records],
        "findings": finding_wires,
        "verified_findings": [item["id"] for item in verified_findings],
        "unverified_findings": [
            item["id"] for item in finding_wires if not item["verified_by_evidence"]
        ],
        "limitations": [
            "Only E3/E4 evidence is reportable; unverified candidates stay visible in JSON but are not proofs.",
            "SARIF contains only verified findings; unverified candidates are omitted rather than downgraded.",
            "A reproduction is bounded by the recorded environment digest and source revision.",
            "This report does not claim coverage beyond the ingested files and executed PoCs.",
        ],
    }
    if report_format == "sarif":
        return {"format": "sarif", "report": sarif, "summary": report}
    return {"format": "json", "report": report, "summary": {
        "campaign_id": campaign.id,
        "verified": len(verified_findings),
        "unverified": len(finding_wires) - len(verified_findings),
        "evidence_records": len(all_records),
        "chain_ok": chain.ok,
    }}
