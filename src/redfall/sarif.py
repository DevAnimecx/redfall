"""SARIF 2.1.0 export for stored scan findings.

What the export claims, and what it refuses to claim:

* Every finding becomes a `result`. Verified findings (`reproduced`) carry
  `properties.redfall.verified = true` and their evidence; unproven candidates
  carry `verified = false` and stay visible — the same doctrine as the rest of
  the pipeline. A consumer that wants only executed proofs filters on that
  flag; nothing here silently drops or upgrades a finding.
* Severity maps to SARIF levels mechanically (critical/high → error,
  medium → warning, low/info → note), and the CVSS floor is exported as the
  `security-severity` property that GitHub code scanning reads.
* `partialFingerprints` uses the finding's dedupe key, so re-imports track the
  same finding across scans.
"""

from __future__ import annotations

from .version import __version__

SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

# The SARIF spec version this log implements. Kept as a constant so the log
# never carries a bare JSON `version` literal that could be mistaken for (or
# drift into) the release version.
SARIF_VERSION = "2.1.0"

LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _level(severity: str) -> str:
    return LEVELS.get((severity or "").lower(), "warning")


def build_sarif(scan: dict, findings: list[dict], tool_version: str = __version__) -> dict:
    """A SARIF log for one scan's stored findings."""
    rules: list[dict] = []
    rule_ids: set[str] = set()
    for finding in findings:
        category = str(finding.get("category") or "unknown")
        if category in rule_ids:
            continue
        rule_ids.add(category)
        rule: dict[str, object] = {
            "id": category,
            "name": category,
            "shortDescription": {"text": str(finding.get("title") or category)},
        }
        score = finding.get("cvss_score")
        if isinstance(score, (int, float)):
            rule["properties"] = {"security-severity": f"{float(score):.1f}"}
        rules.append(rule)

    results: list[dict] = []
    for finding in findings:
        location = finding.get("location") or {}
        line = int(location.get("line") or 0)
        physical: dict[str, object] = {
            "artifactLocation": {"uri": str(location.get("file") or "")},
        }
        if line >= 1:  # a SARIF region must be 1-based; 0 means "no line known"
            physical["region"] = {"startLine": line}
        results.append(
            {
                "ruleId": str(finding.get("category") or "unknown"),
                "level": _level(str(finding.get("severity") or "")),
                "message": {"text": str(finding.get("title") or finding.get("id") or "")},
                "locations": [{"physicalLocation": physical}],
                "partialFingerprints": {
                    "redfall/dedupeKey": str(finding.get("dedupe_key") or finding.get("id") or "")
                },
                "properties": {
                    "redfall": {
                        "id": finding.get("id"),
                        "verified": bool(finding.get("reproduced")),
                        "status": finding.get("status"),
                        "severity": finding.get("severity"),
                        "cvss_score": finding.get("cvss_score"),
                        "symbol": location.get("symbol") or "",
                        "evidence": str(finding.get("evidence") or "")[:2000],
                        "reproduction_run_id": finding.get("reproduction_run_id"),
                    }
                },
            }
        )

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Redfall",
                        "version": tool_version,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": str(scan.get("status") or "") == "completed",
                        "properties": {
                            "redfall": {
                                "scan_id": scan.get("id"),
                                "repo": scan.get("repo"),
                                "commit": scan.get("commit"),
                            }
                        },
                    }
                ],
                "results": results,
            }
        ],
    }
