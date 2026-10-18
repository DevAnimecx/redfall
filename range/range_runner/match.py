"""Deterministic finding↔manifest matching (§9).

The rule is fixed and there is no fuzzy fallback:

    F.category == M.category (or a declared alias)
    AND F.location.file == M.location.file
    AND ( |F.location.line - M.location.lines[0]| <= 5
          OR F.location.symbol == M.location.symbol )

A finding that does not satisfy all three conditions is a false positive. The
scorer never reclassifies a near-miss into a hit, because that is how a range
starts measuring itself instead of the tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

LINE_TOLERANCE = 5

# Alias table. It is intentionally small: every entry is a genuine synonym used
# in the wild for the same defect, not a way to make a miss look like a hit.
CATEGORY_ALIASES: dict[str, str] = {
    "sql_injection": "sqli",
    "sql-injection": "sqli",
    "reflected_xss": "xss_reflected",
    "persistent_xss": "xss_stored",
    "stored_xss": "xss_stored",
    "directory_traversal": "path_traversal",
    "command_injection": "cmd_injection",
    "os_command_injection": "cmd_injection",
    "server_side_request_forgery": "ssrf",
    "metadata_ssrf": "ssrf_metadata",
    "cloud_metadata_ssrf": "ssrf_metadata",
    "auto_binding": "mass_assignment",
    "proto_pollution": "prototype_pollution",
    "insecure_deserialization": "unsafe_deserialization",
    "hardcoded_credentials": "hardcoded_secret",
    "sensitive_data_exposure": "secret_exposure",
    "account_enumeration": "user_enumeration",
    "brute_force": "missing_rate_limit",
    "no_rate_limit": "missing_rate_limit",
    "unbounded_query": "no_pagination_limit",
    "missing_pagination": "no_pagination_limit",
    "negative_value": "negative_amount",
    "url_redirect": "open_redirect",
    "stack_trace_disclosure": "verbose_error",
    "information_disclosure": "verbose_error",
    "weak_hash": "weak_password_hash_md5",
    "md5_password": "weak_password_hash_md5",
    "unverified_webhook": "missing_signature_verify",
    "missing_webhook_signature": "missing_signature_verify",
    "file_upload": "unrestricted_file_type",
    "dangerous_file_type": "unrestricted_file_type",
    "formula_injection": "csv_injection",
    "cors_misconfiguration": "cors_wildcard_credentials",
    "no_csp": "missing_csp",
    "broken_object_level_authorization": "idor",
    "bola": "idor",
}


def canonical_category(category: str) -> str:
    key = (category or "").strip()
    return CATEGORY_ALIASES.get(key, key)


@dataclass
class Match:
    vuln_id: str
    finding_id: str
    category: str
    file: str
    manifest_line: int
    finding_line: int
    symbol_matched: bool
    line_matched: bool
    severity: str = ""

    def how(self) -> str:
        parts = []
        if self.symbol_matched:
            parts.append("symbol")
        if self.line_matched:
            parts.append(f"line±{LINE_TOLERANCE}")
        return "+".join(parts) or "none"


@dataclass
class MatchResult:
    matches: list[Match] = field(default_factory=list)
    unmatched_findings: list[dict[str, Any]] = field(default_factory=list)
    missed_vulns: list[str] = field(default_factory=list)

    @property
    def matched_vuln_ids(self) -> set[str]:
        return {m.vuln_id for m in self.matches}


def category_matches(finding_category: str, manifest_category: str) -> bool:
    return canonical_category(finding_category) == canonical_category(manifest_category)


def location_matches(
    finding_file: str,
    finding_line: int,
    finding_symbol: str,
    manifest_file: str,
    manifest_line: int,
    manifest_symbol: str,
) -> tuple[bool, bool, bool]:
    """Return (overall, line_matched, symbol_matched)."""
    if finding_file != manifest_file:
        return False, False, False
    line_ok = abs(int(finding_line or 0) - int(manifest_line or 0)) <= LINE_TOLERANCE
    symbol_ok = bool(manifest_symbol) and finding_symbol == manifest_symbol
    return (line_ok or symbol_ok), line_ok, symbol_ok


def match(findings: Iterable[dict[str, Any]], vulns: Iterable[Any]) -> MatchResult:
    """Greedy one-to-one matching, best line agreement first.

    One finding can only account for one manifest entry, so a scanner cannot
    score twice by reporting the same defect under two names.
    """
    result = MatchResult()
    findings = list(findings)
    vulns = list(vulns)
    taken_findings: set[str] = set()

    candidates: list[tuple[int, Match]] = []
    for vuln in vulns:
        for finding in findings:
            if not category_matches(str(finding.get("category") or ""), vuln.category):
                continue
            location = finding.get("location") or {}
            overall, line_ok, symbol_ok = location_matches(
                str(location.get("file") or ""),
                int(location.get("line") or 0),
                str(location.get("symbol") or ""),
                vuln.file,
                vuln.anchor_line,
                vuln.symbol,
            )
            if not overall:
                continue
            distance = abs(int(location.get("line") or 0) - vuln.anchor_line)
            candidates.append(
                (
                    distance,
                    Match(
                        vuln_id=vuln.id,
                        finding_id=str(finding.get("id") or ""),
                        category=vuln.category,
                        file=vuln.file,
                        manifest_line=vuln.anchor_line,
                        finding_line=int(location.get("line") or 0),
                        symbol_matched=symbol_ok,
                        line_matched=line_ok,
                        severity=vuln.severity,
                    ),
                )
            )

    candidates.sort(key=lambda pair: (pair[0], pair[1].vuln_id, pair[1].finding_id))
    claimed_vulns: set[str] = set()
    for _distance, candidate in candidates:
        if candidate.vuln_id in claimed_vulns or candidate.finding_id in taken_findings:
            continue
        claimed_vulns.add(candidate.vuln_id)
        taken_findings.add(candidate.finding_id)
        result.matches.append(candidate)

    for finding in findings:
        if str(finding.get("id") or "") not in taken_findings:
            result.unmatched_findings.append(finding)
    for vuln in vulns:
        if vuln.id not in claimed_vulns:
            result.missed_vulns.append(vuln.id)

    result.matches.sort(key=lambda m: m.vuln_id)
    return result
