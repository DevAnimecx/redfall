"""The range gate. Computes every metric from real scan output and prints the verdict.

    python -m range_runner.run --target range/vulnbank --out range/report.json

Thresholds (§9): recall >= 0.60, precision >= 0.85, repro_rate == 1.00,
fix_rate >= 0.50, duration_ms <= 900000.

Nothing here estimates a number. Recall and precision come from matching real
findings against the manifest; repro_rate comes from the `reproduced` flag each
finding carries from its sandbox execution; fix_rate from the fixes recorded
against the matched findings.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .chains import ChainScore, load_chains, score_chains, translate_finding_ids
from .ground_truth import load_manifest, load_manifest_document, severity_breakdown
from .match import MatchResult, match

THRESHOLDS = {
    "recall": (0.60, ">="),
    "precision": (0.85, ">="),
    "repro_rate": (1.00, "=="),
    "fix_rate": (0.50, ">="),
    "duration_ms": (900000, "<="),
}

# Applied only to targets whose manifest declares chains. A chain target is not
# scored by counting vulnerabilities: the unit of work is the path.
CHAIN_THRESHOLDS = {
    "chain_recall": (5 / 6, ">="),
    "chain_link_rate": (1.00, "=="),
    "chain_narrative_rate": (1.00, "=="),
}


@dataclass
class Metrics:
    manifest_total: int
    findings_total: int
    matched: int
    unmatched_findings: int
    missed: int
    recall: float
    precision: float
    repro_rate: float
    fix_rate: float
    duration_ms: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GateReport:
    target: str
    scan_id: str
    metrics: Metrics
    chain_score: ChainScore | None = None
    matches: list[dict[str, Any]] = field(default_factory=list)
    missed_vulns: list[str] = field(default_factory=list)
    false_positives: list[dict[str, Any]] = field(default_factory=list)
    thresholds: dict[str, Any] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)
    passed: bool = False
    manifest_severity: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def compute_metrics(
    *,
    manifest: list[Any],
    findings: list[dict[str, Any]],
    match_result: MatchResult,
    fixes: list[dict[str, Any]],
    duration_ms: int,
) -> tuple[Metrics, float]:
    """Derive the five gate metrics. Returns (metrics, repro_rate)."""
    matched_ids = {m.finding_id for m in match_result.matches}
    reproduced_matched = sum(
        1
        for f in findings
        if str(f.get("id")) in matched_ids and f.get("reproduced") is True
    )
    repro_rate = _ratio(reproduced_matched, len(matched_ids))

    verified_by_finding = {str(f.get("finding_id")): bool(f.get("verified")) for f in fixes}
    fixed_matched = sum(1 for fid in matched_ids if verified_by_finding.get(fid) is True)
    fix_rate = _ratio(fixed_matched, len(matched_ids))

    metrics = Metrics(
        manifest_total=len(manifest),
        findings_total=len(findings),
        matched=len(matched_ids),
        unmatched_findings=len(match_result.unmatched_findings),
        missed=len(match_result.missed_vulns),
        recall=_ratio(len(matched_ids), len(manifest)),
        precision=_ratio(len(matched_ids), len(findings)),
        repro_rate=repro_rate,
        fix_rate=fix_rate,
        duration_ms=int(duration_ms),
    )
    return metrics, repro_rate


def evaluate_chains(score: ChainScore | None) -> list[str]:
    """Threshold violations for the chain metrics. None means no chain target."""
    if score is None:
        return []
    failures: list[str] = []
    checks = {
        "chain_recall": score.chain_recall,
        "chain_link_rate": score.chain_link_rate,
        "chain_narrative_rate": score.chain_narrative_rate,
    }
    for name, (limit, op) in CHAIN_THRESHOLDS.items():
        value = checks[name]
        if op == ">=" and not value >= limit:
            failures.append(f"{name} {value} < required {round(limit, 4)}")
        elif op == "==" and not abs(value - limit) < 1e-9:
            failures.append(f"{name} {value} != required {limit}")
    return failures


def evaluate(metrics: Metrics) -> list[str]:
    """Return the list of threshold violations. Empty means the gate passes."""
    failures: list[str] = []
    checks = {
        "recall": metrics.recall,
        "precision": metrics.precision,
        "repro_rate": metrics.repro_rate,
        "fix_rate": metrics.fix_rate,
        "duration_ms": metrics.duration_ms,
    }
    for name, (limit, op) in THRESHOLDS.items():
        value = checks[name]
        if op == ">=" and not value >= limit:
            failures.append(f"{name} {value} < required {limit}")
        elif op == "==" and not abs(value - limit) < 1e-9:
            failures.append(f"{name} {value} != required {limit}")
        elif op == "<=" and not value <= limit:
            failures.append(f"{name} {value} > allowed {limit}")
    return failures


def load_scan(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict):
        return data
    raise ValueError(f"{path} is not a scan report object")


def run(target: str | Path, scan_path: str | Path, fixes_path: str | Path | None) -> GateReport:
    """Score one scan against the range's ground truth."""
    target_path = Path(target)
    manifest_path = target_path / "manifest.yaml"
    if not manifest_path.exists():
        raise FileNotFoundError(f"no manifest.yaml under {target_path}")

    document = load_manifest_document(manifest_path)
    manifest = load_manifest(manifest_path)
    scan = load_scan(scan_path)
    findings = list(scan.get("findings") or [])
    duration_ms = int(scan.get("duration_ms") or 0)

    fixes: list[dict[str, Any]] = []
    if fixes_path is not None and Path(fixes_path).exists():
        loaded = json.loads(Path(fixes_path).read_text())
        fixes = loaded if isinstance(loaded, list) else list(loaded.get("fixes") or [])

    match_result = match(findings, manifest)
    metrics, _repro = compute_metrics(
        manifest=manifest,
        findings=findings,
        match_result=match_result,
        fixes=fixes,
        duration_ms=duration_ms,
    )
    declared_chains = load_chains(document)
    chain_score: ChainScore | None = None
    if declared_chains:
        # The scanner ids its own findings; the manifest speaks in vuln ids. The
        # matcher's output is the only bridge between the two vocabularies, so a
        # chain is scored only after its ids are translated through it.
        id_map = {m.finding_id: m.vuln_id for m in match_result.matches}
        chain_score = score_chains(
            declared_chains,
            translate_finding_ids(scan, id_map),
            reported_finding_ids=list(id_map.values()),
        )

    failures = evaluate(metrics) + evaluate_chains(chain_score)

    thresholds = {k: f"{v[1]} {v[0]}" for k, v in THRESHOLDS.items()}
    if chain_score is not None:
        thresholds.update(
            {k: f"{v[1]} {round(v[0], 4)}" for k, v in CHAIN_THRESHOLDS.items()}
        )

    return GateReport(
        chain_score=chain_score,
        target=str(target_path),
        scan_id=str(scan.get("scan_id") or scan.get("id") or ""),
        metrics=metrics,
        matches=[{**asdict(m), "how": m.how()} for m in match_result.matches],
        missed_vulns=match_result.missed_vulns,
        false_positives=[
            {
                "id": f.get("id"),
                "category": f.get("category"),
                "location": f.get("location"),
            }
            for f in match_result.unmatched_findings
        ],
        thresholds=thresholds,
        failures=failures,
        passed=not failures,
        manifest_severity=severity_breakdown(manifest),
    )


def format_report(report: GateReport) -> str:
    lines = [
        f"range-runner report for {report.target}",
        f"  scan:              {report.scan_id}",
        f"  manifest vulns:    {report.metrics.manifest_total}",
        f"  findings reported: {report.metrics.findings_total}",
        f"  matched:           {report.metrics.matched}",
        f"  false positives:   {report.metrics.unmatched_findings}",
        f"  missed:            {report.metrics.missed}",
        "",
        "  metrics:",
        f"    recall       {report.metrics.recall:.4f}   (required >= {THRESHOLDS['recall'][0]})",
        f"    precision    {report.metrics.precision:.4f}   (required >= {THRESHOLDS['precision'][0]})",
        f"    repro_rate   {report.metrics.repro_rate:.4f}   (required == {THRESHOLDS['repro_rate'][0]})",
        f"    fix_rate     {report.metrics.fix_rate:.4f}   (required >= {THRESHOLDS['fix_rate'][0]})",
        f"    duration_ms  {report.metrics.duration_ms}   (required <= {THRESHOLDS['duration_ms'][0]})",
        "",
    ]
    if report.matches:
        lines.append("  matched vulnerabilities:")
        for m in report.matches:
            lines.append(
                f"    {m['vuln_id']:<10} {m['category']:<24} {m['file']}:{m['manifest_line']} "
                f"<= {m['finding_id']} ({m['how']})"
            )
        lines.append("")
    if report.missed_vulns:
        lines.append(f"  missed: {', '.join(report.missed_vulns)}")
        lines.append("")
    if report.false_positives:
        lines.append("  unmatched findings (counted as false positives):")
        for fp in report.false_positives:
            loc = fp.get("location") or {}
            lines.append(f"    {fp.get('id')} {fp.get('category')} {loc.get('file')}:{loc.get('line')}")
        lines.append("")
    if report.failures:
        lines.append("  threshold failures:")
        for failure in report.failures:
            lines.append(f"    - {failure}")
        lines.append("")
    score = report.chain_score
    if score is not None:
        lines.extend(
            [
                "  chains:",
                f"    declared       {score.chains_total}",
                f"    recalled       {score.chains_recalled}   "
                f"(required >= {round(CHAIN_THRESHOLDS['chain_recall'][0], 4)})",
                f"    chain_recall   {score.chain_recall:.4f}",
                f"    links made     {score.joins_made}/{score.joins_required}   "
                f"(required == {CHAIN_THRESHOLDS['chain_link_rate'][0]})",
                f"    link_rate      {score.chain_link_rate:.4f}",
                f"    narratives ok  {score.narratives_ok}/{score.chains_total}   "
                f"(required == {CHAIN_THRESHOLDS['chain_narrative_rate'][0]})",
                "",
            ]
        )
        for result in score.results:
            flag = "OK  " if result.complete and result.linked else "MISS"
            detail = ""
            if result.missing_steps:
                detail += f" missing={','.join(result.missing_steps)}"
            if result.missing_joins:
                detail += f" unlinked={' '.join('->'.join(j) for j in result.missing_joins)}"
            if result.narrative_missing:
                detail += f" narrative_missing={result.narrative_missing}"
            lines.append(
                f"    {flag} {result.chain_id:<8} {result.name:<40} "
                f"steps {result.steps_reported}/{result.steps_total}{detail}"
            )
        lines.append("")
    lines.append(f"REDFALL GATE: {'PASS' if report.passed else 'FAIL'}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="range_runner", description="Score a Redfall scan against vulnbank.")
    parser.add_argument("--target", required=True, help="Path to the range target (contains manifest.yaml)")
    parser.add_argument("--scan", help="Path to a scan report JSON produced by `redfall scan`")
    parser.add_argument("--fixes", help="Path to a fixes JSON produced by `redfall fix`")
    parser.add_argument("--out", help="Write the full gate report JSON here")
    args = parser.parse_args(argv)

    scan_path = args.scan
    if scan_path is None:
        scan_path = "/tmp/scan.json"
    if not Path(scan_path).exists():
        print(f"no scan report at {scan_path}; run `redfall scan {args.target} --out {scan_path}` first", file=sys.stderr)
        return 2

    report = run(args.target, scan_path, args.fixes)
    print(format_report(report))
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.as_dict(), indent=2))
        print(f"\nfull report written to {out}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
