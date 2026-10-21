---
title: SARIF output and verified findings
seoTitle: "SARIF 2.1.0 Output with a Verified Flag"
description: "RedFall exports SARIF 2.1.0 for code scanning. Every result carries properties.redfall.verified, so consumers can filter executed proofs from unproven candidates."
path: docs/output/
group: Trust and evidence
kind: cluster
pillar: evidence
order: 3
updated: 2026-10-21
keywords: SARIF verified findings, GitHub code scanning SARIF, vulnerability scanner SARIF output
sources: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html, https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning, https://github.com/DevAnimecx/redfall/blob/main/src/redfall/sarif.py
related: verified-findings, verified-fixes, evidence
---

**RedFall exports SARIF 2.1.0 with one non-negotiable property: `properties.redfall.verified` is present on every result.** A reproduced finding carries `true`; an unproven candidate carries `false`. Nothing is silently dropped or upgraded on the way to a code-scanning consumer.

This page explains the shape of the log, how to filter it, and what the verified flag does and does not mean.

## What does the SARIF log contain?

The exporter builds one run for a scan. The run carries the tool driver, the scan metadata, the rules and the results.

| Field | Content |
| --- | --- |
| `$schema` | SARIF 2.1.0 schema URL |
| `version` | `2.1.0` |
| `runs[0].tool.driver` | Name, version and rules |
| `runs[0].invocations[0]` | `executionSuccessful` and scan metadata |
| `runs[0].results[]` | One result per stored finding or candidate |
| `partialFingerprints` | The finding's dedupe key, so re-imports track the same finding |
| `properties.redfall` | ID, verified, status, severity, CVSS, symbol, evidence and reproduction run ID |

Severity maps mechanically to SARIF levels: critical and high become `error`, medium becomes `warning`, low and info become `note`. The CVSS score is exported as the `security-severity` property that GitHub code scanning reads.

## What does the verified flag mean?

The flag is a boolean of whether the finding reproduced. It is not a confidence score, and it is not a model's self-assessment.

```json
{
  "ruleId": "sqli",
  "level": "error",
  "message": { "text": "SQL injection in loginHandler" },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": { "uri": "src/routes/auth.ts" },
        "region": { "startLine": 41 }
      }
    }
  ],
  "partialFingerprints": {
    "redfall/dedupeKey": "sqli:src/routes/auth.ts:41:loginHandler"
  },
  "properties": {
    "redfall": {
      "id": "fnd-001",
      "verified": true,
      "status": "reproduced",
      "severity": "critical",
      "cvss_score": 9.8,
      "symbol": "loginHandler",
      "evidence": "POST /api/auth/login returned ...",
      "reproduction_run_id": "run-abc123"
    }
  }
}
```

A candidate that did not reproduce carries the same shape with `verified: false`. A consumer that wants only executed proofs filters on the flag; a consumer that wants the full candidate set can read everything.

## How do you export a scan?

Use the report command:

```bash
redfall report <scan-id> --format sarif --out scan.sarif
```

The same command without `--format` prints the stored JSON report. The [CLI reference](/docs/cli/) lists the options.

## How do you filter only verified findings?

With `jq`:

```bash
jq '[.runs[].results[] | select(.properties.redfall.verified == true)]' scan.sarif
```

Or count them:

```bash
jq '[.runs[].results[] | select(.properties.redfall.verified == true)] | length' scan.sarif
```

The filter is deliberately simple. It does not require a model call, a dashboard or a proprietary format.

## What does `executionSuccessful` mean?

`invocations[0].executionSuccessful` is true only when the scan status is `completed`. It is a statement about the scan run, not about each finding. A scan can complete with zero findings, and a scan can be incomplete with some results persisted.

The exporter also includes the scan ID, repository and commit in `invocations[0].properties.redfall`, so a consumer can tie the log to a build.

## What does the export refuse to do?

The exporter's contract is narrow on purpose:

- It does not drop unproven candidates silently.
- It does not upgrade a candidate to verified.
- It does not invent a severity or a CVSS score.
- It does not use a bare `version` literal that could drift into the product version.
- It does not claim that a SARIF import is a proof; the proof is the persisted execution.

The source is `src/redfall/sarif.py`, and the tests cover the empty-findings case, the levels mapping, the verified property and the real-store export.

## Does GitHub code scanning show the flag?

GitHub code scanning reads SARIF results and the `security-severity` property. The `properties.redfall` object is preserved as result properties, so a consumer that reads the raw SARIF can filter on the verified flag. The GitHub UI may not surface every custom property; use the SARIF file or the API when the flag matters.

## What does SARIF not prove?

A SARIF log is a transport format. A `verified: true` result is a claim backed by the persisted request, response and verdict. The log itself does not contain the full transcript; it carries an evidence string truncated to 2,000 characters and a reproduction run ID. The [evidence page](/evidence/) and the stored scan are where the full proof lives.

A `verified: false` result is not a finding. It is a candidate that was considered and did not reproduce, or was not executed. Read the status and the evidence before treating it as a vulnerability.

## Frequently asked questions

### Why export unproven candidates at all?

Because hiding them would make the log less auditable. A reviewer can see what was considered, and a consumer can choose to filter. The verified flag makes the distinction explicit.

### Is the SARIF schema version the same as the RedFall version?

No. The SARIF version is a constant (`2.1.0`), separate from the RedFall release version. That separation is intentional.

### Can I import the log into other tools?

Yes, if the tool accepts SARIF 2.1.0. The custom verified property is preserved in the raw log; a tool that ignores it will still see the result and its location.
