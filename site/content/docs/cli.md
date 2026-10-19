---
title: RedFall CLI reference
seoTitle: "RedFall CLI Reference: scan, fix, report"
description: "Every RedFall 0.1.0 command and option: scan, fix, findings, report, doctor and environment, with the exact flags and what each command refuses to do."
path: docs/cli/
group: Reference
kind: cluster
pillar: install
order: 2
updated: 2026-10-19
keywords: RedFall CLI, vulnerability scanner command line, redfall scan, redfall report SARIF
sources: https://github.com/DevAnimecx/redfall/blob/main/src/redfall/cli.py, https://github.com/DevAnimecx/redfall
related: install, output, verified-fixes
---

**RedFall 0.1.0 has six commands: `scan`, `fix`, `findings`, `report`, `doctor` and `environment`.** The CLI is small on purpose. It starts a scan, reports what the host can do, reads persisted results and emits JSON or SARIF.

The options below are the ones the installed console script accepts. Run `redfall <command> --help` to see the same text on your host.

## What are the global options?

| Command | Purpose |
| --- | --- |
| `redfall --version` | Print the installed version |
| `redfall --help` | List commands |

There are no global flags that bypass prerequisites. A missing sandbox or provider key is reported by the command that needs it.

## `redfall scan`

Scan a repository. Every candidate is executed in a gVisor sandbox; only reproduced candidates become findings.

```bash
redfall scan TARGET [--out PATH] [--quiet]
```

| Option | Meaning |
| --- | --- |
| `TARGET` | Repository directory to scan |
| `--out PATH` | Write the scan report JSON here |
| `--quiet` | Only print the final summary |

A scan needs the full runtime: Docker with gVisor, an LLM provider key, a PostgreSQL store and a target boot contract. On a host without them, the command refuses and names what is missing. It does not produce a partial result that looks complete.

## `redfall fix`

Generate, apply and verify a patch for one finding.

```bash
redfall fix FINDING_ID --target DIRECTORY [--out PATH]
```

| Option | Meaning |
| --- | --- |
| `FINDING_ID` | The finding to repair |
| `--target DIRECTORY` | The target checkout to patch (required) |
| `--out PATH` | Append or replace this finding's fix record in a fixes JSON |

A fix is verified only when the target's own tests pass and the original PoC stops reproducing. The loop makes at most three attempts, then hands the full transcript to a human. The `--out` file is the one `range_runner --fixes` reads. See [verified fixes](/docs/verified-fixes/).

## `redfall findings`

List the findings recorded for a scan.

```bash
redfall findings SCAN_ID [--out PATH]
```

Use this when you want the finding list without the full report. The scan ID is the one returned by `scan` or stored in the database.

## `redfall report`

Print the stored report for a scan.

```bash
redfall report SCAN_ID [--format json|sarif] [--out PATH]
```

| Option | Meaning |
| --- | --- |
| `--format json` | Stored JSON report (default) |
| `--format sarif` | SARIF 2.1.0 for code-scanning consumers |
| `--out PATH` | Write the report here instead of stdout |

The SARIF export carries `properties.redfall.verified` on every result. See [SARIF output](/docs/output/).

## `redfall doctor`

Report exactly which prerequisites the host satisfies.

```bash
redfall doctor
```

The report is human-readable. It checks the real prerequisites rather than assuming them: container runtime, gVisor, provider credential, database and target contract. On the development host used for 0.1.0, it reports the missing runtime and provider instead of inventing a result.

## `redfall environment`

Print the factual host capability report as JSON.

```bash
redfall environment
```

This is the machine-readable form of the doctor report. It is useful in bug reports and CI logs. Do not paste provider keys or target credentials into an issue; the environment report is designed to avoid them.

## What environment variables matter?

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection for the scan store |
| `REDFALL_TEST_DATABASE_URL` | Throwaway database for the test suite |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | Live LLM provider credentials |
| `REDFALL_MODEL_FAST` / `_MID` / `_DEEP` | Optional model tier overrides |
| `REDFALL_HOME` | Installer home for a private virtualenv |

The provider key is read from the environment. The CLI does not write it to the report. Scan transcripts are stored in the database; review them before sharing a scan.

## What does the CLI refuse to do?

- It does not scan without a target.
- It does not execute a PoC without the sandbox.
- It does not call a model without a credential.
- It does not print a finding that was not persisted.
- It does not silently mark a skipped execution as verified.

The [no-mock contract](/docs/no-mock-contract/) is the rule behind those refusals. The [blocked page](/docs/blocked/) records the current host's missing prerequisites.

## Frequently asked questions

### Where is the scan stored?

In the PostgreSQL store configured by `DATABASE_URL`. The report command reads the persisted rows; it does not recompute a scan from a file unless you pass a report path to another tool.

### Can I get SARIF without a full scan?

You can export the stored findings for a scan with `report --format sarif`. A scan that did not run has no findings to export.

### Is there a dry-run mode?

No. A dry run that executes nothing would produce candidates, not findings, and RedFall does not present candidates as findings. Use `doctor` and `environment` to inspect prerequisites before scanning.
