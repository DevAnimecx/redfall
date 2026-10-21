---
title: RedFall CLI reference
seoTitle: "RedFall CLI Reference: scan, fix, campaign, graph, interop"
description: "The RedFall 0.1.1 CLI: scan, fix, findings, report, doctor, environment, campaign, graph, reproduce, policy-check, mcp, interop and adapters."
path: docs/cli/
group: Reference
kind: cluster
pillar: install
order: 2
updated: 2026-10-21
keywords: RedFall CLI, vulnerability scanner command line, redfall scan, redfall report SARIF, redfall campaign, redfall interop
sources: https://github.com/DevAnimecx/redfall/blob/main/src/redfall/cli.py, https://github.com/DevAnimecx/redfall
related: install, output, interop
---

**RedFall 0.1.1 exposes thirteen top-level commands.** Six form the original
scan/fix loop: `scan`, `fix`, `findings`, `report`, `doctor` and `environment`.
The others operate durable campaigns, the persisted code graph, stored-finding
reproduction, policy checks, MCP and the HTTP/A2A gateway. The CLI is a thin
front end over the same persisted records and the same transport-neutral
`ToolRegistry` used by the agents.

The options below are the ones the installed console script accepts. Run
`redfall <command> --help` for the exact flags on your host; group commands have
their own help pages.

## What are the global options?

| Command | Purpose |
| --- | --- |
| `redfall --version` | Print the installed version |
| `redfall --help` | List commands |

There are no global flags that bypass prerequisites. A missing sandbox, provider
key or database is reported by the command that needs it.

## Command map

| Command | What it does |
| --- | --- |
| `scan` | Start a scan; only executed candidates become findings |
| `fix` | Generate, apply and verify a patch for one finding |
| `findings` | List the findings recorded for a scan |
| `report` | Print a stored JSON or SARIF report |
| `doctor` | Report exactly which prerequisites this host satisfies |
| `environment` | Print the host capability report as JSON |
| `campaign` | Create, scope, run, budget, evidence and report durable campaigns |
| `graph` | Index and query persisted code-graph snapshots |
| `reproduce` | Replay a stored finding's PoC in the gVisor sandbox |
| `policy-check` | Check an action against campaign scope or allowed roots |
| `mcp` | Serve or certify the MCP stdio tool surface |
| `interop` | Serve or certify HTTP/OpenAPI and A2A; manage tokens, webhooks and audit |
| `adapters` | List transports and measured adapter certifications |

## `redfall scan`

Scan a repository. Every candidate is executed in a gVisor sandbox; only
reproduced candidates become findings.

```bash
redfall scan TARGET [--out PATH] [--quiet]
```

| Option | Meaning |
| --- | --- |
| `TARGET` | Repository directory to scan |
| `--out PATH` | Write the scan report JSON here |
| `--quiet` | Only print the final summary |

A scan needs the full runtime: Docker with gVisor, an LLM provider key, a
PostgreSQL store and a target boot contract. On a host without them, the command
refuses and names what is missing. It does not produce a partial result that
looks complete.

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

A fix is verified only when the target's own tests pass and the original PoC
stops reproducing. The loop makes at most three attempts, then hands the full
transcript to a human. The `--out` file is the one `range_runner --fixes` reads.
See [verified fixes](/docs/verified-fixes/).

## `redfall findings`

List the findings recorded for a scan.

```bash
redfall findings SCAN_ID [--out PATH]
```

Use this when you want the finding list without the full report. The scan ID is
the one returned by `scan` or stored in the database.

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

The SARIF export carries `properties.redfall.verified` on every result. See
[SARIF output](/docs/output/).

## `redfall doctor`

Report exactly which prerequisites the host satisfies.

```bash
redfall doctor
```

The report is human-readable. It checks the real prerequisites rather than
assuming them: container runtime, gVisor, provider credential, database and
target contract. On the development host used for 0.1.1, it reports the missing
runtime and provider instead of inventing a result.

## `redfall environment`

Print the factual host capability report as JSON.

```bash
redfall environment
```

This is the machine-readable form of the doctor report. It is useful in bug
reports and CI logs. Do not paste provider keys or target credentials into an
issue; the environment report is designed to avoid them.

## `redfall campaign`

Create and operate a durable campaign. A campaign is a persisted state machine,
not an in-memory scan: it carries scope, policy, budget, tasks, leases, evidence
and report readiness across restarts.

```bash
redfall campaign create REPO --objective discovery \
  --budget-usd 10 --budget-tokens 500000 --budget-sandbox-minutes 60
redfall campaign scope CAMPAIGN_ID --scope-json '{"repositories":["."],"hosts":["127.0.0.1"]}'
redfall campaign start CAMPAIGN_ID
redfall campaign run CAMPAIGN_ID --max-tasks 10 --lease-seconds 300
redfall campaign status CAMPAIGN_ID
```

Lifecycle: `create`, `scope`, `start`, `status`, `transition`, `pause`, `resume`,
`cancel`, `report`, `spend`, `list`. Task operations: `campaign task
add|claim|complete|fail|list`. Evidence operations: `campaign evidence
add|list|verify`. Budget operations: `reserve`, `reservations`,
`release-reservation`, `settle-reservation`. Report gates: `readiness`, `export`.

Execution handlers cover graph indexing, scans, stored-finding reproduction and
evidence-gated JSON/SARIF reports. A task cannot spend without a reservation, and
only E3/E4 evidence with a real execution record can make a campaign reportable.

## `redfall graph`

Build and query a persisted, provenance-aware graph snapshot.

```bash
redfall graph index TARGET --campaign-id CAMPAIGN_ID
redfall graph stats --campaign-id CAMPAIGN_ID
redfall graph routes --campaign-id CAMPAIGN_ID
redfall graph paths SOURCE SINK --max-depth 5 --limit 10
```

Subcommands: `index`, `latest`, `stats`, `search`, `routes`, `sources`, `sinks`,
`neighbors`, `node`, `paths`, `inventory`, `diff`. Traversals have hard node
budgets; paths return full provenance. Graph and path-taking operations enforce
campaign roots or `REDFALL_ALLOWED_ROOTS`; an allowlist cannot be widened by a
broader campaign scope.

Graph v1 covers the currently ingested TypeScript/JavaScript/Python source. It
does not synthesize sanitizer nodes or claim complete language coverage.

## `redfall reproduce` and `redfall policy-check`

```bash
redfall reproduce FINDING_ID --target DIRECTORY [--campaign-id CAMPAIGN_ID] [--out PATH]
redfall policy-check {index|scan|reproduce|report|fix} --target DIRECTORY [--campaign-id CAMPAIGN_ID]
```

`reproduce` replays a stored finding's PoC inside the gVisor sandbox and can
append a hash-chained evidence record. `policy-check` answers whether an action
is inside campaign scope or the operator allowlist before work starts.

## `redfall mcp`, `redfall interop` and `redfall adapters`

```bash
redfall mcp serve
redfall mcp certify --out certification.json
redfall interop serve --host 127.0.0.1 --port 8787
redfall interop token create --name reviewer --scopes read,execute
redfall interop webhook add --url https://example.invalid/events --event campaign.reported
redfall interop certify --protocol http
redfall interop certify --protocol a2a
redfall adapters list
redfall adapters certifications
```

MCP is newline-delimited JSON-RPC over stdio. The HTTP/OpenAPI and A2A surfaces
share one listener and one 44-tool registry; see the
[interoperability page](/docs/interop/) for endpoints, scopes, trust labels and
limitations. `certify` starts a fresh server and client and records what actually
passed; it does not certify arbitrary third-party agents.

## What environment variables matter?

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection for the scan store |
| `REDFALL_TEST_DATABASE_URL` | Explicit throwaway database for PostgreSQL-backed tests; absent means skip |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | Live LLM provider credentials |
| `REDFALL_MODEL_FAST` / `_MID` / `_DEEP` | Optional model tier overrides |
| `REDFALL_HOME` | Installer home for a private virtualenv |
| `REDFALL_ALLOWED_ROOTS` | Hard outer filesystem boundary for campaign and graph actions |
| `REDFALL_ARTIFACT_SECRET` | Optional signing secret for gateway artifact URLs |

The provider key is read from the environment. The CLI does not write it to the
report. Scan transcripts are stored in the database; review them before sharing a
scan.

## What does the CLI refuse to do?

- It does not scan without a target.
- It does not execute a PoC without the sandbox.
- It does not call a model without a credential.
- It does not print a finding that was not persisted.
- It does not silently mark a skipped execution as verified.
- It does not widen campaign scope past `REDFALL_ALLOWED_ROOTS`.
- It does not call an untested transport a certified adapter.
- It does not replace a webhook secret or token after its one-time display.

The [no-mock contract](/docs/no-mock-contract/) is the rule behind those
refusals. The [blocked page](/docs/blocked/) records the current host's missing
prerequisites.

## Frequently asked questions

### Where is the scan stored?

In the PostgreSQL store configured by `DATABASE_URL`. The report command reads
the persisted rows; it does not recompute a scan from a file unless you pass a
report path to another tool.

### Can I get SARIF without a full scan?

You can export the stored findings for a scan with `report --format sarif`. A
scan that did not run has no findings to export.

### Is there a dry-run mode?

No. A dry run that executes nothing would produce candidates, not findings, and
RedFall does not present candidates as findings. Use `doctor` and `environment`
to inspect prerequisites before scanning.

### Can I use the campaign commands without a sandbox?

You can create, scope and inspect a campaign, and use graph/evidence operations
that do not execute target code. Any task that runs a PoC or a scan still needs
the same real runtime prerequisites and fails closed without them.
