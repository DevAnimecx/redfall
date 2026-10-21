---
title: Execution-verified vulnerability scanning
seoTitle: "Execution-Verified Vulnerability Scanning"
description: "What execution verification means, why static analyzers produce false positives, and how RedFall turns a taint candidate into a finding that ran against the live app."
path: docs/verified-findings/
group: Start here
kind: pillar
pillar: verified-findings
order: 1
updated: 2026-10-21
keywords: execution-verified vulnerability scanner, verify vulnerability findings, vulnerability scanner false positives
sources: https://github.com/DevAnimecx/redfall, https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md, https://gvisor.dev/docs/
related: no-mock-contract, sandbox, taint-analysis
---

**Execution verification means a finding exists only after its proof of concept ran against the real application and produced the observable effect the scanner predicted.** RedFall's static analysis produces candidates, not findings. A candidate is promoted only when the exploit executed inside a gVisor sandbox and its predicate matched. This page explains the distinction, the pipeline that enforces it, and what the result does not prove.

The practical consequence is simple: a RedFall finding is a replayable event with a request, a response and a verdict, not a pattern match with a confidence score. If the exploit did not reproduce, there is no finding to triage.

## What does execution-verified mean?

A scanner can establish a vulnerability in three different ways, and the differences matter more than the label on the dashboard.

| Evidence level | What the tool actually did | What it can claim |
| --- | --- | --- |
| Pattern match | Matched source text or a rule | The code resembles a known-bad pattern |
| Dataflow analysis | Traced a value from a source to a sink | A path may exist if the application behaves as modelled |
| Execution verification | Ran a request against the live app and observed the effect | This input produced this output on this build |

RedFall uses all three, but only the third one creates a finding. The first two narrow the search space. They do not decide the result.

The distinction is not academic. A taint path can be unreachable because of a mount prefix, a middleware guard, a framework binding, a validator that the analyzer does not model, or a database constraint. A static analyzer that reports the path is not necessarily wrong about the code; it is making a claim it cannot check. Execution is how the claim gets checked.

> Static analysis produces candidates. A finding exists only if it executed.

## Why do static analyzers report false positives?

Static analysis reasons about a model of the program, not the program. The model has to approximate routing, framework behaviour, runtime configuration and data validity. Every approximation is a place where the model and the deployment can diverge.

Common divergences include:

- **Routing.** `router.post('/login')` may be mounted at `/api/auth`, so the real endpoint is `/api/auth/login`. An analyzer that does not resolve the mount reports the wrong path, and a PoC built on the wrong path cannot reproduce.
- **Framework binding.** A decorator, blueprint prefix or middleware chain changes which handler receives a request. The source can look reachable while the runtime route is different.
- **Sanitisation.** A function named `escapeHtml` may or may not neutralise the sink in question. RedFall records sanitisers but never lets them clear taint, because guessing that a sanitiser is sufficient is exactly the kind of assumption that produces false negatives and false positives.
- **Runtime state.** A query may be parameterised by the time it reaches the database, or a feature flag may disable the route. The source alone does not decide.
- **Reachability.** A helper may contain a perfect source-to-sink path that no route calls. The path is real in the file and irrelevant in the application.

Execution collapses these questions into one observable test. Either the request produced the effect or it did not.

## How does RedFall turn a candidate into a finding?

The pipeline has eight stages. Each stage has a different burden of proof, and only the last one is allowed to create a finding.

| Stage | What it produces | What it is allowed to claim |
| --- | --- | --- |
| Ingest | Parsed files, routes, handlers, calls | What the source contains |
| Taint | Source-to-sink paths, interprocedural hops, return flow | Where attacker data may travel |
| Detect surface | Seven adaptive triggers | Where the scan should branch |
| Plan | Branches over the route inventory | How the work is divided |
| Analyse | Candidate findings per branch | What might be exploitable |
| Execute | A PoC run inside the sandbox | Whether the candidate reproduced |
| Chain | A composite PoC over reproduced findings | Whether two proven findings compose |
| Keep or discard | Persisted finding plus request, response and verdict | What is real on this build |

The execute stage is the gate. `harness.mjs` runs inside a Docker container on the gVisor `runsc` runtime. The container boots a real PostgreSQL and the real target application: Node targets through `npm start`, Python targets through a virtualenv and their `redfall.target.json` boot contract. The PoC must assert the observable effect, not merely a 200 response.

A reproduced candidate becomes a `Finding`. The raw request, response and verdict are persisted. The [sandbox page](/docs/sandbox/) explains the isolation boundary; the [taint analysis page](/docs/taint-analysis/) explains how candidates are found.

## What does the no-mock contract forbid?

The no-mock contract is the project rule that makes the evidence meaningful. It forbids simulators, fixture-only paths and host-execution escape hatches from standing in for a real run. `scripts/check_no_mock.py` enforces the rule in CI, and the full history of what could not run is kept in [BLOCKED.md](https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md).

In practice the contract means:

- A missing Docker runtime blocks execution rather than triggering a demo mode.
- A missing LLM credential raises an error rather than returning a canned completion.
- A skipped gVisor test is reported as a skip, not counted as a pass.
- A candidate that did not reproduce is not described as a finding.

The [no-mock contract page](/docs/no-mock-contract/) covers the rule and its enforcement in detail.

## How do you audit a RedFall finding?

A finding should be auditable without trusting the scanner's summary. Four artefacts make that possible:

1. **The request and response.** The persisted PoC shows the exact method, path, headers and body that were sent, and the status, headers and body that came back. The predicate is evaluated against that response.
2. **The verdict.** The finding records whether the predicate held. A finding that exists without a verdict is a bug, not a result.
3. **The SARIF properties.** Every SARIF result carries `properties.redfall.verified` as true or false. Nothing is silently upgraded or dropped. See [SARIF output](/docs/output/).
4. **The commit and target.** The scan is tied to the repository and commit it ran against. A finding is a statement about that build, not about every future build.

A reviewer can replay the request against the same build and compare the response. If the effect depends on state that has changed, the finding should be re-run rather than assumed.

## What execution verification does not prove

Execution verification is strong evidence for one proposition: *this input produced this effect on this build in this environment*. It is not a proof of exploitability in every deployment, and it does not replace human judgement.

It does not prove:

- **Impact beyond the observed effect.** A reproduced SQL injection proves the query was influenced. It does not automatically prove exfiltration of every table, or that the same payload works behind a different database driver.
- **Reachability in production.** The sandbox boots the target with a test database. A production network control or feature flag may change the path.
- **Absence of other vulnerabilities.** A clean scan means no candidate reproduced in the time and scope of the scan. It does not mean the application is secure.
- **That a fix is complete.** A verified fix means the target's tests passed and the original PoC stopped working. It does not mean no variant of the bug remains.

Those limits are recorded rather than hidden. The [evidence page](/evidence/) lists what was measured, on which host, and what remains blocked. The [blocked page](/docs/blocked/) explains the runtime prerequisites that are still missing on the development host.

## Where are the limits recorded?

Every claim on this site should point to one of four places:

| Claim type | Source of truth |
| --- | --- |
| Product behaviour | Repository source and tests |
| Measured results | Commands and dates on the evidence page |
| Unavailable capability | `BLOCKED.md` and the affected code path |
| Release integrity | CI workflow, `SHA256SUMS`, Sigstore attestation |

If a number is not in one of those places, it is not a measured number. That rule is stricter than most marketing pages, and it is the point: the scanner's output should be held to the same standard as the scanner's claims.

## Frequently asked questions

### Is a RedFall finding a proof of exploitability?

It is a proof that a specific PoC produced a specific observable effect against the real application in the sandbox. Impact assessment and production reachability still need human review.

### What happens to candidates that do not reproduce?

They remain candidates and are not promoted to findings. SARIF can carry them with `properties.redfall.verified: false` so a reviewer can see what was considered, but they are not counted as real findings.

### Does RedFall replace static analysis?

No. Static analysis is faster and broader, and RedFall relies on it to find candidates. RedFall adds an execution gate for the cases where a false positive is expensive. The [comparison page](/compare/static-analysis/) explains when each approach fits.
