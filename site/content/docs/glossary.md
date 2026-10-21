---
title: Vulnerability scanning glossary
seoTitle: "Vulnerability Scanning Glossary"
description: "Definitions of execution verification, taint, source, sink, predicate, gVisor, SARIF, verified finding, no-mock contract, adaptive branch and compound score."
path: docs/glossary/
group: Reference
kind: cluster
pillar: evidence
order: 3
updated: 2026-10-21
keywords: vulnerability scanning glossary, taint analysis definition, verified finding, SARIF definition
sources: https://github.com/DevAnimecx/redfall, https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html, https://gvisor.dev/docs/
related: verified-findings, taint-analysis, output
---

**This glossary defines the terms RedFall uses in its reports, documentation and code.** The definitions are short on purpose. Each links to the page that explains the mechanism and its limits.

Definitions are ordered from the dataflow layer outward to the execution and reporting layers.

## Core terms

### Source

A request surface an attacker can influence. In RedFall, sources are `req.body`, `req.query`, `req.params`, `req.headers` and `req.cookies` for TypeScript/JavaScript, and `request.args`, `request.form`, `request.json`, `get_json`, `headers` and `cookies` for Python. Read [taint analysis](/docs/taint-analysis/).

### Sink

An operation whose behaviour changes when attacker-controlled data reaches it. RedFall tracks SQL query, command execution, filesystem, redirect and eval sinks. A sink is where a taint path becomes interesting.

### Taint

The property of data that originated at a source and has not been proven safe. RedFall records taint paths from source to sink, including cross-function hops and return flow.

### Sanitiser

A function or operation that may neutralise tainted data. RedFall records sanitisers but does not let them clear taint automatically, because the scanner cannot prove the sanitiser is sufficient for the sink. Execution settles the question.

### Interprocedural analysis

Analysis that follows data across function boundaries. RedFall's depth-one pass summarises callees and admits a hop only when a real call edge and a matching parameter-to-sink path exist. See [taint analysis](/docs/taint-analysis/).

### Return flow

Taint that travels from a callee's return value to a caller's sink. RedFall proves it separately from argument flow: a callee whose return path reads a source makes the call result tainted at the caller.

### Candidate

A possible vulnerability produced by static analysis. A candidate is not a finding. It becomes a finding only after execution reproduces it. See [execution verification](/docs/verified-findings/).

### Proof of concept (PoC)

The concrete request or sequence that exercises a candidate. A PoC includes the request, the expected observable effect and a predicate that decides whether the effect occurred.

### Predicate

The observable condition that makes a PoC meaningful. A predicate is not "the response was 200"; it asserts the effect, such as a row containing an admin hash or a marker written by an injected command.

### Execution verification

The rule that a finding exists only after its PoC ran against the real application and its predicate matched. RedFall runs PoCs in a Docker container on the gVisor `runsc` runtime. See [the verification pillar](/docs/verified-findings/).

### gVisor

A user-space application kernel that intercepts system calls for a container. RedFall requires the `runsc` runtime so target code does not share the host kernel directly. gVisor is a boundary, not a guarantee that target code is harmless. See [the sandbox](/docs/sandbox/).

### Verified finding

A finding whose PoC reproduced. In SARIF it carries `properties.redfall.verified: true`. A candidate that did not reproduce carries `false`; it is not counted as a finding. See [SARIF output](/docs/output/).

### No-mock contract

The project rule that a result must come from the real system it claims to describe. It forbids demo modes, synthetic fallbacks, fabricated model responses, skipped tests counted as passes and estimated numbers presented as measured. See [the no-mock contract](/docs/no-mock-contract/).

### Adaptive branch

A scan branch spawned mid-scan when one of seven detectors finds new attack surface. An adaptive branch records the trigger type, the finding that revealed the surface, and a spawn time after both the parent start and the trigger discovery. See [adaptive scanning](/docs/adaptive-scanning/).

### Chain

Two or more reproduced findings composed into a multi-step PoC. An edge is admitted only when the composite replay holds the step predicates. A plausible narrative without a replay is not a chain. See [exploit chaining](/docs/exploit-chaining/).

### Compound score

A CVSS-derived score for a chain, computed from its steps and start/end states. The score is a prioritisation aid attached after admission, not a substitute for the replay.

### Range target

A deliberately vulnerable application used as ground truth for the scanner. The four ranges are `vulnbank`, `vulnbank-adaptive`, `chainbank` and `pythonbank`. Never expose them. See [range targets](/docs/ranges/).

### SARIF

The Static Analysis Results Interchange Format, version 2.1.0. RedFall exports one result per stored finding or candidate and preserves the verified flag in `properties.redfall`. See [SARIF output](/docs/output/).

### Fix verification

The rule that a repair is verified only when the target's own tests pass and the original PoC stops reproducing. Three attempts, then a human. See [verified fixes](/docs/verified-fixes/).

### Execution-verified vulnerability scanner

A scanner that gates findings on execution rather than pattern confidence. RedFall is one: its static analysis produces candidates, and the sandbox decides which candidates become findings.

## How should these terms be cited?

Cite the specific page for the mechanism, not this glossary. The glossary is a map; the pages carry the evidence, the source links and the limits. If a definition here conflicts with the code, the code is authoritative and the page should be corrected.
