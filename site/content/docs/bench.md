---
title: The bench and recall
seoTitle: "Vulnerability Scanner Recall: How RedFall Measures What It Misses"
description: "RedFall's benchmark harness measures omission, not just output. The first measured recall is 29.4% on 17 seeded Python flows, and the misses are named and published."
path: docs/bench/
group: Trust and evidence
kind: cluster
pillar: security
order: 27
updated: 2026-11-01
keywords: vulnerability scanner recall, security scanner benchmark, SAST recall measurement, false negative measurement
sources: https://github.com/DevAnimecx/redfall/blob/main/bench/BASELINE.md, https://github.com/DevAnimecx/redfall/blob/main/scripts/check_recall.py
related: cons, roadmap, verified-findings
---

**Every number RedFall published before 0.6.0 counted what the engine produced.
None could see what it failed to produce.** The bench measures omission — and
the first measured number is not flattering.

## The first recall measurement

```
$ redfall bench recall bench/corpora/pythonbank --target range/pythonbank
expected: 17 | found: 5 | missed: 12 | invented: 8
recall: 0.294
```

**Recall is 29.4%.** Of the 17 flows the corpus says exist, the taint stage
finds five.

## What the misses actually are

The five found are exactly the categories taint analysis can see — a request
value reaching a dangerous call: SQL injection, path traversal, SSRF, unsafe
deserialization, all at 1.0.

The twelve missed split in two, and the split matters more than the total:

**Nine are not taint flows at all** — hardcoded secret, secret exposure, weak
password hash, missing rate limit, verbose error, user enumeration, CSV
injection, unrestricted file type, IDOR. Nothing a deeper taint analysis would
reach; these need different detectors.

**Three are taint-shaped and were missed** — `cmd_injection`, `ssrf_metadata`
and `open_redirect`. These are defects, not scope boundaries. They are the first
concrete work items, named rather than aggregated into "improve recall".

## Why this is published

A scanner that silently omits a class looks like it has full coverage. Recall
against a known set is the number that turns "it misses flows" from a suspicion
into a quantity someone can improve against.

The corpus is generated from the range targets' own manifests, so the corpus and
the ground truth cannot drift. Four ship: pythonbank (17 flows), vulnbank (32),
chainbank (12), vulnbank-adaptive (7).

## The regression gate

`scripts/check_recall.py` runs in CI on every push and needs no container
runtime. Three outcomes:

| Outcome | Meaning |
| --- | --- |
| **PASS** | Recall is at or above the committed baseline |
| **FAIL** | Recall dropped, and the newly-missed flow ids are named |
| **STALE** | The corpus fingerprint changed, so the comparison would be meaningless — re-baseline deliberately |

A silent recall regression is the exact failure this catches: the engine finds
fewer real bugs while precision, reproduction and the changelog all still look
healthy.

## The rules the harness enforces

| Rule | Why |
| --- | --- |
| Pre-registration | A corpus chosen after seeing results is a demo; the manifest is hashed |
| Sealed ground truth | The scan function never receives the answers — otherwise it tests whether the engine can read a file |
| A budget may be narrowed, never widened | Widening after pre-registration is how a losing run buys itself a win |
| A report without LIMITATIONS refuses to exist | A benchmark that does not state its own limits is marketing with a number attached |

## What this is not

- **Not a full benchmark.** Recall against a *known* set is a floor, not a
  ceiling. A real application has flows the corpus does not seed.
- **Not multi-language.** pythonbank is Python only; the other three corpora
  exist but have no baseline measured.
- **Not a comparison.** There is no baseline tool in the bundle yet. Running the
  arena against a mainstream SAST at equal budget needs a host with Docker and a
  provider key.

The honest framing — including that the recall is low and why — is in
[the case against RedFall](/docs/cons/) and on the
[repository's baseline document](https://github.com/DevAnimecx/redfall/blob/main/bench/BASELINE.md).
