---
title: Where RedFall sits
seoTitle: "RedFall Positioning: Verification-First Security vs SAST and DAST"
description: "Where RedFall sits among vulnerability scanners: the precision axis, what it does better than a SAST, and the adoption and benchmark gaps it has not closed."
path: docs/positioning/
group: Trust and evidence
kind: cluster
pillar: security
order: 24
updated: 2026-11-01
keywords: vulnerability scanner comparison, SAST vs DAST vs verification, execution-verified scanning, security tool positioning
sources: https://github.com/DevAnimecx/redfall/blob/main/docs/analysis/positioning.md
related: security, verified-findings, cons
---

**RedFall is an evidence-gated scanner: static analysis produces candidates, and
only a reproduced execution makes one a finding.** Most of the category sorts on
a different axis — *how many vulnerabilities can this find?* — and RedFall
answers *how do you know the ones it reports are real?*

> **Read this before the rest.** The public repository has **no measured
> adoption** and **no published benchmark**. Every competitive argument here is
> structural, not measured. The full analysis, with that admission stated first,
> is in the [repository document](https://github.com/DevAnimecx/redfall/blob/main/docs/analysis/positioning.md).

## The precision axis

| Level | What it produces | Who absorbs the error |
| --- | --- | --- |
| L0 Pattern | A rule matched | The triager |
| L1 Dataflow | A source→sink path exists | The triager |
| L2 Reachability | The path is reachable at runtime | A human, with effort |
| L3 Executed | An exploit ran and an observable changed | The tool |
| L4 Independent | Someone else re-ran it from a clean bundle | The tool |

Almost all deployed SAST is L1. RedFall targets **L3 as the default**, with the
machinery for L4 in the evidence chain and the reproduce command carried by
every record. That is a narrower market and a higher bar than "find more
things".

## What it is genuinely better at

- **The no-mock contract is enforced, not asserted.** Every file under `src/` is
  scanned in CI for `eval()`, `mock.patch`, `dry_run` flags and placeholder
  bodies. A feature that cannot be built without faking a result cannot merge.
- **The evidence ledger refuses unproven claims at write time.** An E3/E4 record
  without an execution id, an observable, a reproduce command and an
  environment digest is rejected before it can be stored.
- **Exclusions are published with measurements.** Four categories are excluded —
  timing attack, race condition, `jwt_alg_none`, `jwt_no_expiry` — each with the
  measurement that excluded it.
- **The reasoning layer is a real seam.** Twelve agent drivers, an
  OpenAI-compatible backend, LiteLLM and a router all implement one interface,
  and the provider-key test suite passes unchanged after the extraction.

## What it is worse at

- **No benchmark.** The claim is unproven. This is the biggest gap by a wide
  margin.
- **Two certified languages.** Java, Kotlin and Go are parsed but never
  executed, and those are the enterprise ones the roadmap prioritised.
- **25 classes** against a mature SAST's several hundred rules.
- **Nothing runs on this host.** No Docker, no gVisor, no KVM, no JVM, no Go.

## The honest summary

> RedFall is a verification-first engine with unusually rigorous evidence
> discipline and no published benchmark. Its structural differentiators are real
> and demonstrable in the repository. Its central claim is asserted, not
> measured.

For the full critique, read [the case against RedFall](/docs/cons/).
