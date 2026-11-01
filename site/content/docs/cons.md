---
title: The case against RedFall
seoTitle: "RedFall Limitations: An Honest Critique of the Scanner"
description: "Every serious objection to RedFall, ordered by how much damage it does: no benchmark, uncertified enterprise languages, taint depth, and the economics of execution."
path: docs/cons/
group: Trust and evidence
kind: cluster
pillar: security
order: 25
updated: 2026-11-01
keywords: vulnerability scanner limitations, security tool criticism, SAST false negatives, execution cost security scanning
sources: https://github.com/DevAnimecx/redfall/blob/main/docs/analysis/cons.md
related: security, positioning, verified-findings
---

**A critique of RedFall, written to be usable by someone deciding whether to
adopt it.** Every objection here is one a competent reviewer would raise, and
most are correct.

The full document, with all fourteen sections, is in the
[repository](https://github.com/DevAnimecx/redfall/blob/main/docs/analysis/cons.md).
This page carries the four that decide an adoption.

## 1. The central claim is unmeasured

RedFall's thesis is that execution-verified findings are worth more than
pattern-matched ones. There is no published benchmark comparing it to anything —
no head-to-head, no pre-registered corpus, no raw logs, no independent re-run.
The arena that would produce the number does not exist.

A project whose brand is "claims must be proven" is the least entitled to make
an unproven central claim. This is the top of the roadmap for exactly that
reason.

## 2. The enterprise languages are uncertified

TypeScript/JavaScript and Python are certified. Java, Kotlin and Go are parsed,
symbol-extracted and taint-traced — and **never executed**, because the build
host has no JVM and no Go toolchain. The roadmap's stated priority was
"Java/Kotlin first, highest enterprise demand". The part that shipped
unverified is exactly the part enterprise buyers need.

Every Java or Go finding RedFall produces is a candidate, not a proof — which is
precisely the state RedFall exists to eliminate, now present inside RedFall.

## 3. Taint analysis that will miss real bugs

- **Intraprocedural on JVM and Go.** A value crossing a function boundary is
  invisible — and in an idiomatic Spring or Go codebase that is the majority of
  real flows.
- **Depth-one interprocedural on TS/Python.** A two-hop flow through a helper
  misses.
- **No field-sensitive alias analysis.** A value reaching a sink through
  `req.body.items[0].id` is likely missed.
- **Sanitisers are recorded, never modelled**, so every sanitised flow is still
  reported. That is a precision tax paid on every finding.

It will report dead flows and miss live ones, and there is **no recall estimate**
on any corpus. A security tool that misses silently is worse than one that
reports noisily.

## 4. The economics are a shape, not a number

Executing a candidate costs sandbox minutes and agent tokens; pattern-matching
costs almost nothing. RedFall is more expensive per *finding* by construction,
and the claim that it is cheaper per *true* finding has never been measured. If
the candidate-to-reproduction ratio is bad for a hard class — and it will be —
it can exceed the cost of a human triaging SAST output, which is the thing it is
trying to replace.

## What is *not* a con, despite looking like one

- **Skipped tests.** Skipping and stating the reason is correct. Passing by
  faking would be the con.
- **Narrow class coverage.** Publishing four exclusions *with their
  measurements* is better practice than a silent 300-rule list.
- **Refusing to run without a sandbox.** A "best effort" mode would produce
  unverified findings wearing the same label as verified ones.

Everything else in the full document — the patched session design, the
unbenchmarked concurrency, the unexercised learning loop, tenancy as a filter
rather than a boundary, the root-equivalent socket mount, and the bus factor —
is a fixable gap. These four are the ones that decide whether the project is
worth continuing.
