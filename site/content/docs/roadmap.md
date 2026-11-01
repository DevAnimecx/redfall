---
title: A deeper technical roadmap
seoTitle: "RedFall Roadmap: Benchmark, Taint Depth, Language Certification"
description: "RedFall's next phases, each closing a named objection: the benchmark arena, field-sensitive taint, certifying Java and Go, and measuring the learning loop."
path: docs/roadmap/
group: Trust and evidence
kind: cluster
pillar: security
order: 26
updated: 2026-11-01
keywords: vulnerability scanner roadmap, security tool benchmark, taint analysis depth, field-sensitive analysis
sources: https://github.com/DevAnimecx/redfall/blob/main/docs/roadmap/deeper.md
related: cons, positioning, verified-findings
---

**The plan that follows 0.5.0.** It is written against the weaknesses named in
[the case against RedFall](/docs/cons/), not against a feature list: every phase
closes a specific, stated objection.

The ordering is by **proof**, not by user-visible progress. The next release adds
almost no features — it exists to make the ones that already exist measurable.

## 6.1 The arena, or nothing else matters

Everything else is lower priority. A tool that demands proof of findings and
ships without proof of itself is incoherent.

The protocol, and why each rule exists:

| Rule | Reason |
| --- | --- |
| Pre-registration | A corpus chosen after seeing results is a demo |
| Ground truth sealed | Otherwise the benchmark tests whether the engine can read a file |
| Equal budget | A comparison where one side spent 10× is not a comparison |
| Raw logs published | A summary number without logs behind it is the thing this project objects to |
| Independent re-run | Until someone re-runs it, the result is provisional and says so |

**Metrics:** recall, precision, reproduction rate, cost per true finding, time to
first reproduction, and **flake rate** — how often a verified finding fails to
reproduce on a clean reset three times. A finding that reproduces twice in three
is not a finding.

`redfall bench run` produces a signed, reproducible bundle including a
`LIMITATIONS.md` written by the same run — a required output, not a nicety.

## 6.2 Taint depth

Three separable pieces: **field- and container-sensitive tracking** (a taint
becomes a path, not a name), **interprocedural depth beyond one hop** (function
flow summaries plus a fix-point over the call graph), and **recall measurement**
— the missing number that matters most. Without it, "it misses flows" is a
suspicion; with it, it is a number that can be improved.

## 6.3 Certify the enterprise languages

Not new analysers — **targets**. A bootable Spring application with a JDK in the
sandbox; a Gin service with a Go toolchain. Build the range target *first*, then
use it to find the analyser's bugs. Writing the analyser against no executable
target is how the current JVM engine shipped without anyone knowing which flows
it misses.

## 6.4 Concurrency, characterised

Characterise the pool under load, implement cancellation that leaves no orphaned
container and a valid evidence chain, then **collapse the two execution paths**
into one. Two paths through the core is a compounding liability.

## 6.5 The learning loop, measured

The gate constants were chosen, not derived — `MIN_DELTA = 0.02` on a ten-case
holdout is less than one case. Build a holdout where the gate is arithmetically
meaningful, re-derive the constants from its variance, and publish whether any
lesson promoted. Including the honest outcome if none did.

## What to do first, by value ÷ effort

The phases above are sequenced by dependency. This is sequenced by return, and
the two orders are deliberately different.

| # | Do this | Effort | What it buys |
| --- | --- | --- | --- |
| 1 | **Add a LICENSE** | Minutes | Unblocks legal review and outside contribution |
| 2 | **Run the suite with Docker + gVisor in CI** | Days | Turns the central claim from untested locally into continuously verified |
| 3 | **Ship one GitHub Action** | Days | The difference between a repository and something a team can adopt |
| 4 | **One external verified finding** in a project RedFall did not write | Weeks to months | The only item that changes how the whole project is judged |
| 5 | **The arena** | Weeks | Replaces every structural argument with a number |
| 6 | **One Java or Go category certified** | Weeks | Opens the enterprise market |
| 7 | **A recall number** on a seeded corpus | Weeks | Turns "it misses flows" into a quantity |
| 8 | Deeper taint, transparency log, Firecracker | Months | Worth doing after the rest |

**The uncomfortable observation.** Items 1 to 3 are days of work between them and
none was done, while four subsystems shipped in the 0.5.0 line. That is a
priority inversion rather than a capacity problem, and it is written down here so
it stops being invisible.

## The three numbers this project owes

1. **Recall per language** on a seeded corpus.
2. **Cost per true finding** against a SAST baseline at equal budget.
3. **Flake rate** — how often a verified finding fails to reproduce.

Everything else is machinery for producing those three.
