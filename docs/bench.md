---
title: The bench
description: How RedFall measures what it fails to find, and why a number without its limitations is refused.
---

# The bench

Every number this project published before 0.6.0 counted what the engine
*produced*. None could see what it failed to produce, because there was nothing
there to count. The bench exists to measure omission.

## What it is

A sealed corpus plus a scorer plus a report bundle that must show its work.

```
bench/
  corpora/
    <target>/
      manifest.json      what was committed before any run
      budget.json        the ceiling every tool gets, including baselines
      ground-truth.json  the answers — read only by the scorer
  baselines/
    <target>.json        the recall last measured, for the regression gate
  BASELINE.md            the first measured number, and what it means
```

Four corpora ship, generated from the range targets' own manifests by
`scripts/write_bench_corpus.py`: `pythonbank` (17 flows), `vulnbank` (32),
`chainbank` (12), `vulnbank-adaptive` (7). Because they are generated from the
manifests, the corpus and the ground truth cannot drift — there is one source
for "these flows exist".

## The rules, and why each one is enforced by the code

| Rule | Enforced by |
| --- | --- |
| **Pre-registration** | `manifest_fingerprint` hashes the manifest; a report whose hash differs measured something else |
| **Sealed ground truth** | `Corpus` exposes the answers only through the scorer; the scan function never receives them |
| **A budget may be narrowed, never widened** | `budget_for` raises on a ceiling above the committed one |
| **A report without LIMITATIONS refuses to exist** | `write_report` raises |
| **A run without its raw log is marked, not omitted** | The bundle writes an explicit empty-log marker |

These are structural, not conventional. The convenient implementation of each
produces a number; the correct one refuses.

## The metrics

| Metric | Definition | What it catches |
| --- | --- | --- |
| **Recall** | found ⊘ expected | The omission rate — the number that did not exist before |
| **Invented rate** | unmatched findings ⊘ all findings | Generator noise |
| **Recall by category** | per category | "Python improved" hiding "SQLi regressed" |

Precision, cost per true finding and flake rate need execution — they belong to
the arena as a whole and are not computed by this scorer, which reads source
only. That gap is stated rather than filled with a proxy.

## The first measured number

```
$ redfall bench recall bench/corpora/pythonbank --target range/pythonbank
expected: 17 | found: 5 | missed: 12 | invented: 8
recall: 0.294
```

**29.4%.** Of the 17 flows the corpus says exist, the taint stage finds five.

The five are exactly the categories taint can see — a request value reaching a
dangerous call: SQL injection, path traversal, SSRF, unsafe deserialization, all
at 1.0.

The twelve missed split in two, and the split is the useful part:

- **Nine are not taint flows at all** — a hardcoded secret, a weak hash choice,
  an absent rate limit, a verbose error, a missing pagination bound. No amount
  of taint depth finds these; they need different detectors.
- **Three are taint-shaped and were missed** — `cmd_injection`, `ssrf_metadata`
  and `open_redirect`. These are defects, not scope boundaries, and they are the
  first concrete work items.

The full breakdown is in [`bench/BASELINE.md`](https://github.com/DevAnimecx/redfall/blob/main/bench/BASELINE.md).

## The regression gate

`scripts/check_recall.py` re-measures and compares against
`bench/baselines/<target>.json`. It runs in CI on every push and needs no
container runtime and no Postgres.

Three outcomes:

- **PASS** — recall is at or above the baseline.
- **FAIL** — recall dropped, and the newly-missed flow ids are named.
- **STALE** — the corpus fingerprint changed, so the comparison would be
  meaningless. Not a pass and not a failure; it asks a human to re-baseline
  deliberately rather than letting a corpus edit silently reset the bar.

A silent recall regression is the exact failure this catches: the engine finds
fewer real bugs while every other number — precision, reproduction, the
changelog — still looks healthy.

## What the bench is not

- **Not a full benchmark.** It measures recall against a *known* set, which is
  a floor. A real application has flows the corpus does not seed, and those are
  not counted.
- **Not multi-language.** `pythonbank` is Python only; the other three corpora
  exist but no recall baseline has been measured against them yet.
- **Not the whole engine.** This measures the taint stage. A flow missed here
  might still be surfaced by a framework pack or the branch engine, neither of
  which is wired into the recall command.
- **Not a comparison.** There is no baseline tool in the bundle yet. The arena
  proper — same corpora, same budget, against a mainstream SAST — is the next
  step, and running it needs a host with Docker and a provider key.
