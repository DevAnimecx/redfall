---
title: Ground-truth range targets
seoTitle: "Ground-Truth Range Targets and Measured Results"
description: "The four RedFall ranges: vulnbank, vulnbank-adaptive, chainbank and pythonbank. Seeded vulnerabilities, test counts, replay results and the gate thresholds."
path: docs/ranges/
group: Trust and evidence
kind: cluster
pillar: evidence
order: 2
updated: 2026-10-19
keywords: vulnerability scanner benchmark, vulnerability range targets, PoC replay results, security scanner precision recall
sources: https://github.com/DevAnimecx/redfall, https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md
related: evidence, verified-findings, exploit-chaining
---

**RedFall is measured against four applications built to contain known vulnerabilities.** The ranges are real applications with real tests and real HTTP replays, not fixtures that return canned verdicts. They provide the ground truth for recall, precision, reproducibility and fix verification.

The numbers below are the repository's measured counts. They are not estimates, and they are not a claim that every target in the world will score the same way.

## What are the four ranges?

| Range | What it contains | Tests | Replay result |
| --- | --- | --- | --- |
| `vulnbank` | 32 seeded vulnerabilities, Express/TypeScript target | 76 passed | 30/32 PoCs; 32/32 patches verified |
| `vulnbank-adaptive` | vulnbank plus 7 adaptive surfaces | 91 passed | 7/7 PoCs reproduced |
| `chainbank` | 6 two-step exploit chains | 8 passed | 6/6 chains reproduced end to end |
| `pythonbank` | 17 seeded Python vulnerabilities | 18 passed | 17/17 PoCs over real HTTP |

`pythonbank` needs no database and no container. The TypeScript ranges need Node and a local PostgreSQL; `run_local.sh` is the source of truth for whether a target is running. The [install page](/docs/install/) lists the full prerequisites.

## What does 30/32 mean?

`vulnbank` seeds 32 vulnerabilities. The range has 30 working PoCs and 32 verified patches. Two seeded vulnerabilities do not have a PoC in the manifest, so they are not counted as reproduced. The scanner's recall is measured against the 30 that can be replayed, and the manifest records the misses rather than hiding them.

The category registry covers 25 of 32 seeded categories. The four category exclusions are recorded with measured reasons in `src/redfall/agent/categories.py`:

| Excluded | Why |
| --- | --- |
| Timing attack | ~0.014 ms signal against ~1.1 ms HTTP noise on 2 vCPU; no PoC reproduces |
| Race condition | The target serialises the transfer on one event loop; the window never opens |
| JWT `alg=none` | `jsonwebtoken` 9.0.3 rejects `alg=none` unless the verifier pins it |
| JWT no expiry | No bounded PoC exists; fabricating one would bend the ground truth |

A missing PoC or an excluded category is a coverage limit. It is not a pass, and it is not a finding.

## What are the gate thresholds?

The range runner scores five metrics, plus three chain metrics for targets that declare chains.

| Metric | Threshold |
| --- | --- |
| Recall | >= 0.60 |
| Precision | >= 0.85 |
| Reproducibility rate | == 1.00 |
| Fix rate | >= 0.50 |
| Duration | <= 900,000 ms |
| Chain recall | >= 0.8333 (5 of 6) |
| Chain link rate | == 1.00 |
| Chain narrative rate | == 1.00 |

Matching is exact: category or a declared alias, same file, and either `|line - manifest line| <= 5` or the same symbol. There is no fuzzy fallback. A near-miss is a miss.

The reproducibility requirement is the strictest one: every reported finding must have reproduced. That is the same contract the product claims, applied to the benchmark.

## How do you run a range?

Each target documents its own commands. The measured invocations are:

```bash
# vulnbank-adaptive
cd range/vulnbank-adaptive
./scripts/run_local.sh start
npm test
npx ts-node scripts/replay_poc.ts --all
./scripts/run_local.sh stop

# chainbank
cd range/chainbank
./scripts/run_local.sh start
npm test
npx ts-node scripts/replay_chain_poc.ts
./scripts/run_local.sh stop

# pythonbank (no database, no container)
cd range/pythonbank
python -m pytest tests/ -q
python scripts/replay_poc.py --all
```

The manifests are generated, not hand-edited. The PoC request strings and anchor lines stay consistent with the real source. Regenerating a manifest requires the target's writer script; pythonbank's writer also supports a `--check` mode that its test suite asserts.

## What do the ranges not prove?

The ranges prove that the scanner and the replay paths work against applications with known ground truth. They do not prove:

- That the same recall and precision hold on an arbitrary codebase.
- That the scanner will find every vulnerability class in a real application.
- That a range target's deployment matches production.
- That a fix generalises beyond the seeded patch.

The [evidence page](/evidence/) records the commands, dates and environment. The [blocked page](/docs/blocked/) records what could not be run on the current host.

## Why publish the misses?

Because a benchmark that only publishes successes is not a benchmark. The 30/32 PoC count, the four category exclusions and the two seeded vulnerabilities without a replay are part of the result. A reader can inspect the manifest, rerun the commands and compare.

The no-mock contract applies to the benchmark too: a number that was not measured is not in the table.

## Frequently asked questions

### Do the ranges require Docker?

`pythonbank` does not. The TypeScript ranges need Node and PostgreSQL; a full `redfall scan` also needs Docker with gVisor and a provider key. The range replays exercise the target apps and PoCs over real HTTP.

### Are the ranges safe to run?

They are deliberately vulnerable. Bind them to loopback only, never expose them, and run them on a host you control. See the [security page](/docs/security/).

### Where are the measured counts recorded?

In the repository, the range manifests and [BLOCKED.md](https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md). The [evidence page](/evidence/) is the site's dated summary.
