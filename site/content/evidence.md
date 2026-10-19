---
title: RedFall evidence
seoTitle: "RedFall Evidence: Measured Results and Limits"
description: "The dated evidence ledger: contract checks, 254 tests, 17/17 pythonbank PoCs, 7/7 adaptive PoCs, 6/6 chains, 32/32 patches, Lighthouse/axe results and unmeasured limits."
path: evidence/
group: Trust and evidence
kind: pillar
pillar: evidence
order: 1
updated: 2026-10-19
keywords: RedFall evidence, vulnerability scanner benchmark results, security tool transparency
sources: https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md, https://github.com/DevAnimecx/redfall/blob/main/CHANGELOG.md, https://devanimecx.github.io/redfall/
related: ranges, blocked, output
---

**Every number on this page came from a command that ran, and every gap is named.** The evidence is dated, tied to the repository and separated into what was measured on the development host, what was measured in CI, and what remains blocked. There is no estimate standing in for a measurement.

The last recorded full test run was **254 passed, 5 skipped** with a real PostgreSQL. The five skips are the gVisor-dependent sandbox tests. The current host used for site work has no PostgreSQL or container runtime, so the database-backed subset cannot be re-run here without provisioning one. That caveat is part of the evidence, not a footnote.

## What passed the contract checkers?

The four checkers run in CI and in `make check`. They are fast, deterministic and they fail closed.

| Check | Recorded result |
| --- | --- |
| `python scripts/check_no_mock.py` | `NO-MOCK CONTRACT: PASS` (51 files) |
| `python scripts/check_version.py` | `VERSION CONTRACT: PASS` |
| `python scripts/check_orphans.py` | `ORPHAN CHECK: PASS` (49 modules) |
| `python scripts/check_clean_tree.py` | `CLEAN TREE: PASS` |

The no-mock checker is the one that matters most here: it prevents a demo mode or a synthetic fallback from being added to the product. The [no-mock contract page](/docs/no-mock-contract/) explains the rule.

## What did the test suite measure?

| Suite | Result | Environment |
| --- | --- | --- |
| `python -m pytest tests/ -q` | 254 passed, 5 skipped | Real PostgreSQL, 2026-10-18 |
| `range/pythonbank` pytest | 18 passed | No database, no container |
| `range/vulnbank` tests | 76 passed | Node + PostgreSQL |
| `range/vulnbank-adaptive` tests | 91 passed | Node + PostgreSQL |
| `range/chainbank` tests | 8 passed | Node + PostgreSQL |

The five skips are in `tests/test_sandbox.py` and require a container runtime with gVisor. They skip with a reason; they are not counted as passes. The full ledger is in [BLOCKED.md](https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md).

## What did the range replays measure?

| Range | Replay | Result |
| --- | --- | --- |
| `pythonbank` | `python scripts/replay_poc.py --all` | 17/17 PoCs over real HTTP |
| `vulnbank-adaptive` | `npx ts-node scripts/replay_poc.ts --all` | 7/7 PoCs reproduced |
| `chainbank` | `npx ts-node scripts/replay_chain_poc.ts` | 6/6 chains reproduced end to end |
| `vulnbank` | `./scripts/verify_patches.sh` | 32/32 patches verified |

The ranges are real applications with real tests. The [range targets page](/docs/ranges/) explains the seeded counts, the 30/32 PoC count for vulnbank, the four category exclusions and the gate thresholds.

## What did the release and packaging checks measure?

| Check | Result |
| --- | --- |
| `python scripts/build_release.py` | Wheel and sdist built; `SHA256SUMS` written |
| `scripts/verify_wheel.py` in a fresh venv, outside the checkout | `WHEEL VERIFY: PASS` |
| `gh attestation verify redfall-0.1.0-py3-none-any.whl --repo DevAnimecx/redfall` | Verified |
| Installer on Windows with a throwaway `REDFALL_HOME` | `Redfall 0.1.0 installed.` plus the real doctor report |
| CI package matrix (Ubuntu, Windows, macOS; Python 3.12, 3.13) | Green |

The release checks are about provenance and behaviour. They do not claim the software is free of vulnerabilities. The [release verification page](/docs/release-verification/) gives the commands and the limits.

## What did the site measure?

The redesigned landing page was measured locally on 2026-10-19 against the production build with real Chrome, then the same build was deployed and measured again on the live URL:

| Check | Result |
| --- | --- |
| Lighthouse, local landing desktop | 100 performance / 100 accessibility / 100 best-practices / 100 SEO; LCP 0.4 s; TBT 0 ms; CLS 0 |
| Lighthouse, local landing mobile | 98–100 performance, 100 accessibility/best-practices/SEO across runs; LCP 1.5–1.7 s; TBT 0–10 ms; CLS 0 |
| Lighthouse, local docs page (desktop and mobile) | 100 / 100 / 100 / 100 desktop; 99–100 performance, 100 accessibility/best-practices/SEO mobile; zero client JavaScript |
| Lighthouse, live landing desktop | 100 / 100 / 100 / 100; LCP 0.6 s; TBT 0 ms; CLS 0 |
| Lighthouse, live landing mobile | 98 performance, 100 accessibility/best-practices/SEO; LCP 1.7 s; TBT 60 ms; CLS 0 |
| Lighthouse, live docs page | 100 / 100 / 100 / 100 desktop; 99 performance, 100 accessibility/best-practices/SEO mobile; zero client JavaScript |
| axe-core, landing at 390, 768 and 1280 px | 0 violations at every width |
| axe-core, 22 docs/trust routes at 390 and 1280 px | 0 violations; no horizontal overflow; H1 readable with JavaScript disabled |
| Layout gate at 390, 768 and 1280 px | PASS; document width equals viewport |
| SEO gate | PASS — 24 HTML routes, 23 sitemap URLs, 0 errors; canonical, schema, internal links, OG cards, robots, sitemap, `llms.txt` and IndexNow key all checked |
| JavaScript bundle | 80.9 kB gzipped |
| CSS | 8.22 kB gzipped, inlined on the landing page and shared by the static docs |

The live measurement is the deployed build, not a different one. Pages run [39253506525](https://github.com/DevAnimecx/redfall/actions/runs/39253506525) completed both jobs on 2026-10-19: the SEO gate passed (24 HTML routes, 23 sitemap URLs, 0 errors), the live monitor passed across 23 pages, and IndexNow accepted **23 URLs with HTTP 202**. A missing live path returned **HTTP 404**, not a soft 200.

The layout gate found a real bug that Lighthouse missed: the install `<pre>` blocks were grid items with default `min-width: auto`, forcing a 578 px document on a 390 px phone. The fix was `min-w-0 overflow-hidden`. The accessibility gate found a real bug too: horizontally scrollable code regions were not keyboard-reachable. They are now labelled, focusable regions.

## What was not measured?

The evidence page is only useful if the gaps are as visible as the results.

| Not measured | Why |
| --- | --- |
| A full `redfall scan` on this host | No Docker/gVisor runtime and no LLM provider key |
| The agent-driven fix loop | Requires a live provider key |
| Token economics / cost per scan | No provider key; no baseline run |
| Firecracker microVM path | No `/dev/kvm` on this host |
| Rust orchestrator parity | No Rust implementation to compare |
| Recall and precision on an arbitrary codebase | The ranges are the measured ground truth |
| Backlinks, organic rankings or AI citations | Cannot be manufactured or guaranteed; not a product measurement |

The [blocked page](/docs/blocked/) explains each prerequisite and the smallest real unblock. The [no-mock contract](/docs/no-mock-contract/) explains why a missing measurement is not replaced with a guess.

## How do you reproduce a measurement?

Use the command in the table, not a screenshot. The repository is public, the tests name their properties, and the blocker ledger records the environment. For the test suite, the database URL is explicit:

```bash
export REDFALL_TEST_DATABASE_URL=postgresql+psycopg://vulnbank:Sup3rS3cretBankPwd!@127.0.0.1:5432/redfall_test
python -m pytest tests/ -q
```

For the site, the build and checks are:

```bash
cd site
npm ci
npm run build
npm run check:seo
npx vite preview --port 4173 --strictPort   # in another terminal
npm run check:layout    -- http://localhost:4173/redfall/
npm run check:a11y     -- http://localhost:4173/redfall/
npm run check:docs     -- http://localhost:4173/redfall/
npm run check:lighthouse -- http://localhost:4173/redfall/
node scripts/indexnow.mjs --dry-run          # prints the exact URL list; sends nothing
```

If a number cannot be reproduced, open an issue with the command and the observed output. A correction with a real transcript is more valuable than a green badge.

## What is the gate?

The range runner's thresholds are the standard the product is measured against:

```
recall      >= 0.60
precision   >= 0.85
repro_rate  == 1.00
fix_rate    >= 0.50
duration_ms <= 900000
chain_recall >= 0.8333
chain_link_rate == 1.00
chain_narrative_rate == 1.00
```

A scan that misses a threshold is a miss, not a rounding error. The [range targets page](/docs/ranges/) explains how matching works.

## Frequently asked questions

### Is 254 passed / 5 skipped a current run?

It is the last recorded full run with a real PostgreSQL (2026-10-18). The current site-working host has no PostgreSQL, so the database-backed subset cannot be re-run here without provisioning one. The non-database tests and the range replays are separately recorded.

### Why are five tests skipped?

They require a container runtime with gVisor, which the current host does not have. They run in CI where the runtime exists; here they skip with a reason.

### Does the site measure rankings or citations?

No. Organic rankings, backlinks and AI citations depend on external systems and time. The site records what it can measure directly: build, accessibility, Lighthouse, schema, internal links and indexability.
