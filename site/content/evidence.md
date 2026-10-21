---
title: RedFall evidence
seoTitle: "RedFall Evidence: Measured Results and Limits"
description: "The dated evidence ledger: the 367-test suite, contract checks, range replays, 0.1.1 packaging and site gates, plus unmeasured limits."
path: evidence/
group: Trust and evidence
kind: pillar
pillar: evidence
order: 1
updated: 2026-10-21
keywords: RedFall evidence, vulnerability scanner benchmark results, security tool transparency
sources: https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md, https://github.com/DevAnimecx/redfall/blob/main/CHANGELOG.md, https://github.com/DevAnimecx/redfall/blob/main/RELEASE.md
related: ranges, blocked, output
---

**Every number on this page came from a command that ran, and every gap is named.** The evidence is dated, tied to the repository and separated into what was measured locally, what was measured in CI, and what remains blocked. There is no estimate standing in for a measurement.

The 0.1.1 tree collects **367 tests**. On the development host used for the release, which has no PostgreSQL service and no container runtime, the full suite reported **337 passed, 30 skipped, 0 failed** on 2026-10-21. The 30 skips are 25 PostgreSQL-backed tests plus the five live gVisor tests. The CI run on the tag commit, [39616295334](https://github.com/DevAnimecx/redfall/actions/runs/39616295334), reported **362 passed, 5 skipped in 45.49s** against PostgreSQL 17 on Python 3.12. The `check` job and all six package jobs (Ubuntu, Windows and macOS; Python 3.12 and 3.13) completed successfully. Neither skips nor package jobs are counted as test passes.

## What passed the contract checkers?

The four checkers run in CI and in `make check`. They are fast, deterministic and they fail closed.

| Check | Recorded result |
| --- | --- |
| `python scripts/check_no_mock.py` | `NO-MOCK CONTRACT: PASS` (80 files) |
| `python scripts/check_version.py` | `VERSION CONTRACT: PASS` (11 declarations, 5 lockfile roots) |
| `python scripts/check_orphans.py` | `ORPHAN CHECK: PASS` (78 modules) |
| `python scripts/check_clean_tree.py` | `CLEAN TREE: PASS` |

The no-mock checker is the one that matters most here: it prevents a demo mode or a synthetic fallback from being added to the product. The [no-mock contract page](/docs/no-mock-contract/) explains the rule. The version checker derives the expected version from `src/redfall/version.py`; it does not hardcode the release number in the gate.

## What did the test suite measure?

| Suite | Result | Environment |
| --- | --- | --- |
| `python -m pytest tests/ -q` | 337 passed, 30 skipped in 221.23s | Local Windows, no PostgreSQL or gVisor, 2026-10-21 |
| `python -m pytest tests/ -q` | 362 passed, 5 skipped in 45.49s | CI PostgreSQL 17 / Python 3.12, tag-commit run 39616295334, 2026-10-21 |
| `range/pythonbank` pytest | 18 passed | No database, no container |
| `range/vulnbank` tests | 76 passed | Node + PostgreSQL |
| `range/vulnbank-adaptive` tests | 91 passed | Node + PostgreSQL |
| `range/chainbank` tests | 8 passed | Node + PostgreSQL |

The five CI skips are in `tests/test_sandbox.py` and require a container runtime with gVisor. The 25 additional local skips are the PostgreSQL-backed tests; `REDFALL_TEST_DATABASE_URL` is now required explicitly, so a missing database is a named skip instead of a connection timeout. Neither category is counted as a pass. The full ledger is in [BLOCKED.md](https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md).

## What did the range replays measure?

| Range | Replay | Result |
| --- | --- | --- |
| `pythonbank` | `python scripts/replay_poc.py --all` | 17/17 PoCs over real HTTP |
| `vulnbank-adaptive` | `npx ts-node scripts/replay_poc.ts --all` | 7/7 PoCs reproduced |
| `chainbank` | `npx ts-node scripts/replay_chain_poc.ts` | 6/6 chains reproduced end to end |
| `vulnbank` | `./scripts/verify_patches.sh` | 32/32 patches verified |

The ranges are real applications with real tests. The [range targets page](/docs/ranges/) explains the seeded counts, the 30/32 PoC count for vulnbank, the four category exclusions and the gate thresholds. These range results are unchanged from 0.1.0; the 0.1.1 work did not re-run them on this host, and the page does not pretend it did.

## What did the release and packaging checks measure?

| Check | Result |
| --- | --- |
| `python scripts/build_release.py` | Built `redfall-0.1.1-py3-none-any.whl` and `redfall-0.1.1.tar.gz`; wrote `SHA256SUMS`; both archives contain the harness, prompts and Dockerfile |
| `scripts/verify_wheel.py` in a fresh virtualenv, outside the checkout | `WHEEL VERIFY: PASS`; installed distribution reports 0.1.1 |
| Windows installer with a throwaway `REDFALL_HOME` | `Redfall 0.1.1 installed.`; `install.sh` parses clean with Git Bash |
| `redfall doctor` on the release host | Postgres and Redis MISSING (bounded probe), `runsc` MISSING, LLM provider MISSING; Node/npm OK; exits 1 |
| `gh release download v0.1.1` + SHA-256 comparison against `SHA256SUMS` | Downloaded the published wheel, sdist and checksum file; both hashes matched |
| `gh attestation verify ... --repo DevAnimecx/redfall --signer-workflow DevAnimecx/redfall/.github/workflows/release.yml --source-ref refs/tags/v0.1.1` | Passed for both the wheel and the sdist: signer `release.yml@refs/tags/v0.1.1`, source digest `ba8dbcc`, release run 39617991722 |
| Downloaded wheel installed in a fresh virtualenv outside the checkout | `WHEEL VERIFY: PASS`; installed distribution reports 0.1.1 |
| CI package matrix (Ubuntu, Windows, macOS; Python 3.12, 3.13) | Green on the tag commit: all seven jobs (check plus six package jobs) completed successfully |

The release checks are about provenance and behaviour. They do not claim the software is free of vulnerabilities. The [release verification page](/docs/release-verification/) gives the commands and the limits.

## What did the site measure?

The 0.1.1 site was built and measured locally on 2026-10-21 against the production bundle with real Chrome. It is deployed at <https://devanimecx.github.io/redfall/> by Pages run [39616295475](https://github.com/DevAnimecx/redfall/actions/runs/39616295475).

| Check | 0.1.1 local result |
| --- | --- |
| Lighthouse, landing desktop | 100 performance / 100 accessibility / 100 best-practices / 100 SEO; LCP 0.4 s; TBT 0 ms; CLS 0 |
| Lighthouse, landing mobile | 100 performance / 100 accessibility / 100 best-practices / 100 SEO; LCP 1.5 s; TBT 0 ms; CLS 0 |
| axe-core, landing at 390, 768 and 1280 px | 0 violations at every width |
| axe-core, 23 docs/trust routes at 390 and 1280 px | 0 violations; no horizontal overflow; H1 readable with JavaScript disabled |
| Layout gate at 390, 768 and 1280 px | PASS; document width equals viewport |
| SEO gate | PASS — 25 HTML routes, 24 sitemap URLs, 0 errors; canonical, schema, internal links, OG cards, robots, sitemap, `llms.txt` and IndexNow key all checked |
| JavaScript bundle | 80.97 kB gzipped |
| CSS | 8.27 kB gzipped, inlined on the landing page and shared by the static docs |

The live 0.1.1 deployment is Pages run [39616295475](https://github.com/DevAnimecx/redfall/actions/runs/39616295475) on 2026-10-21. Its build passed the SEO gate (25 HTML routes, 24 sitemap URLs, 0 errors); the deploy job verified the IndexNow key, submitted 24 URLs and received **HTTP 200**, and the live SEO monitor passed 24 sitemap pages. A missing path returned **HTTP 404**. Two Lighthouse runs against the live landing measured desktop **97–98** and mobile **93–99** performance, with 100 for accessibility, best-practices and SEO; the 93 run fell below the 95 performance gate. Live performance is therefore variable and is recorded as a measured range, not certified at 100. The local production build above remains the build gate.

| Live check | Recorded result |
| --- | --- |
| Pages build + deploy, run 39616295475 | PASS; live SEO monitor PASS on 24 sitemap pages |
| IndexNow | 24 URLs submitted, HTTP 200 |
| Live Lighthouse, landing desktop (two runs) | 97 and 98 performance; 100 accessibility / best-practices / SEO |
| Live Lighthouse, landing mobile (two runs) | 93 and 99 performance; 100 accessibility / best-practices / SEO; one run below the 95 performance gate |
| Missing path | HTTP 404 |

The layout gate found a real bug that Lighthouse missed: install `<pre>` blocks were grid items with default `min-width: auto`, forcing a 578 px document on a 390 px phone. The fix was `min-w-0 overflow-hidden`. The accessibility gate found a real bug too: horizontally scrollable code regions were not keyboard-reachable. They are now labelled, focusable regions.

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
| Stable live mobile Lighthouse performance | Two runs measured 93 and 99; the lower run missed the 95 gate. GitHub Pages and runner variance are outside the local build gate |
| Real-user field performance (CrUX) | The site has no traffic volume yet; synthetic Lighthouse is the only measured performance signal |
| Backlinks, organic rankings or AI citations | Cannot be manufactured or guaranteed; not a product measurement |

The [blocked page](/docs/blocked/) explains each prerequisite and the smallest real unblock. The [no-mock contract](/docs/no-mock-contract/) explains why a missing measurement is not replaced with a guess.

## How do you reproduce a measurement?

Use the command in the table, not a screenshot. The repository is public, the tests name their properties, and the blocker ledger records the environment. For the test suite, the database URL is explicit:

```bash
export REDFALL_TEST_DATABASE_URL=postgresql+psycopg://vulnbank:Sup3rS3cretBankPwd!@127.0.0.1:5432/redfall_test
python -m pytest tests/ -q
```

Without that variable, the PostgreSQL tests skip with a named reason. For the site, the build and checks are:

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

### Is 337 passed / 30 skipped a current run?

Yes. It is the complete local run on 2026-10-21 without PostgreSQL or a container runtime. The CI run on the tag commit was 362 passed / 5 skipped. Neither run counts a skip as a pass.

### Why are tests skipped?

Five tests require a container runtime with gVisor, which this host does not have. Twenty-five more require PostgreSQL; they run only when `REDFALL_TEST_DATABASE_URL` is explicitly set. CI sets it and runs the database suite.

### Does 0.1.1 have a verified Sigstore attestation?

Yes. The tag-triggered [release workflow](https://github.com/DevAnimecx/redfall/actions/runs/39617991722) built and attested the published artifacts. `gh attestation verify` passed for both the wheel and the sdist with the signer workflow `release.yml@refs/tags/v0.1.1` and source digest `ba8dbcc`. The downloaded wheel was also installed in a fresh virtualenv outside the checkout and passed `scripts/verify_wheel.py`. The exact hashes are recorded in [`RELEASE.md`](https://github.com/DevAnimecx/redfall/blob/main/RELEASE.md).

### Does the site measure rankings or citations?

No. Organic rankings, backlinks and AI citations depend on external systems and time. The site records what it can measure directly: build, accessibility, Lighthouse, schema, internal links and indexability.
