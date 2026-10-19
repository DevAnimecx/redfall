---
title: What RedFall cannot run yet
seoTitle: "What RedFall Cannot Run Yet, and Why"
description: "The current host has no container runtime and no LLM provider key. Here is the blocker ledger: what cannot run, what was tried, and the smallest real unblock for each."
path: docs/blocked/
group: Trust and evidence
kind: cluster
pillar: evidence
order: 5
updated: 2026-10-19
keywords: RedFall blockers, gVisor unavailable, vulnerability scanner limitations, security tool transparency
sources: https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md, https://gvisor.dev/docs/
related: evidence, sandbox, install
---

**A full RedFall scan cannot run on the development host used for 0.1.0: there is no container runtime for the gVisor sandbox and no LLM provider credential for analysis.** Both are infrastructure gaps, not design gaps. The code paths are written and the failure is loud; nothing falls back to a demo, a fixture or a host-execution escape hatch.

This page is a summary of [BLOCKED.md](https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md), which contains the full commands, dates and measured state. It exists so a reader can see what the scanner did not do before trusting what it did.

## Which blockers are active?

| Blocker | What it prevents | Smallest real unblock |
| --- | --- | --- |
| No container runtime | Any execution-verified finding | Install Docker and register the gVisor `runsc` runtime |
| No LLM provider key | Planning, analysis, PoC generation, fixing, chain analysis | Set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` |
| No KVM | Firecracker microVM work | A host with `/dev/kvm` and the Firecracker tooling |
| No provider key (benchmark) | Token-economics benchmark | A live provider key and a baseline run |
| No Rust parity proof | A side-by-side Rust orchestrator claim | A Rust implementation and a measured comparison |

The first two are the ones that block the product path. The others block additional claims that the project does not make.

## Why is there no sandbox on this host?

The measured check is concrete:

```bash
$ docker --version
docker: command not found
```

The repository's own check reports:

```text
{'runtime': 'runsc', 'ready': False,
 'reasons_unavailable': ['the `docker` CLI is not on PATH'], 'docker_cli': False}
```

The executor requires Docker and the gVisor runtime. A Docker runtime alone is not enough; the isolation boundary is `runsc`. There is no host-execution fallback in the module, and `tests/test_sandbox.py` asserts that every command vector starts with the Docker CLI.

A previous Linux sandbox session (recorded in the 2026-10-11 update in `BLOCKED.md`) did install Docker 26.1.5 and `runsc`, and verified the gVisor Sentry kernel by running a container. That session also found and fixed the `ENTRYPOINT` bug that would have made every reproduction a silent pass. The current host is not that session: it has no container runtime, so the five gVisor tests skip with a reason.

The distinction is important. The sandbox path has been exercised on a Linux host, and the bug it exposed was fixed. It cannot be exercised here.

## Why is there no LLM key?

The analysis stages make live LiteLLM calls with bring-your-own-key credentials. A missing key raises an error:

```text
LLMError: ... Missing credentials.
```

There is no synthetic completion and no cached transcript unless a real transcript exists. The planner, analyser, PoC generator, fixer and chain analyst all depend on the provider. The [architecture pillar](/docs/architecture/) explains where the model sits; it is a proposal engine, not the execution gate.

The missing key means the agent-driven fix loop and the full scan cannot run here. The range's own patch verification and the non-LLM tests can.

## What is real in the meantime?

A lot of the system does not need those two prerequisites. The repository's measured state includes:

| Command | Recorded result |
| --- | --- |
| `python scripts/check_no_mock.py` | PASS (51 files) |
| `python scripts/check_version.py` | PASS |
| `python scripts/check_orphans.py` | PASS (49 modules) |
| `python scripts/check_clean_tree.py` | PASS |
| `python -m pytest tests/ -q` with a real Postgres | 254 passed, 5 skipped |
| `range/pythonbank` pytest | 18 passed |
| `range/pythonbank` replay | 17/17 PoCs over real HTTP |
| `range/vulnbank` tests | 76 passed |
| `range/vulnbank` patches | 32/32 verified |
| `range/vulnbank-adaptive` tests | 91 passed |
| `range/vulnbank-adaptive` replay | 7/7 PoCs |
| `range/chainbank` tests | 8 passed |
| `range/chainbank` replay | 6/6 chains end to end |
| `gh attestation verify` on the released wheel | verified |
| Wheel verification in a fresh venv | PASS |
| Landing page Lighthouse (local production build) | 100/100/100/100 desktop; 98–100 mobile performance with 100 accessibility/best-practices/SEO; docs page 100 desktop, 99–100 mobile performance, 100 elsewhere |
| SEO gate (`npm run check:seo`) | PASS — 24 HTML routes, 23 sitemap URLs, 0 errors |
| axe-core on 22 docs/trust routes (390 and 1280 px) | 0 violations; zero client JavaScript |
| Live Pages deploy ([run 39253506525](https://github.com/DevAnimecx/redfall/actions/runs/39253506525)) | build + deploy succeeded; live SEO monitor PASS on 23 pages; IndexNow accepted 23 URLs with HTTP 202 |
| Live Lighthouse (deployed landing) | 100/100/100/100 desktop; 98 performance, 100 accessibility/best-practices/SEO mobile |
| Live 404 check | missing path returned HTTP 404 with the custom page |

The 254 passed / 5 skipped result was measured with a real PostgreSQL. The host currently used for site work has no PostgreSQL either, so the database-backed subset cannot be re-run here without provisioning one. The [evidence page](/evidence/) records that caveat.

## What does a skipped test mean?

The five skips are the gVisor-dependent sandbox tests. They skip because the runtime is absent, and the skip reason says so. They are not counted as passes, and they are not removed from the suite to make the number look cleaner.

The same rule applies to the full scan: `redfall scan` refuses and names both prerequisites. That refusal is the implemented behaviour, not an error page standing in for a result.

## What would it take to clear the blockers?

**Sandbox:** a host with Docker plus gVisor installed and registered. The daemon configuration is:

```jsonc
// /etc/docker/daemon.json
{ "runtimes": { "runsc": { "path": "/usr/local/bin/runsc" } } }
```

`redfall doctor` turns green when `runsc` appears in `docker info`. Nothing in `src/redfall/sandbox/` needs to change.

**Provider:** export a real key. Tier routing honours `REDFALL_MODEL_FAST`, `_MID` and `_DEEP` if you want specific models. The call is live; there is no offline mode.

**Both:** a Postgres database for the store, and a target with a boot contract. The [install page](/docs/install/) lists the full set.

## What does this mean for the site's claims?

The site does not claim that a full scan ran on this host. It claims that the execution path was built, that the sandbox path was exercised on a Linux host, that the non-LLM paths were measured, and that the current host cannot run the full scan. Those are different statements, and the difference is the point of the no-mock contract.

If a future update clears a blocker, the evidence table should change with a command and a date. Until then, the blocker remains visible.

## Frequently asked questions

### Is RedFall unusable without Docker?

No. Ingestion, taint analysis, route extraction, SARIF export, the unit/contract suite and the `pythonbank` replay work without Docker. Execution-verified findings require the sandbox.

### Why not add a demo mode for the site?

Because a demo mode would make the site's central claim false. The [no-mock contract](/docs/no-mock-contract/) forbids it.

### Where is the full ledger?

[BLOCKED.md](https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md) in the repository. It includes the exact commands, the environment and the historical Linux session.
