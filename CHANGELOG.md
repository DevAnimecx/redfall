# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-10-19

The first release. Everything below was verified on the development host with a
real Postgres, real target applications over real HTTP, and a built wheel
installed into a fresh virtualenv. What could not run there (gVisor sandbox
execution, live LLM calls) refuses loudly and is listed in
[`BLOCKED.md`](BLOCKED.md) with the exact unblock.

### Added

- **Ingestion** — tree-sitter parsing for TS/TSX/JS/JSX/MJS and Python;
  symbols, imports (named, aliased, namespace, CommonJS `require`, Python
  relative imports), dependency and git facts.
- **Taint analysis** — intraprocedural source→sink flow per function, plus a
  depth-one interprocedural pass in both languages: parameters seeded to prove
  what a caller's taint can reach, **return flow** proving what a callee's
  sources hand back, and a **call graph** that route attribution follows across
  files. Ambiguity is dropped, never guessed. Sanitisers are recorded and never
  silently clear taint.
- **Route frameworks** — Express, Fastify, koa-router and NestJS decorators;
  Flask/FastAPI blueprints with prefix resolution through imports.
- **Adaptive branching** — a recursive branch tree with seven spawn triggers
  detected from real source (dynamic imports, dynamic routes, plugin systems,
  DB-stored code, webhooks, feature flags, env conditionals).
- **Cross-branch chaining** — attack graph over discovered findings, compound
  CVSS, and the chain narrative; `range/chainbank` reproduces 6/6 chains.
- **Sandbox validation** — Docker + gVisor executor and an in-box exploit
  harness that runs Node and Python targets (venv boot with a
  `redfall.target.json` contract, `app.py` fallback, `target-missing` otherwise).
- **Verified fix loop** — patch application on branches with verification; never
  auto-merged.
- **Range targets with ground truth** — `vulnbank` (32 seeded vulns),
  `vulnbank-adaptive` (7 adaptive surfaces), `chainbank` (6 chains),
  `pythonbank` (17 seeded vulns, real HTTP PoC replay 17/17).
- **Range-runner gate** — deterministic scorer: 5 core metrics plus 3 chain
  metrics over scan and fix outputs.
- **SARIF 2.1.0 export** — `redfall report <scan-id> --format sarif`; every
  result carries `properties.redfall.verified`, so unproven candidates stay
  visible and nothing is upgraded or dropped.
- **Packaging** — pure-Python wheel (`py3-none-any`) with the sandbox harness,
  prompts and Dockerfile included; `scripts/verify_wheel.py` proves an installed
  wheel from outside the checkout; CI packaging matrix on Ubuntu, Windows and
  macOS across Python 3.12/3.13.
- **Installers** — `scripts/install.sh` (Linux, macOS) and
  `scripts/install.ps1` (Windows) with a `redfall doctor` report at the end.
- **Contracts** — no-mock, version, orphan and clean-tree checkers, all run by
  `make check` and CI.

### Verified

- `python -m pytest tests/ -q` → **250 passed, 5 skipped** (the five gVisor
  skips), against a real Postgres.
- pythonbank: **17/17** PoCs reproduced over real HTTP; **18** target tests.
- vulnbank: **32/32** patches verified; 76 tests. vulnbank-adaptive: 91 tests,
  7/7 PoCs. chainbank: 8 tests, 6/6 chains.
- `scripts/verify_wheel.py` → `WHEEL VERIFY: PASS` from a fresh virtualenv,
  with the interprocedural taint found through the installed wheel.
- vulnbank scan parity after the return-flow work: 27 routes, 20 taint paths,
  11 call edges, 0 over-claims; self-scan: 51 files, 0 parse errors.

[0.1.0]: https://github.com/DevAnimecx/redfall/releases/tag/v0.1.0
