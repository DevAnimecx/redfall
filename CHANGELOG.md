# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-10-21

Patch-level consolidation of everything landed after the `v0.1.0` tag. It ships
the campaign/evidence layer (Phase 1), the persisted graph and resumable runner
(Phase 2), the HTTP/OpenAPI + A2A v1.0 gateway (Phase 3), and the site,
documentation, SEO and release-hardening changes built on top of them. `0.1.0`
remains the first release; this entry records the measured state of the current
tree.

### Added

- **Phase 3 agent interoperability gateway** — one stdlib
  `ThreadingHTTPServer` serves the same 44-tool `ToolRegistry` over HTTP/OpenAPI
  and A2A v1.0 on one address. HTTP adds `GET /healthz`,
  `GET /v1/openapi.json`, `GET /v1/tools`, `POST /v1/tools/{name}`, admin-only
  `GET /v1/audit` and HMAC-signed `GET /v1/artifacts/{id}`. A2A adds the Agent
  Card at `/.well-known/agent-card.json`, JSON-RPC at `/a2a/v1`, SSE streaming,
  `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`
  and `SubscribeToTask`, with deterministic cancellation before execution and
  cooperative cancellation during a call. Push notifications return `-32003`;
  multi-turn continuation returns `-32004`.
- **Gateway security and operations** — `AgentToken` rows store only SHA-256
  digests with explicit scopes (`read`, `execute`, `write`, `admin`), optional
  hourly quotas and immediate revocation; tool executions, unknown-tool
  attempts and scope/quota denials are audited. Tokens are created, listed and
  revoked only through the CLI. `redfall interop serve|token|webhook|audit|
  certify` is the operator surface. Webhooks use HMAC-SHA256
  (`X-Redfall-Signature: sha256=<hex>`), idempotent per-subscription/event
  enqueue, at most three attempts, no redirects, and loopback/link-local URL
  policy. Tool results are labelled `untrusted-repository-data` in the JSON
  envelope, the `X-Redfall-Trust` header and A2A artifact metadata.
- **Executable interop contracts** — `redfall interop certify --protocol http`
  launches a fresh gateway subprocess against a temporary database and
  repository and runs 10 checks; `--protocol a2a` runs 11. Both report
  `certified=True` locally. The checks use a real socket, real tool execution,
  SSE streaming and signed artifacts.
- **Phase 2 execution layer** — a persisted, provenance-aware code graph v1
  (`graph_snapshots`, `graph_nodes`, `graph_edges`) built from real ingestion,
  with bounded search/traversal/paths/inventory and snapshot diff; a resumable
  campaign runner with lease heartbeats, preflight budget reservations, measured
  settlement, retries and blocked handling; real task handlers for graph, scan,
  stored-finding reproduction and evidence-gated JSON/SARIF reports; and 44 MCP
  stdio tools covering campaigns, graph, scans, findings, reproduction,
  evidence, reports, policy checks and adapter certifications.
- **Executable MCP adapter contract** — `redfall mcp certify` launches a fresh
  stdio server process, completes the MCP handshake, checks every core tool
  schema, persists a campaign and task, indexes real source, denies an
  out-of-scope path and returns a protocol-visible error for an unknown tool.
  The result is stored as a timestamped `AdapterCertification`; it certifies the
  shipped server, not arbitrary third-party agents.
- **Phase 2 CLI and scope hardening** — `redfall graph` (index/latest/stats/
  search/routes/sources/sinks/neighbors/paths/inventory/diff), `campaign run`,
  reservations, readiness/export, `reproduce`, `policy-check`, `mcp certify` and
  adapter listings. Graph and reproduction path-taking commands enforce campaign
  roots or `REDFALL_ALLOWED_ROOTS`; when the allowlist is set, a broader campaign
  root is ignored, so an MCP client cannot widen the operator boundary.
- **Phase 1 campaign kernel** — durable `campaigns`, `campaign_tasks` and
  `campaign_events` tables; an explicit state machine from `draft` through
  `reported` (with `paused`/`blocked` resume semantics); dependency-aware task
  claims with worker leases, expiry requeue and retry limits; and atomic budget
  enforcement for USD, tokens and sandbox minutes before spend is recorded.
  Campaigns are persisted through the existing SQLAlchemy `create_all` path, so
  a Postgres deployment gets the new tables on startup without a migration step.
- **Tamper-evident evidence ledger** — append-only `evidence_records` with
  per-campaign SHA-256 hash chains. E0–E2 are hypotheses/observations; only
  E3/E4 are reportable, and those records are rejected unless they carry an
  execution id, observable, reproduction command and environment digest.
  `redfall campaign evidence verify` and the report-readiness tool recompute the
  chain and name the first broken link.
- **Campaign CLI and agent tools** — `redfall campaign` supports `create`,
  `scope`, `start`, `status`, `transition`, `pause`, `resume`, `cancel`,
  `report`, `spend`, reservations, `run`, `task` and `evidence`, plus
  `readiness`/`export`. The transport-neutral `ToolRegistry` is the same
  implementation behind the CLI, MCP, HTTP and A2A surfaces.
- **Landing page, documentation and evidence** — a one-page React + Tailwind
  landing page, statically prerendered at build time, plus generated Markdown
  docs/trust pages with zero client JavaScript, deployed to
  <https://devanimecx.github.io/redfall/> by `.github/workflows/pages.yml`.
- **Technical SEO + GEO/AEO system** — one canonical per page, unique titles and
  descriptions, hreflang, a real 404, `sitemap.xml`, `robots.txt` with named AI
  crawlers, a byte-identical `llms.txt` at repo and site root, generated
  1200×630 OG cards, JSON-LD graphs (Organization, Person, WebSite,
  SoftwareApplication, WebPage, FAQPage, BreadcrumbList, TechArticle), an
  IndexNow key plus submission script, a weekly live SEO monitor workflow, and
  the operating manual in [`site/SEO.md`](site/SEO.md). Build gates:
  `check:seo`, `check:docs`, `check:layout`, `check:a11y`, `check:lighthouse`.
- **Brand assets** — vector lockups (dark, light, mark), a generated social card
  and touch icons, and a path-geometry guard that keeps the SVG and generator
  from drifting.
- **Release contract** — `scripts/check_version.py` now derives the expected
  version from `src/redfall/version.py`, checks the site release module, package
  manifests and npm lockfile roots, and refuses drift. Release-contract tests
  cover the metadata, changelog, site and `llms.txt` surfaces.

### Changed

- **Landing page rebuilt as a dark design system** — exact token layer
  (`#050505` / `#0d0d0d` / `#ff0033`), Inter self-hosted from a single 47 kB
  Latin variable font, SVG orbital hero with reduced-motion fallbacks, a
  full-screen mobile menu, copy states and a 1200 px content grid. The
  JavaScript bundle is **80.9 kB gzipped**; CSS is **8.22 kB gzipped** and
  inlined into the prerendered HTML.
- **Accessibility and layout are CI contracts** — `axe-core` runs at 390, 768
  and 1280 px and must report zero violations; `mobile_check.mjs` drives real
  Chrome and fails on any unclipped horizontal overflow. Both found real bugs
  during the rebuild, which are fixed.
- **PostgreSQL tests are explicit** — the suite now requires
  `REDFALL_TEST_DATABASE_URL` and skips database-backed tests when it is absent,
  instead of falling back to a hardcoded local database and waiting on
  connection timeouts. CI supplies the URL, so database coverage is unchanged.
- **Public surface documentation** — the CLI reference, architecture,
  installation, release-verification and interoperability pages now describe the
  shipped commands and transports, with the limits of each.

### Fixed

- **Mobile layout overflow on the landing page** — install code blocks are
  CSS-grid children and `<pre>` forced the track to 554 px, producing 188 px of
  sideways scroll on a 390 px phone. `mobile_check.mjs` now catches this class of
  bug in CI.
- **Dark logo lockup** — the white “Fall” was invisible on a light background;
  the dark variant now carries an opaque plate.
- **Stale test-harness fallback** — the suite no longer treats a connection
  timeout as a test result. Missing database configuration is a skip with a
  named reason.
- **Bounded database probe** — `redfall doctor` now caps the PostgreSQL connect
  attempt at three seconds, so an unreachable database is reported instead of
  leaving the command waiting for the operating system's TCP timeout. A real
  socket test asserts the probe fails within ten seconds.

### Verified before publication

- **Phase 3 focused tests:** **53 passed** across auth/HTTP, A2A, webhooks,
  contracts and CLI. The real-subprocess HTTP contract passes 10 checks and the
  A2A contract passes 11, with `certified=True`.
- **CI:** run
  [39313598416](https://github.com/DevAnimecx/redfall/actions/runs/39313598416)
  completed green on 2026-10-19 after the test-harness fix: the Postgres 17 /
  Python 3.12 `check` job ran **357 passed, 5 skipped in 63.08s**, and all six
  wheel/installer package jobs passed. The five skips are live gVisor tests; the
  runner has no `runsc`.
- **Local no-PostgreSQL run:** **337 passed, 30 skipped, 0 failed** in 196.67s.
  The 30 skips are 25 PostgreSQL-backed tests plus the five live gVisor tests.
  Neither category is counted as a pass.
- **Site:** the 0.1.1 production build passed the SEO gate (25 HTML routes, 24
  sitemap URLs), axe (23 docs/trust routes, 0 violations), layout and Lighthouse
  (100/100/100/100 on desktop and mobile; mobile LCP 1.5s) as recorded in
  [`site/content/evidence.md`](site/content/evidence.md). The live deployment
  follows publication. The 0.1.1 build and wheel verification are recorded in
  [`RELEASE.md`](RELEASE.md); published-artifact verification is added after the
  release workflow completes.
- **Known limits:** no local PostgreSQL, Docker/gVisor runtime or LLM key; A2A
  push notifications and multi-turn continuation are not implemented; the
  gateway has no built-in TLS or multi-tenancy; adapter certification covers the
  shipped surfaces only. See [`BLOCKED.md`](BLOCKED.md).

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

- `python -m pytest tests/ -q` → **254 passed, 5 skipped** (the five gVisor
  skips), against a real Postgres.
- pythonbank: **17/17** PoCs reproduced over real HTTP; **18** target tests.
- vulnbank: **32/32** patches verified; 76 tests. vulnbank-adaptive: 91 tests,
  7/7 PoCs. chainbank: 8 tests, 6/6 chains.
- `scripts/verify_wheel.py` → `WHEEL VERIFY: PASS` from a fresh virtualenv,
  with the interprocedural taint found through the installed wheel.
- vulnbank scan parity after the return-flow work: 27 routes, 20 taint paths,
  11 call edges, 0 over-claims; self-scan: 51 files, 0 parse errors.

[0.1.1]: https://github.com/DevAnimecx/redfall/releases/tag/v0.1.1
[0.1.0]: https://github.com/DevAnimecx/redfall/releases/tag/v0.1.0
