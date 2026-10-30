# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-10-30

**Platform.** RedFall becomes something a team can run rather than a tool one
person runs. Four additions, each opt-in, each keeping the defaults of the
release before it: an enterprise control plane, a learning loop that only
learns from reproduced outcomes, an isolation ladder with a capacity plan, an
agent mesh with separated duties, and a deployment image.

The thread running through all five is the same one that runs through the rest
of the project: a claim is only as good as the thing that checks it. Tenancy is
derived from a credential rather than accepted from a request. A lesson cites
the E3/E4 evidence that produced it or it is not created. The capacity plan
refuses to guess a number it cannot read. The critic is not the author. The
healthcheck is a capability check, not a liveness ping.

### Added

- **Tenancy, roles, policy and audit export** — an isolation boundary a team
  can be put behind. A credential resolves to a tenant and the scope built from
  it is the only thing queries filter on, so no request field can widen it. Five
  roles with explicit permission sets, per-tenant policy rules evaluated before
  an action runs, and a JSONL/CSV audit export whose resume point is anchored to
  the last record it wrote rather than the wall clock.
- **The learning loop** — `propose` reads the evidence record and checks its
  grade, taking no grade argument, so a caller cannot assert that its own claim
  is verified. Candidate → shadow → holdout evaluation → promotion → rollback,
  with the gate re-checked at promotion and the *worst* holdout deciding.
- **An isolation ladder and a capacity planner** — Firecracker, gVisor and plain
  containers described as one ladder with a probe each, plus the arithmetic that
  says how many units of one a host can hold. On the 1982 MiB host this was
  written against, the 50-concurrent-microVM target computes to two.
- **The agent mesh** — eight named roles, each with the smallest tool allowlist
  its job needs and the separation constraints that matter: `exploit` must not
  share an agent with `critic` or `verifier`, and `verifier` must not share one
  with `fixer`. A binding that collapses an explicit pair is refused; one that
  collapses only by falling back to a default is warned about and carried in the
  plan.
- **A deployment image and stack** — the orchestrator image, a compose file with
  Postgres and Redis, and a healthcheck wired to `redfall doctor --quiet`. The
  README states the Docker socket risk in plain words and documents the
  socket-proxy alternative.

### Changed

- **`redfall doctor`** now has `--quiet` and prints two new rows: the strongest
  isolation tier this host supports and the concurrency it plans for.

### Verified

- `python -m pytest tests/ -q` → **746 passed, 34 skipped, 0 failed**.
- All four contract checkers pass: no-mock, orphans, version (11 declarations,
  5 lockfile roots) and clean-tree.
- The three new subsystems carry their own adversarial tests: reading another
  tenant's campaign by id returns nothing while the row stays put; a lesson
  cannot be proposed from an E1 hypothesis; two holdouts that disagree block a
  promotion; `exploit` and `critic` bound to one agent is refused.

### Not verified on this host

- **No Docker, so the deployment image has never been built and the stack has
  never been brought up.** The deploy tests verify the manifests parse and their
  invariants hold — non-root user, declared volumes, no committed credential,
  healthcheck wired to the capability check — and nothing more.
- **No KVM and no Firecracker**, so no microVM has booted and no startup latency
  been measured. The p50/p95 figures are published targets, and the microVM
  concurrency has been computed and refused, not demonstrated.
- **No holdout set**, so no lesson has been promoted on real data. The gates and
  their refusals are tested; the learning *gain* is not measured.
- **No multi-agent campaign has run**, so no claim is made that routing one role
  to one vendor and another to a second improves anything.
- **No OIDC or SAML provider is wired up.** `idp_subject` is stored and nothing
  authenticates against it: the identity-provider half of SSO is not built.

## [0.4.0] - 2026-10-30

**Deeper, broader, faster.** RedFall reads four languages instead of two, runs
branches concurrently instead of one at a time, and stops redoing work it has
already done. The engine itself is unchanged — every change here is a seam or an
addition, which is what makes the speed numbers credible rather than a rewrite
that happens to be faster on the day it is measured.

The honesty rule holds throughout: a language ships only with the analysis it
can actually do, and a category that cannot be reproduced on this host is listed
with a measured reason rather than a claim.

### Added

- **Java and Kotlin** — a fourth `LanguageSupport` bundle. Routes come from
  Spring and JAX-RS annotations, with the class-level `@RequestMapping` prefix
  joined onto the method path, and Kotlin is read by the same parser because its
  grammar keeps Java's declaration shapes. Sources are the request bindings —
  `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`,
  `@CookieValue`, `@MatrixVariable`, `@ModelAttribute`, `@RequestPart` — not the
  URL alone.
- **Go** — `net/http`, gorilla/chi and Gin/Echo route registration, read from
  the call rather than from a decorator. Sinks are receiver-gated: `Command` on
  `os/exec` is process execution, `Command` on someone's own type is not, and a
  name that cannot be resolved to a recognised receiver is not called a sink at
  all.
- **Language attribution** — `language_name_for()` maps a suffix to a language
  and answers `"unknown"` when none is known, replacing two separate defaults
  that attributed every unrecognised file to JavaScript.
- **Concurrent branches** — branches run on a worker pool bounded by
  `config.sandbox_pool_size`, a setting that existed but was wired to nothing.
  The shared branch tree, the findings callback and the spawn queue all stay on
  the caller's thread; only the sandbox work is parallel.
- **Per-call database sessions** — `run_branch`, `validate` and `ingest` take an
  optional session. The sequential path is byte-identical to before, so the
  existing behaviour is not a special case of the new behaviour.
- **Workspace pool** — a target is copied once per scan into a template and
  checked out per PoC, instead of copied once per PoC.
- **Parse cache** — a SQLite-backed content-addressed cache for parsed files,
  versioned by `CACHE_VERSION` and encoded as JSON rather than pickled. A
  read failure is treated as a miss, never as a crash.
- **Semantic reasoning cache** — a second lookup key derived from the canonical
  form of a prompt, so a rephrased question reuses an answer. A hit records what
  it reused.
- **Transaction state merges** — `update_scan_state` merges under WATCH/MULTI
  and retries, raising rather than silently dropping a merge.

### Changed

- **Ingestion records the language it parsed**, in both the persisted rows and
  the graph, from one shared map.
- **`tree-sitter-go`, `tree-sitter-java` and `tree-sitter-kotlin` are
  dependencies**, so a Go or JVM service parses from a clean install.

### Verified

- `python -m pytest tests/ -q` → **560 passed, 34 skipped, 0 failed**.
- All four contract checkers pass: no-mock (120 files), orphans (118 modules),
  version (11 declarations, 5 lockfile roots) and clean-tree.
- The 44 new language tests run real source through the real pipeline. The Go
  import-binding and receiver-gating tests each pin a behaviour whose obvious
  alternative is wrong: recording `net/http` instead of `http` breaks every sink
  resolution while still parsing cleanly, and an unguarded `Command` invents an
  exec finding with no exploit behind it.

### Not verified on this host

- **No Docker, no gVisor, no JVM and no Go toolchain are installed here.** No
  Spring, Gin or `net/http` application is executed, no PoC is replayed, and no
  category is certified. The language work is verified by running the analysers
  over source; it is *not* verified by reproducing a vulnerability in a running
  service. That gap is stated rather than papered over.
- **The concurrency changes are exercised, not benchmarked.** The pool, the
  per-call sessions and the caches have tests that pin their contracts; the
  speed-up figures in the plan are targets, not measurements, and are not
  claimed here.
- **The Redis-gated state tests skip** without a Redis server, so the
  merge-under-WATCH path is unit-tested and not integration-tested here.

## [0.3.0] - 2026-10-29

**The console.** RedFall grows a control plane: `redfall dashboard` starts a
local HTTP server over the same tool registry the CLI, MCP and A2A surfaces
use. An operation is defined once and every surface calls it, so the console
cannot drift from the command line. Alongside it, the reasoning layer stops
probing agents on every call, and a fix can be attempted without touching the
operator's checkout.

### Added

- **Dashboard API** — a stdlib `ThreadingHTTPServer` exposing health, version,
  agents, reasoning, projects, scans, findings, reports and the one-click fix.
  No framework, no second source of truth: every route delegates to a
  registered tool.
- **Live event stream** — Server-Sent Events over a bounded in-process bus. A
  running scan emits `scan:start`, `branch`, `finding`, `spend` and `scan:done`.
  A scan mints its stream id *before* it starts, so a browser subscribes before
  the first event instead of racing it.
- **Bounded, honest bus** — a slow subscriber loses the oldest events rather
  than growing the server without limit, and is told it fell behind. Losing an
  event is visible, never silent.
- **Project allowlist** — a scan target outside the configured roots is refused
  with `403 out_of_scope`, the same gate the agent gateways use.
- **Token-gated binds** — the server binds loopback by default and refuses a
  non-loopback bind without a bearer token.
- **`redfall_fix_propose`** — attempts a fix inside a throwaway git worktree,
  runs the target's tests and replays the PoC there, then removes the worktree
  and returns the patch. The operator's checkout is never written to. A finding
  that was never reproduced is refused by default, with that reason stated.
- **The console** — a Next.js application talking to the API: an overview, a
  live scan view driven by the event stream, a findings and proof workspace, an
  agent page, and a results page. The previous page read a saved report from
  disk and could only ever show a finished scan; it is replaced.

### Changed

- **Agent detection is cheap after the first call.** Each driver probes its
  `--version` once per process and caches it, and `describe_all()` probes
  concurrently. `redfall agent list` went from about seven seconds to roughly
  five on a cold call and nothing afterwards.
- **Two tools were added to the registry** — `redfall_agents_list` and
  `redfall_reasoning_describe`, both read-scoped — bringing the advertised
  count to 46.
- **The dashboard documents itself** — a new guide covers the routes, the
  stream, the scope gates and what the bus does not claim.

### Fixed

- **`CustomAgentDriver` never called its parent initialiser**, so the version
  cache it inherits did not exist on an instance built from a `redfall.toml`
  spec.
- **An invalid `redfall.toml` is now a hard error.** A parse failure used to be
  swallowed and the loader fell through to environment variables, so a typo
  silently changed which backend the engine used.

### Verified

- `python -m pytest tests/ -q` → **440 passed, 30 skipped, 0 failed**.
- All four contract checkers pass: no-mock, orphans, version and clean-tree.
- The dashboard's socket contract is exercised against a real server: JSON
  routes, a `404` body, a live SSE stream and a rejected token.
- Version contract: 11 declarations and 5 lockfile roots agree on 0.3.0.

## [0.2.0] - 2026-10-29

**Bring your own agent.** RedFall no longer needs an AI API key. The engine
reasons through a `ReasoningBackend`, and one implementation of that is an
installed agent RedFall drives (Claude Code, Codex, Gemini CLI and nine more).
A provider key is now one option among several rather than a requirement.

### Added

- **ReasoningBackend seam** — one interface for every reasoning call, with the
  JSON repair loop and budget accounting shared on the base class so a finding
  looks the same whichever backend produced it. `LiteLLMBackend` is the 0.1.x
  behaviour moved behind the seam with no change; `test_llm.py` still passes
  unchanged, which is the evidence it is behaviour-preserving.
- **Agent drivers (12)** — `claude-code`, `codex`, `gemini-cli`, `aider`,
  `cursor`, `goose`, `openhands`, `continue`, `cline`, `kilo`, `qwen-code`,
  `crush`. Each runs its real non-interactive entry point and passes the prompt
  as a single argv element, never through a shell.
- **Custom driver** — describe an unknown agent (command, args, env passthrough,
  where the reply lives in stdout) in `redfall.toml` and it behaves like a
  shipped driver.
- **Executable agent contract** — `redfall agent certify <name>` runs the agent
  for real and records four checks: installed, answers, returns parseable JSON,
  exits cleanly. Certified only when all four pass.
- **Backend config** — `redfall.toml` read ahead of the 0.1.x env vars. Kinds:
  `auto`, `litellm`, `agent`, `openai_compat`, `custom`, `router`. A config file
  that exists but cannot be parsed is a hard error, not a silent fall-through.
- **OpenAI-compatible backend** — one code path for Ollama, vLLM, LM Studio,
  OpenRouter and any gateway.
- **Multi-agent routing** — route by tier and take a consensus across N agents,
  keeping a finding only where at least `min_agree` agree. Agreement is a prior,
  never proof: the sandbox still executes every result.
- **`redfall agent list|detect|certify|config`** — the operator surface.

### Changed

- **`check_prerequisites` no longer requires a provider key** for `scan` and
  `fix`; an installed agent satisfies the reasoning prerequisite. When neither
  exists, `auto` refuses and names both options rather than falling back.
- **`redfall doctor`** reports the resolved reasoning backend, so a host with an
  agent and no key reads as ready to reason.

### Notes

- A finding is still only counted as real when the sandbox reproduces it, so a
  host without a container runtime still refuses to scan. That is unchanged.


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

### Verification record

- **Phase 3 focused tests:** **53 passed** across auth/HTTP, A2A, webhooks,
  contracts and CLI. The real-subprocess HTTP contract passes 10 checks and the
  A2A contract passes 11, with `certified=True`.
- **CI:** run
  [39616295334](https://github.com/DevAnimecx/redfall/actions/runs/39616295334)
  completed green on the tag commit: the Postgres 17 / Python 3.12 `check` job
  ran **362 passed, 5 skipped in 45.49s**, and the six package jobs (Ubuntu,
  Windows and macOS; Python 3.12 and 3.13) completed successfully. The five
  skips are live gVisor tests; the runner has no `runsc`.
- **Local no-PostgreSQL run:** **337 passed, 30 skipped, 0 failed** in 221.23s.
  The 30 skips are 25 PostgreSQL-backed tests plus the five live gVisor tests.
  Neither category is counted as a pass.
- **Site:** the 0.1.1 production build passed the SEO gate (25 HTML routes, 24
  sitemap URLs), axe (23 docs/trust routes, 0 violations), layout and Lighthouse
  (100/100/100/100 on desktop and mobile; mobile LCP 1.5s) as recorded in
  [`site/content/evidence.md`](site/content/evidence.md). Pages run
  [39616295475](https://github.com/DevAnimecx/redfall/actions/runs/39616295475)
  deployed it, the live monitor passed 24 sitemap pages and IndexNow accepted 24
  URLs with HTTP 200. Two live Lighthouse runs measured desktop 97–98 and mobile
  93–99; one mobile run missed the 95 performance gate, so live performance is
  recorded as a range rather than certified at 100.
- **Published release:** [v0.1.1](https://github.com/DevAnimecx/redfall/releases/tag/v0.1.1)
  was published by release workflow run
  [39617991722](https://github.com/DevAnimecx/redfall/actions/runs/39617991722)
  with the wheel, sdist and `SHA256SUMS`. Downloaded-asset verification passed:
  the wheel hash is `860510a73750c45f88e71c0fca876affe39ef4d9f11cf369673daf24d79e74fa`
  and the sdist hash is
  `14be7d3994139f4802d3a0ab8c8d82876dade51b430f0b135dc94fa4579a06c3`.
  `gh attestation verify`, restricted to `release.yml@refs/tags/v0.1.1` and
  source ref `refs/tags/v0.1.1`, passed for both artifacts, and the downloaded
  wheel installed outside the checkout with `WHEEL VERIFY: PASS`.
- **Known limits:** no local PostgreSQL, Docker/gVisor runtime or LLM key; A2A
  push notifications and multi-turn continuation are not implemented; the
  gateway has no built-in TLS or multi-tenancy; adapter certification covers the
  shipped surfaces only; the live mobile Lighthouse score is not stable above the
  95 performance gate. See [`BLOCKED.md`](BLOCKED.md).

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

[0.5.0]: https://github.com/DevAnimecx/redfall/releases/tag/v0.5.0
[0.4.0]: https://github.com/DevAnimecx/redfall/releases/tag/v0.4.0
[0.3.0]: https://github.com/DevAnimecx/redfall/releases/tag/v0.3.0
[0.2.0]: https://github.com/DevAnimecx/redfall/releases/tag/v0.2.0
[0.1.1]: https://github.com/DevAnimecx/redfall/releases/tag/v0.1.1
[0.1.0]: https://github.com/DevAnimecx/redfall/releases/tag/v0.1.0
