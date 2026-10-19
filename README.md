<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/redfall-logo-dark.svg">
    <img src="assets/redfall-logo-light.svg" alt="RedFall - autonomous vulnerability discovery and verified repair" width="440">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/DevAnimecx/redfall/actions/workflows/ci.yml"><img src="https://github.com/DevAnimecx/redfall/actions/workflows/ci.yml/badge.svg" alt="ci status"></a>
  <a href="https://github.com/DevAnimecx/redfall/releases"><img src="https://img.shields.io/github/v/release/DevAnimecx/redfall" alt="latest release"></a>
  <a href="https://devanimecx.github.io/redfall/"><img src="https://img.shields.io/badge/website-devanimecx.github.io%2Fredfall-ff2b2b" alt="website"></a>
  <img src="https://img.shields.io/badge/platforms-windows%20%7C%20linux%20%7C%20macos-blue" alt="platforms">
  <img src="https://img.shields.io/badge/python-3.12%20%7C%203.13-blue" alt="python versions">
  <img src="https://img.shields.io/badge/tests-309%20collected-blue" alt="309 tests collected; the full suite runs in CI">
  <img src="https://img.shields.io/badge/findings-executed%20proofs%20only-brightgreen" alt="findings are executed proofs only">
  <a href="scripts/check_no_mock.py"><img src="https://img.shields.io/badge/no--mock%20contract-enforced%20in%20CI-brightgreen" alt="no-mock contract enforced in CI"></a>
</p>

**RedFall is an autonomous vulnerability scanner that proves every finding by executing it.** It reads a target's real source with tree-sitter (TypeScript, JavaScript and Python), tracks attacker-controlled data from request surface to sink — including across function boundaries — generates a candidate exploit for every lead, runs it inside a sandbox (Docker + gVisor) against the real application, and reports only what reproduced. It then attempts a repair and calls a fix verified only when the target's own tests still pass *and* the original PoC stops working.

<https://devanimecx.github.io/redfall/> · [Install](#install) · [How a finding becomes real](#how-a-finding-becomes-real) · [FAQ](#faq) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [BLOCKED.md](BLOCKED.md)

The governing constraint is the no-mock contract (§1, extended by §2): a finding
exists only if it was executed against a real running target, and every number in
a report came from a command that actually ran. `scripts/check_no_mock.py`
enforces the parts of that which are mechanically checkable, and it runs in CI.


---

## Status right now

| Component | State |
| --- | --- |
| Ingestion (tree-sitter TS/TSX/JS + Python, symbols, taint incl. cross-function hops, deps) | **Built and verified against real targets** |
| Route frameworks (Express, Fastify, koa-router, NestJS decorators, Flask/FastAPI) | **Built and verified** — each recognised by its real registration shape |
| Adaptive branching (recursive tree, 7 spawn triggers) | **Built and verified** — all 7 triggers fire on real source |
| Cross-branch chaining (attack graph, compound CVSS, narrative) | **Built and verified** — 6/6 chains reproduce on `chainbank`; the LLM-proposed chain stage is wired end to end and structurally reviewed |
| Range-runner gate (matcher, 5 metrics + 3 chain metrics) | **Built and verified** |
| Campaign kernel + resumable runner (durable state, leases, budgets, retries) | **Built and tested** — state machine, dependency tasks, heartbeat leases, preflight reservations and settlement, retry/blocked semantics, and real graph/scan/reproduce/report handlers; 35 focused SQLite/CLI/MCP tests passed locally; the Phase 2 Postgres-backed suite passed in CI (304 passed, 5 environment skips; run 39286891463) |
| Evidence ledger (E0–E4, SHA-256 hash chain, report gate) | **Built and tested** — tamper detection, replayability validation and a required E3/E4 gate |
| Code graph v1 (persisted, provenance-aware) | **Built and tested** — real ingestion into `graph_snapshots`, `graph_nodes` and `graph_edges`; bounded search, traversal, paths, inventory and snapshot diff. Covers the currently ingested TypeScript/JavaScript/Python source; not a completeness or all-language claim |
| Agent tools / MCP stdio (44 tools) | **Built and tested** — real subprocess JSON-RPC session; campaign/runner, graph, scan, finding, reproduction, evidence and report tools |
| HTTP/OpenAPI gateway | **Built and tested** — `POST /v1/tools/{name}` executes the same 44-tool registry; OpenAPI 3.1 is generated from that registry; bearer tokens, scopes, quotas, audit and signed artifact URLs |
| A2A v1.0 agent | **Built and tested** — Agent Card, `SendMessage`/`SendStreamingMessage`/`GetTask`/`ListTasks`/`CancelTask`/`SubscribeToTask`, SSE task/status/artifact envelopes, cooperative cancellation and HMAC-signed artifacts; push notifications are explicitly not implemented |
| Executable adapter contracts | **Built and tested** — `redfall mcp certify` (stdio), `redfall interop certify --protocol http` (10 checks) and `--protocol a2a` (11 checks) launch a fresh server/client against a real socket and a temporary database; certification covers the shipped surfaces only. CI run [39310704310](https://github.com/DevAnimecx/redfall/actions/runs/39310704310): **357 passed, 5 skipped** (live gVisor), all package jobs passed |
| No-mock enforcement | **Passing** (`NO-MOCK CONTRACT: PASS`, 80 files) |
| Data layer (Postgres 17 + Redis) | **Built and verified** |
| Packaging (any platform Python 3.12 runs on) | **Built and verified** — the wheel ships the harness, prompts and Dockerfile; installed into a fresh venv and driven from outside the checkout (`WHEEL VERIFY: PASS`); CI matrix on Ubuntu/Windows/macOS |
| Installers (`scripts/install.sh`, `scripts/install.ps1`) | **Built and verified** — the PowerShell installer was executed end to end on this host into a throwaway home; the POSIX script is syntax-checked against a real shell here and both are executed by the CI package matrix on Ubuntu/Windows/macOS |
| Release supply chain (Sigstore attestations, SHA256SUMS, weekly dependency audit) | **Built** — releases are constructed and attested by CI from the tagged source; `pip-audit` runs weekly |
| SARIF 2.1.0 export (`redfall report --format sarif`) | **Built and verified** — every result carries `properties.redfall.verified`; unproven candidates stay visible |
| Landing page + documentation (`site/`, React + Tailwind landing, static Markdown docs) | **Live and measured** — <https://devanimecx.github.io/redfall/> and 22 docs/trust pages, deployed by the Pages workflow on 2026-10-19. Live Lighthouse: landing 100/100/100/100 desktop, 98 performance with 100 elsewhere mobile; docs 100/100/100/100 desktop, 99 performance with 100 elsewhere mobile. IndexNow accepted 23 URLs with HTTP 202; live monitor passed 23 pages |
| Sandbox (Docker + gVisor) | **Built, refuses on this host** — no container runtime |
| LLM (LiteLLM BYOK) | **Built, refuses without a key** — live calls only |
| Scale-out (Firecracker microVMs, Rust orchestrator, NATS) | **Not started** — see [`BLOCKED.md`](BLOCKED.md) |
| Token-economics benchmark | **Not started** — needs a provider key |

Two things stop a full scan on this host: no container runtime and no LLM
credential. Both are recorded in [`BLOCKED.md`](BLOCKED.md) with what was tried
and the smallest real unblock. Neither has a fallback path.

---

## The three claims, and what currently backs each

Redfall's argument is that it finds more, explains more, and costs less. Only the
first two can be demonstrated without a provider key.

**1. The attack surface grows during the scan.** A source-only scan enumerates
what the source says. Seven kinds of surface exist only at runtime, and
`src/redfall/branching/adaptive.py` detects each from real target source:

| Trigger | Example in `range/vulnbank-adaptive` |
| --- | --- |
| `dynamic_import` | `require(process.env.PLUGIN_PATH)` |
| `dynamic_route_registration` | `app.use(dynamicRouter)` |
| `plugin_system` | `fs.readdirSync(dir)` → `require(full)` |
| `db_stored_code` | SQL text read from `query_config`, then executed |
| `webhook_discovery` | `/api/hooks/register`, `/api/hooks/deliver` |
| `feature_flag` | `if (process.env.FEATURE_BETA_EXPORT === 'on')` |
| `env_conditional` | `if (process.env.NODE_ENV === 'production')` |

All seven are detected and each spawns a real branch. The tree enforces the
ordering that makes an adaptive branch honest: `created_at` is strictly after the
parent started *and* after the triggering finding was discovered, and every
adaptive branch records `triggering_finding_id` and `trigger_reason`. A branch
planned up front and labelled adaptive is detectable from the timestamps alone.

**2. Flaws combine.** Branches are analysed independently, so a chain is only
visible once their findings are merged into one attack-state graph
(`src/redfall/chain/`). `range/chainbank` is a target built for this: six chains,
each two steps, each reproducing end to end over HTTP.

```
CHN-01  none → secret:owner_email → user_creds:bob          IDOR → account takeover
CHN-02  none → db_read:users → admin_creds:admin            SQLi → admin session
CHN-03  user_creds:admin → file_write:plugin_dir → code_exec:app
CHN-04  user_creds:alice → ssrf_reach:internal → secret:cloud_credentials
CHN-05  none → secret:jwt_key → db_write:accounts           key leak → forged admin
CHN-06  none → none → session_token:carol                   open redirect → token theft
```

An edge enters the graph only when the step it describes actually happened — the
model proposes a chain over already-reproduced findings, structural review
accepts or refuses it, the whole chain is replayed as one composite PoC in the
same sandbox as everything else, and only hops whose predicates held become
edges. Every edge must join at least two independently reproduced findings.
Compound severity is floored at the worst single hop and capped at 10.0: chaining
can add risk but cannot remove it.

A chain that review refuses is kept in the report as refused, with the reasons —
"the model claimed this path and it did not run" is a fact the report has to be
able to state. The range scorer translates the scanner's own finding ids into the
manifest's vocabulary through the matcher's output, so a scanner cannot score a
join it never stated, and a join through a finding outside ground truth does not
count as a join between the steps on either side.

The chain scorer measures three separate things, because they fail separately:
`chain_recall` (every step reported), `chain_link_rate` (the steps connected),
and `chain_narrative_rate` (the chain explained in the required terms). A report
can find all twelve findings and link none of them; that is the failure
`chainbank` exists to catch, and the scorer shows it.

**3. It costs less.** Not yet demonstrated. The comparison requires a genuine
tool-calling baseline on the same branch, model, sandbox and target, and there is
no provider key here. No estimate is offered in its place.

---

## Layout

```
redfall/
├── src/redfall/
│   ├── config.py               prerequisites, asserted not assumed
│   ├── llm.py                  LiteLLM BYOK, tiers, budget, verbatim transcripts
│   ├── orchestrator.py         ingest → plan → branch → analyse → execute → chain
│   ├── cli.py                  redfall scan | fix | findings | report | campaign | graph | mcp | interop | doctor | environment
│   ├── sarif.py                SARIF 2.1.0 export (verified flag on every result)
│   ├── campaign/               explicit state machine, dependency tasks, leases, budget enforcement
│   ├── evidence/               E0–E4 ledger, SHA-256 hash chain, reportability gate
│   ├── interop/                tool registry, MCP stdio, HTTP/OpenAPI + A2A gateway, tokens, audit, webhooks, artifacts, contracts
│   ├── ingestion/              tree-sitter parsing (TS/JS + Python), symbols, taint (intra + cross-function in both languages), deps, git, languages.py registry
│   ├── branching/              tree.py (recursive, adaptive) + adaptive.py (7 detectors)
│   ├── chain/                  plan.py, executor.py, stage.py, graph.py, cvss_compound.py, narrative.py
│   ├── agent/                  categories.py + prompts/ (5 stages)
│   ├── sandbox/                Docker+gVisor executor and its image
│   ├── validation/             harness.mjs — the exploit runner inside the box (Node and Python targets)
│   ├── fix/                    applier + verified-fix loop
│   └── store/                  SQLAlchemy models, Postgres, Redis state
├── range/
│   ├── vulnbank/               32 seeded vulns, 76 tests, 30/32 PoCs, 32/32 patches
│   ├── vulnbank-adaptive/      vulnbank + 7 adaptive surfaces, 91 tests, 7/7 PoCs
│   ├── chainbank/              6 two-step chains, 8 tests, 6/6 chains reproduce
│   ├── pythonbank/             17 seeded vulns, 18 tests, 17/17 PoCs over real HTTP
│   └── range_runner/           deterministic scorer, 5 metrics + 3 chain metrics
├── site/                       React + Tailwind landing page (prerendered static) and 22 generated docs/trust pages
├── web/                        Next.js 15 dashboard (scan + gate + chains)
├── assets/                     logo lockups and mark (SVG, dark/light)
├── scripts/                    the four contract checkers, verify_wheel.py, install.sh / install.ps1, build_release.py, generate_brand_assets.py
├── .github/workflows/          ci (checks + 3-OS packaging and installers), release (attested artifacts), security (weekly pip-audit), pages (landing deploy)
├── tests/                      362 collected tests; CI: 357 passed, 5 skipped (live gVisor), Postgres 17; 53 Phase 3 focused tests pass locally
├── llms.txt                    machine-readable project summary for answer engines (byte-identical to site/dist/llms.txt)
├── site/SEO.md                 technical SEO/GEO operating manual and 90-day calendar
├── CONTRIBUTING.md             the no-mock rule, where each stage lives, PR contract
├── SECURITY.md                 vulnerability reporting, supply-chain checks, range-target warning
├── CHANGELOG.md                0.1.0 - what shipped, with the measured numbers
└── BLOCKED.md                  what cannot run here, and why
```

---

## Agent access: MCP, HTTP/OpenAPI and A2A

Phase 2 built the execution layer. Phase 3 exposes it over protocols without
duplicating a handler per transport: MCP, HTTP and A2A all call the same
transport-neutral `ToolRegistry`.

- **Durable campaigns and a resumable runner** — explicit states (`draft`
  through `reported`), dependency-aware tasks, heartbeat leases, preflight
  budget reservations, measured settlement, retries, and blocked campaigns when
  a real prerequisite is missing.
- **A tamper-evident evidence ledger** — E0–E4 records chained with SHA-256.
  Only E3/E4 are reportable, and they must carry an execution id, observable,
  reproduction command and environment digest.
- **A persisted code graph** — `redfall_graph_index` parses the target through
  the same ingestion pipeline as a scan, then stores deterministic snapshots,
  provenance-bearing nodes/edges and bounded queries.
- **Execution tools** — graph index/query/diff/inventory, scan, finding lookup,
  stored-finding reproduction, chain verification and evidence-gated JSON/SARIF
  reports. A report is refused unless the chain verifies and at least one
  E3/E4 record is linked to a finding.
- **MCP stdio** — 44 tools over newline-delimited JSON-RPC.
- **HTTP/OpenAPI** — one process serves `GET /healthz`, `GET /v1/openapi.json`,
  `GET /v1/tools` and `POST /v1/tools/{name}`. Tool output carries
  `"trust": "untrusted-repository-data"` and an
  `X-Redfall-Trust: untrusted-repository-data` header. `GET /v1/audit` requires
  the `admin` scope. Artifacts are served through HMAC-SHA256 signed URLs with a
  15-minute default TTL.
- **A2A v1.0** — `GET /.well-known/agent-card.json` advertises one JSON-RPC
  interface at `POST /a2a/v1`: `SendMessage`, `SendStreamingMessage`,
  `GetTask`, `ListTasks`, `CancelTask` and `SubscribeToTask`. Streaming uses
  server-sent events with task, status-update and artifact-update envelopes.
  `SendMessage` blocks by default (capped at 120 seconds); set
  `returnImmediately: true` to return a submitted task. Artifacts carry the same
  trust label and a signed URL.
- **Security and audit** — bearer tokens are stored only as SHA-256 digests,
  carry explicit `read`/`execute`/`write`/`admin` scopes and an optional hourly
  quota, and are revoked immediately. Every tool execution, including an
  unknown-tool, scope or quota denial, is written to the audit trail. Token
  management is CLI-only; the gateway never mints tokens.
- **Executable contracts** — `redfall interop certify --protocol http|a2a`
  starts a fresh gateway subprocess against a temporary database and repository,
  then exercises discovery, authentication, scope/quota denial, real tool
  execution, audit, the A2A task lifecycle, artifacts, cancellation, error
  mapping and streaming. The result is persisted as an `AdapterCertification`.

```bash
redfall campaign create ./my-service --objective discovery --budget-usd 10
redfall campaign run cmp-... --max-tasks 5
redfall graph latest --campaign-id cmp-...
redfall mcp serve                # MCP client connects over stdin/stdout
redfall mcp certify              # real stdio contract, stored as measured evidence

redfall interop token create --name ci --scopes read,execute --quota-per-hour 60
redfall interop serve --database-url "$DATABASE_URL" --public-url https://redfall.example
redfall interop certify --protocol http
redfall interop certify --protocol a2a
redfall interop webhook add --url https://ci.example/redfall --events 'campaign.*,task.*'
redfall interop webhook deliver
redfall interop audit --limit 50
```

The MCP process uses `DATABASE_URL` (or `--database-url`). MCP filesystem
operations and the graph/reproduction commands are allowed only inside a
campaign root. When `REDFALL_ALLOWED_ROOTS` is set it is a hard outer boundary:
a campaign root that is not inside it is ignored, so an agent cannot widen its
access by creating a campaign. Callers can ask `redfall_policy_check` before
acting.

The interoperability gateway uses `DATABASE_URL` (or `--database-url`) and binds
`127.0.0.1:8787` by default. `--public-url` is what the Agent Card and artifact
links advertise; set it to the externally reachable HTTPS origin when a reverse
proxy terminates TLS. The gateway itself does not terminate TLS and should not
be exposed directly. It does not invent state: if the database is unavailable,
startup fails with the real error.

Webhooks are operator-configured and signed with
`X-Redfall-Signature: sha256=<hex>` over the exact request body. Deliveries are
deduplicated per subscription and event, attempted at most three times across
`webhook deliver` invocations, and never follow redirects. A new subscription
receives only events created after it; historical events are not replayed.
Loopback targets require the explicit `--allow-loopback` operator flag, and
link-local targets are always refused. Private-network targets are allowed on
purpose for on-prem receivers, and a hostname is not re-resolved against a
private-IP denylist; treat webhook creation as an operator-only capability.

Limitations are part of the contract. A2A push notifications are not
implemented (`capabilities.pushNotifications: false`; the config methods return
JSON-RPC `-32003`), A2A multi-turn continuation messages are rejected, a
`WORKING` task is cancelled cooperatively (a tool call that already ran may have
produced side effects), and a gateway restart does not automatically resume
tasks that were in flight. The hourly quota is a pre-call check, not a
distributed rate limiter, so concurrent submissions can briefly exceed it.
There is no built-in multi-tenancy: use one database per deployment and a
reverse proxy for TLS, rate limits and network policy.

This is still not the completed 1.0 campaign platform. Environment synthesis,
multi-role campaigns, sanitizer-node synthesis, additional languages,
self-learning and the four-hour campaign remain future work. A scan also still
needs Docker + gVisor and an LLM key; when either is absent the task is reported
as blocked instead of simulated.

---

## Install

Linux, macOS or Windows, Python 3.12+ (3.13 supported). The package is a
pure-Python wheel (`py3-none-any`): no compiled extensions, no post-install
hooks, nothing running that you cannot read.

**Windows** (PowerShell):

```powershell
git clone https://github.com/DevAnimecx/redfall.git; cd redfall
.\scripts\install.ps1
```

**Linux / macOS**:

```bash
git clone https://github.com/DevAnimecx/redfall.git && cd redfall
./scripts/install.sh
```

Both installers use `pipx` when it is present (isolated, recommended) and a
private virtualenv otherwise — never system-wide, never elevated — and finish
with `redfall doctor`, the host's real capability report. With any package
manager you already use:

```bash
pipx install git+https://github.com/DevAnimecx/redfall   # isolated
uv pip install git+https://github.com/DevAnimecx/redfall # or in a uv venv
pip install redfall-0.1.0-py3-none-any.whl               # a verified release wheel
redfall doctor                                           # exactly what this host can and cannot run
```

Release artifacts are built by CI from the tagged source, published with
`SHA256SUMS` and attested with Sigstore, so a download is verifiable instead of
trusted:

```bash
gh attestation verify redfall-0.1.0-py3-none-any.whl --repo DevAnimecx/redfall
```

The wheel carries everything the runtime reads — the sandbox harness
(`redfall.validation`), the agent prompts, the sandbox Dockerfile — and
`scripts/verify_wheel.py` proves it: install into a fresh virtualenv, run it
from a directory outside the checkout, and it must still parse, taint and find
the interprocedural flow. `pip install -e ".[dev]"` plus `pip install -e range`
is `make install`, the development setup.

Prefer one page first? <https://devanimecx.github.io/redfall/> is the same
project, same claims, same evidence, without scrolling a README.

## Quick start

```bash
make install          # redfall + range-runner, editable, with dev deps
make check            # every contract checker plus the test suite
make check-no-mock    # NO-MOCK CONTRACT: PASS
make test             # full suite; DB tests use Postgres when configured, live gVisor tests skip honestly without runsc
make doctor           # what this host can and cannot do
```

The database-backed tests need a reachable Postgres. Point them at a throwaway
database with `REDFALL_TEST_DATABASE_URL`; without it they fall back to the
local defaults declared in the tests (`redfall`/`redfall_test` on
`127.0.0.1:5432`):

```bash
export REDFALL_TEST_DATABASE_URL=postgresql+psycopg://vulnbank:Sup3rS3cretBankPwd!@127.0.0.1:5432/redfall_test
```

The range targets. Each needs a local Postgres; `run_local.sh` is used when
Docker is unavailable, and treats the port owner — not a pidfile — as the source
of truth for whether the app is running.

```bash
# vulnbank-adaptive: the 7 adaptive surfaces
cd range/vulnbank-adaptive
./scripts/run_local.sh start                 # :4001
npm test                                     # 91/91
npx ts-node scripts/replay_poc.ts --all      # 7/7 reproduced
./scripts/run_local.sh stop

# chainbank: the 6 chains
cd range/chainbank
./scripts/run_local.sh start                 # :4002
npm test                                     # 8/8
npx ts-node scripts/replay_chain_poc.ts      # 6/6 chains reproduced end to end
./scripts/run_local.sh stop

# pythonbank: the Python ground truth (no database, no container)
cd range/pythonbank
python -m pytest tests/ -q                   # 17/17
python scripts/replay_poc.py --all           # 17/17 reproduced over real HTTP
```

The manifests are generated, never hand-edited — the PoC request strings and the
anchor lines have to stay consistent with the real source. Regenerate with
`python3 scripts/write_manifest.py` in the target directory; pythonbank's script
also takes `--check`, which is what its test suite asserts.

A scan, on a host with gVisor and a provider key:

```bash
export OPENAI_API_KEY=sk-...
redfall scan range/chainbank --out scan.json
redfall fix <finding-id> --target range/chainbank --out fixes.json   # repeat per finding; the file merges
python -m range_runner.run --target range/chainbank --scan scan.json --fixes fixes.json --out range/report.json
# → REDFALL GATE: PASS | FAIL, with every metric printed

cd web && npm run build && npm run start   # dashboard on :3000, reads ../scan.json + ../range/report.json
```

`redfall fix --out` appends one record per finding (`finding_id`, `verified`,
`status`, the test and PoC outcomes). Re-running it for the same finding replaces
that record, so the fixes file is the one `range_runner --fixes` scores.

For code-scanning consumers, the stored report exports as SARIF 2.1.0:

```bash
redfall report <scan-id> --format sarif --out redfall.sarif
```

Every finding is a `result`; verified ones carry
`properties.redfall.verified = true` and their evidence, unproven candidates
carry `false` — the export never drops or upgrades a finding. Severity maps to
SARIF levels mechanically and the CVSS floor is exported as
`security-severity`, with the dedupe key as the partial fingerprint.

---

## Site, documentation and SEO

The public surface is deliberately small and static:

- **Landing page** (`/redfall/`): React + Tailwind, prerendered to HTML, with
  inlined CSS, a self-hosted Inter subset (SIL OFL 1.1, licence beside the
  font), JSON-LD and a hash-based meta CSP.
- **22 documentation and trust pages** under `/docs/`, `/compare/`, `/evidence/`,
  `/about/` and `/privacy/`: generated from Markdown with **zero client
  JavaScript**, shared cached CSS, breadcrumbs, related links and visible dates.
- **Discovery files**: `sitemap.xml` (23 URLs), `robots.txt`, `llms.txt` at the
  repo root and site root, a public IndexNow key, per-page 1200×630 OG cards and
  a real custom 404 that returns HTTP 404.

The operating manual is [`site/SEO.md`](site/SEO.md): technical SEO, schema,
content clusters, internal linking, GEO/AEO, honest backlink strategy, monitoring
and a 90-day calendar. It separates implemented work from tasks that require a
human Google/Bing account. No ranking, backlink or AI citation is guaranteed or
fabricated.

Verify the whole surface from a clean lockfile:

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
```

Recorded 2026-10-19 on the local production build: SEO gate PASS (24 HTML
routes, 23 sitemap URLs, 0 errors), axe 0 violations on all docs routes at 390
and 1280 px, Lighthouse 100/100/100/100 desktop, and 98–100 mobile performance
with 100 accessibility/best-practices/SEO (every category above the 95 gate).

The same build is live. Pages run
[39253506525](https://github.com/DevAnimecx/redfall/actions/runs/39253506525)
passed build and deploy, the live monitor passed all 23 pages, IndexNow accepted
23 URLs with HTTP 202, and a missing path returned HTTP 404. Live Lighthouse:
landing 100/100/100/100 desktop, 98 performance with 100 elsewhere mobile; docs
100/100/100/100 desktop, 99 performance with 100 elsewhere mobile. Full evidence
is in [`BLOCKED.md`](BLOCKED.md) and
[`CHANGELOG.md`](CHANGELOG.md); the weekly
[`seo-monitor`](.github/workflows/seo-monitor.yml) workflow re-checks the live
site.

---

## How a finding becomes real

1. **Ingest.** Every `.ts`/`.js`/`.py` file is parsed with tree-sitter. Routes,
   handlers, middleware, DB/exec/fs/fetch calls and imports are extracted.
   Registration styles are recognised by their real shapes: Express and
   Fastify/koa-router verb calls, NestJS `@Controller`/`@Get` decorators (lifted
   to full paths), and Python Flask/FastAPI blueprints. Express mounts and Flask
   blueprint prefixes are resolved through the imports so `router.post('/login')`
   becomes `POST /api/auth/login`.
2. **Taint.** Intraprocedural source→sink flow per enclosing function. Sources
   are `req.body|query|params|headers|cookies` (Python:
   `request.args|form|json|get_json|headers|cookies`); sinks are query, exec, fs,
   redirect and eval. A sanitiser is **recorded but never clears taint** — Redfall
   does not claim to know that `escapeHtml` neutralises an SQL sink. Both
   languages then get a depth-one **interprocedural pass** (`ingestion/inter.py`
   for Python, `ingestion/inter_ts.py` for TS/JS): each callee's parameters are
   pre-tainted to build a per-function summary, and a call site becomes a hop
   only when the argument is already tainted by a real source and the matching
   parameter reaches a sink — resolved through import bindings (relative ESM
   specs, aliases, namespaces, CommonJS `require`, Python relative imports),
   never guessed, with the caller named in the taint's `via` chain. The other
   direction — **return flow** — is proved the same way: a callee whose return
   path reads a source (or a local derived from one) makes every call result
   tainted at the caller's sink, and pass-throughs of parameters are never
   claimed by the summary because the caller's own real taint already covers
   them. Every resolvable call also becomes an edge in the **call graph**
   (`call_edges`), which route attribution follows: a taint in a helper counts
   as reachable from the route whose handler can call it, transitively and
   across files.
3. **Detect new surface.** The seven adaptive detectors run over the same source.
   Anything they find spawns a branch mid-scan rather than being deferred.
4. **Plan.** The model splits the route inventory into branches; references to
   files or routes that do not exist in the graph are dropped.
5. **Analyse.** Each branch gets its real source, its proven taint paths and the
   installed dependency versions, and returns candidate findings.
6. **Execute.** A PoC is generated and run by `harness.mjs` inside a gVisor
   container that boots a real PostgreSQL and the real target app — Node targets
   through `npm start`, Python targets through a virtualenv and their
   `redfall.target.json` boot contract. The predicate must assert the observable
   effect, not merely a 200.
7. **Chain.** Reproduced findings go to the chain stage: the model proposes
   wirings over them and the responses they actually produced, `plan.py` reviews
   each proposal structurally, the chain is replayed as one composite PoC in the
   same sandbox, and only hops whose predicates held become graph edges. The
   graph is rebuilt from the persisted rows, never from the stage's memory.
8. **Keep or discard.** Only a reproduced candidate becomes a `Finding`. The raw
   request, response and verdict are persisted.

A fix is `verified` only when the target's suite passes **and** the original PoC
no longer succeeds. Three attempts, each fed the real failure text; after that
the finding goes to a human with the full transcript.

---

## Coverage

25 of the 32 seeded `vulnbank` categories. The four exclusions and their measured
reasons live in `src/redfall/agent/categories.py` — each is excluded because a
real reproduction could not be obtained, not because it seemed hard.

| Excluded | Why |
| --- | --- |
| `timing_attack` | ~0.014 ms signal against ~1.1 ms HTTP noise on 2 vCPU; no PoC reproduces |
| `race_condition` | the target serialises the transfer on one event loop; the window never opens |
| `jwt_alg_none` | `jsonwebtoken` 9.0.3 rejects `alg=none` unless the verifier pins it |
| `jwt_no_expiry` | no bounded PoC exists; fabricating one would bend the ground truth |

---

## Gate thresholds

Vulnerability targets:

```
recall      >= 0.60
precision   >= 0.85
repro_rate  == 1.00
fix_rate    >= 0.50
duration_ms <= 900000
```

Targets whose manifest declares `chains` are also scored on:

```
chain_recall         >= 0.8333   (5 of 6)
chain_link_rate      == 1.00
chain_narrative_rate == 1.00
```

Matching is exact — `category` (or a declared alias), same `file`, and
`|line − manifest line| <= 5` **or** the same `symbol`. There is no fuzzy
fallback; a near-miss is recorded as a miss.

---

## FAQ

### What is RedFall?

RedFall is an autonomous vulnerability scanner that proves findings by
execution. It ingests a target's real source with tree-sitter (TypeScript,
JavaScript, Python), tracks attacker-controlled data from request surface to
sink — across function boundaries, with return flow — generates a candidate
exploit for each lead, runs it inside a gVisor sandbox against the running
application, and reports only what reproduced. It then attempts a repair and
verifies it against the target's own test suite.

### How does RedFall verify a finding instead of guessing?

Static analysis never produces findings, only candidates. A candidate becomes a
finding only when its exploit ran inside the sandbox against the real
application and its observable predicate matched. Every SARIF result carries
`properties.redfall.verified` — true or false — and nothing is ever upgraded or
dropped behind your back.

### Which languages and frameworks are covered?

TypeScript/TSX, JavaScript/JSX and Python. Route extraction covers Express,
Fastify, koa-router and NestJS decorators, plus Flask and FastAPI with
blueprint/router prefix resolution. Taint analysis has a depth-one
interprocedural pass in both language pairs, including unseeded return-flow
summaries, and an inter-file call graph.

### What does a full scan require?

Docker with a gVisor runtime and one LLM provider key (bring-your-own-key via
LiteLLM). There is no dry-run mode: `redfall doctor` prints exactly what the
current host can and cannot run, and refuses to guess. Anything unrunnable is
listed in [`BLOCKED.md`](BLOCKED.md) with its smallest real unblock.

### How are fixes verified?

The fix loop patches on a branch, runs the target's own tests, and re-runs the
original PoC; a fix is *verified* only when the suite still passes **and** the
PoC stops reproducing. Failure text is fed back into up to three attempts, then
the transcripts go to a human. Nothing is committed or pushed for you.

### Why some skipped tests?

The five skips in CI run 39310704310 are the live sandbox-execution tests:
GitHub's runner has Docker but no `runsc` gVisor runtime, so they skip rather
than pretend. The same five skip on this host for the same reason. The no-mock
contract forbids simulating them, so a skip is never counted as a pass; the
sandbox's refusal path is covered by tests that do run.

### Where is the source and are releases verifiable?

The full source, tests and ground-truth range targets are public in this
repository. Releases are built by CI from the tagged commit, published with
`SHA256SUMS` and attested with Sigstore, so `gh attestation verify` proves the
wheel came from this repository's release workflow.

---

## Contributing

Small scoped commits, evidence over adjectives. Start with
[`CONTRIBUTING.md`](CONTRIBUTING.md): the no-mock rule, where each stage lives,
and what a reviewable change looks like. The short version — run `make check`,
bring a proof for every claim, and if something cannot run on your host, put it
in [`BLOCKED.md`](BLOCKED.md) instead of faking it. Bug reports use the issue
template and include the output of `redfall doctor`.

## Security

- The `range/` directories are **deliberately vulnerable applications** built as
  ground truth. Never deploy them; never point Redfall at systems you do not own
  or have written permission to test. Details in [`SECURITY.md`](SECURITY.md).
- Report vulnerabilities in Redfall itself through GitHub private vulnerability
  reporting — not in a public issue.
- Supply chain: the package is pure Python with no install-time hooks; releases
  are built by CI from the tagged source, attested with Sigstore and published
  with `SHA256SUMS`; dependencies are audited weekly by `pip-audit`. See
  [`SECURITY.md`](SECURITY.md) for the verification commands.

## Changelog

[`CHANGELOG.md`](CHANGELOG.md) — 0.1.0 is the first release. Every number in it
was measured on a real host; [`BLOCKED.md`](BLOCKED.md) lists what could not run
there and the smallest real unblock for each.
