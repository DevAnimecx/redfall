# RedFall 1.0 — Autonomous, Evidence-Gated Codebase Security

> **Status: plan, not a release note.** This document describes a destination and
> the path to it. Nothing below should be read as shipped until it has a real
> test, a reproducible run, or a published benchmark result.
>
> **Implementation status (2026-10-30):** the 0.4.0 line is implemented —
> everything below the 0.1.1 baseline (durable campaigns/tasks/leases/budgets,
> the E0–E4 hash-chained evidence ledger, graph v1, the resumable runner, MCP
> stdio, the HTTP/OpenAPI + A2A v1.0 gateway), plus the 0.2.0 agent seam, the
> 0.3.0 console, and the 0.4.0 speed, depth and language work: concurrent
> branches on a bounded pool, per-call sessions, a workspace pool, a parse cache
> and a semantic reasoning cache, and Java/Kotlin and Go ingestion.
>
> Local Windows verification of 0.4.0: compile clean, no-mock **120 files
> PASS**, orphan **118 modules PASS**, version **11 declarations / 5 lockfile
> roots PASS**, clean-tree PASS, and the full suite reported **560 passed, 34
> skipped, 0 failed**.
>
> **The 0.4.0 language and speed work is not certified.** Java/Kotlin and Go are
> analysed over real source but never executed — this host has no JVM and no Go
> toolchain — so no category is certified for them. The concurrency and caching
> changes have contract tests, not benchmarks: the speed figures in §5 are
> targets, and no measured number is claimed here.
>
> Still unimplemented: A2A push notifications and multi-turn continuation,
> environment recipes/synthesis, multi-role campaigns, sanitizer-node synthesis,
> C#/.NET and PHP/Ruby, interprocedural analysis for the JVM and Go engines,
> self-learning, external-agent certification beyond the shipped surfaces, and
> the four-hour campaign. See [`CHANGELOG.md`](CHANGELOG.md).
>
> Baseline: RedFall `0.4.0`, 2026-10-30.
>
> The plan deliberately avoids promising “all vulnerabilities”, “any language”,
> “self-evolving” or “best” as facts. It defines how those claims would be
> earned, measured and, where necessary, bounded.

---

## 0. Executive summary

RedFall today is a **verified two-language scanner**: TypeScript/JavaScript and
Python, a static graph, LLM-assisted analysis, real PoC execution inside
Docker + gVisor, adaptive branches, exploit chains, and fixes that are only
called verified when the PoC stops working and the target's tests still pass.
That is a strong foundation, but it is still a **pipeline** with a fixed set of
stages and a narrow environment model.

The next product is a **campaign platform**: an agentic system that can be given
an authorised repository, a budget and a goal, and then run a long, resumable,
multi-role campaign that builds a deep code graph, forms and tests hypotheses,
synthesises the runtime environment, proves impact in a sandbox, proposes a
root-cause fix, proves the fix, and leaves an auditable evidence bundle.

The strategic bet is not “a better model”. Models are rented and replaceable.
The moat is the hard, compounding infrastructure around them:

1. **Verification fabric** — arbitrary applications can be built, run, attacked
   and reset safely, with reproducible evidence.
2. **Environment synthesis** — the unglamorous ability to make real repositories
   run without a human hand-holding every stack.
3. **Code intelligence** — a language-agnostic graph plus certified framework
   packs, not a pile of regexes.
4. **Evidence-gated learning** — skills, framework models and routing policies
   improve only from verified outcomes, under evaluation gates.
5. **Agent interoperability** — RedFall is the security execution layer that
   Claude, Codex, Hermes, IDE agents and enterprise orchestrators can call.

### The one-sentence product

> **Bring your own agent. RedFall supplies the code graph, campaign runtime,
> sandbox, proof, repair and learning layer.**

### The 12-month destination

- **6 certified language packs** (TypeScript/JavaScript, Python, JVM
  Java/Kotlin, Go, C#/.NET, PHP; Ruby is the next candidate) and a documented
  adapter SDK for more. “Any language” becomes a direction with evidence, not a
  slogan.
- **50–60 verified vulnerability classes**, each with a written proof contract,
  not just a CWE label.
- **Long-horizon campaigns** that can run unattended for hours, resume after a
  failure, and stop on budget or saturation rather than on a fixed prompt count.
- **30+ certified agent and agent-framework adapters** through MCP, A2A,
  HTTP/OpenAPI and CLI contracts; the long tail is covered by protocol
  compatibility, not bespoke glue for every brand.
- **A learning loop** that turns verified campaigns into tested skills,
  framework models and routing policies, with shadow/canary promotion and
  rollback. No learning from unverified model output.
- **Enterprise controls**: tenancy, SSO, RBAC/ABAC, policy-as-code, audit,
  self-hosted/air-gapped deployment, SIEM/ticketing integration and a
  reproducible benchmark arena.
- **A public claim only after a pre-registered, independently reproducible
  head-to-head benchmark** — not a demo, not a cherry-picked repository and not
  a marketing superlative.

### The north-star metric

```
NorthStar =
  (verified true findings × verified fix acceptance)
  ────────────────────────────────────────────────────
  (model cost + compute cost + engineer minutes)
```

with non-negotiable guardrails:

- reported precision ≥ 0.90 at the claimed severity;
- PoC reproducibility ≥ 0.95 from the evidence bundle;
- zero unsandboxed execution of target code;
- zero findings without an evidence pointer;
- human approval for destructive tests and for merging fixes.

These are **provisional targets** until the baseline arena is running. They are
not current measured results.

---

## 1. What the words will mean

The user-facing story should be ambitious. The internal contract must be
precise. These definitions are the contract.

| Phrase | What it will mean | What it will never mean |
| --- | --- | --- |
| **Agentic, autonomous** | A campaign can plan, act, observe, recover and stop within a budget, with a durable state machine. | An unsupervised agent attacking production or making irreversible changes. |
| **Self-learning / evolving** | The system proposes, tests and promotes better skills, framework models, prompts and routing policies from verified outcomes. | The model rewriting its own safety policy, evaluation set or production code without gates. |
| **Finds all vulnerabilities** | High measured recall on a defined, versioned corpus, with residual risk reported. | A literal guarantee over arbitrary software. |
| **Any language / framework** | A universal graph core plus certified language and framework packs; experimental adapters can exist without being sold as certified. | Claiming support because tree-sitter has a grammar. |
| **Fixes deeply** | Root-cause patches with regression tests, proof that the original PoC fails, the suite passes and a re-scan is clean. | Sink-level sanitisation that hides the bug or breaks behaviour. |
| **30+ agents** | 30 adapters pass a published contract suite; any MCP/A2A/OpenAI-compatible agent can attach through the gateway. | 30 logos on a slide without a test. |
| **Beats all security AI agents** | A statistically significant win on a pre-registered benchmark, with non-inferior precision, reproducibility and cost, reproducible by a third party. | A demo against one vulnerable app or a vendor-authored comparison. |
| **Enterprise-grade** | Tenant isolation, SSO, audit, policy, data residency, signed artefacts and a deployment model that security teams can approve. | A compliance certificate that has not been audited. |
| **Hacks your codebase** | Authorised, scoped, sandboxed testing of code you own or are contracted to test. | Testing third-party systems without permission, persistence or data exfiltration. |

### The honest scope of “autonomous”

A campaign may be autonomous in **reasoning and execution**, but not in
**authority**:

- scope and target allowlist are human-approved;
- destructive or externally visible tests require policy approval;
- patches are proposed, never silently merged;
- a human can pause, inspect, steer or terminate at any point;
- every action is attributable to a campaign, an agent role, a tool and a
  policy decision.

---

## 2. Baseline: what exists, precisely

This is the starting point the plan is built on. It is intentionally narrow.

| Layer | Current state | Where it lives |
| --- | --- | --- |
| Ingestion | tree-sitter parsing for TS/TSX/JS and Python; symbols; intra- and cross-function taint; route extraction for Express/Fastify/Koa/Nest and Flask/FastAPI | `src/redfall/ingestion/` |
| Language registry | exactly two support bundles; adding a language means implementing parse/symbols/taint | `src/redfall/ingestion/languages.py` |
| Planning | LLM planner emits branches; every route must be covered exactly once | `src/redfall/agent/prompts/planner.md` |
| Analysis | LLM analyser produces candidate findings with evidence and PoC instructions | `src/redfall/agent/agent.py` |
| Verification | Docker + gVisor; Node/Python harness; only `reproduced: true` counts | `src/redfall/validation/validator.py`, `src/redfall/sandbox/` |
| Adaptation | reproduced findings can spawn new branches; exploit chains are replayed as one composite PoC | `src/redfall/branching/adaptive_scan.py`, `src/redfall/chain/` |
| Repair | patch, run target tests, re-run original PoC; up to three attempts; unverified fixes are left for a human | `src/redfall/fix/fixer.py` |
| Models | LiteLLM BYOK, fast/mid/deep tiers, budgets, verbatim transcripts, exact-match cache | `src/redfall/llm.py` |
| State | PostgreSQL for durable rows, Redis for scan/branch state | `src/redfall/store/` |
| Interfaces | CLI, JSON report, SARIF | `src/redfall/cli.py`, `src/redfall/sarif.py` |
| Ground truth | `pythonbank`, `vulnbank`, `vulnbank-adaptive`, `chainbank`; 25 verified categories; 4 deliberately excluded with measured reasons | `range/`, `src/redfall/agent/categories.py` |
| Evidence culture | no-mock contract; live provider calls only; missing prerequisites fail the scan; recorded transcripts and execution rows | `scripts/check_no_mock.py`, `BLOCKED.md` |

### The gaps that matter

1. **Fixed pipeline, not a campaign.** The stages are real, but the system does
   not maintain a long-lived task graph, choose its own next tool, or recover
   from a failed environment without a human.
2. **Depth-one interprocedural analysis.** Useful, but not enough for
   framework-heavy Java, generated code, multi-service auth flows or
   field-sensitive alias problems.
3. **Two language ecosystems.** Coverage is honest but tiny relative to the
   enterprise request.
4. **Narrow runtime model.** Node and Python targets with known recipes; no
   general environment synthesis for arbitrary builds, databases, queues,
   browsers or multi-service systems.
5. **One model per stage, no model router.** No capability probe, no learned
   routing, no cost-aware fallback.
6. **No persistent learning.** Prompts and framework knowledge are static;
   verified campaigns do not compound.
7. **No interoperability layer.** An external agent cannot call RedFall as a
   tool; RedFall cannot call another agent.
8. **No enterprise control plane.** No tenancy, SSO, policy-as-code, audit
   export, self-hosted deployment or SIEM integration.
9. **No benchmark arena.** There is excellent ground truth, but no fair,
   pre-registered comparison against other approaches.

---

## 3. Strategy: what actually makes it better

### 3.1 The five moats

| Moat | Why it is hard | Why it compounds |
| --- | --- | --- |
| **Verification fabric** | Building, running, attacking and resetting arbitrary apps safely is an operations problem, not a prompt problem. | Every supported stack becomes reusable infrastructure. |
| **Environment synthesis** | Repositories have unique build, migration, seed, auth and service dependencies. | Recipes accumulate and make the next repository cheaper. |
| **Code intelligence** | Whole-program semantics, framework models and incremental indexing are deep engineering. | Framework packs and graph queries improve every campaign. |
| **Evidence-gated learning** | Most systems cannot tell a real success from a plausible one. | Verified outcomes become tested skills and better routing. |
| **Interoperability** | Agents, IDEs and enterprises all speak different protocols. | RedFall becomes the default execution layer rather than another chat UI. |

The model is not a moat. The model is a replaceable reasoning engine behind a
capability registry and a budget.

### 3.2 Three ways to attach

1. **RedFall inside your agent** — run RedFall as an MCP server and/or HTTP
   service. Claude Code, Codex CLI, OpenCode, Cursor, Windsurf, Cline, Goose or
   an enterprise orchestrator calls RedFall tools to index, scan, verify and fix.
2. **Your agent inside RedFall** — RedFall's model gateway can use Anthropic,
   OpenAI, Google, Nous Hermes, local vLLM/Ollama or any OpenAI-compatible
   endpoint. The agent kernel routes work by capability and cost.
3. **Agent-to-agent** — expose RedFall as a specialised security agent over A2A
   so a multi-agent enterprise workflow can delegate “find, prove and fix this
   class of issue” without knowing RedFall's internals.

### 3.3 What not to build

- A new general-purpose coding agent. There are already too many.
- A regex scanner with an LLM wrapper.
- A model fine-tune before the evidence pipeline exists.
- A marketplace of 30 integrations before the adapter contract exists.
- A dashboard before the campaign API is stable.
- A “100% coverage” claim in any language.

### 3.4 Sequencing rationale

The order is deliberate: each layer makes the next one measurable.

1. **Arena and evidence first.** Without a baseline and an evidence schema,
   “better” is a feeling. This is also the cheapest work relative to its value.
2. **Graph second.** It is the shared substrate for planning, taint, auth,
   frameworks and fixes.
3. **Campaign and agent kernel third.** Autonomy is only useful once the tools
   return trustworthy graph and runtime observations.
4. **Environment synthesis fourth.** This is the largest operational moat and
   the main reason most scanners stop at static analysis.
5. **Interop fifth.** MCP/A2A distribution is high-leverage, but it exposes
   whatever the core can actually do; it is not a substitute for depth.
6. **Fix proof sixth.** Repair is the enterprise buying reason, but it must stand
   on verified reproduction and a runnable environment.
7. **Learning seventh.** Skills and framework models need a trustworthy outcome
   stream; otherwise the system learns to be confidently wrong.
8. **Enterprise controls last, but designed in from the start.** Tenancy,
   policy and audit are not a wrapper added after the architecture is fixed.

---

## 4. Target architecture

```text
                         ┌──────────────────────────────────────────────┐
                         │  Clients: IDE agents · CLI agents · CI/CD    │
                         │  SOC tools · enterprise orchestrators        │
                         └──────────────────────┬───────────────────────┘
                                                │
                    ┌───────────────────────────▼───────────────────────────┐
                    │  Interop Gateway                                      │
                    │  MCP · A2A · HTTP/OpenAPI · webhooks · CLI adapters   │
                    │  auth · scopes · quotas · capability negotiation       │
                    └───────────────────────────┬───────────────────────────┘
                                                │
                    ┌───────────────────────────▼───────────────────────────┐
                    │  Campaign Control Plane                               │
                    │  scope · task graph · scheduler · budget · policy      │
                    │  durable state · pause/resume · approvals · audit      │
                    └───────────────┬───────────────────────┬───────────────┘
                                    │                       │
              ┌─────────────────────▼───────┐   ┌───────────▼─────────────────┐
              │  Code Intelligence Graph    │   │  Agent Kernel               │
              │  syntax · semantics · CFG   │   │  roles · tools · context    │
              │  routes · auth · taint      │   │  critic · verifier · router │
              │  deps · config · IaC        │   │  prompt/skill registry      │
              └─────────────────────┬───────┘   └───────────┬─────────────────┘
                                    │                       │
                    ┌───────────────▼───────────────────────▼───────────────┐
                    │  Verification Fabric                                  │
                    │  sandbox pools · environment synthesis · fixtures     │
                    │  HTTP/browser/gRPC drivers · PoCs · chains · resets   │
                    └───────────────────────────┬───────────────────────────┘
                                                │
                    ┌───────────────────────────▼───────────────────────────┐
                    │  Evidence Ledger · Fix & Proof Engine · Reporting     │
                    │  E0–E4 evidence · reproducibility bundle · SARIF      │
                    └───────────────────────────┬───────────────────────────┘
                                                │
                    ┌───────────────────────────▼───────────────────────────┐
                    │  Memory & Learning (gated)                            │
                    │  cases · skills · framework models · router · evals   │
                    └───────────────────────────────────────────────────────┘
```

### Design laws

1. **No evidence, no finding.** A report row must point to an execution or a
   static artefact; a model's assertion is E0 and is not reportable.
2. **No sandbox, no execution.** Target code never runs on the host.
3. **No replay, no verification.** A PoC that cannot be reproduced from its
   bundle is a hypothesis, not a finding.
4. **No budget, no campaign.** Every task has token, CPU, sandbox-minute,
   wall-clock and network limits.
5. **No consent, no learning.** Customer code is not used for global training or
   shared memory by default.
6. **No policy, no write.** Patches, external network calls and destructive
   probes require a policy decision.
7. **No silent fallback.** Missing prerequisites fail with an exact reason; they
   never degrade into a fabricated result.
8. **Boring durable core.** Postgres, object storage, queues and idempotent
   workers before exotic orchestration.

---

## 5. Workstreams

### 5.1 Code Intelligence Graph

**Current.** Tree-sitter syntax for two languages, local symbol tables, a
depth-one interprocedural pass, route extraction and taint seeds.

**Target.** A language-agnostic, provenance-aware code graph that can answer
security questions at repository scale.

#### Graph model

Nodes:

`Repository, Commit, File, Module, Package, Class, Function, Parameter, Route,
AuthPolicy, TrustBoundary, Source, Sink, Sanitizer, DataStore, Config, Secret,
Dependency, Container, IaCResource, Test, BuildRecipe`

Edges:

`CONTAINS, IMPORTS, CALLS, OVERRIDES, FLOWS_TO, SANITIZES, REACHES, HANDLES,
GUARDS, READS, WRITES, DEPENDS_ON, EXPOSES, CONFIGURES, TESTS`

Each node and edge carries:

- repository, commit and source span;
- language and generated/test/vendor flags;
- analyzer provenance (`tree-sitter`, LSP, compiler, Semgrep, CodeQL, Joern,
  model-assisted and then verified);
- confidence and the evidence IDs that support it.

#### Analysis layers

1. **Syntax** — tree-sitter for every supported language; fast, universal.
2. **Semantics** — compiler/LSP frontends where available: TypeScript compiler,
   Python `pyright`/`jedi`, Java `javac`/JavaParser, Go `packages`/SSA, C#
   Roslyn, PHP `php-parser`, Ruby Prism, Rust `rust-analyzer`, C/C++ `clangd`.
3. **Dataflow** — field-sensitive, context-sensitive where the budget allows;
   IFDS/IDE-style interprocedural taint; alias summaries; framework-aware
   source/sink/sanitizer models.
4. **Analyzer mesh** — Semgrep, CodeQL, Joern, language linters, secret
   scanners, SCA/OSV, IaC/container scanners. These produce **hypotheses and
   evidence**, never automatic “verified” findings.
5. **Framework packs** — declarative route/auth/source/sink models in YAML or a
   small DSL, with conformance fixtures. A pack is certified only when its
   fixtures pass in CI.
6. **Incremental indexing** — git diff + content hashes; invalidate changed
   nodes and dependent edges; cache analysis summaries by content hash.

#### Storage

Start with PostgreSQL adjacency tables + JSONB properties + recursive CTEs. Add
materialised path summaries and per-query caches. A dedicated graph database is
an option only if measured p95 query latency demands it; it is not a default.

#### Interfaces

- `graph.index(repo, commit)`
- `graph.query(cypher_like_or_structured_query, budget)`
- `graph.paths(source, sink, constraints)`
- `graph.routes()`, `graph.auth_matrix()`, `graph.entrypoints()`
- `graph.diff(base, head)` for PR-mode scans
- `graph.evidence(node_or_edge, span)`

#### Exit criteria

- The graph is the single source of truth for routes, sources, sinks and auth in
  all four existing range targets.
- Every edge has provenance and a source span.
- A 1M-LOC repository can be indexed incrementally without re-parsing unchanged
  files, with a measured time and memory budget.
- A framework pack cannot be marked certified without its fixture suite.

---

### 5.2 Campaign Control Plane

**Current.** A scan executes a fixed sequence of stages and branch runs; Redis
holds transient state; recovery is limited.

**Target.** A durable, resumable campaign with a task graph, budgets, policies
and human gates.

#### Campaign state machine

```text
DRAFT -> SCOPED -> INDEXING -> RECON -> HYPOTHESIS -> PROBE
      -> EXPLOIT -> IMPACT -> FIX -> VERIFY -> REPORTED
                     \-> BLOCKED / PAUSED / FAILED / CANCELLED
```

A campaign owns:

- scope: repositories, branches, commits, environments, allowed hosts;
- budget: USD, tokens, sandbox minutes, wall clock, concurrency, egress;
- policy: allowed techniques, destructive-test approvals, data handling;
- objective: discovery, reproduction, chain, fix, regression or compliance;
- evidence and artefacts;
- human interventions.

#### Scheduling and value of information

The planner should not just enumerate files. It should rank **next actions** by
expected verified impact per unit cost:

```
priority(hypothesis) =
  expected_impact
  × probability_of_reproduction
  × novelty
  ─────────────────────────────────────
  estimated_cost + risk_penalty
```

The scheduler uses leases, idempotency keys and checkpointed task results. A
worker crash must not duplicate a sandbox explosion or lose a reproduced
finding.

#### Stop conditions

- budget exhausted;
- coverage saturation: no new routes/functions/hypotheses in the last N tasks;
- all high-value paths exhausted;
- policy risk gate reached;
- operator pause or cancel;
- an environment blocker that cannot be fixed within budget.

“Stop because the prompt ended” is not a valid stop condition.

#### Human gates

- scope approval;
- external network access;
- destructive or state-changing tests;
- production-like data;
- patch merge;
- skill/framework-model promotion in v1.

#### Interfaces

- `POST /campaigns`
- `GET /campaigns/{id}`, `GET /campaigns/{id}/events` (SSE)
- `POST /campaigns/{id}/pause|resume|cancel`
- `POST /campaigns/{id}/approvals/{gate}`
- `GET /campaigns/{id}/evidence`
- `GET /campaigns/{id}/report.sarif`

#### Exit criteria

- A campaign survives worker restart and resumes from the last committed task.
- Budgets are enforced before model and sandbox calls, not after.
- Every state transition is auditable.
- A four-hour unattended campaign completes on `vulnbank-adaptive` with human
  intervention only at scope and merge gates.

---

### 5.3 Agent Kernel

**Current.** Five prompt stages (planner, analyser, PoC generator, chain
analyst, fixer), one model tier per call, no general tool loop.

**Target.** A multi-role agent kernel with typed tools, context management,
independent verification and model routing.

#### Roles and separation of duties

| Role | Job | Cannot do |
| --- | --- | --- |
| Recon | map entrypoints, auth, data stores, build/runtime | declare a finding |
| Static analyst | build hypotheses from graph paths | execute target code |
| Planner | choose next actions and budget | execute or verify |
| Exploit author | write a candidate PoC | mark it verified |
| Runtime operator | build/run/reset the target, drive HTTP/browser | change the finding |
| Chain analyst | compose validated primitives | invent edges |
| Critic | challenge assumptions and propose alternatives | approve its own work |
| Fixer | produce a root-cause patch and regression test | verify the patch |
| Verifier | execute proof ladder in a clean environment | edit the patch |
| Reporter | render evidence into SARIF/HTML/JSON | add facts not in evidence |

No agent grades its own output. The verifier is a separate role with a separate
tool policy and, ideally, a different model family.

#### Typed tools

`read_file`, `search_code`, `graph_query`, `graph_paths`, `list_routes`,
`read_config`, `run_build`, `run_tests`, `start_service`, `reset_service`,
`http_request`, `browser_action`, `grpc_call`, `db_query`, `run_poc`,
`apply_patch`, `git_diff`, `scan_dependencies`, `read_logs`, `report`.

Every tool declares:

- JSON input/output schema;
- required permission;
- cost (tokens, time, sandbox minutes);
- idempotency and cancellation semantics;
- whether it can mutate state;
- what evidence it returns.

#### Context management

- structured “evidence notebook” instead of dumping the repository into a
  prompt;
- retrieval by graph neighbourhood, not by filename similarity alone;
- summaries are generated but always link back to raw spans and execution IDs;
- untrusted repository content is labelled as data, never as instructions;
- secrets are redacted before model calls and restored only inside the sandbox.

#### Model routing

- capability registry: tool calling, JSON schema, context window, latency, cost,
  data residency, streaming;
- tiers: fast triage, mid analysis, deep exploit/chain, code-specialised fix;
- learned router (contextual bandit) with hard guardrails;
- fallback only to a model that passes the capability probe;
- no model call without a budget reservation.

#### Exit criteria

- A campaign can solve a task that requires at least three different tools and
  recover from a failed tool call.
- The verifier rejects a plausible but unexecuted finding every time.
- The critic produces a measurable reduction in false positives on the arena.
- Model routing reduces cost per verified finding without reducing recall.

---

### 5.4 Verification Fabric

**Current.** Docker + gVisor, a Node/Python harness, known build commands for
the range targets, one PoC at a time.

**Target.** A safe, general runtime for arbitrary applications and multi-service
systems.

#### Sandbox tiers

| Tier | Use | Properties |
| --- | --- | --- |
| Development | local debugging only | never counts as verified |
| gVisor | default verified execution | user-space kernel, seccomp, no host mounts, read-only source |
| Firecracker/Kata | enterprise/high-assurance | microVM isolation, per-campaign network policy |
| Air-gapped pool | regulated customers | no external egress, local model gateway |

#### Environment synthesis

Detect and generate a `BuildRecipe` for:

- Node/TypeScript (`package.json`, lockfile, Vite/Next/Nest/Express);
- Python (`pyproject`, requirements, Flask/FastAPI/Django);
- Java/Kotlin (Maven/Gradle, Spring Boot);
- Go (`go.mod`, net/http, Gin/Echo/Fiber);
- .NET (`csproj`, ASP.NET Core);
- PHP (Composer, Laravel/Symfony);
- Ruby (Bundler, Rails);
- containers (`Dockerfile`, Compose, Kubernetes manifests).

A recipe contains:

```text
install -> build -> migrate -> seed -> start -> healthcheck -> auth setup
        -> test command -> reset command -> fixture reset
```

If a recipe cannot be produced, the campaign records an **environment blocker**
with the exact failing command and log. It does not fake a runtime.

#### Multi-service and browser support

- Docker Compose / Testcontainers-style service graphs;
- databases, queues, caches and identity providers;
- Playwright for browser flows, XSS, CSRF and session behaviour;
- HTTP/gRPC/WebSocket clients;
- deterministic clocks, seeds and fixture resets where possible;
- network allowlists and canary hosts for SSRF proof.

#### Evidence ladder

| Grade | Meaning | Reportable? |
| --- | --- | --- |
| E0 | Model or human assertion | No |
| E1 | Static path / plausible source-to-sink | No (hypothesis only) |
| E2 | Dynamic probe without impact proof | No |
| E3 | Exploit reproduced in the target runtime | Yes, with impact caveat |
| E4 | E3 + impact demonstrated + reset/replay + regression test | Yes, “verified” |

Only E3/E4 contribute to the verified-finding count. A flaky PoC is quarantined
until it reproduces N times from a clean reset; it is never rounded up.

#### Reproducibility bundle

Every verified finding ships with:

- repository, commit, submodules, lockfiles;
- container image digest and sandbox tier;
- environment variables (secrets redacted, placeholders documented);
- seed/fixtures and reset procedure;
- PoC, driver and exact command;
- expected observable (HTTP status, body marker, database state, canary hit);
- logs/traces and timestamps;
- re-scan result and fix diff (if any).

#### Exit criteria

- At least 95% of verified PoCs reproduce from their bundle on a clean host.
- A multi-service Node + Postgres + Redis target runs end to end.
- A browser-driven XSS/CSRF proof works in the sandbox.
- No target code runs outside a sandbox in any test.

---

### 5.5 Fix and Proof Engine

**Current.** Patch generation, target tests, original PoC replay, three attempts.
Good baseline; still mostly sink-level and single-service.

**Target.** Root-cause repair with proof and reviewable delivery.

#### Fix pipeline

1. Root-cause analysis over the graph and evidence, not just the sink line.
2. Patch generation with repository conventions and minimal diff.
3. Regression test generation that fails before the patch and passes after.
4. Verification:
   - original PoC fails;
   - target test suite passes;
   - new regression test passes;
   - re-scan of the affected path is clean;
   - no new high-severity finding on the changed surface;
   - behaviour/performance checks where available.
5. Patch ranking: minimality, root-cause depth, test quality, blast radius.
6. Delivery: branch, signed commit, PR/MR with evidence links, reviewer
   checklist, rollback instructions.
7. Human approval before merge.

#### Fix quality

A fix is not “verified” merely because the PoC stops working. It must also not
break the application. A fix that disables a feature, hard-codes a test value or
removes authentication is rejected even if the PoC fails.

#### Exit criteria

- ≥70% of proposed patches are accepted by design partners on the first or
  second review (provisional target).
- Every verified patch has a regression test that fails on the parent commit.
- Re-scan of the patched campaign produces no recurrence of the same finding.
- Patch bundles can be applied outside the RedFall workspace.

---

### 5.6 Evidence Ledger and Reporting

**Current.** Database rows for scans, branches, findings, sandbox runs, LLM
calls and fixes; JSON and SARIF output.

**Target.** An append-only, hash-chained evidence ledger that is the only source
for reports.

#### Ledger rules

- Append-only; corrections are new events, not edits.
- Hash chain per campaign; export includes the chain for tamper evidence.
- Every report row references finding IDs, evidence IDs, execution IDs and the
  environment digest.
- The report generator fails closed if a reference is missing.
- Retention and redaction are policy-driven.

#### Report surfaces

- SARIF 2.1.0 for code scanning;
- JSON for automation;
- HTML/Markdown for humans;
- CSV for risk registers;
- Jira/Linear/GitHub Issues with evidence links;
- SBOM/VEX for supply-chain workflows;
- SIEM export (Splunk, Elastic, Sentinel) in enterprise mode;
- executive summary separated from technical proof.

#### Exit criteria

- A report cannot be generated from an unsupported claim.
- Every finding is replayable from the bundle.
- The same finding has a stable fingerprint across commits unless the code
  location genuinely changes.
- Redaction is tested against secrets and PII fixtures.

---

### 5.7 Memory and Learning

**Current.** Static prompts; exact-match LLM cache; no durable learning from
campaign outcomes.

**Target.** Evidence-gated learning that compounds without turning the product
into an unaccountable self-modifying system.

#### Learning loop

```text
Campaign
  -> verified outcomes + human feedback
  -> candidate learning unit
  -> offline evaluation arena
  -> shadow run
  -> canary (small % of campaigns)
  -> promote or rollback
```

#### Learning units

| Unit | What is learned | Promotion gate |
| --- | --- | --- |
| **Case memory** | verified finding, path, environment, PoC, fix | hash/provenance; no duplicate; tenant policy |
| **Skill** | a reusable procedure with preconditions, tools and success test | fixture tests + no benchmark regression + human sign-off (v1) |
| **Framework pack** | routes, auth, sources, sinks, sanitizers for a stack | labelled fixtures; precision/recall thresholds; no new false positives |
| **Router policy** | which model/tool budget wins for a context | non-inferior verified recall, lower cost, bounded exploration |
| **Prompt** | better instructions for a role | offline eval win + safety tests + canary |
| **Model adapter/fine-tune** | provider-specific behaviour or a tuned model | held-out improvement, safety regression suite, explicit customer consent |

#### What is learned from

Only outcomes with E3/E4 evidence, explicit human labels, or reproducible
public benchmark data. Unverified model output is **not** training data.

Start with retrieval and tested skills, not fine-tuning. Retrieval and skills
are inspectable, reversible and cheap to evaluate; a fine-tune is none of those
until the evidence pipeline is mature. Model fine-tuning is a late-stage option
for narrow, well-measured gaps, not the first version of “learning”.

#### Anti-poisoning and isolation

- provenance and signatures on every learned unit;
- tenant-private memory by default;
- global skills only from public/consented data or customer opt-in;
- no cross-tenant retrieval;
- immutable evaluation sets with access control;
- adversarial tests for prompt injection and reward hacking;
- human review for high-impact promotions;
- immediate rollback and drift alarms.

#### What is not learnable

- the safety policy;
- the definition of “verified”;
- the evidence requirements;
- the evaluation set;
- permission to run outside the sandbox.

#### Exit criteria

- A skill learned from one campaign improves a held-out campaign without
  reducing precision.
- Framework-pack learning is accepted only after its fixture suite passes.
- A canary promotion can be rolled back automatically on a metric regression.
- No cross-tenant retrieval is possible in tests.

---

### 5.8 Interoperability Gateway

**Current (Phase 3).** One gateway process exposes the same 44-tool registry
over MCP stdio, HTTP/OpenAPI and A2A v1.0 JSON-RPC/SSE. Bearer tokens, scopes,
hourly quotas, audit, signed artifacts and HMAC webhooks are implemented.
A2A push notifications, multi-turn continuation, a CLI adapter contract, TLS
termination and built-in multi-tenancy remain open.

**Target.** Any agent can use RedFall, and RedFall can use any suitable agent or
model, without special-casing every vendor.

#### Three protocol surfaces

1. **MCP server** — tools and resources for coding agents.
   - `redfall.index`, `redfall.query_graph`, `redfall.routes`
   - `redfall.scan`, `redfall.campaign_status`, `redfall.pause`
   - `redfall.findings`, `redfall.evidence`, `redfall.reproduce`
   - `redfall.propose_fix`, `redfall.verify_fix`, `redfall.report`
   - `redfall.policy_check`
2. **A2A agent** — an Agent Card and task lifecycle for enterprise
   orchestrators: skills, input/output modes, auth, streaming, cancellation,
   artefacts.
3. **HTTP/OpenAPI + webhooks** — every capability, for agents and CI systems
   that do not speak MCP or A2A.

For agents that only have a CLI, use a **headless adapter contract**:

```text
agent --non-interactive --json
  stdin: task, tools, budget, policy, workspace
  stdout: structured events and final artefact
  exit codes: success / blocked / cancelled / error
```

No screen-scraping of interactive UIs.

#### Model gateway

Keep LiteLLM as one adapter, but add a capability probe and a provider registry:

- Anthropic Claude (API and Claude Code);
- OpenAI GPT/Codex (API and Codex CLI);
- Google Gemini (API and Gemini CLI);
- Nous Research Hermes via OpenRouter, vLLM or Ollama if it exposes compatible
  tool calling;
- local models (vLLM, Ollama, llama.cpp) for air-gapped deployments;
- Azure OpenAI, AWS Bedrock, Google Vertex.

“Hermes” is treated as a model/provider target, not hard-coded into the core. A
Hermes-branded agent runtime can attach through MCP/A2A/CLI like any other
agent.

#### Adapter tiers

| Tier | Requirement |
| --- | --- |
| **Certified** | contract suite + live end-to-end scan + cancellation/resume + artifact exchange |
| **Compatible** | protocol handshake + one smoke scan; known limitations documented |
| **Experimental** | community adapter; no support claim |

#### Target adapter list (illustrative; certify, don't claim)

Coding agents and IDEs: Claude Code, OpenAI Codex CLI, Gemini CLI, OpenCode,
Cursor, Windsurf, Cline, Roo Code, Continue, Aider, Goose, Sourcegraph Amp,
JetBrains Junie, Kiro, Qwen Code, Crush, Kilo Code, Zed, Warp, Replit Agent.

Enterprise and orchestration: GitHub Copilot coding agent, Amazon Q Developer,
Sourcegraph Cody, Tabnine, Augment Code, Qodo, Devin, Factory, LangGraph,
CrewAI, AutoGen, OpenAI Agents SDK, Semantic Kernel, PydanticAI.

Model endpoints: Anthropic, OpenAI, Google, Nous Hermes, Meta Llama, Mistral,
Qwen, DeepSeek, local vLLM/Ollama.

The public matrix will list only tested status. “30+ agents” means 30 certified
adapters, not 30 logos.

#### Security

- OAuth 2.1 / API keys with scopes;
- per-agent quotas and campaign policy;
- no agent can widen its own scope;
- artifact encryption and signed URLs;
- audit every tool call with agent identity, campaign, input hash and result;
- prompt-injection defences: repository content is untrusted data; tool outputs
  are labelled; secrets are redacted.

#### Exit criteria

- 5 certified adapters by day 90; 30 by month 12.
- A Claude Code session can run a real campaign through MCP and retrieve SARIF.
- A Codex CLI session can do the same without RedFall-specific prompt hacks.
- An A2A orchestrator can delegate a scan and receive a signed evidence bundle.
- Cancellation and resume work across every certified adapter.

---

### 5.9 Enterprise Control Plane

**Current.** Single-user CLI and local services; no tenancy or enterprise auth.

**Target.** A control plane that a security team can approve.

#### Controls

| Area | Target |
| --- | --- |
| Tenancy | org/project/repository scopes; row-level isolation; per-tenant object prefixes and KMS keys |
| Identity | OIDC/SAML SSO; SCIM; MFA; service accounts |
| Authorisation | RBAC + ABAC; roles: owner, admin, security engineer, developer, auditor, viewer |
| Policy | OPA/Rego: allowed repos/branches/hosts, destructive-test limits, egress, retention, model providers |
| Audit | append-only, exportable to SIEM; actor, agent, campaign, tool, policy decision |
| Data | encryption in transit/at rest; customer-managed keys; region pinning; no training by default |
| Deployment | SaaS, single-tenant VPC, self-hosted Kubernetes, air-gapped |
| Supply chain | signed images, SBOM, SLSA provenance, pinned dependencies, scanner-scans-itself |
| Observability | OpenTelemetry traces/metrics/logs; per-campaign cost and SLOs |
| Integrations | GitHub App, GitLab, Bitbucket, Azure DevOps, Jenkins, Jira, Linear, Slack, Teams, Splunk, Elastic, Sentinel |
| Reporting | SARIF, JSON, HTML, CSV, VEX, SBOM, compliance mappings |

#### Scale and SLOs

- 1M-LOC repository indexing within a documented budget;
- 100 concurrent campaigns per cluster (target);
- API p95 latency and campaign throughput measured, not assumed;
- graceful degradation: queueing is visible; no silent result loss.

#### Compliance

- SOC 2 Type I/II readiness and ISO 27001 gap assessment after design-partner
  traction;
- no certification claim before an audit;
- data processing agreement and subprocessor list;
- penetration test of the platform itself before enterprise GA.

#### Exit criteria

- A design partner can onboard via SSO, scope a repository, run a campaign and
  export evidence to its SIEM.
- Tenant isolation is proven by adversarial tests.
- An air-gapped deployment can run with local models and no egress.
- A security questionnaire can be answered with evidence, not adjectives.

---

## 6. Language and framework coverage

The core stays language-agnostic. A language is **certified** only when all of
the following exist:

1. parser and symbol extraction;
2. control-flow and dataflow analysis;
3. framework pack for routes/auth/sources/sinks/sanitizers;
4. build/run/reset recipe;
5. at least 10 ground-truth cases with real PoCs;
6. ≥95% reproduction on the pack's fixtures;
7. no regression in the arena;
8. documentation and evidence.

### Waves

| Wave | Languages | Frameworks / surfaces | Status target |
| --- | --- | --- | --- |
| 0 (current) | TypeScript, JavaScript, Python | Express, Fastify, Koa, Nest, Flask, FastAPI | deepen, not just maintain |
| 1 (months 1–6) | Java, Kotlin, Go | Spring Boot, Jakarta, JAX-RS, net/http, Gin, Echo, Fiber | certified |
| 2 (months 5–9) | C#/.NET, PHP, Ruby | ASP.NET Core, Laravel, Symfony, Rails | certified |
| 3 (months 9–12) | Rust, C/C++, Swift, Scala, Elixir | Axum/Actix, clang/CMake, SwiftSyntax, Play, Phoenix | experimental → selective certification |
| Surfaces | — | GraphQL, gRPC, WebSocket, queues, serverless, containers, IaC, mobile, AI/LLM apps | per-pack certification |

### “Any language” architecture

- universal graph and evidence model;
- thin language adapters for syntax and semantics;
- declarative framework packs;
- environment recipe SDK;
- conformance kit and public certification matrix;
- no claim that a grammar alone equals support.

---

## 7. Vulnerability depth

A CWE label is not a proof. Every class needs a **proof contract**: what must be
demonstrated, what counts as impact, and what is out of scope.

### Wave 1 — deepen the existing base

Injection (SQL/NoSQL/command/template), XSS, path traversal, SSRF and cloud
metadata, IDOR/broken object authorization, mass assignment, unsafe
deserialization, secrets, open redirect, file upload, CORS/CSRF, security
misconfiguration, weak crypto, missing signature verification, rate/pagination
limits, business-logic invariants already covered by the ranges.

Examples of proof contracts:

- **SQL injection**: inject syntax that changes the result or data state, not
  merely produces an error.
- **IDOR**: authenticated principal A accesses principal B's object; proof
  includes both identities and the ownership check.
- **SSRF**: request reaches a controlled internal canary; metadata access is
  proven against a canary endpoint, never real cloud credentials.
- **XSS**: payload executes in a real browser context; stored XSS survives a
  reload; CSP behaviour is recorded.
- **Deserialization**: controlled object construction or code path, not just a
  suspicious `unserialize` call.
- **Race/TOCTOU**: invariant violation under controlled concurrency, repeated
  enough to rule out flake.

### Wave 2 — enterprise web and identity

OAuth/OIDC/JWT misuse, session fixation, authorization matrix failures,
multi-tenant isolation, request smuggling, cache poisoning, host-header attacks,
GraphQL authorization and batching, gRPC auth, queue/worker trust boundaries,
deserialization across languages, dependency/CI-CD supply chain, container and
Kubernetes misconfiguration.

### Wave 3 — platform and AI systems

- cloud/IaC: Terraform, CloudFormation, Kubernetes, Helm, Docker;
- mobile: Android/iOS deep links, exported components, WebViews, secret storage;
- AI/LLM applications: prompt injection, insecure tool use, RAG poisoning,
  sensitive-data disclosure, excessive agency, unsafe output handling;
- memory safety: C/C++ and `unsafe` Rust with sanitizers and crash triage;
- cryptographic misuse and key lifecycle.

### Wave 4 — app-specific invariants

Business logic cannot be found by generic rules alone. The system needs:

- user-supplied invariants and threat models;
- differential testing against a reference implementation;
- state-machine exploration;
- property-based tests;
- human-in-the-loop confirmation for ambiguous impact.

This is where a deep agent can outperform a rule scanner, but only with a real
oracle. “The model thinks this is a bug” is not an oracle.

---

## 8. Benchmark and competitive programme

“Best” is a measurement, not a tagline. The arena is a first-class product.

### Corpora

1. Existing ranges: `pythonbank`, `vulnbank`, `vulnbank-adaptive`, `chainbank`.
2. Public synthetic suites: OWASP Benchmark and Juliet, used for category
   coverage and baseline comparison — with their limitations documented.
3. Real-CVE reproductions with pinned vulnerable and fixed commits, buildable in
   the sandbox.
4. `EnterpriseBench`: multi-service applications with auth, databases, queues,
   browsers, cloud metadata canaries and realistic business logic.
5. A private holdout set, rotated and access-controlled, to prevent benchmark
   overfitting.

### Baselines

- current RedFall;
- deterministic analyzers (Semgrep, CodeQL) plus an LLM triage layer;
- open-source agent frameworks with security prompts;
- commercial agents where terms permit, run by an independent evaluator.

### Metrics

| Metric | Definition |
| --- | --- |
| Verified recall | verified true findings / ground-truth findings |
| Precision | verified true findings / reported findings |
| Reproduction rate | bundles that reproduce / verified findings |
| Fix acceptance | patches accepted by maintainers / proposed patches |
| Cost per verified finding | total model + compute + human cost / verified true findings |
| Time to verify | p50/p95 from campaign start to E4 |
| Autonomy | human interventions per campaign |
| Coverage | routes/functions analysed / total |
| Chain depth | validated multi-step chains per campaign |
| Regression escape | vulnerabilities found later that were in scope and missed |

No single composite score should hide a precision or cost regression. The
primary metric is pre-registered per benchmark; the rest are guardrails.

### Fairness protocol

- same repository commits, hardware class, time limit and model budget;
- seeds, retries and concurrency documented;
- raw logs and evidence bundles published where licences allow;
- multiple runs with confidence intervals;
- no cherry-picked repository;
- no training on the holdout;
- independent re-run before any public “best” claim.

### “Beats all” gate

A superiority claim requires all of:

1. a statistically significant win on the pre-registered primary metric;
2. non-inferior precision, reproduction and cost;
3. a holdout set the team did not tune on;
4. an independent re-run;
5. a published limitations section.

Until then, the claim is “competitive on our benchmark”, not “best”.

---

## 9. Delivery plan

Dates assume a start in late October 2026 and a small senior team. They are
planning ranges, not promises.

### Team shape (target)

| Role | Count | Focus |
| --- | --- | --- |
| Code intelligence / compilers | 2 | graph, language packs, dataflow |
| Runtime / sandbox / infrastructure | 2 | verification fabric, environments, scale |
| Agent / ML systems | 2 | kernel, routing, memory, learning gates |
| Platform / enterprise | 2 | control plane, auth, policy, integrations |
| Security research | 1 | proof contracts, arena, ground truth |
| Product / design | 1 | workflows, reports, design partners |
| SRE / security | 0.5–1 | deployment, isolation, incident response |
| Technical writing | 0.5 | docs, evidence, benchmark reports |

A smaller team can run the same sequence with narrower language and adapter
targets; it cannot safely skip the evidence and isolation work.

### Phases

| Phase | Weeks | Main outcome | Exit criteria |
| --- | --- | --- | --- |
| **0. Measure and foundation** | 1–4 | baseline arena, evidence schema, graph v1, campaign skeleton, MCP v1 | baseline report; one external agent runs a scan; unsupported evidence is rejected |
| **1. Campaign kernel** | 5–16 | durable tasks, multi-role agents, resumable campaigns, environment recipes for Node/Python, 10 adapters | four-hour campaign; 95% reproduction; 5 certified adapters |
| **2. Verification and repair** | 17–28 | multi-service/browser runtime, fix proof v2, Java/Go/C#, 20 adapters, enterprise alpha | 8-hour campaign; 6 language packs; 70% fix acceptance target; 20 adapters |
| **3. Learning and enterprise** | 29–40 | skills/framework/router learning, 30 adapters, SSO/RBAC/audit, benchmark report | learning improves held-out results without precision loss; 30 certified adapters; design partners |
| **4. Scale and proof** | 41–52 | performance, air-gapped deployment, independent benchmark, GA readiness | published benchmark; security review; SLA; GA checklist |

### 30 / 60 / 90 days

#### Days 1–30 — make the baseline undeniable

- Freeze a benchmark manifest: repositories, commits, expected findings, proof
  contracts, budgets.
- Add `bench/` runner and a report schema; record current recall, precision,
  reproduction, cost and time.
- Add the evidence ledger schema and the E0–E4 ladder; migrate current findings
  without changing their verdicts.
- Build graph v1: unify Python/TS symbols, routes, sources, sinks and auth into
  one queryable model with provenance.
- Add `src/redfall/campaign/` with a durable task table and a minimal state
  machine; keep existing stages as tools.
- Add MCP server v1 with `index`, `scan`, `findings`, `evidence`, `reproduce`,
  `report`.
- Add adapter contract tests and certify Claude Code, Codex CLI and OpenCode
  first; add a generic MCP fixture.
- Add one environment recipe abstraction and prove it on the existing ranges.

**Exit evidence:** baseline report, one real external-agent scan, one rejected
unsupported finding, one resumed campaign.

#### Days 31–60 — make it agentic

- Add roles and tool allowlists: recon, analyst, planner, exploit author,
  runtime operator, critic, fixer, verifier.
- Add resumable checkpoints, leases, budget reservations and stop conditions.
- Add graph query tools and a hypothesis queue; replace fixed branch enumeration
  with value-of-information ranking.
- Add multi-service runtime (Node + Postgres + Redis) and browser proof.
- Add fix proof v2: regression test, re-scan, patch ranking.
- Add Java and Go experimental packs; certify one.
- Certify 10 adapters; publish the matrix with limitations.
- Add memory v1: case retrieval and a skill registry with tests.

**Exit evidence:** an unattended four-hour campaign; a resumed worker; a patch
with a failing-before/passing-after regression test; 10 adapter contracts.

#### Days 61–90 — make it compounding and sellable

- Add skill promotion gates and a shadow/canary mechanism.
- Add framework-pack learning with fixture validation and human approval.
- Add model capability registry and cost-aware routing.
- Add enterprise alpha: OIDC, RBAC, policy-as-code, audit export, tenant
  isolation tests.
- Certify 20 adapters; add A2A and an HTTP SDK.
- Add 2 more language packs (C#/.NET, PHP) or deepen Java/Go.
- Run the arena against baselines; publish an internal report with limitations.
- Start 3–5 design-partner pilots with written scope and success criteria.

**Exit evidence:** learning gain on a held-out task; tenant-isolation report;
20 certified adapters; design-partner findings and fix acceptances.

### Build vs integrate

| Capability | Decision |
| --- | --- |
| Parser frontends | integrate tree-sitter + compiler/LSP; build the unified graph |
| Deterministic analyzers | integrate Semgrep/CodeQL/Joern/language tools; normalise evidence |
| Sandbox | gVisor first; add Firecracker/Kata for enterprise |
| Workflow durability | Postgres task graph first; evaluate Temporal at scale |
| Browser | Playwright |
| Secrets/SCA | OSV, Syft, Trivy, secret scanners |
| Model access | LiteLLM + capability registry |
| Agent protocols | MCP and A2A first; HTTP/OpenAPI as the universal fallback |
| Reporting | SARIF + JSON + HTML; ticketing integrations |
| Auth | OIDC/SAML via a proven identity provider; do not invent auth |

---

## 10. Engineering standards and the no-mock contract

The existing no-mock contract is a competitive advantage. Extend it; do not
weaken it.

### Rules

1. Every feature has an executable acceptance test.
2. Every finding has an evidence pointer and a reproducibility bundle.
3. Every external analyzer result is a hypothesis until executed.
4. Every model call is real, budgeted and recorded; no synthetic fallback.
5. Every sandbox execution is isolated and attributable.
6. Every learning promotion is versioned, evaluated and reversible.
7. Every adapter has a contract test.
8. Every benchmark claim has a commit, environment digest and raw log.

### Adversarial tests

- a “liar” model that returns a plausible finding with no execution → rejected;
- a report with a missing evidence ID → generation fails;
- a flaky PoC → quarantined, not verified;
- a malicious repository that contains prompt-injection text → ignored as data;
- a tenant trying to retrieve another tenant's memory → denied;
- an adapter that cancels mid-scan → campaign remains consistent;
- a model provider that disappears → explicit blocked state, not a fake result;
- a patch that disables the vulnerable feature → rejected by behaviour checks.

### CI gates

- unit/integration tests;
- no-mock contract;
- evidence schema validation;
- adapter contract suite;
- arena regression;
- sandbox escape and network policy tests;
- tenant isolation tests;
- signed artefacts and SBOM.

---

## 11. Risks and mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Scope explosion across languages | Thin support everywhere | Certify in waves; adapter SDK; publish limits |
| Untrusted code escapes the sandbox | Critical | gVisor/Firecracker, no host mounts, egress deny, seccomp, ephemeral workers, external security review |
| Prompt injection from repository content | False actions/data leak | treat code as untrusted data; tool allowlists; secret redaction; policy engine |
| Model inconsistency | False positives/negatives | E0–E4 ladder, independent verifier, critic, deterministic analyzers |
| Flaky dynamic proofs | Erosion of trust | repeated clean-reset reproduction, flake quarantine, deterministic fixtures |
| Cost blow-up | Unit economics | budgets, routing, caching, early stopping, value-of-information |
| Benchmark gaming | Reputation | holdout, pre-registration, external re-run, raw logs |
| Agent protocol churn | Integration debt | capability probes, contract tests, versioned adapters, HTTP fallback |
| Tenant data leakage | Enterprise blocker | row-level isolation, per-tenant keys, no cross-tenant retrieval, pen test |
| “Autonomous fix” breaks code | Customer harm | proof pipeline, tests, human merge gate, rollback |
| Abuse of offensive capability | Legal/safety | authorised scope, allowlists, policy approvals, no persistence/exfiltration |
| Team tries to build everything | Burnout | moats first; integrate commodity components; narrow ICP |

---

## 12. Non-goals

- A guarantee of finding every vulnerability.
- Unsupervised exploitation of production systems.
- Automatic public disclosure of vulnerabilities.
- A model that rewrites its own safety policy or evaluation set.
- Training on customer code without explicit consent.
- A logo wall of untested agent integrations.
- A “best” claim without a reproducible benchmark.
- Replacing human security judgement for high-impact business logic.
- Building a general-purpose IDE or coding assistant.

### Authorised-use boundary

RedFall 1.0 is designed for code the customer owns or is contracted to test. The
enterprise product will require:

- a written scope and target allowlist;
- repository/branch/environment selection, not an arbitrary URL;
- sandbox-only execution with egress policy;
- no persistence, lateral movement, data destruction or credential use;
- redaction of secrets and personal data from evidence;
- a disclosure workflow for findings that affect third parties;
- audit of every campaign and tool call.

The product should make the safe path the easy path. If a user wants to point it
at someone else's production system, the correct answer is a contract and a
scope, not a prompt.

---

## 13. Decisions required before Phase 1

1. **First ICP**: AppSec teams at large enterprises, AI-coding platforms, MSSPs,
   or regulated industries? This determines language order and deployment.
2. **Deployment first**: SaaS, single-tenant VPC, or self-hosted Kubernetes?
3. **Model policy**: BYOK only, bundled models, or both?
4. **Language order**: Java/Kotlin + Go first, or C#/.NET + PHP?
5. **Benchmark publication**: public leaderboard, private arena, or both?
6. **Commercial model**: per campaign, per repository, per seat, or platform
   subscription?
7. **Design partners**: which 3–5 organisations will provide real repositories,
   ground truth and fix review?
8. **“Hermes” target**: a Nous Research model endpoint, a specific agent runtime,
   or both? The adapter differs, even though the gateway can cover the model.
9. **Licence/open-core boundary**: which parts are open source, which are
   enterprise, and under what licence. This blocks public distribution decisions.
10. **Data policy**: retention, customer-managed keys, whether any telemetry or
    model training is opt-in, and which regions are supported first.

---

## 14. Definition of done for RedFall 1.0

Provisional, to be recalibrated after the Phase 0 baseline:

- [ ] 6 certified language packs; 10 experimental; public support matrix.
- [ ] 50–60 vulnerability classes with proof contracts; 25 current classes
      retained and deepened.
- [ ] 30 certified agent adapters; MCP, A2A and HTTP/OpenAPI surfaces.
- [ ] 8-hour unattended campaign with pause/resume and human gates.
- [ ] ≥95% PoC reproduction from clean bundles.
- [ ] ≥90% reported precision at claimed severity on the arena.
- [ ] ≥70% first-or-second-review fix acceptance with design partners.
- [ ] Multi-service, browser and database-aware verification.
- [ ] Evidence ledger with tamper-evident export; no report without evidence.
- [ ] Learning loop with shadow/canary promotion and automatic rollback.
- [ ] Enterprise alpha: SSO, RBAC, policy-as-code, audit, tenant isolation.
- [ ] Self-hosted/air-gapped deployment with local models.
- [ ] Public benchmark report with baselines, raw logs and limitations.
- [ ] Platform penetration test and SOC 2 readiness assessment.
- [ ] A written “what we cannot do” page that is as prominent as the claims.

---

## Appendix A — proposed module layout

```text
src/redfall/
  campaign/      durable task graph, scheduler, budgets, state machine
  graph/         schema, builders, query API, provenance
  environment/   stack detection, recipes, build/run/reset
  interop/       mcp/, a2a/, http/, adapters/
  evidence/      ledger, bundles, schema validation
  learning/      memory, skills, framework models, router, evals
  enterprise/    auth, policy, tenancy, audit
  runtime/       sandbox pools, service graph, browser/gRPC drivers
  reporting/     sarif, html, json, vex, integrations
bench/
  corpora/       manifests, commits, expected findings
  runners/       fair-budget harness
  reports/       generated results and limitations
tests/
  contract/      adapters, evidence, no-mock guards
  isolation/     sandbox and tenant boundaries
  arena/         ground-truth regression tests
```

## Appendix B — MCP tool surface (illustrative)

```text
redfall.index(repo, commit, include, exclude)
redfall.query_graph(query, budget)
redfall.routes(repo, commit)
redfall.start_campaign(scope, objective, budget, policy)
redfall.campaign_status(campaign_id)
redfall.pause(campaign_id) / redfall.resume(campaign_id)
redfall.findings(campaign_id, grade=E3)
redfall.evidence(finding_id)
redfall.reproduce(finding_id)
redfall.propose_fix(finding_id)
redfall.verify_fix(fix_id)
redfall.report(campaign_id, format="sarif")
redfall.policy_check(action, context)
```

Every tool returns a structured result with `evidence_ids`, `cost`,
`next_actions` and an explicit `blocked_reason` when it cannot proceed.

## Appendix C — evidence record (illustrative)

```json
{
  "evidence_id": "ev_01J...",
  "campaign_id": "cmp_01J...",
  "grade": "E4",
  "finding_id": "fnd_01J...",
  "claim": "IDOR lets principal A read principal B's invoice",
  "source": {"kind": "execution", "execution_id": "exe_01J..."},
  "environment_digest": "sha256:...",
  "poc_hash": "sha256:...",
  "expected_observable": {"status": 200, "body_contains": "invoice-b"},
  "reproduce_command": "redfall reproduce fnd_01J...",
  "artifacts": ["logs.txt", "trace.json", "response.http"],
  "created_at": "2026-10-19T00:00:00Z",
  "previous_hash": "sha256:..."
}
```

The report generator refuses to render a finding whose evidence record is
missing, unverified or fails schema validation.

## Appendix D — adapter contract (illustrative)

```text
1. handshake and capability discovery
2. authentication and scope negotiation
3. submit a task with tools, budget and policy
4. stream structured progress events
5. exchange artifacts and evidence IDs
6. cancel and receive a consistent terminal state
7. resume after a transient failure
8. report cost and token usage
9. redact secrets in logs
10. pass the no-mock negative test
```

An adapter is not “supported” until all ten pass in CI and one live end-to-end
campaign succeeds.

---

## Closing

RedFall does not need to be the smartest model to win. It needs to be the system
that can **prove** what it found, **reproduce** it, **fix** it and **learn** from
the result without lowering its evidence bar. That is the defensible product:
not an AI that claims to hack everything, but an autonomous security layer whose
claims survive a clean machine, a hostile repository and an independent
evaluator.
