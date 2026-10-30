# RedFall — Master Plan, 0.2.0 → 0.5.0

> Status: **plan for approval.** Nothing here is a release note. Each item is
> done when it has a real test, a reproducible run, and a measured number — the
> same bar `scripts/check_no_mock.py` already enforces.

Baseline: **v0.1.1** (2026-10-21). Two-language verified scanner, campaign
runtime, evidence ledger, graph v1, 44 MCP/HTTP/A2A tools, LiteLLM BYOK.

The core shift this plan makes:

**0.1.x = "RedFall has its own AI."**
**0.5.0 = "RedFall has no AI of its own. It borrows yours."**

RedFall stops being an LLM product and becomes an **AI-agnostic security
execution layer**: any agent (Claude Code, Codex, Cursor, Gemini CLI, Aider,
Goose, OpenHands, …) plugs in, and RedFall supplies the code graph, the sandbox,
the proof, the fix, and the dashboard. Zero provider keys required.

---

## 0. Honest baseline — what actually exists vs. what you asked for

Measured from the tree, not the README.

| You asked for | State at 0.1.1 | Gap |
| --- | --- | --- |
| "Doesn't need an AI API" | ❌ Requires `OPENAI_API_KEY`/`ANTHROPIC_API_KEY`; `check_prerequisites` **hard-fails** the scan without one (`config.py:159`) | The whole model layer must become pluggable |
| "Connects to your agents" | ⚠️ RedFall *is* an MCP **server** (agents call it). It is **not** an MCP **client** — it cannot call out to Claude Code/Codex to borrow their reasoning | Needs an outbound agent-driver layer (the inverse direction) |
| "12 agents supported" | ❌ 0 agent drivers | New subsystem |
| "Custom option" | ⚠️ Only via `REDFALL_MODEL_*` env vars → LiteLLM | Needs a first-class provider/agent registry + config file |
| "Amazing dashboard" | ⚠️ A **read-only static** Next.js report viewer (644 lines, reads JSON off disk, `force-dynamic`) | Needs live, interactive, streaming control plane |
| "Real working agents find real vulns" | ✅ Real engine, but **LLM-driven** and blocked without a key | Rewire so the *agent* does the reasoning, not LiteLLM |
| "One-click fix" | ⚠️ `fix/fixer.py` exists but is reachable only via CLI/agent tool, unverified without sandbox | Needs UI one-click + applier safety rails |
| "Blazing fast" | ⚠️ Sequential per-branch; exact-match cache only | Needs parallelism, incremental index, cache graph |
| "Advanced system" | ✅ Genuinely strong: taint, chains, evidence ledger, SARIF | Depth/speed/languages are the gaps |

**Verdict: the scanner is ~70% built and good. The *product you're describing* is ~15% built.** The missing 85% is concentrated in three places: **(1) the model layer → agent layer rewrite, (2) the dashboard, (3) breadth/depth/speed.**

---

## 1. Architecture decision (read this first)

Everything below depends on one choice. I recommend **all three, layered**:

```
                 ┌─────────────────────────────────────────┐
   Agent CLIs ──►│  AgentDriver  (0.2.0)                   │  ← "BYO agent, no key"
   (claude,      │  spawns a local agent, speaks its       │
    codex, …)    │  protocol, returns structured JSON      │
                 └────────────────┬────────────────────────┘
                                  │
                 ┌────────────────▼────────────────────────┐
   HTTP APIs ───►│  ProviderAdapter (0.2.0)                │  ← "custom / any API"
   (OpenAI,      │  LiteLLM + OpenAI-compatible + local    │
    Ollama, …)   │  (Ollama/vLLM) — kept from 0.1.x        │
                 └────────────────┬────────────────────────┘
                                  │
                 ┌────────────────▼────────────────────────┐
   The engine ──►│  ReasoningBackend interface (core)      │  ← one seam
   (unchanged    │  .complete(stage, messages) -> JSON     │
    ingestion,   │  .propose_chain(...) / .propose_fix(...)│
    sandbox,     │  .budget / .transcript                  │
    evidence)    └─────────────────────────────────────────┘
```

**Rule:** the engine only ever calls `ReasoningBackend`. `AgentDriver` and
`ProviderAdapter` are two implementations of it. That is a small, testable
refactor of `llm.py` (514 lines) and is the single highest-leverage change in
this plan.

Why this matters: it means "no AI API needed" is not a special mode — it's just
`backend = AgentDriver("claude-code")` instead of `backend = LiteLLM(...)`.

---

# 0.2.0 — "Bring Your Own Agent"  — ✅ SHIPPED 2026-10-29

**Theme:** Zero keys. The agent you already pay for becomes RedFall's brain.
**Size:** ~6 subsystems, largest release. **Unblocks everything after it.**

> **Implemented.** Ship-review state, all measured locally:
>
> - `ReasoningBackend` seam in `src/redfall/reasoning/`; `LiteLLMBackend` behind
>   it with the 0.1.x suite unchanged (proof it is behaviour-preserving).
> - 12 drivers in `src/redfall/agents/drivers/` + the custom escape hatch;
>   `redfall agent certify` runs one for real (4 checks).
> - `AgentBackend`, `OpenAICompatBackend`, `RouterBackend` (tier routing +
>   consensus); `redfall.toml` config with the 0.1.x env vars still honoured.
> - Engine wired through the factory; `scan`/`fix` no longer require a provider
>   key. `redfall agent list|detect|certify|config` on the CLI; two new interop
>   tools (46 total).
> - **Self-test (`tests/test_agent_driven_scan.py`):** RedFall drives RedFall via
>   a real agent subprocess with both provider keys removed, over real ingestion
>   of `range/vulnbank` (21 files, 27 routes).
> - **Full suite: 379 passed, 30 skipped, 0 failed.** All four contract checkers
>   pass (`NO-MOCK` 107 files, orphans 105/105, version, clean tree).
> - **Tested with RedFall itself:** `redfall agent detect` resolves to
>   `agent:claude-code` on this host with no key present; a scan now refuses on
>   the *sandbox* alone (no container runtime), not on a missing key.

### 0.2.1 — ReasoningBackend seam (foundation)

- Extract `ReasoningBackend` protocol from `llm.py`: `complete()`, `budget`,
  transcripts, `model_for_tier`, JSON repair (`extract_json` is already clean
  and reusable).
- `LiteLLMBackend` = today's behaviour, behind the interface. Tests unchanged →
  proof the refactor is behaviour-preserving.
- Move `check_prerequisites` LLM check from **hard-fail** to
  **"no backend configured"** and let `AgentDriver` satisfy it.
- **Done when:** full 0.1.1 suite passes with zero LLM-behaviour diffs, plus new
  interface-conformance tests.

### 0.2.2 — AgentDriver framework

- `AgentDriver` ABC: `detect()`, `invoke(prompt, schema) -> dict`, `capabilities()`,
  `cost_estimate()`, `health()`.
- Two transport modes, covering most of the field:
  - **`cli`** — spawn `claude -p`, `codex exec`, etc., pass prompt via stdin,
    parse JSON from stdout.
  - **`mcp`** — RedFall as MCP *client* to an agent that exposes one.
  - (future) **`openai_compat`** — for local agents exposing an API.
- **Structured-output contract:** the driver must return JSON matching the
  engine's existing schemas (finding, chain, fix). Drivers wrap the prompt with
  the schema and validate; failure → `JSONParseError` (already exists).
- **Conformance harness** `redfall agent certify <name>` mirroring
  `redfall mcp certify`: fresh subprocess, handshake, one real JSON task, one
  refusal case. Emits an `AdapterCertification` row — reuse the existing table.
- **Done when:** `certify` produces a real, timestamped certification row for a
  driver, with the same no-mock discipline as the interop certifier.

### 0.2.3 — The 12 shipped drivers (0.2.3–0.2.6)

Ship in waves so each wave is certifiable on its own.

| Wave | Version | Drivers | Notes |
| --- | --- | --- | --- |
| W1 | 0.2.3 | **Claude Code**, **Codex CLI**, **Gemini CLI**, **Aider** | Highest demand; all have clean non-interactive CLI modes |
| W2 | 0.2.4 | **Cursor Agent CLI**, **Goose**, **OpenHands**, **Continue** | Mixed CLI/API |
| W3 | 0.2.5 | **Cline**, **Kilo Code**, **Qwen Code**, **Crush** | Community + OSS agents |
| W4 | 0.2.6 | **Custom** (user-defined JSON spec) | The escape hatch; makes "12+" honest |

- Each driver: `detect()` via `shutil.which` + version probe; graceful
  `AgentNotInstalled` naming the exact install command.
- **`redfall agent list`** shows detected drivers + version + certification state.
- **Done when:** each wave's drivers pass `certify` in CI (skip-if-absent, like
  the existing 5 live-gVisor skips — never fake a pass).

### 0.2.7 — Custom backend & config file

- `redfall.toml` (or `~/.config/redfall/config.toml`) — first-class config so
  users stop juggling env vars.
- `[backend] kind = "agent" | "litellm" | "openai_compat" | "custom"`.
- **Custom agent spec:** name, command, prompt template, output parse (JSON
  path or regex), env passthrough. This is how someone wires an agent we
  never heard of.
- **Custom provider spec:** base_url + model + key env → OpenAI-compatible.
  Covers Ollama, vLLM, LM Studio, OpenRouter, any gateway.
- **Done when:** a config-only, no-code addition of a brand-new agent works end
  to end and is covered by a test that uses a stub command (real subprocess, not
  a mock — consistent with the no-mock contract's *intent*).

### 0.2.8 — Multi-agent routing

- Route **by tier**: `fast` tier → cheap/local agent, `deep` tier → strongest
  agent. E.g. classify with Gemini CLI, propose chains with Claude Code.
- Route **by capability**: driver declares `supports_long_context`,
  `supports_schema`, `max_output`.
- **Consensus mode:** run the same analysis prompt across N agents, keep
  findings where ≥k agree → then always verify in the sandbox (agreement is a
  prior, never proof).
- **Done when:** routing is config-driven and measured — a test shows a
  two-driver config actually invoked both on the right stages.

---

# 0.3.0 — "Live Control Plane" (the dashboard)  — ✅ SHIPPED 2026-10-29

**Theme:** From static report viewer → real-time security operations console.
**Size:** ~5 subsystems. Frontend-heavy.

### 0.3.1 — Backend for the UI

- RedFall has **no HTTP API for the UI** today (there's an agent gateway; the web
  app reads files). Add a purpose-built API:
  - `GET /api/scans`, `GET /api/scans/{id}`, `GET /api/scans/{id}/events` (SSE)
  - `POST /api/scans`, `POST /api/scans/{id}/pause|resume|cancel`
  - `GET /api/findings`, `POST /api/findings/{id}/reproduce`
  - `POST /api/findings/{id}/fix` (one-click), `GET /api/graph/...`
  - Reuse the existing `ToolRegistry` handlers — **do not duplicate logic.**
- Reuse the A2A SSE plumbing already written for streaming (`interop/a2a.py`).
- **Done when:** every UI action maps to an existing, tested tool handler.

### 0.3.2 — Live scan view

- Real-time branch tree (the adaptive tree already emits events via `on_event`
  in `orchestrator.py` — surface it).
- Live token/cost/budget meters; live finding stream; severity × category
  heatmap.
- **Done when:** a running scan streams events to the browser with no polling
  and no fabricated placeholders (the current UI's "we do not invent data"
  stance stays — but now with nothing missing to invent).

### 0.3.3 — Findings & proof workspace

- Every finding → evidence chain (E0–E4), PoC, transcript, sandbox exit code,
  SARIF view, one-click reproduce.
- Diff view for the proposed fix, side by side with the PoC result
  (`reproduced: before / after`).

### 0.3.4 — One-click fix (safe by construction)

- **Dry-run by default.** Apply writes to a **branch**, never the working tree,
  and only after the fixer's own gate: PoC fails + target tests pass.
- Show blast radius: files touched, tests affected, confidence. Refuse on
  low confidence and say why (matches the `BLOCKED.md` honesty culture).
- Bulk fix with per-fix review; export as patch / PR.
- **Done when:** a fix applied via the UI is verifiable by rerunning the PoC in
  the UI, and a refused fix states its reason.

### 0.3.5 — Multi-project / campaign console

- Project switcher, campaign list, budget board, diff-since-last-scan.
- Auth: local single-user first; RBAC/SSO deferred to 0.5.0.
- **Done when:** two projects coexist with isolated scans/findings.

**Note on your "clean first" ask:** 0.3.0 is where the `web/` app gets rewritten
properly (typed API client, real component structure, no `force-dynamic` file
reads). I'd do the cleanup **inside 0.3.0**, not as a separate sweep — the old
UI is replaced, so cleaning it first is wasted work.

---

# 0.4.0 — "Deeper, Broader, Faster"  — ✅ SHIPPED 2026-10-30 (languages uncertified)

**Theme:** More real vulnerabilities, more languages, materially faster.
**Size:** ~6 subsystems + benchmarking.

### 0.4.1 — Speed (make it "way faster")

Measured targets, not vibes:

| Lever | Change | Expected |
| --- | --- | --- |
| **Parallel branches** | Branch analysis is sequential today → worker pool (bounded by sandbox pool) | ~N× on N cores |
| **Sandbox pool reuse** | Warm pool instead of per-PoC container spin-up | −60–80% per-PoC wall time |
| **Incremental index** | Hash files; re-index only changed (graph v1 has snapshots already) | seconds on re-scan |
| **Reasoning cache v2** | Semantic (not just exact-match) cache + cross-scan reuse | fewer agent calls |
| **Agent concurrency** | Multiple driver invocations in flight | fewer stalls |

- **Done when:** a benchmark number exists for each, in CI, on the range targets.

### 0.4.2 — Depth (find the hard ones)

- **Multi-hop taint** (today: bounded interprocedural). Add field-sensitive
  alias analysis, container-element tracking, sanitizer modeling.
- **Framework packs v2:** auth/session flows, ORM query builders (Prisma,
  TypeORM, SQLAlchemy, Django ORM), template engines, deserialization.
- **Vulnerability classes 25 → 45+**, each with a *proof contract* (the
  `Category` dataclass already has `proof`/`fix_strategy` — extend it).
- **Business-logic flaws** (race conditions, price/quantity tampering, workflow
  bypass, mass assignment) — the classes the current 25 don't cover.
- **Done when:** each new category reproduces against its own range target; new
  categories that can't reproduce are listed in `NOT_COVERED` with the reason
  (existing honest pattern).

### 0.4.3 — Languages (2 → 6+)

Extend `ingestion/languages.py` — the registry was designed for this.

- **0.4.1:** Java + Kotlin (JVM, Spring) — highest enterprise demand.
- **0.4.2:** Go (net/http, Gin, Echo).
- **0.4.3:** C# / .NET (ASP.NET Core).
- **0.4.4:** PHP (Laravel, Symfony) + **Ruby** (Rails).
- Each: parse + symbols + taint + route extraction + a range target + certified.
- **Done when:** a language ships only with a real vulnerable target it reproduces
  against — no "tree-sitter grammar exists" claims.

### 0.4.5 — Environment synthesis

- The hardest real blocker: making arbitrary repos actually *run* in the sandbox.
- Recipes: detect stack → generate Dockerfile/compose → seed DB → start services.
- Start with Node/Python (today's recipes), then JVM/Go/.NET.
- **Done when:** an unseen repo boots to a healthy state without hand-holding,
  and failures are recorded (not faked).

### 0.4.6 — Benchmark arena

- Pre-registered, reproducible head-to-head vs. other tools on a versioned
  corpus. This is what makes any "better than everything" claim real instead of
  marketing — and the README already refuses unearned superlatives.
- **Done when:** `redfall bench run` produces a signed, reproducible result bundle.

---

# 0.5.0 — "Platform"

**Theme:** It becomes infrastructure a team can adopt.
**Size:** heaviest, but mostly additive.

- **0.5.1 Enterprise control plane** — multi-tenancy, RBAC/ABAC, SSO (OIDC/SAML),
  policy-as-code, audit export, SIEM/SOAR + ticket integration, air-gapped deploy.
- **0.5.2 Learning loop** — verified campaigns → tested skills/framework models/
  routing policies, with shadow/canary promotion and rollback. **Only from
  verified outcomes** — never from raw model output.
- **0.5.3 Scale-out** — Firecracker microVMs, the Rust orchestrator, NATS
  (currently in `BLOCKED.md`). Horizontal campaigns.
- **0.5.4 Agent mesh** — RedFall both calls agents and is called by them;
  multi-agent campaigns with roles (recon / exploit / fix / verify) where each
  role can be a *different* vendor's agent.
- **0.5.5 Distribution** — Docker image, one-line install, managed option.
- **0.5.6 Public claim** — only after the 0.4.6 arena result is third-party
  reproducible.

---

## 2. Sequencing & dependencies

```
0.2.0  RationaleBackend + AgentDriver + 12 drivers + custom   ← everything needs this
  │
  ├──► 0.3.0  Live dashboard  (consumes the API; independent of drivers, but
  │           far more useful once any agent can drive a scan)
  │
  └──► 0.4.0  Speed + Depth + Languages  (benefits from drivers: parallel agents)
                │
                └──► 0.5.0  Platform
```

- **0.3.0 can run in parallel with 0.4.0** if you staff two tracks — they touch
  different files (web/ vs src/redfall/ingestion/).
- **0.2.0 blocks nothing but enables everything** — do it first.

### Suggested personnel split (if you have 2+ contributors)
- **Track A:** 0.2.0 → 0.2.x drivers.
- **Track B:** 0.3.0 dashboard (starts once 0.3.1 API lands on Track A's 0.2.1).
- **Track C:** 0.4.x language packs (start Java early; it's the longest pole).

---

## 3. What I'd cut or defer (honesty section)

- **Named-agent count is a vanity metric.** "12 agents" is marketing; two
  transports (`cli` + `openai_compat`) cover ~90% of real agents. Ship the
  **Custom** driver first-class and the count follows for free. I'd certify 12
  but *sell* the generality.
- **0.5.x is not 2026 work.** The arena (0.4.6) and environment synthesis
  (0.4.5) are each bigger than 0.2.0. Don't let 0.5.0's scope leak backward.
- **Don't rewrite the engine.** It's the best part of this repo. Everything here
  is additive or a seam, except `web/` (replaced) and `llm.py` (wrapped).
- **The no-mock contract is a feature, not friction.** Every new subsystem obeys
  it. That's what makes any "better" claim defensible.

---

## 4. First 5 concrete commits (if approved)

1. `refactor(llm): extract ReasoningBackend protocol; LiteLLM as first impl`
2. `feat(agent): AgentDriver ABC + CLI transport + JSON contract validation`
3. `feat(agent): claude-code driver + redfall agent certify`
4. `feat(config): redfall.toml + backend selection (agent|litellm|openai_compat|custom)`
5. `feat(api): scan SSE endpoint backing the dashboard`

Each is independently testable and lands a working increment.
