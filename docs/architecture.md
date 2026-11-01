---
title: Architecture
description: RedFall's module map, the direction of data flow, and the four seams every new capability goes through.
---

# Architecture

RedFall is organised around four seams. Almost every capability in the system is
an implementation of one of them, which is what keeps breadth affordable in a
project this size.

| Seam | Contract | Implementations | Add one by |
| --- | --- | --- | --- |
| **Language registry** | `LanguageSupport` — is_supported, parse, symbols, taint | 5 languages | Supplying four callables |
| **Reasoning backend** | `ReasoningBackend` — complete a prompt, return structured output | 4 kinds, 12 agent drivers | Implementing one method |
| **Tool registry** | Named operation, scope, handler | 47 tools | Registering a handler |
| **Isolation tier** | `RuntimeTier` — name, isolation level, footprint, probe | 3 tiers | Declaring a tier and its probe |

Everything else — the graph, the branching engine, the chain stage, the
dashboard, the enterprise plane — is built *on* those seams rather than
alongside them.

---

## Module map

```
src/redfall/
  ── entry points ──────────────────────────────────────────────────
  cli.py            the `redfall` command; doctor, scan, findings, reproduce, fix
  cli_agents.py     `redfall agent`   — list, detect, certify
  cli_dashboard.py  `redfall dashboard`
  cli_tenant.py     `redfall tenant`  — create, members, policy, audit-export
  cli_learning.py   `redfall learn`   — propose, evaluate, promote, rollback
  cli_mesh.py       `redfall mesh`    — roles, check, can
  orchestrator.py   drives one scan end to end
  config.py         configuration, prerequisite checks
  triggers.py       the seven adaptive spawn triggers
  version.py        the single source of truth for the version

  ── ingestion ─────────────────────────────────────────────────────
  ingestion/
    languages.py    THE LANGUAGE REGISTRY — one LanguageSupport per language
    tree.py         ParsedFile: a parsed file and a text accessor
    symbols.py      shared symbol dataclasses (FileSymbols, RouteSymbol, ...)
    taint.py        shared taint dataclasses (Taint, ScopeTaint)
    parser_ts.py    TypeScript / JavaScript
    symbols.py, taint.py, inter.py, inter_ts.py   the TS engine
    parser_py.py, symbols_py.py, taint_py.py      the Python engine
    parser_java.py, symbols_jvm.py, taint_jvm.py  the JVM engine (Java + Kotlin)
    parser_go.py, symbols_go.py, taint_go.py      the Go engine
    cache.py        content-addressed parse cache
    ingest.py       the ingest loop — walks a tree, calls the registry
    persist.py      writes files, symbols, taint paths into the store
    deps.py, gitrepo.py
    (22 modules)

  ── analysis ──────────────────────────────────────────────────────
  graph/            persisted, provenance-aware code graph (5 modules)
  branching/        the adaptive branch tree, the worklist, the workspace pool
  chain/            cross-branch exploit chaining and compound CVSS
  agent/            the exploit authoring stage; categories.py is the class registry
  agents/           the 12 agent CLI drivers (18 modules)

  ── execution ─────────────────────────────────────────────────────
  validation/       the sandbox driver: boot the target, run the PoC, evaluate
  sandbox/
    docker_gvisor.py  the container executor
    tiers.py          THE ISOLATION LADDER and the capacity planner
  range/  (repo root) the ground-truth targets: vulnbank, pythonbank, chainbank

  ── record ────────────────────────────────────────────────────────
  evidence/         the E0–E4 ledger and its hash chain
  store/            SQLAlchemy models, engine, models_tenant, models_learning
  fix/              the repair loop
  reporting/ , sarif.py

  ── surfaces ──────────────────────────────────────────────────────
  interop/          MCP stdio, HTTP/OpenAPI, A2A, webhooks, audit (12 modules)
  dashboard/        the console API and its SSE event bus

  ── platform ──────────────────────────────────────────────────────
  enterprise/       tenancy, roles, policy, audit export (5 modules)
  learning/         the lesson registry and its promotion gates (3 modules)
  mesh/             role definitions and backend binding (3 modules)

  ── reasoning ─────────────────────────────────────────────────────
  reasoning/
    backend.py        THE REASONING SEAM + the semantic cache
    agent_backend.py  an installed agent as a backend
    litellm_backend.py, openai_compat.py
    router.py         per-tier routing and consensus
    factory.py        the only constructor the engine uses
```

## Direction of data flow

```
                    ┌───────────────┐
   source tree ────► │  ingestion    │ ────► ParsedFile
                    │  (registry)   │
                    └───────────────┘
                            │ symbols, taint
                            ▼
                    ┌───────────────┐
                    │  graph        │ ────► graph_nodes / graph_edges
                    │  builder      │
                    └───────────────┘
                            │
                            ▼
                    ┌───────────────┐     ┌──────────────┐
                    │  branching    │◄────┤ reasoning    │  (agent asks a model,
                    │  (branch tree)│     │ backend seam │   or an installed agent)
                    └───────────────┘     └──────────────┘
                            │ candidates
                            ▼
                    ┌───────────────┐
                    │  validation   │ ────► sandbox tier (firecracker│gvisor│container)
                    │  (execute)    │
                    └───────────────┘
                            │ reproduced / not
                            ▼
                    ┌───────────────┐
                    │  evidence     │ ────► hash-chained records
                    │  ledger       │
                    └───────────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
      ┌───────────────┐           ┌──────────────┐
      │  fix loop     │           │  reporting   │  SARIF / JSON / console
      └───────────────┘           └──────────────┘
```

**The rule the arrows encode:** nothing flows *backwards*. A candidate does not
become more credible because a model was confident about it; only execution at
the `validation` stage changes its grade. This is why static analysis can be
approximate without compromising the output — its errors are absorbed at the
gate rather than propagated into a report.

## The four seams in detail

### Adding a language

`ingestion/languages.py` holds a tuple of `LanguageSupport` records, each with
four callables:

```python
@dataclass(frozen=True)
class LanguageSupport:
    name: str
    is_supported: Callable[[str | Path], bool]
    parse:        Callable[[str | Path, bytes | None], ParsedFile | None]
    symbols:      Callable[[ParsedFile], FileSymbols]
    taint:        Callable[[ParsedFile, FileSymbols], list[Taint]]
```

A new language supplies those four and is added to `SUPPORTED`. The ingest loop
never changes. The shared `FileSymbols`, `RouteSymbol`, `Taint` and `ScopeTaint`
dataclasses are what the graph and the branch engine consume, so a language that
produces them is immediately visible to everything downstream.

There is deliberately **no node-type abstraction layer**. Each engine writes its
own tree-walking against its own grammar. An abstraction over five unrelated
grammars would be a worse artifact than five honest walkers, and it would hide
the per-language facts that matter — that Go imports bind their last path
segment, that a Java annotation arrives as `marker_annotation` when it has no
arguments.

**A language is certified only when a category reproduces against a real target
it can execute.** Supplying the analyser is not certification, and the registry
distinguishes the two.

### Adding a reasoning backend

Implement `ReasoningBackend`. The factory is the only constructor the rest of
the engine uses:

```python
make_backend(config: BackendConfig, *, session_factory, budget) -> ReasoningBackend
```

It never falls back to something weaker. If no backend can be constructed it
raises and names the options, because a scan whose quality depends on which
agents happened to be installed would produce findings nobody could reproduce.

### Adding a tool

Register a handler with a name, a scope and a callable. Every surface — the CLI,
MCP stdio, the HTTP gateway, A2A, the dashboard — delegates to the same
registry, so an operation is defined once and cannot drift between surfaces.

### Adding an isolation tier

Declare a `RuntimeTier` with its name, isolation level, per-unit memory and CPU,
startup latency and a probe function. The probe returns the reasons the tier is
unavailable, empty when it is ready. `detect_tier()` walks the ladder
strongest-first and picks the first ready tier at or above the required
isolation — so a host with both KVM and Docker gets the microVM without an
operator choosing.

## Concurrency

The project is thread-based, not asyncio. The established pattern is a
short-lived session per unit of work, plus a lock for shared scalars.

Branches run on a `BranchWorklist` bounded by `config.sandbox_pool_size`. The
shared branch tree, the findings callback and the spawn queue all stay on the
caller's thread; only sandbox work is parallel. Workers catch `BaseException`
and return it rather than re-raising, so one failing branch cannot take down the
scan.

Per-call database sessions are an **opt-in seam**: `run_branch`, `validate` and
`ingest` accept an optional session. The sequential path is byte-identical to
what it was before parallelism existed.

> This last point is a known liability, not a feature. Two execution paths
> through the core is a compounding maintenance cost — see
> [cons §7](analysis/cons.md#7-a-single-shared-sqlalchemy-session-design-patched).

## Storage

| Store | Holds | Engine |
| --- | --- | --- |
| Postgres | campaigns, findings, evidence chain, graph, tenants, lessons | SQLAlchemy 2.0 |
| SQLite | local console use, and the parse cache | same models |
| Redis | shared scan state and merge-under-WATCH | optional |

`store/db.py` calls `create_all`, which is idempotent, so a fresh database is
provisioned on first use without a migration tool. Schema changes to an existing
database are additive columns with defaults.

## Where a change belongs

| Changing | Goes in |
| --- | --- |
| How a language is parsed or traced | `ingestion/` — and add to the registry only when a target proves it |
| What a scan does next | `branching/`, then `triggers.py` if it is a new signal |
| How a finding is proven | `validation/` and `evidence/ledger.py` |
| What the engine knows | `graph/` |
| How it reasons | `reasoning/` behind the seam |
| What is exposed | `interop/tools.py` — the registry is the single definition |
| How it is isolated | `sandbox/tiers.py` — declare a tier, do not special-case |
| What a team may do | `enterprise/roles.py` — the permission table is the spec |
