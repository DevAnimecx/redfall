---
title: How RedFall works
seoTitle: "RedFall Architecture: From Source to Verified Finding"
description: "The RedFall scan pipeline: tree-sitter ingestion, taint analysis, adaptive branches, LLM planning, gVisor execution, chaining and verified repair."
path: docs/architecture/
group: How it works
kind: pillar
pillar: architecture
order: 1
updated: 2026-10-19
keywords: vulnerability scanner architecture, taint analysis pipeline, gVisor vulnerability scanner
sources: https://github.com/DevAnimecx/redfall, https://tree-sitter.github.io/tree-sitter/, https://gvisor.dev/docs/
related: taint-analysis, sandbox, adaptive-scanning
---

**RedFall is an orchestrated pipeline: ingest the real source, find tainted routes, split the work into branches, generate candidate findings, execute each candidate in a gVisor sandbox, chain only what reproduced, and verify a repair against the target's own tests.** Each stage writes evidence the next stage reads; no stage is allowed to skip the execution gate.

This page describes the architecture as it exists in the 0.1.0 source. Component names match the repository layout so a reviewer can follow a claim into the code. Capabilities that are written but cannot run on the development host are separated from capabilities that were measured.

## What is the scan pipeline?

The orchestrator runs six stages. The names are stable across the CLI, the database and the SARIF export.

| Stage | Module | Input | Output |
| --- | --- | --- | --- |
| Ingest | `ingestion/` | Repository files | Parsed files, symbols, routes, calls, dependencies, git metadata |
| Plan | `orchestrator.py` + `branching/tree.py` | Route inventory and call graph | A recursive branch tree |
| Analyse | `agent/` + `llm.py` | Branch scope, taint paths, dependency versions | Candidate findings |
| Execute | `sandbox/` + `validation/harness.mjs` | Candidate and boot contract | Reproduced finding or a discard |
| Chain | `chain/` | Reproduced findings and their responses | Verified graph edges and a composite PoC |
| Fix | `fix/` | One finding and the target | Verified patch or a human handoff |

The [execution verification pillar](/docs/verified-findings/) explains why the execute stage is the only one allowed to create a finding. This page explains how the stages are assembled and where state lives.

## How does ingestion work?

Ingestion is deterministic and language-aware. Every `.ts`, `.tsx`, `.js`, `.jsx` and `.py` file is parsed with tree-sitter. The parser extracts:

- Files, symbols and their source ranges.
- Route registrations and the handler that receives the request.
- Middleware, imports and call edges.
- Database, `exec`, filesystem, redirect and fetch calls.
- Package manifests and installed dependency versions.
- The target commit, so a scan is tied to a build.

Route extraction is shape-aware rather than regex-based. It recognises Express and Fastify/koa-router verb calls, NestJS `@Controller`/`@Get` decorators lifted to full paths, and Python Flask/FastAPI blueprints. Express mounts and Flask blueprint prefixes are resolved through imports, so `router.post('/login')` mounted under `/api/auth` becomes `POST /api/auth/login`. The [taint analysis page](/docs/taint-analysis/) covers the dataflow pass; the [languages page](/docs/languages/) covers exactly what is and is not parsed.

## How does taint analysis find candidates?

Taint analysis runs inside each enclosing function first. Sources are the request surfaces an attacker controls: `req.body`, `req.query`, `req.params`, `req.headers` and `req.cookies` in JavaScript, and `request.args`, `request.form`, `request.json`, `get_json`, `headers` and `cookies` in Python. Sinks are query, exec, filesystem, redirect and eval calls.

A depth-one interprocedural pass then connects functions. Each callee's parameters are pre-tainted to build a per-function summary. A call site becomes a hop only when the argument is already tainted by a real source and the matching parameter reaches a sink. Resolution uses import bindings — relative ESM specifiers, aliases, namespaces, CommonJS `require`, Python relative imports — never name matching. The caller is named in the taint's `via` chain.

Return flow is proved the same way. If a callee's return path reads a source or a local derived from one, every call result is tainted at the caller's sink. Pass-throughs of parameters are not claimed by the summary, because the caller's own taint already covers them. Every resolvable call also becomes an edge in the `call_edges` graph, which route attribution follows transitively and across files.

Sanitisers are recorded but never clear taint. That is deliberate: RedFall does not claim to know that a function called `escapeHtml` neutralises an SQL sink. The execution gate is how that question gets answered.

## How does the branch tree control work?

Planning splits the route inventory into branches rather than sending the whole repository to a model in one prompt. Branches are recursive: a branch can spawn children with narrower scope. The tree records the parent, the scope files and routes, the depth and the reason a branch exists.

Seven adaptive detectors run over the same source and can spawn a branch mid-scan. The [adaptive scanning page](/docs/adaptive-scanning/) lists the seven surfaces and the rules that keep spawning honest, including the requirement that a child's `spawned_at` is strictly after both the parent's start and the trigger's discovery.

References to files or routes that do not exist in the graph are dropped at plan time. A model proposal is not a scope grant.

## Where does the LLM sit?

The model is a proposal engine, not an authority. It receives a branch's real source, proven taint paths and installed dependency versions, and returns candidate findings. A candidate still has to survive the sandbox.

`llm.py` uses LiteLLM with bring-your-own-key credentials. It supports model tiers and a token/cost budget, and stores verbatim request and response transcripts. If no credential is configured, the call raises an error rather than returning a synthetic completion. That behaviour is part of the no-mock contract.

The model also appears in the chain stage: it proposes wirings over findings that already reproduced, and `chain/plan.py` reviews each proposal structurally before anything is replayed. The [exploit chaining page](/docs/exploit-chaining/) describes the admission rules.

## How is state stored?

The data layer is SQLAlchemy over PostgreSQL, with Redis for runtime state. The persisted rows are the record of the scan: scans, branches, taint paths, candidate findings, reproduced findings, chain edges, fix attempts and the raw request/response/verdict for each execution.

The chain graph is rebuilt from persisted rows, never from the stage's in-memory state. That makes the graph auditable after the process exits and prevents a model narrative from becoming the source of truth. The SARIF exporter reads the same store, so the log a reviewer downloads is derived from the same rows the scanner used. See [SARIF output](/docs/output/).

## What fails closed?

The architecture is built so that missing prerequisites produce a visible failure rather than a fallback. `config.py` asserts prerequisites instead of assuming them. `redfall doctor` reports which prerequisites the host satisfies; `redfall environment` prints the capability report as JSON.

The failure points that matter most:

| Missing prerequisite | Behaviour |
| --- | --- |
| Docker or a gVisor runtime | Execution cannot start; no finding is reported |
| LLM provider key | The LLM call raises; no canned completion |
| Target boot contract | The sandbox cannot boot the app; the candidate does not reproduce |
| Postgres | The store cannot persist the scan; the pipeline stops |

The development host used for 0.1.0 has no container runtime and no provider key, so a full `redfall scan` cannot run here. That is recorded in [BLOCKED.md](https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md) and summarised on the [blocked page](/docs/blocked/). The code paths that can run — ingestion, taint analysis, route extraction, range replays and the unit/contract suite — were measured.

## What is built, and what is not?

The 0.1.0 repository is explicit about the boundary. Built and verified components include ingestion for TypeScript/JavaScript and Python, intra- and interprocedural taint with return flow, the seven adaptive detectors, the branch tree, the chain planner/executor/graph, the fix loop, SARIF export, the gVisor executor and its harness, the store, the CLI, the four range targets and the scorer.

The [README status table](https://github.com/DevAnimecx/redfall#status-right-now) is the authoritative summary. The [blocked page](/docs/blocked/) records the infrastructure that is written but unexercised on this host, including the sandbox and live LLM calls. Nothing in this documentation converts an unexercised path into a measured capability.

## How can you inspect the architecture?

Start from the repository rather than a diagram:

1. `src/redfall/orchestrator.py` for the stage order.
2. `src/redfall/ingestion/ingest.py` for parsing and the taint entry point.
3. `src/redfall/branching/tree.py` and `adaptive.py` for the branch model.
4. `src/redfall/sandbox/` and `src/redfall/validation/harness.mjs` for execution.
5. `src/redfall/chain/` for composition and admission.
6. `src/redfall/store/models.py` for the persisted record.
7. `tests/` for the properties each module is expected to hold.

The source is public, the tests name the properties they check, and [CONTRIBUTING.md](https://github.com/DevAnimecx/redfall/blob/main/CONTRIBUTING.md) documents the no-mock rule a change must preserve.

## Frequently asked questions

### Is the pipeline one model call?

No. Ingestion and taint analysis are deterministic. The model is used per branch to propose candidates and in the chain stage to propose wirings; both proposals are reviewed and executed before they become results.

### Why use a branch tree instead of scanning the whole repository at once?

A smaller scope gives the model the real source and the taint paths that matter for that branch, and it makes failures attributable. A branch that cannot be planned is a visible scope error, not a silent omission in a giant prompt.

### Can I run a scan without gVisor?

You can run ingestion, taint analysis and the parts of the range suite that do not need a container. You cannot produce a verified finding, because that requires execution. The CLI reports the missing prerequisite rather than pretending.
