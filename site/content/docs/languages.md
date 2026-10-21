---
title: Languages and frameworks supported
seoTitle: "Supported Languages and Frameworks | RedFall"
description: "RedFall parses TypeScript, JavaScript and Python with tree-sitter, recognises Express, Fastify, NestJS, Flask and FastAPI routes, and covers 25 of 32 seeded categories."
path: docs/languages/
group: How it works
kind: cluster
pillar: architecture
order: 7
updated: 2026-10-21
keywords: TypeScript vulnerability scanner, Python security scanner, Express security, Flask security scanner
sources: https://tree-sitter.github.io/tree-sitter/, https://github.com/DevAnimecx/redfall/blob/main/src/redfall/agent/categories.py
related: taint-analysis, ranges, architecture
---

**RedFall 0.1.1 reads TypeScript, JavaScript and Python.** It parses the source with tree-sitter, extracts routes, handlers, calls and dependencies, and runs taint analysis for both language families. It does not claim Java, Go, Rust, C# or PHP coverage.

The language boundary is deliberate. A parser that half-understands a language produces routes and taint paths that look plausible and fail at execution. RedFall would rather name the supported set than advertise a language it cannot parse.

## Which file types are parsed?

| Language family | Extensions | Parser |
| --- | --- | --- |
| TypeScript / JavaScript | `.ts`, `.tsx`, `.js`, `.jsx` | tree-sitter TypeScript/JavaScript |
| Python | `.py` | tree-sitter Python |

The language registry exposes the same four operations for every supported language: support check, parse, symbol extraction and taint analysis. Adding a language means supplying those operations, not editing the ingestion loop.

The parser extracts files, symbols, routes, handlers, middleware, calls, imports, database/exec/fs/fetch calls and package metadata. The git commit is recorded with the scan so a finding is tied to a build.

## Which frameworks are recognised?

Route extraction recognises registration shapes, not just a generic `app.get` pattern.

| Framework | Recognition |
| --- | --- |
| Express | Router and app verb calls; mounts resolved through imports |
| Fastify | Verb calls and plugin-style registration |
| koa-router | Router verb calls |
| NestJS | `@Controller` and `@Get`/`@Post` decorators lifted to full paths |
| Flask | Blueprints, route decorators and blueprint prefixes |
| FastAPI | Route decorators and router prefixes |

Mount and blueprint prefixes are resolved through imports, so `router.post('/login')` under `/api/auth` becomes `POST /api/auth/login`. A route that is registered through an unsupported indirection may be missed; the [adaptive scanning page](/docs/adaptive-scanning/) describes the detectors that widen scope when the source suggests runtime registration.

## How many vulnerability categories are covered?

The category registry covers **25 of 32** seeded categories. The four exclusions are recorded with measured reasons rather than hidden.

| Excluded category | Measured reason |
| --- | --- |
| Timing attack | ~0.014 ms signal against ~1.1 ms HTTP noise on 2 vCPU; no PoC reproduces |
| Race condition | The target serialises the transfer on one event loop; the window never opens |
| JWT `alg=none` | `jsonwebtoken` 9.0.3 rejects `alg=none` unless the verifier pins it |
| JWT no expiry | No bounded PoC exists; fabricating one would bend the ground truth |

The count is 25 supported categories plus the four exclusions listed by the registry. The repository's `categories.py` is the source of truth. The [range targets page](/docs/ranges/) reports the seeded counts and the replay results.

The exclusions are not a claim that those vulnerabilities do not matter. They are a claim that this target could not produce a reproducible proof for them. A category that cannot reproduce would push the reproducibility rate below 1.00 for a reason unrelated to the category, so it is left out rather than faked.

## Does RedFall support TypeScript types?

The parser understands TypeScript syntax, decorators and imports. The taint model is value-flow based; it does not run a full TypeScript type-checker. That means a type-level guarantee is not part of the analysis. The execution gate is what settles whether a candidate is real.

## What about dependency and configuration analysis?

Ingestion records installed dependency versions and package metadata, and the analyzer receives them with the branch source. It does not claim a full software-composition-analysis product. The [comparison page](/compare/static-analysis/) explains where RedFall sits relative to SCA and SAST tools.

## What is not supported?

RedFall 0.1.1 does not parse:

- Java, Kotlin or Scala
- Go
- Rust
- C or C++
- C# or .NET
- PHP
- Ruby

It also does not claim complete coverage of every framework in the supported languages. A custom router or a framework-specific macro may not be recognised. The [blocked page](/docs/blocked/) records the broader capability limits; the [evidence page](/evidence/) records what was measured.

## How do you check whether a target is in scope?

Run ingestion against the target and inspect the route and file counts. If the target is TypeScript, JavaScript or Python and uses a recognised framework, the parser should produce routes. If the route inventory is empty, that is a coverage signal, not a clean scan.

The [CLI reference](/docs/cli/) shows the commands. The [architecture pillar](/docs/architecture/) explains how ingestion feeds taint and branching.

## Frequently asked questions

### Is JavaScript supported separately from TypeScript?

Yes. Both are parsed through the same TypeScript/JavaScript parser family, and `.js`/`.jsx` files are included.

### Does RedFall scan Python web frameworks other than Flask and FastAPI?

Flask and FastAPI route extraction are explicitly recognised. Other Python frameworks may still be parsed as source, but route attribution is not claimed.

### Why only three language families?

Because the execution and harness paths were built and measured for those families. Adding a language requires a parser, taint support, a target boot contract and a replay path, not just a file extension.
