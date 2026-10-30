---
title: Languages and frameworks supported
seoTitle: "Supported Languages and Frameworks | RedFall"
description: "RedFall parses TypeScript, JavaScript, Python, Java, Kotlin and Go with tree-sitter, recognising Express, FastAPI, Spring, net/http, Gin and Echo routes."
path: docs/languages/
group: How it works
kind: cluster
pillar: architecture
order: 7
updated: 2026-10-30
keywords: TypeScript vulnerability scanner, Python security scanner, Java security scanner, Go security scanner, Spring security, Gin security
sources: https://tree-sitter.github.io/tree-sitter/, https://github.com/DevAnimecx/redfall/blob/main/src/redfall/agent/categories.py
related: taint-analysis, ranges, architecture
---

**RedFall 0.5.0 reads five languages: TypeScript/JavaScript, Python, Java,
Kotlin and Go.** Two are certified; two are not, and the difference is stated
here rather than buried.

It parses the source with tree-sitter, extracts routes, handlers, calls and
dependencies, and runs taint analysis for each. It does not claim Rust, C#,
PHP or Ruby coverage.

The language boundary is deliberate. A parser that half-understands a language
produces routes and taint paths that look plausible and fail at execution.
RedFall would rather name the supported set than advertise a language it cannot
parse.

## Which file types are parsed?

| Language family | Extensions | Parser | Status |
| --- | --- | --- | --- |
| TypeScript / JavaScript | `.ts`, `.tsx`, `.js`, `.jsx` | tree-sitter TypeScript/JavaScript | **Certified** |
| Python | `.py`, `.pyw` | tree-sitter Python | **Certified** |
| Java | `.java` | tree-sitter Java | **Read, uncertified** |
| Kotlin | `.kt`, `.kts` | tree-sitter Kotlin | **Read, uncertified** |
| Go | `.go` | tree-sitter Go | **Read, uncertified** |

> **Certified means a category reproduces against a real target the language can
> run.** The build host has no JVM and no Go toolchain, so no Spring, JAX-RS,
> net/http, Gin or Echo application has been executed and no category has been
> certified for Java, Kotlin or Go. The analysers are tested over real source;
> they are not claimed to reproduce a vulnerability in a running service.

The language registry exposes the same four operations for every supported
language: support check, parse, symbol extraction and taint analysis. Adding a
language means supplying those operations, not editing the ingestion loop.

A file whose language nobody recognises is reported as `unknown` rather than
defaulted to JavaScript, so a misattributed file is visible instead of quiet.

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
| Spring (Java/Kotlin) | `@GetMapping`, `@PostMapping`, `@RequestMapping` and the JAX-RS verbs, with the class-level `@RequestMapping` prefix joined onto the method path |
| net/http (Go) | `http.HandleFunc` and `http.Handle`, read from the call rather than a decorator |
| gorilla/chi, Gin, Echo (Go) | Method registration on a router, plus `r.Group("/api")` mounts |

The JVM and Go analysers are **intraprocedural**: they propagate taint through
local variables within a function and do not yet follow a value across a call.
The depth-one interprocedural pass described below applies to the TypeScript and
Python engines.

Two Go-specific facts are worth knowing because both are cases where the obvious
reading is wrong. An import binds its **last path segment**, so `net/http` is
used as `http` — recording the whole path breaks every sink resolution while the
parse still looks clean. And a sink is **receiver-gated**: `Command` on
`os/exec` is process execution, `Command` on someone's own type is not, and a
name that cannot be resolved to a recognised receiver is not called a sink at
all, because a taint path to something unexploitable is a finding with no
exploit behind it.

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
