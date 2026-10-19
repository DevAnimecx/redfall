---
title: Taint analysis for TypeScript and Python
seoTitle: "Taint Analysis for TypeScript, JavaScript and Python"
description: "How RedFall tracks request data from source to sink, resolves cross-file calls through imports, and handles return flow without guessing sanitisers."
path: docs/taint-analysis/
group: How it works
kind: cluster
pillar: architecture
order: 2
updated: 2026-10-19
keywords: taint analysis TypeScript, taint analysis Python, source sink vulnerability scanner, interprocedural taint analysis
sources: https://tree-sitter.github.io/tree-sitter/, https://owasp.org/www-community/attacks/Code_Injection, https://github.com/DevAnimecx/redfall
related: verified-findings, languages, architecture
---

**Taint analysis answers one question: can data an attacker controls reach a dangerous operation?** RedFall tracks request surfaces — body, query, params, headers and cookies — to sinks such as SQL queries, command execution, filesystem access, redirects and eval. It does this inside each function, then across function boundaries through resolved imports and a call graph. A taint path is a candidate, not a finding.

This page describes the analysis as implemented in the 0.1.0 source. The important design choices are the ones that make the result auditable: sources and sinks are enumerated, sanitisers do not silently clear taint, interprocedural hops must be real call edges, and return flow is proved separately from argument flow.

## What are sources and sinks?

A **source** is a request surface an attacker can influence. A **sink** is an operation whose behaviour changes when attacker data reaches it. The lists are deliberately explicit.

| Language | Sources | Sinks |
| --- | --- | --- |
| TypeScript / JavaScript | `req.body`, `req.query`, `req.params`, `req.headers`, `req.cookies` | SQL query, `exec`, filesystem, redirect, `eval` |
| Python | `request.args`, `request.form`, `request.json`, `get_json`, `headers`, `cookies` | SQL query, `exec`, filesystem, redirect, `eval` |

The scanner records the enclosing function, the source expression, the sink call, the file and line, and the path that connects them. It also records sanitisers it sees along the path, but it does not let a sanitiser clear taint. That is a deliberate refusal to guess.

## Why does a sanitiser not clear taint?

Because knowing that a function neutralises a sink requires knowing what the function does, what encoding the sink expects, and whether the runtime path actually uses the sanitised value. A function called `escapeHtml` is not evidence that an SQL sink is safe. A function called `parseInt` may remove an injection primitive in one context and not another.

Recording the sanitiser instead of clearing taint has two effects:

- It avoids false negatives caused by optimistic modelling.
- It can produce candidates that a human later dismisses as sanitised. That is acceptable because the execution gate decides, not the analyzer.

The alternative — treating a familiar name as proof — is how a scanner ends up silently missing a real bug because the sanitiser was applied to the wrong branch.

## How does intraprocedural analysis work?

The first pass walks each function and connects sources to sinks inside that function. A simple JavaScript handler looks like this:

```js
router.post("/login", async (req, res) => {
  const email = req.body.email;
  const row = await pool.query(
    `SELECT * FROM users WHERE email = '${email}'`
  );
  res.json(row.rows[0]);
});
```

The source is `req.body.email`. The sink is the `pool.query` call. The taint path is the interpolation of `email` into the query string. The route extraction has already resolved the mount prefix, so the path is attributed to the real endpoint rather than to a bare `/login`.

A Python equivalent uses the framework's request object:

```python
@app.route("/reports")
def reports():
    department = request.args.get("department")
    return conn.execute(
        f"SELECT * FROM reports WHERE department = '{department}'"
    ).fetchall()
```

The same pass records the source and the sink. It does not need to know whether the query is exploitable; that is the sandbox's job.

## How does interprocedural analysis work?

Real applications move data through helpers. A route may pass a parameter to a service function that builds the query three files away. RedFall's depth-one interprocedural pass handles that by summarising callees.

1. Each callee's parameters are pre-tainted.
2. The analysis records which parameters reach which sinks in that function.
3. A call site becomes a hop only when the argument at the call site is already tainted by a real source and the matching parameter reaches a sink.
4. The hop is resolved through import bindings, not by matching function names.

Resolution covers relative ESM specifiers, aliases, namespaces, CommonJS `require`, and Python relative imports. If the binding cannot be resolved, the call is not guessed into a hop. The caller is named in the taint's `via` chain, so a reviewer can follow the path from route to sink.

Every resolvable call also becomes an edge in the `call_edges` graph. Route attribution follows those edges transitively and across files. That is how a taint in a shared helper is attributed to the route whose handler can reach it.

## How is return flow handled?

Return flow is the other direction: a function returns attacker-controlled data, and the caller uses the result at a sink. RedFall proves it separately.

If a callee's return path reads a source, or a local derived from one, the summary marks the return as tainted. The caller's use of the call result at a sink then becomes a hop. Pass-throughs of parameters are not claimed by the return summary, because the caller's own argument taint already covers them. This distinction prevents double-counting and keeps the `via` chain readable.

A return-flow path is still a candidate. It must survive execution like any other.

## Which frameworks and shapes are recognised?

Route extraction is part of the same ingestion layer, and it recognises real registration shapes rather than a generic `app.get` regex:

| Framework | What is recognised |
| --- | --- |
| Express | Verb calls on routers and apps, mount prefixes resolved through imports |
| Fastify / koa-router | Verb calls and plugin-style registration |
| NestJS | `@Controller` and `@Get`/`@Post` decorators lifted to full paths |
| Flask | Blueprints, route decorators and blueprint prefixes |
| FastAPI | Route decorators and router prefixes |

The [languages page](/docs/languages/) lists the file extensions and the exclusions. If a route is not extracted, a real taint path may still exist in the file but cannot be attributed to an endpoint. That is a coverage limit, not a finding.

## What does taint analysis miss?

Taint analysis is a static approximation. It can miss:

- **Dynamic dispatch.** A function selected at runtime through a map or dependency injection may not resolve to a static callee.
- **Depth beyond one hop.** The 0.1.0 interprocedural pass is depth-one; longer chains may require multiple summaries that are not composed.
- **Framework magic.** A custom middleware may rewrite the request object in a way the parser does not model.
- **Sanitiser semantics.** As above, the scanner records but does not clear. That can produce candidates a human dismisses.
- **Data validity.** A path may be unreachable because a validator rejects the input before the sink. Execution is how that gets settled.

The [verified findings pillar](/docs/verified-findings/) explains why those misses are acceptable: the output is a candidate until it runs. A static miss is a coverage gap; a fabricated finding would be a contract violation.

## How do you inspect a taint path?

The persisted path names the source, the sink, the file and line, and the `via` chain. The CLI and the stored report expose it. A reviewer can open the file at the recorded line and follow the chain to the route. If the chain names a call edge, the import binding should be visible in the source.

The [architecture pillar](/docs/architecture/) shows where taint sits in the pipeline, and the [SARIF page](/docs/output/) shows how the finding is exported with its verified flag.

## Frequently asked questions

### Is taint analysis the same as vulnerability detection?

No. It detects possible dataflow. RedFall treats the result as a candidate and requires execution before calling it a finding.

### Why depth-one interprocedural analysis?

It covers the common helper boundary without claiming a whole-program proof. The limit is documented rather than hidden, and the execution gate handles the candidates it finds.

### Does RedFall analyse TypeScript types?

It parses TypeScript and JavaScript syntax with tree-sitter. The taint model is value-flow based; it does not attempt a full TypeScript type-checker.
