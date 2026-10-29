---
title: The dashboard
seoTitle: "RedFall Dashboard: Live Scan Control Plane and Findings Console"
description: "Run redfall dashboard for a local console over the same tool registry the CLI uses: start scans, follow a live stream, read findings with evidence, propose a fix."
path: docs/dashboard/
group: Reference
kind: pillar
pillar: dashboard
order: 3
updated: 2026-10-29
keywords: vulnerability scanner dashboard, live scan console, security findings dashboard, redfall dashboard, self-hosted security console
sources: https://github.com/DevAnimecx/redfall
related: cli, agents, interop, verified-fixes
---

`redfall dashboard` starts a local HTTP server that exposes the same tool
registry the CLI, MCP and A2A surfaces use. It is not a second implementation of
anything: each route calls one registered tool, so an operation is defined once
and cannot drift between the console and the command line.

```bash
redfall dashboard --project /path/to/repo --port 8787
```

The server binds loopback by default. A non-loopback bind refuses to start
without a bearer token, because a console that can start a scan is a console
that can run code against a target — that is not something to expose by
accident.

## What the console shows

**A live scan.** `POST /api/scans` returns `202` with a scan id immediately and
runs the scan on a worker thread. The id is minted before the scan starts, so a
browser can subscribe to `/api/scans/{id}/events` and be listening *before* the
first event rather than racing it. Events arrive as Server-Sent Events, one
named type per change: `scan:start`, `branch`, `finding`, `spend` and
`scan:done`.

**Findings with their proof.** A finding is only ever listed with the evidence
that produced it. The proof panel carries the evidence chain, the reproduction
status and a button that replays the proof of concept in the sandbox through the
same `redfall_reproduce` tool the CLI calls.

**A fix proposal that is never applied.** `POST /api/findings/{id}/fix` calls
`redfall_fix_propose`, which attempts the repair inside a **throwaway git
worktree** — it edits files, runs the target's tests and replays the PoC there,
then deletes the worktree and returns the patch. Your checkout is never written
to. A finding that was never reproduced is refused by default, with that reason
stated, because a fix for an unproven bug cannot be shown to work.

## Routes

| Method | Path | What it does |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness, version and database state |
| `GET` | `/api/version` | Server version and advertised tool count |
| `GET` | `/api/agents` | Agent drivers and which are installed |
| `GET` | `/api/reasoning` | The backend the effective config would build |
| `GET` | `/api/projects` | Repositories the server may scan |
| `GET` | `/api/scans` | Recent scans, newest first |
| `GET` | `/api/scans/{id}` | One scan with its findings |
| `GET` | `/api/scans/{id}/events` | Server-Sent Events for that scan |
| `POST` | `/api/scans` | Start a scan; returns `202` and a scan id |
| `POST` | `/api/scans/{id}/cancel` | Cancel a running scan |
| `GET` | `/api/findings` | Findings, filterable by severity, category and reproduction |
| `GET` | `/api/findings/{id}` | One finding with its evidence |
| `POST` | `/api/findings/{id}/reproduce` | Re-run the PoC in the sandbox |
| `POST` | `/api/findings/{id}/fix` | Propose a fix in a throwaway worktree |
| `GET` | `/api/reports/{id}` | The report bundle for a scan |

## Scope and limits

* The project allowlist is enforced on every scan request: a target outside the
  configured roots is refused with `403 out_of_scope`, the same way the agent
  gateways refuse one.
* The event bus serves **one process**. A subscriber that cannot keep up loses
  the oldest events and is told it fell behind; losing an event is visible, never
  silent. A multi-worker deployment needs Redis pub/sub and is not claimed here.
* This is a single-operator console. Multi-tenant access control is a later
  version; the token gates the door rather than partitioning it.
