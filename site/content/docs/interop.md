---
title: Agent interoperability
seoTitle: "RedFall Agent Interoperability: MCP, HTTP/OpenAPI and A2A"
description: "How RedFall exposes the same 44-tool registry over MCP, HTTP/OpenAPI and A2A v1.0, with bearer scopes, trust labels, audit and signed artifacts."
path: docs/interop/
group: Reference
kind: cluster
pillar: install
order: 3
updated: 2026-10-21
keywords: RedFall A2A, RedFall OpenAPI, MCP vulnerability scanner, agent interoperability, bearer token scopes
sources: https://github.com/DevAnimecx/redfall/tree/main/src/redfall/interop, https://a2a-protocol.org/, https://spec.openapis.org/oas/v3.1.0.html
related: cli, security, architecture
---

**RedFall exposes one tool registry over MCP, HTTP/OpenAPI and A2A v1.0; the
transport does not change the tool implementation.** All three surfaces call the
same persisted campaign, graph, scan, reproduction, evidence and report code.
There is no per-protocol handler that can drift into different behaviour.

The HTTP and A2A surfaces share one stdlib `ThreadingHTTPServer` and one address.
MCP remains newline-delimited JSON-RPC over stdio. The agent surfaces are
operator-controlled: tokens are created and revoked through the CLI, every
authenticated tool call is authorised against the tool's required scope, and
tool outputs carry an explicit untrusted-data label.

## What endpoints are exposed?

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/healthz` | GET | Process and database health, including the version |
| `/.well-known/agent-card.json` | GET | Public A2A Agent Card |
| `/v1/openapi.json` | GET | Generated OpenAPI 3.1 document |
| `/v1/tools` | GET | Authenticated tool inventory |
| `/v1/tools/{name}` | POST | Execute one tool with a JSON arguments object |
| `/v1/audit` | GET | Admin-only audit trail |
| `/v1/artifacts/{id}` | GET | HMAC-signed artifact download |
| `/a2a/v1` | POST | A2A JSON-RPC; SSE for streaming methods |

Start it with:

```bash
redfall interop serve --host 127.0.0.1 --port 8787
```

`--public-url` sets the externally visible base used by the Agent Card and
artifact links. The default bind is loopback; exposing the gateway beyond a
trusted network is the operator's decision and requires a TLS terminator,
because the gateway does not implement TLS itself.

## How does authentication work?

Create a token with an explicit scope set:

```bash
redfall interop token create --name reviewer --scopes read,execute --quota-per-hour 60
```

The plaintext token is printed once. The database stores only its SHA-256 digest,
so a lost token cannot be recovered; revoke it and create another. Revocation is
immediate. `--quota-per-hour 0` means unlimited.

The scopes are:

| Scope | Grants |
| --- | --- |
| `read` | Read-only tools: graph queries, campaign status, findings and evidence reads |
| `execute` | Reproduction and other tools that execute target code |
| `write` | Mutating tools: campaign lifecycle, graph indexing, scans, reports and token-safe writes |
| `admin` | Audit reads and other administrative operations |

Every HTTP request and A2A call uses `Authorization: Bearer <token>`. A missing
or invalid token is `401`; an insufficient scope is `403`; an exceeded hourly
quota is `429`. Denials and unknown-tool attempts are audited alongside
successful executions.

## How do you call a tool over HTTP?

```bash
curl -sS http://127.0.0.1:8787/v1/tools/redfall_graph_stats \
  -H "Authorization: Bearer $REDFALL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"campaign_id":"campaign-id"}'
```

A successful response is a JSON envelope:

```json
{
  "protocol": "http",
  "tool": "redfall_graph_stats",
  "trust": "untrusted-repository-data",
  "result": {}
}
```

The same trust label is sent in `X-Redfall-Trust` and attached to A2A artifact
metadata. It is a handling instruction: repository content can contain text that
looks like instructions, so consumers must treat it as data, not as agent
commands.

## How does A2A work?

The Agent Card advertises the A2A v1.0 service at `/a2a/v1`. A2A uses JSON-RPC
2.0 with these methods:

- `SendMessage` — submit one tool call and wait for completion by default.
- `SendStreamingMessage` — submit and receive SSE task, status and artifact
  events.
- `GetTask`, `ListTasks` — read persisted task state.
- `CancelTask` — cancel before execution or cooperatively during a call.
- `SubscribeToTask` — attach to an existing task's SSE stream.

One message carries one tool call in a data part:

```json
{
  "tool": "redfall_graph_stats",
  "arguments": {"campaign_id": "campaign-id"}
}
```

`SendMessage` blocks for up to 120 seconds by default; `returnImmediately: true`
returns the submitted task instead. Task rows are the source of truth for
polling and streaming. Cancellation before a worker starts is deterministic;
cancellation during execution is cooperative and reports that side effects may
already exist. Push notifications are not implemented and return JSON-RPC
`-32003`; multi-turn task continuation returns `-32004`.

## What about artifacts and webhooks?

A2A artifacts are stored with a SHA-256 digest and a signed URL. The default URL
lifetime is 15 minutes. The signing secret comes from
`REDFALL_ARTIFACT_SECRET` or a persisted `InteropSetting`; rotating it invalidates
old links.

Operator webhooks subscribe to campaign events:

```bash
redfall interop webhook add --url https://example.invalid/events \
  --event campaign.reported --events campaign.blocked
redfall interop webhook deliver
```

Deliveries are signed with `X-Redfall-Signature: sha256=<hex>` over the raw body,
retried at most three times, and deduplicated by `(subscription_id, event_id)`.
Redirects are refused. Loopback targets require `--allow-loopback`; link-local
targets are always refused. Private-network hostnames are allowed, which is
useful for self-hosting but means this is not a complete SSRF boundary.

## How do you know a transport actually works?

Run the executable contract against a fresh server and a temporary database:

```bash
redfall interop certify --protocol http
redfall interop certify --protocol a2a
redfall mcp certify
```

The HTTP contract performs 10 checks and the A2A contract 11; both use a real
socket, real tool execution, SSE streaming where applicable, and signed
artifacts. The result is stored as a timestamped `AdapterCertification`. A
certification covers the shipped RedFall surfaces at that time; it is not a
certificate for third-party agents or for a deployment that adds its own proxy,
TLS terminator or identity provider.

## What are the limits?

- No built-in TLS, authentication proxy or multi-tenancy.
- No A2A push notifications or multi-turn continuation.
- In-flight A2A tasks are not automatically resumed after a gateway restart.
- The hourly quota is a pre-call check, not a distributed rate limiter;
  concurrent submissions can briefly exceed it.
- Audit covers tool executions, unknown-tool attempts and denials, not every A2A
  `GetTask`/`ListTasks`/`CancelTask`/`SubscribeToTask` or HTTP discovery read.
- The gateway calls the same tool code as MCP; a bug in a tool is not made safer
  by changing transports.

These are deliberate boundaries, not hidden fallbacks. The
[blocked page](/docs/blocked/) records the environment gaps on the development
host, and [release verification](/docs/release-verification/) explains how to
check what was published.
