---
title: Deployment
seoTitle: "Deploy RedFall as a Service: Docker Image and Compose Stack"
description: "Deploy RedFall's orchestrator as a container: an image kept separate from the sandbox it drives, a compose stack with Postgres and Redis, and a real healthcheck."
path: docs/deploy/
group: Start here
kind: cluster
pillar: install
order: 4
updated: 2026-10-30
keywords: deploy vulnerability scanner, docker security scanner, self-hosted security scanning, RedFall docker compose
sources: https://github.com/DevAnimecx/redfall/blob/main/deploy/Dockerfile, https://github.com/DevAnimecx/redfall/blob/main/deploy/docker-compose.yml
related: install, sandbox, enterprise
---

**RedFall 0.5.0 ships a deployment image and a compose stack**, so it can run as
a service rather than as a CLI on a laptop.

> **What this page does not claim.** There is no Docker on the build host, so
> **the image has never been built and the stack has never been brought up.**
> The deploy tests verify the manifests parse and their invariants hold — a
> non-root user, declared volumes, no committed credential, a healthcheck wired
> to the capability check. They say nothing about whether the image runs.

## Two images, and why they are separate

| Image | What it is | Where it is built |
| --- | --- | --- |
| **Orchestrator** | The process that reads source, plans, and drives sandboxes | `deploy/Dockerfile` |
| **Sandbox** | What an exploit actually runs inside, with the harness and a target's runtime | `src/redfall/sandbox/images/redfall-sandbox/` |

Keeping them apart is not tidiness. The orchestrator is the component that has
to stay trusted; the sandbox is the component that runs hostile code. An image
that was both would put the engine inside the boundary it exists to sit outside
of.

## One command, local

```bash
cd deploy
REDFALL_DASHBOARD_TOKEN=$(openssl rand -hex 32) docker compose up --build
```

That brings up Postgres, Redis and the engine, and serves the console on
`http://127.0.0.1:8787`. Set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` to reason
through a provider; without one the engine needs an agent CLI installed, which
this image does not carry.

## The healthcheck is a capability check

```
HEALTHCHECK CMD ["redfall", "doctor", "--quiet"]
```

RedFall has no fallback execution path. A container that cannot start a sandbox
**cannot scan**, so reporting it healthy because the process is up would be a lie
a load balancer believes. `--quiet` makes the exit code the answer, which is
what a healthcheck needs.

## The Docker socket, stated plainly

The engine mounts `/var/run/docker.sock`. **That socket is equivalent to root on
the host**: anything that can reach it can start a container with the host
filesystem mounted. RedFall needs it because starting a sandbox *is* talking to
a container runtime. There is no configuration that makes the need go away.

The default stack mounts it directly because a one-command local run is worth
more than a hardened default nobody sets up. A deployment that matters should
put a socket proxy in between, allowing only the calls RedFall makes —
`CONTAINERS`, `IMAGES` and `POST` on, and `VOLUMES: 0`, `NETWORKS: 0`, `EXEC: 0`
off. With volumes and networks off, a compromised engine cannot mount a host
path into a container it creates. The full proxy configuration is in
`deploy/README.md`.

This narrows a large hole. It does not close it. Run the engine on a host that
holds nothing else.

## What is on volumes

| Volume | Holds | If it is lost |
| --- | --- | --- |
| `redfall-state` | work directory, evidence bundles, artefact cache | every recorded `reproduce_command` stops resolving |
| `redfall-db` | campaigns, findings, the evidence hash chain, tenants, lessons | campaigns are gone; the ledger cannot be verified |

The evidence ledger is a hash chain. Losing a link does not merely lose a record
— it makes every later record unverifiable, because each commits to its
predecessor's digest. Back the database up *with* the state volume if you want a
reproduction to still run after a restore.

## Configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `DATABASE_URL` | — | Required. Where campaign state lives. |
| `REDIS_URL` | — | Optional. Shared scan state across replicas. |
| `REDFALL_ALLOWED_ROOTS` | — | The hard outer boundary on filesystem paths. **Set it.** |
| `REDFALL_SANDBOX_POOL_SIZE` | `3` | Concurrent branch workers; what the capacity plan checks. |
| `REDFALL_TENANCY` | off | Enforce tenant isolation. See [Tenancy](/docs/enterprise/). |
| `REDFALL_POLICY` | closed | `open` makes policy rules additive rather than allow-listing. |
| `REDFALL_DASHBOARD_TOKEN` | — | Required to bind a non-loopback address. |

`REDFALL_ALLOWED_ROOTS` is the one to get right. It is not a default for a
campaign's scope; it is a ceiling a campaign cannot widen. A campaign can set its
own scope and an MCP client can create a campaign, so the only path that stays
closed is the one the operator pinned.

## What this deployment does not do

- **No TLS and no reverse proxy.** The engine binds loopback and refuses a
  non-loopback bind without a token, but it terminates no TLS.
- **No Kubernetes manifest.** An image and a compose stack are what exists. A
  chart is separate work and is not claimed here.
- **No air-gapped build.** The image installs from PyPI at build time. An
  air-gapped deployment needs a mirror and a pre-built wheel, and nothing here
  has been tested without network access.

For the isolation tiers a host can run and the concurrency it supports, see
[Sandbox](/docs/sandbox/).
