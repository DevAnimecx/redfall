# Deploying RedFall

Two images and one stack. This directory builds the **orchestrator** — the
process that reads a target's source, plans campaigns and drives sandboxes. The
**sandbox** image, which is what an exploit actually runs inside, is built
separately from `src/redfall/sandbox/images/redfall-sandbox/`.

Keeping them apart is not tidiness. The orchestrator is the component that has
to stay trusted; the sandbox is the component that runs hostile code. An image
that is both would put the engine inside the boundary it exists to sit outside
of.

---

## One command, local

```bash
cd deploy
REDFALL_DASHBOARD_TOKEN=$(openssl rand -hex 32) docker compose up --build
```

That brings up Postgres, Redis and the engine, and serves the console on
`http://127.0.0.1:8787`. Set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` in the
environment to reason through a provider; without one the engine needs an agent
CLI installed, which this image does not carry.

The first run builds the sandbox image too, because a campaign cannot start one
that does not exist:

```bash
docker compose exec engine redfall doctor
```

`doctor` prints what this deployment can actually run. It is also the image's
healthcheck, so a container that reports unhealthy is a container that cannot
scan — not a container that is merely busy.

---

## The Docker socket, and why this is not production-ready as written

The engine mounts `/var/run/docker.sock`. That socket is equivalent to root on
the host: anything that can reach it can start a container with the host
filesystem mounted. RedFall needs it because starting a sandbox *is* talking to
a container runtime. There is no configuration that makes the need go away.

The default stack mounts it directly because a one-command local run is worth
more than a hardened default nobody sets up. A deployment that matters should
put a socket proxy in between and allow only the calls RedFall makes:

```yaml
  socket-proxy:
    image: tecnativa/docker-socket-proxy
    environment:
      CONTAINERS: 1   # create, start, stop, remove, inspect
      IMAGES: 1       # inspect the sandbox image
      POST: 1         # required to create; without it the proxy is read-only
      EXEC: 0         # the engine never execs into a running container
      VOLUMES: 0
      NETWORKS: 0
      SWARM: 0
      SYSTEM: 0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

and point the engine at `DOCKER_HOST=tcp://socket-proxy:2375` instead of
mounting the socket. `VOLUMES: 0` and `NETWORKS: 0` are the two that matter:
with them off, a compromised engine cannot mount a host path into a container it
creates.

This is not a substitute for running the engine on a host that holds nothing
else. It narrows a large hole; it does not close it.

---

## What is on volumes, and why

| Volume | Holds | If it is lost |
| --- | --- | --- |
| `redfall-state` | work directory, evidence bundles, artefact cache | every recorded `reproduce_command` stops resolving |
| `redfall-db` | campaigns, findings, the evidence hash chain, tenants, lessons | campaigns are gone; the ledger cannot be verified |

The evidence ledger is a hash chain. Losing a link does not merely lose a
record — it makes every later record unverifiable, because each one commits to
its predecessor's digest. Back `redfall-db` up with the same care as the
findings it holds, and back it up *with* `redfall-state` if you want a
reproduction to still run after a restore.

---

## Configuration

All of it comes from the environment. The names are the ones the engine already
reads, so the same values work in a compose file and on a host:

| Variable | Default | Effect |
| --- | --- | --- |
| `DATABASE_URL` | — | Required. Postgres the campaign state lives in. |
| `REDIS_URL` | — | Optional. Shared scan state across engine replicas. |
| `REDFALL_ALLOWED_ROOTS` | — | The hard outer boundary on filesystem paths. Set it. |
| `REDFALL_SANDBOX_POOL_SIZE` | `3` | Concurrent branch workers, and what the capacity plan checks. |
| `REDFALL_TENANCY` | off | Enforce tenant isolation. See `redfall tenant --help`. |
| `REDFALL_POLICY` | closed | `open` makes policy rules additive rather than allow-listing. |
| `REDFALL_DASHBOARD_TOKEN` | — | Required to bind a non-loopback address. |

`REDFALL_ALLOWED_ROOTS` is the one to get right. It is not a default for a
campaign's scope; it is a ceiling that a campaign cannot widen. A campaign can
set its own scope, and an MCP client can create a campaign, so the only path
that stays closed is the one the operator pinned.

---

## What this deployment does not do

- **No TLS and no reverse proxy.** The engine binds loopback and refuses a
  non-loopback bind without a token, but it terminates no TLS. Put it behind
  something that does.
- **No multi-replica coordination beyond Redis.** Two engines against one
  database work, and campaign leases keep them from claiming the same task; a
  campaign's *branches* are not sharded across replicas.
- **No Kubernetes manifest.** A compose stack and an image are what exists. A
  chart is a separate piece of work and is not claimed here.
- **No air-gapped build.** The image installs from PyPI at build time. An
  air-gapped deployment needs a mirror and a pre-built wheel, and nothing here
  has been tested without network access.
