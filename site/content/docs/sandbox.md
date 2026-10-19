---
title: How the gVisor sandbox executes a PoC
seoTitle: "gVisor Sandbox: How RedFall Executes a Proof of Concept"
description: "Inside RedFall's execution boundary: Docker on the gVisor runsc runtime, a real target boot, raw HTTP replay, and a predicate that decides whether a finding exists."
path: docs/sandbox/
group: How it works
kind: cluster
pillar: architecture
order: 3
updated: 2026-10-19
keywords: gVisor sandbox vulnerability scanner, docker runsc security testing, proof of concept execution
sources: https://gvisor.dev/docs/, https://docs.docker.com/engine/security/, https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md
related: verified-findings, blocked, architecture
---

**The sandbox is where a candidate stops being an opinion.** RedFall runs the target application and a real PostgreSQL inside a Docker container on the gVisor `runsc` runtime, sends the PoC over a real socket, and evaluates the predicate against the real response. A candidate that does not reproduce is not a finding.

The execution boundary is the product's central safety claim, so it is worth being precise about what it does and does not do.

## What is the execution boundary?

The boundary has three layers:

| Layer | What it provides | What it does not provide |
| --- | --- | --- |
| Docker container | Process, filesystem and capability isolation | A strong kernel boundary on its own |
| gVisor `runsc` | A user-space application kernel that intercepts syscalls | A guarantee that target code is harmless |
| Harness and predicate | A real boot, a real request, an observable assertion | Proof of impact beyond the observed effect |

Docker constrains the process. gVisor changes the kernel surface the process can reach: the container's syscalls are handled by the gVisor Sentry rather than directly by the host kernel. RedFall's executor requires the `runsc` runtime and refuses to run without it.

The container is started with a deliberately narrow vector:

- `--runtime=runsc`
- `--cap-drop=ALL`
- `--security-opt=no-new-privileges`
- `--pids-limit=256`
- memory and CPU caps
- per-run labels
- a workspace mount at `/work`
- guaranteed cleanup

The container runs as uid 10001. The harness and the target run inside that boundary; the host is not used as an execution fallback.

## What does the sandbox actually run?

The harness is not a request replayer that assumes the app is already up. It performs a real boot:

1. Start PostgreSQL inside the container.
2. Install and boot the target. Node targets use `npm start`. Python targets use a virtualenv and the target's `redfall.target.json` boot contract, or a root `app.py`.
3. Wait for `/health` to answer.
4. Replay the raw HTTP request over a real socket.
5. Parse the response, including chunked transfer encoding.
6. Evaluate the PoC predicate against the parsed response.

An unknown target tree is reported as `target-missing`. The harness does not guess an entry point. That matters because a guessed entry point would turn a broken boot into a false negative or, worse, a false positive against the wrong process.

The harness also handles the less glamorous parts that decide whether a proof is real: HTTP request parsing, chunked transfer decoding, CSV parsing and predicate evaluation. Those paths were verified against live HTTP traffic on the development host, including the real `VULN-001` predicate from the manifest. Two genuine bugs were found that way; without the checks they would have turned successful exploits into false negatives.

## What is a predicate?

A predicate is the observable condition that makes the exploit meaningful. A response code of 200 is not enough: a login page returns 200 whether or not authentication was bypassed. The predicate has to assert the effect.

Examples from the range manifests:

- A SQL injection predicate checks that a row appears whose email field holds a bcrypt hash for the admin user.
- An account-takeover chain checks that the reset token is a 32-character hex string and that the subsequent admin request succeeds.
- A command-injection predicate checks the marker the injected command wrote, not just that the route responded.

The predicate is data, not a model's opinion at report time. It is evaluated against the real response and the verdict is persisted with the request and response.

## What is the boot contract?

A target has to tell the sandbox how to start it. `redfall.target.json` is that contract: the command, the working directory, the environment and the health path. The Python boot contract was verified end to end on the development host: the real `range/pythonbank/redfall.target.json` resolves to `python -m pythonbank.app` with `cwd=src` and `PYTHONBANK_PORT=$PORT`, and that command line boots pythonbank and answers 200 on `/health`.

The host Python stood in for the sandbox's virtualenv Python in that check. The argv, cwd and environment semantics are the same; the test is about the contract, not about the kernel. The kernel boundary itself requires the container runtime, which is why the sandbox tests skip on this host.

## What did testing the boundary find?

The sandbox work produced two findings that are worth recording because they show why execution matters.

**The ENTRYPOINT swallowed argv.** The sandbox image declared `ENTRYPOINT ["/bin/bash", "-lc"]`. A caller-supplied command vector is appended to an entrypoint, so `command=["node", "harness.mjs"]` became `bash -lc node harness.mjs`, which ran `node` with `$0="harness.mjs"` and no arguments. The harness never ran, yet the run exited 0 with empty output. For a validator, that is the worst failure mode: every reproduction would have looked like a silent pass. The fix was `ENTRYPOINT []`, and five tests now cover output capture, the `/work` mount, the non-root uid, argv delivery and the gVisor Sentry kernel.

**A restrictive workdir was not traversable.** The container runs as uid 10001 and bind-mounts the host workdir. A workdir created `0700` — which is what `tempfile.mkdtemp` and pytest's `tmp_path` produce — is not traversable by that uid. The failure surfaced as `cat: /work/marker.txt: Permission denied`, not as a configuration error. A checked-out repo is `0755` and works. The limitation is documented for callers that stage workspaces with restrictive permissions.

Both findings were found by running the boundary, not by reading it.

## What does the sandbox not prove?

The sandbox proves that a specific request produced a specific observable effect against a specific build inside the boundary. It does not prove:

- **Production reachability.** Network controls, feature flags and deployment differences can change the path.
- **Full impact.** A reproduced SQL injection proves the query was influenced; it does not enumerate every table or prove exfiltration.
- **That the target is safe to run.** The `range/` targets are deliberately vulnerable. Never expose them. The sandbox limits the blast radius; it does not make hostile code benign.
- **That a fix is complete.** The fix loop re-runs the original PoC and the target's tests. It does not prove that no variant remains.

The [evidence page](/evidence/) records what was measured, and the [blocked page](/docs/blocked/) records the current host's missing runtime. The [install page](/docs/install/) lists the prerequisites for a real scan.

## Why gVisor instead of a plain container?

A plain container shares the host kernel. For a tool that deliberately executes attacker-controlled input against a deliberately vulnerable application, sharing the kernel is a larger attack surface than necessary. gVisor's Sentry handles syscalls in user space, and the executor checks for the `runsc` runtime rather than assuming Docker is enough.

gVisor is not a microVM and it is not a claim of perfect isolation. It is a stronger boundary than the default container runtime for this workload, and it is the boundary the code actually requires.

## Frequently asked questions

### Can RedFall run a PoC without Docker?

No. The executor refuses without the Docker CLI and the gVisor runtime. There is no host-execution fallback.

### Why does the sandbox start a database?

The target app needs its real dependencies to boot. A real PostgreSQL is part of the target's runtime, so the harness starts one. A mocked database would change the behaviour under test.

### Why do five tests skip on the development host?

They require a container runtime and gVisor. The host used for 0.1.0 has neither, so the tests skip with a reason rather than passing. They run in CI where the runtime exists.
