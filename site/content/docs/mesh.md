---
title: The agent mesh
seoTitle: "Separated AI Agent Roles for Security Scanning | RedFall Mesh"
description: "Eight named agent roles with the smallest tool allowlist each needs, and a refusal when the exploit author and the critic resolve to the same agent."
path: docs/mesh/
group: How it works
kind: cluster
pillar: agents
order: 21
updated: 2026-10-30
keywords: multi-agent security scanning, AI agent separation of duties, independent verification AI, agent roles security
sources: https://github.com/DevAnimecx/redfall/blob/main/src/redfall/mesh/roles.py, https://github.com/DevAnimecx/redfall/blob/main/src/redfall/mesh/binding.py
related: agents, verified-findings, learning
---

**RedFall 0.5.0 adds the agent mesh.** Eight named roles, each with its own tool
allowlist and its own separation constraints, and each bindable to a different
vendor's agent.

> **What this page does not claim.** No multi-agent campaign has been run on the
> build host. The roles, tools, bindings and refusals are tested; no claim is
> made that routing one role to one vendor and another to a second improves
> anything, because no holdout exists here to measure that against.

## Why roles, and why separation

Asking one agent to author an exploit and then judge whether it worked produces
a report that looks **identical** to an independently verified one. The failure
is silent. That is the entire reason the mesh exists: not to route work
efficiently, but to make sure the thing that judges is not the thing that
authored.

A role is a job, not a prompt. It carries a purpose, a tool set, and — where it
matters — a constraint that it must not share a backing agent with another role.

## The eight roles

| Role | Purpose | Can assert findings |
| --- | --- | --- |
| `recon` | Map the target: entry points, routes, data stores, trust boundaries | No |
| `analyst` | Turn the map into candidate flows worth chasing | No |
| `planner` | Rank candidates and choose which to spend budget on | No |
| `exploit` | Author and run a proof for one candidate | **Yes** |
| `runtime_operator` | Bring the target up in the sandbox and keep it reachable | No |
| `critic` | Attack a proposed finding: does it reproduce, does it matter | No |
| `fixer` | Propose a repair for a confirmed finding | No |
| `verifier` | Judge a repair: tests pass, proof stops working | No |

`exploit` is the **only** role that can assert a finding. A verifier confirms
someone else's finding; it does not originate one. A test asserts this, so a
future edit that hands assertion to another role fails the suite.

## The tool sets are the smallest each job needs

Every tool a role holds is a way it could do the thing separation is meant to
prevent. So the allowlists are narrow on purpose:

- The **verifier** holds no `redfall_fix_propose`. A verifier that can write the
  fix can make its own proof pass.
- The **fixer** holds no `redfall_reproduce`. The fixer judges nothing; running
  the proof is the verifier's job.
- The **critic** can reproduce and read evidence, but cannot write a fix.

Calling outside the allowlist **raises** rather than returning false. A role
reaching outside its tools is either a bug or an attempt, and both should stop
the work rather than be logged and stepped over.

```bash
$ redfall mesh can verifier redfall_fix_propose
role 'verifier' may not call 'redfall_fix_propose';
it holds 19 tool(s) and this is not one of them
```

## Separation constraints

`exploit` must not share an agent with `critic` or `verifier`. `verifier` must
not share one with `fixer`. Those are the pairs where a shared blind spot would
sit on both sides of a judgement.

## Binding, and the one deliberate softening

```bash
$ redfall mesh check --role exploit=codex --role critic=gemini
```

```toml
[mesh]
default = "claude-code"

[mesh.roles]
exploit = "codex"
critic = "gemini"
```

Most teams will run one agent everywhere. A rule that simply refused would make
the mesh unusable for them, so the two collapse cases are treated differently:

| Case | Result |
| --- | --- |
| Two roles the operator **explicitly bound** to one agent | **Refused.** `exploit` and `critic` both set to `codex` is a contradiction of their own instruction. |
| A collapse that only arises because **unassigned roles fall back** to the default | **Warning**, carried in the plan. The team has not made a contradictory binding decision; they have made none. |

`--strict` promotes the second case to an error for a deployment that wants the
strong reading. `--allow-shared` accepts the *error* case and records the weaker
guarantee in the plan, so a report can state it rather than implying
independence that is not there.

`redfall mesh check` exits nonzero when the binding contradicts itself, so a
preflight catches "the critic is the author" before a campaign runs rather than
after a report is written.

## Why this was worth building before the vendors existed

The alternative to a mesh is a router, and a router picks *a* backend for a
call. The mesh picks *which agent plays which part*, which is a different
question. It also means the isolation tiers in [Sandbox](/docs/sandbox/) and the
roles here describe the same shape: a trusted orchestrator directing isolated
workers, each with exactly the authority its job needs.

## What is not here

- **No automatic per-role model selection.** Roles are bound by configuration,
  not chosen by a scheduler.
- **No measured benefit.** The separation is a correctness argument, not a
  benchmark result. Whether critic-on-a-different-vendor catches more is
  unmeasured here.
- **No enforcement at the vendor boundary.** A role bound to `codex` is trusted
  to be `codex`; the mesh decides which command to run, and the driver framework
  decides how.
