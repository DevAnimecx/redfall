---
title: Adaptive scanning: seven runtime surfaces
seoTitle: "Adaptive Vulnerability Scanning: 7 Runtime Surfaces"
description: "Dynamic imports, plugin loaders, database-stored code, feature flags and webhooks change the attack surface mid-scan. RedFall spawns a branch when one appears."
path: docs/adaptive-scanning/
group: How it works
kind: cluster
pillar: architecture
order: 4
updated: 2026-10-19
keywords: adaptive vulnerability scanning, dynamic import security, plugin vulnerability scanner, feature flag security
sources: https://github.com/DevAnimecx/redfall, https://github.com/DevAnimecx/redfall/blob/main/src/redfall/triggers.py
related: architecture, exploit-chaining, ranges
---

**A source-only scan freezes the attack surface at the moment it reads the files.** Real applications grow surface at runtime: a plugin directory is loaded, a route is registered from a config table, a feature flag enables a handler, a webhook is discovered. RedFall runs seven detectors over the same source and spawns a branch when one of them finds new surface.

The mechanism is called adaptive scanning because the branch tree changes during the scan. It is not a second scanner bolted on top; it is a rule for when the existing scanner should widen its scope.

## What are the seven adaptive surfaces?

The trigger types are enumerated in one place, `src/redfall/triggers.py`, and enforced by the branch tree and the store. There are exactly seven.

| Trigger | What it detects | Why it matters |
| --- | --- | --- |
| `dynamic_import` | Imports computed at runtime | The imported module may not appear in the static dependency graph |
| `dynamic_route_registration` | Routes registered from data or loops | The route inventory is incomplete without the registration path |
| `plugin_system` | Plugin directories and loaders | The plugin boundary often has weaker validation than the core |
| `db_stored_code` | Code or templates stored in the database | The payload is not in the repository and can change after deployment |
| `webhook_discovery` | Webhook endpoints and dispatchers | An outbound integration can become an inbound attack surface |
| `feature_flag` | Code gated by a runtime flag | The route exists in source but may be dark in one deployment |
| `env_conditional` | Behaviour switched by environment variables | Production and test paths can differ materially |

A surface records the trigger type, the file, the name, the line and the reason. The same surface detected twice is deduplicated; two different triggers in the same file produce two branches rather than colliding.

## Why spawn a branch instead of widening the first prompt?

Because scope is the unit of accountability. A branch has a parent, a file and route scope, a depth, a priority and, for an adaptive branch, the finding that triggered it and the reason. A branch that fails can be attributed to a scope. A giant prompt that silently omits a plugin directory cannot.

The branch tree is recursive. A child can spawn a grandchild if it finds new surface, up to the configured depth cap. The cap is enforced and reported rather than ignored.

## What rules keep adaptive spawning honest?

Adaptive scanning is a place where a model could invent work. The tree prevents that with structural rules, not prompt instructions.

- **A real trigger is required.** An adaptive branch must name one of the seven trigger types.
- **A triggering finding is required.** There is no adaptive branch without the finding that revealed the surface.
- **The timestamp must be causally possible.** The branch's `spawned_at` must be strictly after both the parent's start and the trigger's discovery. A branch cannot predate the thing that caused it.
- **The parent must exist.** An unknown parent is refused rather than assumed.
- **The same surface is deduplicated.** Re-detecting a surface does not create duplicate work.
- **The depth cap is enforced.** The scan stops widening at the configured limit and reports it.

Those rules are tested against a real Postgres because they are properties of persisted state, not of an in-memory object. The [evidence page](/evidence/) records the counts.

## How is priority assigned?

Not all new surface is equally urgent. The priority function ranks code-execution surface above disclosure surface. The tested ordering is:

```
plugin_system
  > dynamic_import
  > db_stored_code
  > dynamic_route_registration
  > feature_flag
  > env_conditional
```

An unknown trigger falls to a default priority rather than raising, so a future detector cannot crash a scan simply by being new. The ordering is a scheduling decision, not a severity claim; the sandbox still decides whether a candidate is real.

## What does the real target demonstrate?

`range/vulnbank-adaptive` is `vulnbank` plus seven adaptive surfaces. Its test suite has 91 tests, and the replay script reports 7/7 PoCs reproduced. The repository's adaptive tests exercise all seven trigger types against the real target files, including the plugin route that contains two surfaces.

The point of the range is not that the detectors fire. It is that the spawned work is attributable, deduplicated and causally ordered, and that the resulting findings reproduce. The [range targets page](/docs/ranges/) lists the counts and commands.

## What can adaptive scanning miss?

The detectors are static heuristics. They can miss:

- A route registered through a framework or indirection they do not recognise.
- A plugin loaded by a path computed at runtime.
- A database-stored payload that is not present in the target at scan time.
- A feature flag whose value is not known to the scanner.
- A webhook whose registration happens outside the repository.

A missed surface is a coverage gap. It is not a finding, and it is not counted as one. The execution gate still applies to every branch that is spawned.

## How does this connect to chaining?

Adaptive branches can surface the second step of an attack. A plugin upload route may be found by one branch, while the loader that executes the plugin is found by another. The [exploit chaining page](/docs/exploit-chaining/) explains how reproduced findings are composed; adaptive scanning is one way the graph gets the findings it needs.

## Frequently asked questions

### Does adaptive scanning run a second static analyzer?

No. The detectors run over the same parsed source as the rest of ingestion. They decide when to widen scope, not how to analyse a file.

### Can a model create an adaptive branch without evidence?

No. The tree requires a trigger type and a triggering finding, and it checks the timestamp ordering. A model proposal that does not satisfy those rules is refused.

### Why is the branch tree persisted?

Because the causal rules are about persisted state: parent, trigger, discovery time and spawn time. An in-memory tree would not let a reviewer verify them after the scan.
