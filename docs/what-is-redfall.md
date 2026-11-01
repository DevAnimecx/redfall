---
title: What RedFall is
description: A complete description of RedFall in one document — the problem it addresses, the mechanism it uses, the evidence model, and the limits it publishes.
---

# What RedFall is

**RedFall is an autonomous vulnerability scanner that proves every finding by
executing it.** It reads a target's source, traces attacker-controlled data to
dangerous sinks, generates a candidate exploit, runs that exploit against the
real application inside an isolated sandbox, and reports only what reproduced.
It then attempts a repair and calls the fix verified only when the target's own
tests still pass *and* the original exploit stops working.

That is the whole idea. Everything else in this repository is machinery for
making it true rather than approximately true.

---

## The problem

A vulnerability scanner produces a list. Some entries are real, some are not,
and the scanner does not tell you which. The cost of that ambiguity falls on
whoever reads the list — a human triager who must reproduce each candidate
before believing it, or worse, a release manager who either trusts the list and
delays a ship for nothing, or distrusts it and ships a real bug.

The cost is not the false positive itself. It is that a list with unknown
error rates cannot be *acted on*: it can only be triaged. Triage is the most
expensive form of security work because it is unbounded and it never ends.

Static analysis cannot fix this. Whether a source-to-sink path exists is a
property of the code; whether the resulting bug is *exploitable* is a property
of the running system, and no amount of reading the code settles it.

## The mechanism

RedFall separates the two questions and answers each with the instrument that
can:

| Question | Instrument | Output |
| --- | --- | --- |
| Where might attacker data reach something dangerous? | Static analysis over a parsed graph | A **candidate** |
| Does it actually? | An exploit executed against the running target | A **finding** |

Static analysis is cheap, fast and approximate — a good candidate generator. It
is a bad oracle. RedFall uses it only for the job it is good at, and adds the
step that turns a guess into a claim.

```
  source ──────────────────────────────────────────────────────────────►
   │
   │  ingest        tree-sitter parses each file, extracts routes,
   │                handlers, calls, imports and dependencies
   ▼
  graph           a persisted, provenance-aware model of the codebase
   │
   │  branch        an adaptive tree of analysis branches; seven triggers
   │                open new branches when the target suggests them
   ▼
  candidate       a source→sink flow, with a reason and a confidence
   │
   │  author        an agent writes a proof of concept for the candidate
   ▼
  execute         the target boots in a sandbox; the PoC runs over a real
   │              socket; a predicate is evaluated against the real response
   ▼
  finding         ONLY if the predicate matched. Otherwise the candidate
   │              is recorded as unreproduced, with the failure
   ▼
  repair          a patch is attempted on a scratch checkout, the target's
   │              tests run, and the original PoC is replayed. Verified only
   ▼              when both pass
  evidence        every step above is a hash-chained record, and a report
                  cannot be generated without one
```

## The evidence model

Every claim RedFall makes about a target is recorded as a linked evidence
record with a grade:

| Grade | Means | Reportable |
| --- | --- | --- |
| **E0** | An opinion. A model suggested something. | No |
| **E1** | Static observation. A path exists in the source. | No |
| **E2** | Dynamic observation. Something happened at runtime. | No |
| **E3** | Reproduced. An exploit ran and an observable changed. | **Yes** |
| **E4** | Reproduced with impact. As E3, plus a demonstrated consequence. | **Yes** |

The ledger refuses to write an E3/E4 record that lacks an execution id, an
observable, a reproduce command and an environment digest. It is not possible
to record a reportable finding without having the things that make it
reportable, because the validation runs at write time rather than at read time.

Each record commits to its predecessor's digest. Changing a record breaks every
later one, which is what makes the ledger tamper-evident rather than merely
append-only.

## What "sandbox" means here

The target application and a real database run inside a container on a
user-space-kernel runtime. The exploit is sent over a real socket. The predicate
is evaluated against the real response.

The isolation is a ladder rather than a single configuration:

| Tier | Isolation | Needs |
| --- | --- | --- |
| Firecracker | Each workload has its own kernel | KVM, the jailer |
| gVisor | A user-space kernel intercepts syscalls | Docker with `runsc` |
| Container | A plain container; shares the host kernel | Docker |

RedFall picks the strongest tier the host supports and refuses to run if it has
none — there is no fallback path that executes without isolation, because a
finding produced without isolation is not a finding this project will claim.

Alongside it is a **capacity plan**: the arithmetic of how many concurrent
units a host can hold, computed from measured memory, CPU and the per-tier
footprint. It refuses rather than guessing when it cannot read a number.

## How the engine reasons

RedFall does not require an AI provider key. Reasoning is an interface, and four
things implement it:

- **An installed agent** — Claude Code, Codex, Gemini CLI, and nine more — driven
  through its own non-interactive entry point
- **A provider key**, through LiteLLM
- **Any OpenAI-compatible endpoint** — Ollama, vLLM, LM Studio, a gateway
- **A router** that picks a backend per task, or takes a consensus across several

The proof this is a seam and not a wrapper: the provider-key test suite passes
unchanged after the abstraction was extracted.

## The agent mesh

Eight named roles, each with the smallest tool allowlist its job needs:

| Role | Job |
| --- | --- |
| recon | Map the target: routes, data stores, trust boundaries |
| analyst | Turn the map into candidates worth chasing |
| planner | Rank the candidates and choose where budget goes |
| exploit | Author and run a proof |
| runtime_operator | Bring the target up and keep it reachable |
| critic | Attack a proposed finding |
| fixer | Propose a repair |
| verifier | Judge a repair |

The separation is enforced, not suggested. The verifier holds no tool that
writes a fix; the fixer holds no tool that runs the proof; and a binding that
puts the exploit author and the critic on the same agent is refused — because a
self-judged proof produces a report that looks identical to an independently
verified one.

## What it reads

TypeScript, JavaScript, Python, Java, Kotlin and Go.

Two of those are **certified**, meaning a category reproduces against a real
target the language can run. Four are not, and the distinction is stated
wherever the languages are listed. Java, Kotlin and Go are parsed and traced
but have never been executed by this code on the build host.

## What it does not do

- It does not attack arbitrary hosts. It scans source you point it at, inside a
  sandbox it builds. No persistence, no lateral movement, no credential use.
- It does not replace a SAST or SCA platform. Its coverage is narrower (25
  vulnerability classes) and its cost per candidate is higher by construction.
- It does not commit or push fixes. It proposes a patch on a scratch checkout.
- It does not defend at runtime. It is a pre-release and periodic instrument.

## The honest caveat

**RedFall has no published benchmark result.** Its central claim — that
execution-gated findings are worth their cost — is a structural argument, not a
measurement. The arena that would produce the number does not exist yet.

That gap is documented in [the case against RedFall](analysis/cons.md), it is
the first phase of [the roadmap](roadmap/deeper.md), and it is the reason this
document does not assert that RedFall is better than anything.

For where it sits relative to other tools, read
[positioning](analysis/positioning.md). For what is wrong with it, read
[cons](analysis/cons.md). Both are written to be useful to someone deciding
whether to trust it — which means both contain material the project would
rather not have to publish.
