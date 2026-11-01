# A deeper technical plan

This is the plan that follows 0.5.0. It is written against the weaknesses named
in [cons.md](../analysis/cons.md), not against a feature wish-list: every phase
below exists to close a specific, stated objection.

The prior plan (`docs/history/PLAN-0.2-to-0.5.md`) is spent — 0.2.0 through 0.5.0 all
shipped. This one is deliberately harder, because the easy work is done.

**Read this first if you read nothing else:** the ordering is by *proof*, not
by user-visible progress. The next release adds almost no features. It exists to
make the ones that already exist measurable.

---

## Phase 6.1 — The arena, or nothing else matters

> **Started, 0.6.0.** The recall half of this phase shipped: sealed corpora,
> the omission scorer, the regression gate, and the report bundle that refuses
> to exist without a LIMITATIONS section. What remains is the *comparison* —
> running a baseline SAST on the same corpora under the same budget, which
> needs a host with Docker and a provider key. The first measured recall is
> 29.4% on `pythonbank`; see `bench/BASELINE.md`.

**Objection closed:** "the central claim is unmeasured" (§1, cons.md).

Everything else in this document is lower priority than this. A tool that
demands proof of findings and ships without proof of *itself* is incoherent.

### What has to exist

```
bench/
  corpora/
    <corpus>/
      manifest.json        # repos, commits, expected findings, proof contracts
      budget.json          # wall clock, tokens, sandbox minutes, $ ceiling
      ground-truth.json    # the answers, sealed until the run completes
  runners/
    run.mjs / run.py       # drives one tool under one budget on one corpus
    normalise.py           # every tool's output -> one finding schema
  reports/
    <run-id>/              # raw logs, per-finding evidence, the summary
```

### The protocol, and why each rule is there

1. **Pre-registration.** The corpus, the expected findings and the budget are
   committed *before* the run. A corpus chosen after seeing results is a
   demo.

2. **Ground truth sealed.** `ground-truth.json` is read only by the scorer,
   never by the engine. Otherwise the benchmark tests whether the engine can
   read a file.

3. **Equal budget.** RedFall gets the same wall-clock and the same dollar
   ceiling as the baseline it is compared to. A comparison where one side spent
   ten times as much is not a comparison of tools.

4. **Raw logs published.** Every run emits its full log and every finding's
   evidence bundle. A summary number without the logs behind it is the thing
   this project exists to object to.

5. **Independent re-run.** The report names the exact command and the
   environment digest so someone else can reproduce it. Until someone does,
   the result is provisional and the report says so.

### The metrics, defined precisely

| Metric | Definition | Why this one |
| --- | --- | --- |
| **Recall** | Reproduced ⊘ Expected, per category | The honest coverage number |
| **Precision** | Reproduced ⊘ Reported | The number the whole thesis rests on |
| **Reproduction rate** | Reproduced ⊘ Candidates executed | Measures the generator, not the gate |
| **Cost per true finding** | (tokens + sandbox-minutes + $) ⊘ Reproduced | The economic claim, as a number |
| **Time to first reproduction** | Wall clock to the first verified finding | What a developer actually feels |
| **Flake rate** | Findings that reproduce < 3/3 on clean reset | Trust erosion rate |

**Flake rate is not optional.** A finding that reproduces twice in three tries
is not a finding, and a benchmark that counts it as one is measuring luck.

### Baselines

At minimum: one mainstream SAST (Semgrep or CodeQL) and one DAST (ZAP or an
equivalent) on the same corpora, same budget. A comparison against nothing is
not a comparison.

### Done when

`redfall bench run` produces a signed, reproducible bundle containing the raw
logs, the per-finding evidence, the summary against a stated baseline, and a
`LIMITATIONS.md` written by the same run. **The limitations file is a required
output, not a nicety** — a benchmark that does not state its own limits is
marketing with a number attached.

### Unlock requirement

A host with Docker and a provider key. This is the phase the build host cannot
complete, and saying so is the point of the table in `BLOCKED.md`.

---

## Phase 6.2 — Taint depth, because misses are the real failure

**Objection closed:** "taint analysis that will miss real bugs, and cannot say
so" (§6, cons.md).

Three separable pieces, in order of value.

### 6.2.1 Field- and container-sensitive tracking

Today a taint is a name. It has to become a *path*:

```
obj.body.user.id        # a field path, not the name `obj`
items[0].callback       # an element path, not the name `items`
arr[*]                  # a wildcard element, for the union of a container
```

**Design constraint:** the existing `ScopeTaint` shape carries
`tainted: dict[str, str]`. Widening it to a path-keyed map is a compatibility
break in the shared data model, which every language engine reads. Do it once,
in one release, with the old key shape as a derived view so the engines migrate
one at a time.

**Done when:** a flow through a destructured property and a flow through an
array element both reproduce on the Python range, and the existing suites are
unchanged.

### 6.2.2 Interprocedural depth beyond one hop

Depth-one handles the common case: a request value passed to a helper that
reaches a sink. The misses are two and three hops through a service layer,
which is the normal shape of a Spring or Django application.

**Design:** summarize each function once — a *flow summary* mapping parameter
index to reachable sinks, plus a return-value taint — then fix-point over the
call graph. This is standard and it is expensive; it needs the graph to be
complete and the summaries cached, which is why it comes after the graph work,
not before.

**Hard constraint:** a fix-point over a cyclic call graph must terminate. The
summaries must be monotone and the lattice finite, or the analyser hangs on the
first recursive service.

### 6.2.3 Recall measurement — the missing number that matters most

There is no recall estimate for this engine on any corpus. Without one, "it
misses flows" is a suspicion and with one it is a number that can be improved.

**What to build:** a *seeded-corpus* harness — a target where every vulnerable
flow is known and labelled, and the engine is scored on how many it finds and
how many it invents. This is the same shape as the category range targets,
extended to measure omission rather than only reproduction.

**Done when:** every release reports recall per language and per category, and a
regression in it fails CI the way a test failure does.

---

## Phase 6.3 — The enterprise languages, certified

**Objection closed:** "two certified languages, and the enterprise ones are not
among them" (§3, cons.md).

Not new analysers — *targets*.

For Java/Kotlin: a bootable Spring application with the seeded categories, a
JDK in the sandbox image, and a build that completes offline. For Go: the
equivalent with a Go toolchain and a Gin service.

**The ordering matters and is inverted from the roadmap.** Build the range
target *first*, then use it to find the analyser's bugs. Writing the analyser
against no executable target is how the current intraprocedural JVM engine
shipped without anyone knowing which flows it misses.

**Done when:** each language has a range target on which its categories
reproduce, and `redfall language certify <name>` prints the reproduction
results rather than a green tick.

---

## Phase 6.4 — Cancellation, backpressure and the second execution path

**Objection closed:** "a single shared-SQLAlchemy-session design, patched"
(§7) and "concurrency is tested, never benchmarked" (§8).

Three pieces of real work:

1. **Characterise the pool.** A branch tree that spawns faster than
   `sandbox_pool_size` drains: what happens to the queue, the memory, and the
   budget accounting? Today this is unspecified.
2. **Cancellation.** A campaign cancelled mid-branch must stop the sandbox,
   release the reservation and leave the evidence chain valid. Today the
   sequential path is the tested one.
3. **Collapse the two paths.** Once parallel execution is the default and
   characterised, delete the sequential special case. Two paths through the
   core is a compounding liability.

**Done when:** a cancelled campaign under load leaves no orphaned container, no
leaked reservation and a verifiable chain, proven by a test that kills a
running run.

---

## Phase 6.5 — The learning loop, actually measured

**Objection closed:** "the learning loop is unexercised on real data" (§9).

The gate constants were chosen (`MIN_DELTA = 0.02` on a ten-case holdout is
*less than one case*). That is a guess wearing a decimal point.

**What to do:**

1. Build a holdout big enough that the gate is arithmetically meaningful —
   roughly, a delta below `1/√n` is not distinguishable from noise at this
   sample size.
2. Re-derive the constants from the holdout's variance rather than picking
   round numbers.
3. Run the full loop on real data and publish whether any lesson promoted,
   and whether the promoted ones held.

**Including the honest outcome.** If no lesson ever clears the gate on real
data, that is the finding, and it goes in the changelog.

---

## Phase 6.6 — Making breadth affordable again

**Objection closed:** "breadth is a liability dressed as a feature" (§5).

Not by removing surface. By making composition testable.

- **A seam conformance suite.** Every language engine, every reasoning backend,
  every interop surface passes the *same* contract test. A new backend that
  passes is trusted; one that does not cannot land.
- **Composition tests.** Not "does the cache work" and "does the pool work" but
  "does a cached, pooled, parallel scan produce byte-identical findings to a
  sequential uncached one". This is the test that would have caught the
  sequential-path divergence before it needed preserving.
- **A subsystem owner file.** For each module, the person who answers for it.
  With one maintainer this is aspirational; writing it down is how the gap
  becomes visible instead of implicit.

---

## Sequencing and dependencies

```
6.1 Arena ─────────────────► measures everything else
   │
   ├─ needs: Docker + provider key (host it does not have — see BLOCKED.md)
   │
6.2 Taint depth ──► needs 6.2.3 (recall) to know if it helped
   │
   └─ 6.2.1 field-sensitivity blocks 6.2.2 (summaries need paths, not names)
   │
6.3 Languages ────► independent; needs a range target per language, not the arena
   │
6.4 Concurrency ──► independent; needs a host with a container runtime
   │
6.5 Learning ─────► needs 6.1 (a holdout is a small arena)
   │
6.6 Breadth ──────► last; it is the discipline that keeps the rest honest
```

**The dependency that dominates:** 6.1, 6.4 and 6.5 all need a host with
Docker. This document cannot finish on the machine it was written on, and the
smallest real unblock is recorded in `BLOCKED.md` rather than assumed here.

---

## What this plan refuses to do

- **Refuse to add a feature to a phase as a reward for finishing it.** Every
  phase above closes an objection. A phase that cannot name its objection is
  not ready to be scheduled.
- **Refuse to publish a benchmark number without its raw logs.** The moment
  this project does that, it has become the thing it was built to argue
  against.
- **Refuse to certify a language without executing it.** That is the rule the
  current JVM and Go engines already follow, and it is not negotiable for
  convenience.

## Two phases the sections above do not cover

### 6.7 Custody — make a bundle portable and signed

The evidence chain proves a record is internally consistent. It does not yet
prove the bundle *travelled* intact, and it cannot be verified by someone who
does not have the database.

- **Signed, portable bundles.** A finding as a single artefact carrying its
  evidence record, its PoC, its environment digest and a signature, so a third
  party can verify it without trusting this installation.
- **A transparency log.** An append-only public log of bundle hashes, so a
  claim cannot be quietly retracted after publication.
- **Reproduce from the bundle on a stranger's machine.** The acceptance test for
  the two above: someone with the bundle and a container runtime reproduces the
  finding without contacting anyone.

This is the phase that turns "checkable" from a property of the source into a
property of the artefact, and it is what makes §3.1's custody argument actually
true rather than merely plausibly true.

### 6.8 Ecosystem — where a developer already is

- **A GitHub Action** that runs a scan in CI. Today there is none, which is the
  single cheapest thing standing between this repository and adoption.
- **A pull-request bot** that posts a finding where the author already is,
  rather than into a JSON file.
- **Ticketing integration** — Jira, Linear, GitHub Issues.

An honest note on ordering: these are ranked *below* the arena in importance and
*above* it in urgency. Adoption precedes the benchmark that would justify
adoption, which is an uncomfortable thing to write down and nonetheless the
situation.

---

## What to do first — ranked by value ÷ effort

If the goal is results rather than a feature list, this is the order. It is
deliberately not the same order as the phases above, which are sequenced by
dependency rather than by return.

| # | Do this | Effort | What it buys |
| --- | --- | --- | --- |
| 1 | ~~Add a LICENSE~~ **done, 0.6.0** | Minutes | Unblocks legal review and outside contribution. The cheapest item on any list in this repository. |
| 2 | **Run the suite with Docker + gVisor in CI on every push** | Days | Turns the central claim from "untested locally" into "continuously verified", and retires the largest technical objection |
| 3 | **Ship one GitHub Action** | Days | The difference between a repository and something a team can adopt |
| 4 | **One external verified finding** in a project RedFall did not write | Weeks to months, and unpredictable | The only item that changes how the whole project is judged |
| 5 | **The arena** | Weeks | Replaces every structural argument in the positioning document with a number |
| 6 | **One Java or Go category certified** by executing a real service | Weeks | Opens the enterprise market the roadmap targeted |
| 7 | **A recall number** on a seeded corpus | Weeks | Turns "it misses flows" from a suspicion into a quantity |
| 8 | Deeper taint, the transparency log, Firecracker, the Rust orchestrator | Months | Worth doing *after* one through seven, and worth much less before them |

**The uncomfortable observation about this table — kept, because it was true.**
Items 1, 2 and 3 were days of work between them and none had been done, while
four subsystems shipped in the 0.5.0 line. That was a priority inversion, not a
capacity problem. Items 1 and 2 closed in 0.6.0; the observation stays as the
record of what it took to notice.

---

## The three numbers this project owes

If the next year produces nothing else, it should produce these:

1. **Recall per language** on a seeded corpus.
2. **Cost per true finding**, against a SAST baseline, at equal budget.
3. **Flake rate** — how often a verified finding fails to reproduce on a clean
   reset.

Everything else in this document is machinery for producing those three.
