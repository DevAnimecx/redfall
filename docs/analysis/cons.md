# The case against RedFall

A critique written to be usable by someone deciding whether to adopt this, and
by whoever maintains it next. Every objection here is one a competent reviewer
would raise, and most of them are correct.

Ordered by how much damage the objection does.

---

## 1. The central claim is unmeasured

**The objection.** RedFall's entire thesis is that execution-verified findings
are worth more than pattern-matched ones. There is no published benchmark
comparing it to anything. No head-to-head, no pre-registered corpus, no raw
logs, no independent re-run. `bench/` does not exist.

**Why it does more damage than the others.** Every other tool in the category
can be evaluated by a buyer. This one asks for trust on the strength of an
argument about *how* it works. An argument is not evidence, and a project whose
brand is "claims must be proven" is the least entitled to make an unproven one.

**What would fix it.** The arena, run on a frozen corpus, against at least one
mainstream SAST and one DAST, with raw logs and a stated budget. Until that
exists, this document is the correct place to say so loudly.

**Honest status:** known, named, not done. It is the top item in the roadmap
for exactly this reason — see [deeper.md](../roadmap/deeper.md).

---

## 2. It runs nothing on the build host

**The objection.** No Docker, no gVisor, no KVM, no JVM, no Go toolchain. The
test suite reports `746 passed, 34 skipped` — and among those skips are the
sandbox tests that would prove the headline capability.

**The steelman against RedFall.** A reader cloning this repository cannot
reproduce the one thing it claims to do. They get an ingestion engine, a graph,
a planner and a lot of machinery with a large hole where execution should be.

**The steelman for it.** The project says so, everywhere, in detail, with the
exact reason and the smallest real unblock in `BLOCKED.md`. Most projects in
this position show a demo video. This one shows a ledger.

**The honest verdict.** The transparency is genuinely rare and does not
neutralise the objection. A skipped test is still a test that did not run.

---

## 3. Two certified languages, and the enterprise ones are not among them

**The objection.** TypeScript/JavaScript and Python are certified. Java,
Kotlin and Go are parsed, symbol-extracted and taint-traced — and never
executed, so no category is certified for them. The roadmap's stated priority
was "Java/Kotlin first, highest enterprise demand". The part that shipped
unverified is exactly the part enterprise buyers need.

**Why this happened, honestly.** The language *analysers* are the easy 80%.
The range target — a vulnerable Spring app that boots, a Gin app that boots,
a Go toolchain in the sandbox — is the expensive 20%, and this host cannot run
it. Shipping the analyser without the certification is defensible; claiming
coverage without the caveat would not have been.

**What it costs.** Every Java/Go finding is a candidate, not a proof. That is
precisely the state RedFall exists to eliminate, now present inside RedFall.

---

## 4. The economic case is a shape, not a number

**The objection.** Executing a candidate costs sandbox minutes and agent
tokens. Pattern-matching costs almost nothing. RedFall is more expensive per
*finding* by construction, and the claim that it is cheaper per *true* finding
is arithmetic nobody has run.

**The specific risk.** If the ratio of candidates to reproductions is bad — and
for a hard class it will be — the cost per true finding can exceed the cost of
having a human triage the SAST output, which is the thing it is trying to
replace. The tool is then not merely more expensive; it is more expensive *and*
slower.

**What is known.** The category registry, the branch pool and the reasoning
cache all exist to bound this. None of them has been measured against a
baseline. `BLOCKED.md` names the missing provider key as the blocker for the
token-economics benchmark.

---

## 5. Breadth is a liability dressed as a feature

**The objection.** Five languages, a graph, a branching engine, a chain stage,
a fix loop, MCP, HTTP, A2A, a dashboard, tenancy, policy, an audit export, a
learning loop, an agent mesh, isolation tiers, a deployment image. For one
maintainer, that is not a product — it is a surface area.

**The concrete failure modes.**

- **No subsystem gets the depth it deserves.** The JVM taint engine is
  intraprocedural. The TypeScript/Python engine has a depth-one interprocedural
  pass. Neither is a research-grade dataflow analysis, because the time went
  into the sixteenth subsystem instead of the second.
- **Integration surface grows faster than test coverage.** Each seam is tested
  at its boundary; the *composition* of ten seams is not.
- **A bug anywhere is a bug in the claim.** The no-mock contract is enforced
  per file, but a correct file composed with a correct file can still produce a
  wrong finding.

**The honest counter.** The breadth is achieved through real seams, which is
the only structure under which breadth is affordable. That is a better answer
than most breadth-first projects have. It is still not a good answer; it is a
less-bad one.

---

## 6. Taint analysis that will miss real bugs, and cannot say so

**The objection.**

- **Intraprocedural on JVM and Go.** A value that crosses a function boundary
  is invisible. This is not a limitation at the margin; it is the majority of
  real flows in an idiomatic Spring or Go codebase.
- **Depth-one interprocedural on TS/PY.** A two-hop flow through a helper
  misses. Three hops, certainly.
- **No field-sensitive alias analysis, no container-element tracking.** A
  value in `req.body.items[0].id` reaching a sink through a destructure is
  likely missed.
- **Sanitisers are recorded, never modelled.** Every sanitised flow is still
  reported as tainted. That is the safe direction for recall and it is a
  precision tax paid on every finding, forever.

**The specific consequence.** RedFall will report flows that are dead and miss
flows that are live. The first is noise; the second is the failure that matters,
because a security tool that misses silently is worse than one that reports
noisily. There is no recall estimate for this engine on any corpus.

---

## 7. A single shared-SQLAlchemy-session design, patched

**The objection.** The orchestrator was built around one `Session`. Parallel
branches required an opt-in per-call session seam, threaded through
`run_branch`, `validate` and `ingest`. That seam now exists and the sequential
path is preserved byte-identically — which is the polite way of saying there are
now two execution paths through the core, and the sequential one is the one
that runs when anything goes wrong.

**Why it is on this list.** Two paths through the heart of the engine is a
maintenance liability that compounds. Every future change to branch execution
must be correct in both.

---

## 8. Concurrency is tested, never benchmarked

**The objection.** The roadmap promised measured speed-ups: parallel branches
"~N× on N cores", warm sandbox pool "−60–80% per-PoC wall time", incremental
index "seconds on re-scan". None was measured. The concurrency changes have
contract tests — the pool yields what it should, sessions are per-call, caches
hit — and no wall-clock numbers at all.

**Why this is more than a missing number.** Cancellation, failure propagation
and backpressure under a real branch tree are the interesting cases, and a
contract test does not exercise them. The pool bounds work at
`sandbox_pool_size`; what happens to a tree that spawns faster than the bound
drains is not characterised.

---

## 9. The learning loop is unexercised on real data

**The objection.** No holdout exists on the build host, so no lesson has been
promoted on real data. The gates are tested; the *effect* is not. Every
statement about learning gain is a statement about machinery.

**The subtler objection.** The gate constants (`MIN_DELTA = 0.02`,
`MIN_HOLDOUT_N = 10`, `MIN_AGREEMENT = 0.8`) were chosen, not derived. On a
holdout of ten cases, a 0.02 delta is *less than one case*. The gate may be
arithmetically too weak to distinguish a real improvement from sampling noise,
and nobody has run it far enough to know.

---

## 10. Tenancy is a filter, not a boundary

**The objection.** Multi-tenancy is enforced by a scope object applied in the
query builder. A query written without the filter is a cross-tenant read, and
nothing at the database layer prevents it. There is no row-level security, no
separate database per tenant, no per-tenant encryption key.

**The specific risk.** A future contributor writes a new query and forgets the
filter. The tests cover the queries that exist; they cannot cover the one that
does not yet.

**And:** no OIDC, no SAML. The `idp_subject` column exists and nothing
authenticates against it. "Enterprise" here means tenant-scoped RBAC over a
bearer token, which is a smaller thing than the word implies.

---

## 11. The deployment mounts a root-equivalent socket

**The objection.** `docker.sock` is mounted into the orchestrator. That socket
is equivalent to root on the host. The stack documents the socket-proxy
alternative and does not default to it, on the grounds that a one-command local
run is worth more than a hardened default nobody configures.

**Why that reasoning is uncomfortable.** It is the same argument every insecure
default makes. The mitigation is documentation, and documentation is not a
control. A deployment that follows the README literally gets a container with
host-root reach.

---

## 12. Packaging, licensing, and bus factor

**The objection.** No declared license, so public readability is not a grant of
reuse. One maintainer. No corporate support contract. No security review by a
third party. No SBOM beyond what the release workflow emits.

For a tool that executes untrusted code and reads a customer's source, each of
these is a procurement blocker independent of the technical merit.

---

## 13. Two more the first draft of this document missed

### 13.1 The repair loop is shallow

A fix is proposed on a branch, the target's tests run, the PoC is replayed.
Three attempts, then a human sees the transcript. That is the whole loop.

What is missing: a library of repair strategies; ranking of candidate patches;
checking that a patch is *minimal*; checking it does not break a neighbouring
behaviour the tests do not cover; and any guarantee that the patch is the
idiomatic fix for this codebase rather than merely a working one.

"Verified" here means narrowly "tests pass and the PoC stops reproducing" — and
a one-line `if (false)` can satisfy both. The adversarial test that guards
against that is **one test, not a systematic check** of the class.

### 13.2 The abandonment risk is real

One maintainer, one project, a very large scope, and a plan that grew faster
than its results. The 0.5.0 line added four subsystems — tenancy, learning, an
agent mesh, a deployment story — while the core claim (a verified finding
against a third-party target) remained undemonstrated.

A reader is entitled to conclude: *this is ambitious, carefully documented,
rigorously tested within its own frame, and it may never produce the one result
that would prove it works.* That reading is currently correct.

---

## 14. What is *not* a con, despite looking like one

Stated because a critique that lists everything is not a critique.

- **The skipped tests.** Skipping and reporting the reason is correct. Passing
  by faking would be the con. This is the opposite of a problem.
- **The narrow category coverage.** 25 classes is narrow; publishing the four
  exclusions *with their measurements* is better practice than a competitor's
  silent 300-rule list.
- **The refusal to run without a sandbox.** No fallback execution path is a
  feature. A "best effort" mode would produce unverified findings wearing the
  same label as verified ones.
- **The intraprocedural JVM engine.** Shipping an honest narrow analyser is
  better than shipping a wide one that pretends. The con is the *certification*
  gap, not the analysis depth.

---

## 15. The summary a reviewer should take away

RedFall's engineering discipline is real and its evidence model is the best
thing in the repository. Its weaknesses are not sloppiness — they are the
predictable cost of building verification infrastructure before measuring
verification outcomes, on one host, with one maintainer.

The three objections that would sink an adoption decision:

1. **No benchmark.** The claim is unproven.
2. **The enterprise languages are uncertified.** The target market is
   unserved by the part that shipped.
3. **Breadth over depth.** No single subsystem is best-in-class.

The objection that would sink it technically:

4. **Taint depth.** It will miss real flows, and cannot currently tell you how
   many.

Everything else on this list is a fixable gap. These four are the ones that
decide whether the project is worth continuing.

---

## 16. What would change the verdict

Each of these removes a specific objection above, ordered by how much it would
change the picture. If you are deciding whether to invest attention in RedFall,
this is the order in which that attention would be earned.

| Do this | Removes |
| --- | --- |
| Find and disclose **one real vulnerability** in a project RedFall did not write, with a reproduce bundle a stranger can run | §1 becomes moot; §13.2 |
| Run the **full suite with Docker + gVisor in CI on every push**, and publish the pass rate | §2, the largest technical gap |
| Build the **arena** and publish recall, precision and cost per true finding against a SAST baseline | §1, §4 |
| Certify **one Java or Go category** by executing a real service | §3 |
| Promote **one lesson** against a holdout that was not used to propose it | §9 |
| Depth beyond one hop, with a **recall number** attached | §6 |
| Wire **one identity provider** and run a two-tenant isolation test | §10 |
| Ship a **GitHub Action** that runs a scan in CI | §13.2 |
| Add a **LICENSE** | §12, §13.2 — the cheapest item on this list |

The first two are the ones that matter. Everything above them in this document
is survivable; those two decide whether any of the rest is worth fixing.
