---
title: Glossary
description: The words RedFall uses precisely, and the looser meaning each one is deliberately not using.
---

# Glossary

Several words in this project mean something narrower than their everyday
sense. Where that is true, the everyday sense is stated too — the gap is usually
the point.

---

**AEO** — Answer engine optimisation. Making a page quotable by a system that
answers a question directly rather than returning a list of links. RedFall's
docs are written to be quotable, which is why limits appear in the same
paragraph as capabilities: a claim without its boundary is not quotable by
anything careful.

---

**candidate** — A source→sink flow produced by static analysis. *Not* a
finding. A candidate is a hypothesis with a reason. Everyday usage conflates the
two, and that conflation is what RedFall exists to eliminate.

---

**campaign** — A durable unit of work with a budget, a state machine and a task
graph. Distinct from a **scan**, which is one ingestion-and-analysis pass. A
campaign may run several scans.

---

**category** — One vulnerability class, with a CWE, a severity, the signals that
suggest it, a proof contract and a fix strategy. The registry holds 25 supported
categories and 4 exclusions. A category **ships only if its proof reproduces**
against a range target; otherwise it appears in `NOT_COVERED` with the
measurement that excluded it.

---

**certification** — For a **language**, that one of its categories reproduces
against a real target the language can execute. For an **agent driver**, that it
answers a real prompt with valid JSON from this host. Neither is a claim about
the thing in general — both are claims about a specific version, on a specific
host, at a specific time.

*Everyday usage:* "supported". RedFall distinguishes "parsed" from "certified"
and never uses one to mean the other.

---

**chain** — A multi-step exploit where an earlier step enables a later one. The
chain stage composes reproduced steps into a compound attack and scores it.

---

**E0–E4** — The evidence grades. E0 an opinion, E1 a static observation, E2 a
dynamic observation, E3 a reproduction, E4 a reproduction with demonstrated
impact. Only E3 and E4 are reportable. See [the evidence model](evidence-model.md).

---

**environment digest** — A hash over what the target and sandbox were. Its
purpose is to make "it worked on my machine" a falsifiable statement rather than
an excuse.

---

**finding** — A candidate that executed and whose predicate matched. A finding
has an evidence record; a candidate does not. This is the central distinction in
the project.

---

**flake** — A finding that fails to reproduce on a clean reset within three
attempts. A flaky proof is quarantined rather than reported, because a finding
that reproduces two times in three is not a finding.

---

**gVisor** — A user-space application kernel. The container's syscalls are
handled by the gVisor Sentry rather than directly by the host kernel, so a
compromise inside the sandbox reaches an emulated kernel rather than the real
one. One tier on the [isolation ladder](#isolation-tier).

---

**isolation tier** — One rung on the sandbox ladder: Firecracker (own kernel),
gVisor (emulated kernel), container (shared kernel). Each declares its per-unit
memory and CPU footprint and a probe. The engine picks the strongest tier the
host supports and refuses to run if there is none.

---

**learning loop** — The mechanism by which a reproduced outcome becomes a stored
lesson. *Not* a model update. A lesson is an observation with provenance; it
goes through candidate → shadow → holdout evaluation → promotion, and it is
refused at creation if it cannot cite an E3/E4 record.

---

**mesh** — The eight named agent roles and the binding that assigns an agent to
each. Its purpose is separation of duties: a critic that is the author is not a
critic, and the mesh refuses a binding that collapses that pair.

---

**no-mock contract** — The rule that no shipped code may fake a result.
Enforced mechanically by `scripts/check_no_mock.py`, which scans every file
under `src/` for `eval()`, `time.sleep()` as a wait, `mock.patch`, `dry_run`
flags, `NotImplementedError`, bare `pass` and ellipsis bodies. It runs in CI.

The contract's consequence is uncomfortable and deliberate: the test suite
reports **34 skipped** rather than 34 passed, because this host has no container
runtime.

---

**PoC** — Proof of concept. The exploit a candidate becomes. Writing one is the
`exploit` role's job and is separated from judging it.

---

**predicate** — The condition evaluated against the real response that decides
whether a reproduction happened. Written before the run, not after it — a
predicate chosen once the response is visible is not a test.

---

**provenance** — For a graph node, where it came from: which file, which line,
which scan. For a lesson, which evidence record produced it. RedFall records
provenance everywhere, because a fact without one cannot be checked.

---

**range** — A ground-truth target under `range/`: a real, deliberately
vulnerable application with a manifest of known vulnerabilities. The only place
in the repository where a finding is proven rather than argued.

---

**reproduce** — To run a recorded PoC against a clean target and observe the
predicted result. `redfall reproduce <finding-id>` does exactly this from the
evidence record.

---

**scan** — One ingestion and analysis pass. See **campaign**.

---

**sandbox** — The isolation boundary a PoC executes inside. A Docker container
on a user-space-kernel runtime, with no host mounts, dropped capabilities and a
pids limit. There is **no fallback execution path**: if the sandbox cannot
start, the engine refuses rather than degrading.

---

**seam** — An interface with more than one implementation, where the second
implementation exists to prove the first is not a wrapper. RedFall has four:
language, reasoning backend, tool registry, isolation tier. A "seam" with one
implementation is an abstraction; the test is whether a second one lands
without touching the callers.

---

**sink** — A call that does something dangerous with its argument: a database
query, a process execution, a filesystem write, an outbound request. The sink
kinds are `db | exec | fs | fetch`.

Sinks are **receiver-gated** where the name is ambiguous. `Command` on `os/exec`
is process execution; `Command` on someone's own type is not. A name that cannot
be resolved to a recognised receiver is not called a sink at all, because a
taint path to something unexploitable is a finding with no exploit behind it.

---

**source** — An input surface that carries attacker-controlled data: a request
parameter, a header, a body field, a path segment.

---

**taint** — The property of having been derived from a source. RedFall propagates
taint per function.

**A recorded sanitiser never clears taint.** Whether a sanitiser is adequate is a
property of the running system, not of the source, so the sanitiser is recorded
in the taint path's `via` field and the sandbox decides. This is a deliberate
precision cost paid to avoid a class of false negatives.

---

**tenant** — An isolation boundary in the enterprise plane. **A tenant is
derived, never accepted**: a credential resolves to a tenant, and the scope
built from it is the only thing queries filter on. No API takes a tenant id a
client can choose.

---

**tool** — A named operation in the registry, with a scope and a handler. About
46 exist. Every surface — CLI, MCP, HTTP, A2A, dashboard — delegates to the
registry, so an operation is defined once and cannot drift between surfaces.

---

**workspace pool** — A target is copied once per scan into a template and
checked out per PoC, rather than copied once per PoC.

---

**verified fix** — A patch for which the target's own test suite still passes
*and* the original PoC stops reproducing. Nothing is committed or pushed on the
operator's behalf.
