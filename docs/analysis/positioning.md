# Where RedFall sits

> **Provenance of this document.** Everything about RedFall itself is derived
> from this repository: the code, the tests, the blocker ledger and the ranges.
> Everything about the market is written from the author's knowledge and is
> **not** backed by a survey, a benchmark this project ran, or a competitor's
> published numbers. Treat the second half as a set of hypotheses to test, not
> as findings. Where a claim would need data this repository does not have, it
> says so.

---

## 1. The one-sentence position

RedFall is an **evidence-gated** vulnerability engine: static analysis produces
candidates, and only a reproduced execution makes one a finding.

Most of the category sorts on a different axis. The question they answer is
*"how many vulnerabilities can this find?"* RedFall answers *"how do you know
the ones it reports are real?"* Those are not the same product, and the second
one has a smaller addressable market and a much higher bar to clear.

That is the honest framing, and it is also the risk: a smaller market and a
harder bar is a worse business and a better tool.

## 2. The axis, stated precisely

Every scanner sits somewhere on a spectrum from *suggestion* to *proof*:

| Level | What it produces | Who absorbs the error |
| --- | --- | --- |
| L0 — Pattern | A regex or rule matched | The triager |
| L1 — Dataflow | A path from source to sink exists in the code | The triager |
| L2 — Reachability | The path is reachable in the built artefact | A human, with effort |
| L3 — Executed | An exploit ran and an observable changed | The tool |
| L4 — Independent | Someone else re-ran it from a clean bundle | The tool |

RedFall's design target is **L3, with the machinery for L4** — the evidence
ledger's hash chain, the reproduction command in every record, and the range
harness that replays a finding from a clean checkout.

Almost all deployed SAST is L1. A well-run DAST is L2–L3 for some classes.
RedFall is an attempt to make L3 the *default* rather than a premium tier.

The map, with the honest uncertainty marked:

```
                        higher precision, narrower coverage
                                        ▲
                                        │
                            RedFall ●   │   (target: L3 as the default)
                                        │
         DAST (ZAP/Burp,                │
         running) ●  ───────────────────┤
                                        │
         SAST ●                         │
         (Semgrep/CodeQL)               │
                                        │
         SCA ●  (dependabot,            │
         Trivy)                         │
                                        │
                                        ▼
                        lower precision, broader coverage
```

**What this diagram is not:** a quality ranking. A tool low on the precision
axis is not worse — it is answering a different question, and for "do we have a
vulnerable dependency anywhere in 400 repos" SCA is the right instrument and
RedFall is the wrong one.

## 3. The category, and who is in it

The relevant category is **autonomous security agents** — systems that plan,
act and verify against a live target rather than reporting on code. This is a
young category and its membership is disputed. The families:

| Family | What they do | How they decide something is real |
| --- | --- | --- |
| **Autonomous pentest agents** | Given a target, plan and execute an attack chain end to end | An exploit succeeded against a live target |
| **AI-assisted SAST** | LLM reads code, proposes likely vulnerabilities, triages SAST output | A model judged the path plausible |
| **Verification-first scanners** | Reproduce each candidate before reporting | A PoC ran and an observable changed |
| **Agentic fix systems** | Propose or apply repairs | Tests pass |

RedFall is in the third family, with a reach into the fourth (it proposes and
verifies fixes) and a rejected claim on the first: it does not do free-form
attack planning against an arbitrary host. It scans source you can point it at,
in a sandbox it can build.

That rejection is deliberate and it is the single most important scoping
decision in the project. See [§6](#6-what-redfall-deliberately-does-not-do).

### 3.1 The named landscape

Four families occupy the space, and RedFall does not beat all of them.
**The competitor facts below are from the author's knowledge and are not
independently verified by this repository; treat the specifics as provisional
and the structural comparisons as the durable part.**

**Autonomous exploitation platforms.** The closest system to RedFall's thesis:
it also insists a finding is unproven until it runs, against live targets, at
scale, with a public competitive record. RedFall's honest edge against this
family is **custody, not capability**:

| | An exploitation platform | RedFall |
| --- | --- | --- |
| Target | Deployed applications, over the network | Source trees it ingests and boots itself |
| Unit of proof | Working exploit plus request/response | Reproduce command, environment digest, hash-chained ledger link |
| Chain of custody | A decision log | An append-only hash chain with E0–E4 grading, where the report refuses unproven records |
| Track record | Public competitive results | Range targets only |

A result from a trusted platform is trusted because the platform is trusted. A
RedFall result is *checkable* because the record is a hash chain a stranger can
walk and re-run. That is a real difference and it is not a market-winning one on
its own.

**AI-assisted SAST.** This is the family a buying decision would actually
compare RedFall against, and **on breadth RedFall loses badly.** These products
scan every repository in an organisation continuously, cover languages and
ecosystems RedFall does not, integrate into the pull-request flow developers
already use, and have years of tuning behind their precision figures. RedFall
scans one target at a time, on a host, with a container runtime present.

The structural difference, rather than a size difference: their finding is a
**claim with a confidence score**; a RedFall finding is a **claim plus the
execution that proved it**. "75% fewer false positives" is a precision claim —
the residual is still false positives, just fewer. RedFall's design target is
zero *reported* false positives, because nothing unproven is reported at all.
That is a stronger guarantee, it costs far more per finding, and that is exactly
why this is a niche and not a replacement.

**Graph and dataflow engines.** Deterministic, deep, language-typed analysis.
Excellent at precisely the multi-hop taint RedFall explicitly does not do —
RedFall's interprocedural pass is **depth-one only**, documented as a deliberate
bound. These tools find classes RedFall's bounded analysis provably cannot.

**Human pentesting.** Still better than any automated system at business logic,
chained privilege escalation, and anything requiring intent. RedFall's 25
categories include some business-logic entries, and its exclusions are honest
that it cannot reproduce the ones needing concurrency or timing.

### 3.2 The strategic read

The three families above are not competitors RedFall beats. They are the reason
it should not try to. RedFall's only defensible position is as a **verification
layer** that sits after an existing SAST/SCA and converts a sample of its
high-severity output into proven-or-disproven findings. That is a smaller claim
than "better scanner", and it is the only one the code supports.

## 4. Where RedFall is genuinely ahead

These are differences the repository can demonstrate, not marketing claims.

### 4.1 The no-mock contract is enforced, not asserted

`scripts/check_no_mock.py` scans every file under `src/` for `eval()`,
`time.sleep()` as a wait, `mock.patch`, `dry_run` flags, `NotImplementedError`,
bare `pass` and ellipsis bodies. It runs in CI. A feature that cannot be built
without faking a result cannot be merged.

Almost every security tool has a "demo mode" or a fixture that returns
plausible data when the real thing is unavailable. This project bans the shape
of that. The consequence is uncomfortable and visible: the suite reports
`34 skipped` rather than `34 passed`, because this host has no container
runtime — and the blocker ledger names what would change that.

**Why this is defensible:** it is a cultural constraint embedded in tooling. A
competitor can copy the framing in a README; copying the constraint means
giving up every shortcut their roadmap currently depends on.

### 4.2 The evidence ledger refuses to report what it cannot prove

`EvidenceLedger.append` validates by grade. An E3/E4 record without an
`execution_id`, an observable, a reproduce command and an environment digest is
rejected at write time, not filtered at read time. The chain is a SHA-256 hash
of each record over its predecessor's digest.

The failure mode this designs against is specific: a tool that reports a
finding it did not verify produces a report indistinguishable from one that
did. The ledger makes the two different objects.

### 4.3 Honest exclusions are recorded with measured reasons

Four categories are excluded and each carries the measurement that excluded it
— timing attack (`~0.014 ms` signal against `~1.1 ms` HTTP noise on 2 vCPU),
race condition (the target serialises on one event loop), `jwt_alg_none` (the
pinned dependency rejects it), `jwt_no_expiry` (no bounded PoC exists).

A scanner that silently omits a class looks like it has full coverage. A
scanner that publishes *why* it omitted one is telling you how to read the rest
of its results. This is the single most trustworthy thing in the repository.

### 4.4 Bring-your-own-agent is a real seam, not a wrapper

`ReasoningBackend` is an interface. Twelve agent CLI drivers, an
OpenAI-compatible backend, a LiteLLM backend and a router all implement it. The
proof it is a seam rather than decoration: `tests/test_llm.py` passes unchanged
after the extraction. Twelve vendor integrations that share one contract is a
structurally different thing from one model behind a flag.

### 4.5 The failure modes are designed against, and named

- The **critic is not the author** — the mesh refuses a binding that puts
  `exploit` and `critic` on one agent, because a self-judged proof looks
  identical to an independently verified one.
- **Learning is gated on reproduction** — `propose` takes no grade argument, so
  a caller cannot declare its own claim verified.
- **The capacity plan refuses to guess** — on a host whose memory it cannot
  read, it returns zero with a reason rather than a number.
- **Tenancy is derived, never accepted** — no request carries a tenant id a
  client can choose.

Each is a place where the easy implementation produces a result that *looks*
right. That is the pattern this project is built on.

### 4.6 Breadth that is unusual in the verification-first family

Verification-first tools tend to be narrow — deep on one class, one language,
one framework. RedFall carries: five languages, an adaptive branch tree with
seven spawn triggers, cross-branch exploit chaining, a persisted provenance
graph, MCP/HTTP/A2A interop surfaces, a console, tenancy and an agent mesh.

That breadth is achieved by *making the seams real* — the language registry,
the reasoning backend, the tool registry, the isolation tiers — rather than by
accumulating special cases. It is also the project's largest liability. See
[cons.md](cons.md).

## 5. Where RedFall is behind — the uncomfortable section

This is the section a positioning document normally omits. Its absence is why
most positioning documents are useless.

### 5.0 Nobody is using it

**At the time of writing: 1 star, 0 forks, 0 watchers on the public
repository.** No design partner, no external scan, no third-party re-run.

Every structural argument in §4 is an argument that has convinced exactly one
person — its author. That is not evidence against the arguments, but it is
evidence that they have not been tested on anyone who could disagree.

The failure mode this predicts is specific and worth naming: **the discipline
was built for a scale that did not arrive.** A check that every finding
reproduces is cheap when there is one user; it is the correct design either way,
but "we have not measured it" and "nobody has tried it" compound each other. The
project has optimised for a standard no one has yet asked it to meet.

This is stated first because a positioning document that describes a market
position without mentioning adoption is describing an aspiration.

### 5.1 No published benchmark result

**This is the biggest gap, and it is not close.** Every competitive claim in
this document is a structural argument, not a measurement. The arena
(`bench/`) does not exist. There is no head-to-head against Semgrep, CodeQL, a
DAST, or another agent, on a pre-registered corpus with raw logs.

A tool whose entire thesis is "claims must be proven" ships without a proof of
its central claim. That is the sharpest criticism available against this
project, and it is correct.

### 5.2 The certified-language surface is two languages

TypeScript/JavaScript and Python are certified. Java, Kotlin and Go are parsed
and traced but **not certified** — no JVM or Go toolchain on the build host, so
no Spring or Gin application has ever been executed by this code.

The enterprise demand the roadmap targets (Java/Kotlin first) is exactly the
part that is unverified. That is a real ordering problem, not a documentation
problem.

### 5.3 Nothing runs end to end on the build host

No Docker, no gVisor, no KVM, no JVM, no Go. Every execution-adjacent claim in
the README is backed by CI or by a range run on another host, never by a live
demonstration here. The project is honest about this everywhere, which is good,
and it still means a reader cannot reproduce the headline claim from the repo
alone without bringing their own hardware.

### 5.4 The economic case is unproven

RedFall spends sandbox minutes and agent tokens per candidate. A scanner that
executes is more expensive per finding than one that pattern-matches, by
construction. The bet is that it is cheaper per *true* finding — triage cost,
rework, disclosure cost.

That bet has not been measured. `BLOCKED.md` names the missing provider key as
the reason the token-economics benchmark cannot run. Until it does, the
economic argument is a hypothesis with a plausible shape.

### 5.5 Narrower coverage than a mainstream SAST, on purpose

25 supported categories against a mature SAST's several hundred rules. For
"enumerate every weakness in this codebase", RedFall is the wrong tool. It is a
targeted instrument, and it should be sold as one.

### 5.6 Single-maintainer and unlicensed

No corporate backing and one maintainer. (Apache-2.0 was added in 0.6.0, resolving the licence half of this.) For a tool that
executes untrusted code and touches source, that is a real procurement barrier
that has nothing to do with technical quality.

## 6. What RedFall deliberately does not do

Stated because a boundary that is not written down gets crossed by accident.

- **Not a general-purpose attack platform.** No free-form exploitation of an
  arbitrary host. It scans source you point it at, inside a sandbox it builds.
  No persistence, no lateral movement, no credential use.
- **Not a full type checker.** The taint model is value-flow, not type-flow.
- **Not a replacement for SAST or SCA.** It consumes the former's output as
  candidates and adds an execution gate.
- **Not an autonomous fixer.** The fix loop patches a scratch checkout and
  returns a patch. Nothing is committed or pushed for you.
- **Not a real-time defence.** It is a pre-release and periodic instrument, not
  a WAF or a runtime guard.

## 7. Positioning, stated for three audiences

**For a developer:** this is the scanner you point at a branch before a release
when a false positive would cost you a day, and you are willing to trade
coverage breadth for the confidence that what it reports is real.

**For an AppSec lead:** this is a verification layer that sits *after* your
existing SAST/SCA, converting a sample of their high-severity output into
proven-or-disproven findings — which is a cheaper way to buy precision at the
top of the funnel than replacing the funnel.

**For a security researcher:** this is a testbed for evidence-gated
autonomy — a codebase where every claim about a finding must survive an
execution and a hash chain, and where the tooling refuses to let you fake it.

## 8. The honest one-line summary

> RedFall is a verification-first security engine with unusually rigorous
> evidence discipline and no published benchmark. Its structural differentiators
> are real and demonstrable in the repository. Its central claim — that
> execution-gated findings are worth the cost — is asserted, not measured, and
> the next thing this project owes anyone reading it is that measurement.
