---
title: Execution-verified scanning vs static analysis
seoTitle: "Execution-Verified vs Static Analysis"
description: "A fair comparison of static analysis, DAST and execution-verified scanning: what each proves, where each fits, and when RedFall's narrower execution gate is worth it."
path: compare/static-analysis/
group: Reference
kind: cluster
pillar: evidence
order: 1
updated: 2026-10-21
keywords: static analysis vs dynamic analysis, execution-verified scanner, SAST vs DAST, vulnerability scanner comparison
sources: https://semgrep.dev/docs/, https://codeql.github.com/docs/, https://owasp.org/www-community/Vulnerability_Scanning_Tools
related: verified-findings, evidence, ranges
---

**Static analysis and execution verification answer different questions.** Static analysis asks whether a dangerous pattern or dataflow exists in the code. Execution verification asks whether a specific input produces a specific effect against the running application. Neither replaces the other, and a fair comparison starts with that distinction.

RedFall is narrower than a general-purpose SAST or SCA platform. It is built for the moment when a finding must be proven before someone acts on it.

## What does each approach actually do?

| Approach | What it analyses | What it can claim | Typical strength |
| --- | --- | --- | --- |
| Pattern SAST | Source text and syntax | The code resembles a known-bad pattern | Fast, broad, easy to run in CI |
| Dataflow SAST | Source-to-sink paths in a model | A path may exist | Finds complex flows across files |
| DAST | A running application from outside | An input produced a response | Tests the deployed surface |
| Execution-verified scanning | Real source plus a real PoC in a sandbox | This input produced this effect on this build | Evidence strong enough to act on |
| SCA | Dependency manifests and advisories | A dependency version has a known issue | Supply-chain coverage |

RedFall combines tree-sitter ingestion, dataflow analysis and execution. It does not claim to be a complete SAST platform, a DAST scanner or an SCA product. The [architecture pillar](/docs/architecture/) shows which parts exist.

## Where is static analysis the better choice?

Static analysis is better when you need breadth, speed and early feedback. It can run on every pull request without booting the application, and it can point at code that is hard to reach dynamically. It is also better when the application cannot be run in a sandbox, or when the team needs a policy gate rather than a proof.

Use static analysis when:

- You want to cover a large codebase quickly.
- You need findings before the application is deployable.
- The rule is a clear pattern with a low false-positive cost.
- You cannot execute the target.
- You need a broad inventory rather than a proof.

The major SAST tools document their own dataflow and rule models. Semgrep's docs describe pattern-based and taint rules; CodeQL's docs describe database queries over a code representation. Those are legitimate approaches, and RedFall uses static analysis too.

## Where is execution verification the better choice?

Execution verification is better when a false positive is expensive. A finding that requires a day of triage, a release block or a customer notification should be a proof, not a lead.

Use execution verification when:

- A finding will trigger an incident or a disclosure.
- The path depends on framework routing or runtime configuration.
- The code is reachable but the exploitability is uncertain.
- You need a replayable request and response for a reviewer.
- You need to know that a fix actually stops the exploit.

RedFall's execution gate is strict: a candidate that does not reproduce is not a finding. That reduces the number of results and increases the cost of each result. The [verification pillar](/docs/verified-findings/) explains the trade-off.

## How do the outputs differ?

| Output property | Static analysis | RedFall |
| --- | --- | --- |
| Result | Candidate or alert | Verified finding, plus unproven candidates marked false |
| Evidence | Rule ID, location, path | Request, response, predicate, verdict |
| False positives | Managed by triage and suppression | Rejected by execution |
| Runtime required | Usually none | Docker + gVisor + provider key |
| Speed | Fast | Slower; bounded by execution |
| Coverage | Broad | Narrower; three language families |
| Fix verification | Usually out of scope | Tests plus original PoC replay |

The output difference is the point. A static alert says "this may be exploitable." A RedFall finding says "this request produced this effect on this build," with the request and response stored.

## What about DAST?

DAST tests a running application from the outside and can find issues that static analysis misses. It is complementary. RedFall differs in that it starts from the real source, builds a target-specific PoC from a taint path, and executes it in a controlled sandbox with a boot contract. A DAST scanner may find a similar issue, but it does not necessarily connect the request to the source location or verify a repair against the target's tests.

## How should a team choose?

Use a layered approach:

1. **Static analysis and SCA** for broad, fast coverage on every change.
2. **Execution verification** for the findings that will block a release or trigger disclosure.
3. **DAST** for the deployed surface and authentication flows.
4. **Human review** for impact, business context and fixes.

The mistake is treating any one layer as a complete answer. Static analysis without execution produces candidates; execution without static analysis has to guess where to aim; DAST without source context is hard to repair.

## What does RedFall not replace?

- A SAST platform with hundreds of rules and a policy engine.
- An SCA product with advisory feeds and licence analysis.
- A DAST scanner with authenticated crawl coverage.
- A manual penetration test.
- A secure-code-review programme.

The [evidence page](/evidence/) and the [range targets page](/docs/ranges/) show what RedFall was measured against. The [blocked page](/docs/blocked/) shows what it cannot run on the current host.

## Frequently asked questions

### Is execution verification always better than static analysis?

No. It is better when the cost of a false positive is high and the target can be executed. It is worse when you need speed, breadth or coverage of code you cannot run.

### Does RedFall use static analysis?

Yes. Ingestion and taint analysis are static. The difference is that their output is a candidate, not a finding. See [taint analysis](/docs/taint-analysis/).

### Can I use RedFall alongside Semgrep or CodeQL?

Yes. They answer different questions. A common pattern is to use a broad SAST tool for coverage and RedFall for the small set of findings that need execution proof.
