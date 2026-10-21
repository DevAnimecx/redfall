---
title: The no-mock contract
seoTitle: "The No-Mock Contract for Security Tooling"
description: "RedFall's no-mock contract forbids demo modes, simulated findings and synthetic numbers. Here is the rule, what it bans, how CI enforces it, and what it does not cover."
path: docs/no-mock-contract/
group: Start here
kind: cluster
pillar: verified-findings
order: 3
updated: 2026-10-21
keywords: no-mock contract, security tool honesty, vulnerability scanner evidence
sources: https://github.com/DevAnimecx/redfall/blob/main/CONTRIBUTING.md, https://github.com/DevAnimecx/redfall/blob/main/scripts/check_no_mock.py, https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md
related: verified-findings, blocked, output
---

**The no-mock contract is RedFall's rule that a result must come from the real system it claims to describe.** No demo mode, no synthetic fixture path, no host-execution escape hatch, no canned model completion, and no number that was estimated and then presented as measured. The rule is enforced by a CI checker and a written blocker ledger, not by good intentions.

The contract exists because security tools are uniquely good at producing confident fiction. A scanner that cannot execute can still print a finding; a model can still produce a plausible exploit; a dashboard can still show a green number. Each of those outputs looks like evidence until someone tries to reproduce it.

## What does the contract require?

The contract has two directions. A claim about a real system must be backed by an execution against that system, and a claim that cannot be backed must be reported as blocked rather than replaced with a simulation.

| Requirement | What it means in practice |
| --- | --- |
| Real ingestion | Parse the target's real source, not a fixture that resembles it |
| Real execution | Run the PoC against the real application in the sandbox |
| Real model calls | Use a live provider call or a cached real transcript |
| Real numbers | Measure with a command; name the command and the date |
| Real skips | Report a skipped test as skipped, with the reason |
| Real blockers | Keep a written ledger of what cannot run and why |

The [verification pillar](/docs/verified-findings/) explains how the execution gate works. This page is about the rule that keeps the gate from being bypassed.

## What does the contract forbid?

The forbidden list is deliberately concrete, because "be honest" is not a testable rule.

- **A demo mode.** There is no switch that produces example findings when the sandbox is missing.
- **A synthetic fallback path.** A missing container runtime does not trigger a host-execution path or a fixture that returns a canned verdict.
- **A fabricated model response.** A missing provider key raises an error. It does not return a completion that looks real.
- **Treating a skip as a pass.** The five gVisor-dependent tests are reported as five skips when no runtime is present. They are not counted as five passes.
- **Silent candidate promotion.** SARIF carries `properties.redfall.verified` on every result. A candidate is not quietly upgraded because a model was confident.
- **Estimated numbers in evidence tables.** If a number was not measured, it is absent or labelled blocked.

The [blocked page](/docs/blocked/) is the public record of the third and fourth points. It names the missing prerequisites, the commands that were tried, the smallest real unblock, and what is real in the meantime.

## How is the contract enforced?

Three mechanisms keep the rule from becoming a slogan.

1. **`scripts/check_no_mock.py`.** The checker scans the source for forbidden fallback patterns and exits non-zero on a violation. It runs in CI and in `make check`, and its output is a contract line rather than a warning.
2. **Tests against real artefacts.** The test suite uses a real Postgres where persistence is the property under test, real target applications for the range replays, and real HTTP for the harness checks. The suite does use test doubles where the property is pure logic; it does not present a doubled result as a verified finding.
3. **`BLOCKED.md`.** The blocker ledger is part of the repository. It records the environment, the failed attempts, the smallest unblock and the measured state. A reader can check whether a capability was exercised or only written.

The contract is also documented in [CONTRIBUTING.md](https://github.com/DevAnimecx/redfall/blob/main/CONTRIBUTING.md), so a pull request that weakens it is reviewable as a contract change rather than a style preference.

## What does the contract not forbid?

It does not forbid unit tests with fakes. A test that checks a parser's handling of a malformed token does not need a live target, and using a fake there is not a claim about a live target. The line is whether the artefact is presented as evidence about the real system.

It also does not forbid caching. If an identical prompt has a stored real request and response, RedFall may reuse that transcript and mark it `cached=true`. The cached object is a real transcript, not a synthesized one.

Finally, it does not forbid saying "I don't know." The correct output for an unmeasured capability is a blocker, not a guess.

## How do you check a claim?

Use the same four questions for any claim on this site or in the repository:

1. **What command produced this?** If there is no command, there is no measurement.
2. **What was the environment?** Operating system, Python version, database, container runtime, provider key.
3. **Was it executed or inferred?** A file that exists is not a capability that ran.
4. **What is the failure mode?** If the prerequisite disappears, does the tool fail loudly or fall back silently?

A claim that cannot answer those questions should be treated as marketing, even when it is well intentioned.

## Where does the contract appear in the product?

The contract is visible in the interface as well as the code:

- The CLI's `doctor` and `environment` commands report prerequisites rather than assuming them.
- `redfall scan` refuses when the sandbox or provider is missing, and names both blockers.
- SARIF exports unproven candidates with `verified: false` instead of dropping them silently.
- The fix loop records the test result and the PoC result separately, and marks a fix verified only when both hold.
- The website labels measured results with their commands and dates, and links to the blocker ledger.

The [SARIF page](/docs/output/) shows the verified flag in context. The [blocked page](/docs/blocked/) shows what the contract costs in practice: a full scan cannot run on the current development host, so the site does not claim one did.

## Frequently asked questions

### Does the no-mock contract mean every test uses a live external service?

No. It means a claim about a live system is backed by a live check. Pure-logic tests can use doubles, and the repository says which is which.

### Why publish the blocker ledger instead of hiding it?

Because a missing prerequisite is information. A reader deciding whether to trust a scan needs to know whether the execution path was exercised on the host that produced the result. Hiding that would make every other number less credible.

### Is the contract enforced on pull requests?

Yes. The checker runs in CI, and the contribution guide requires a change that weakens a real-execution guarantee to be explicit and reviewable.
