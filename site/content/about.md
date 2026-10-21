---
title: About RedFall
seoTitle: "About RedFall and Its Maintainer"
description: "Who maintains RedFall, why the project exists, how to verify the work, what the public identity is, and which claims the project deliberately does not make."
path: about/
group: Project
kind: page
order: 1
updated: 2026-10-21
keywords: about RedFall, RedFall maintainer, DevAnimecx
sources: https://github.com/DevAnimecx/redfall, https://github.com/DevAnimecx/redfall/releases, https://github.com/DevAnimecx/redfall/actions
related: evidence, security, privacy
---

**RedFall is maintained in public by DevAnimecx, the GitHub identity behind the repository.** The project is a working 0.1.1 release, not a company, a support contract or a research demo. Its claims are meant to be checked against the source, the tests and the blocker ledger rather than accepted from a byline.

This page explains who is responsible for the work, how to verify it, and what the project does not claim.

## Who maintains RedFall?

RedFall is maintained by **DevAnimecx**. The public identity is the GitHub account, and the repository, commits, issues and release history are the record of the work.

The project does not publish a legal name, a postal address, a corporate affiliation or a support phone number. It also does not publish an author photo or a fabricated biography. If you need to establish identity for a security report, use the GitHub account and the signed release attestations; if you need a legal entity for procurement, this project is not the right fit.

The [Person schema](/about/) on this page names the maintainer and links to the GitHub profile. The [release verification page](/docs/release-verification/) shows how to check that an artifact came from this repository.

## Why does RedFall exist?

Because vulnerability scanners are good at producing candidates and bad at telling you which ones are real. A team can spend a day triaging a finding that a runtime check would have dismissed in minutes. A finding that reaches a customer, a regulator or a release gate should be a proof.

RedFall's answer is execution. The scanner reads real source, tracks attacker-controlled data to sinks, builds a proof of concept, runs it against the live application in a gVisor sandbox, and reports only what reproduces. It then verifies repairs against the target's own tests. The [verification pillar](/docs/verified-findings/) is the full argument.

The project is also an argument about evidence. If a capability cannot run on the host, the project says so. If a test skips, the skip is reported. If a number was not measured, it is not in the evidence table. That rule is the [no-mock contract](/docs/no-mock-contract/).

## How can you verify the work?

Use the public artefacts:

| What | Where |
| --- | --- |
| Source and history | [github.com/DevAnimecx/redfall](https://github.com/DevAnimecx/redfall) |
| Tests | `tests/` and the CI workflows |
| Range targets | `range/` with their own test suites and replay scripts |
| Measured results | [Evidence](/evidence/) and [BLOCKED.md](https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md) |
| Release artefacts | [v0.1.1 release](https://github.com/DevAnimecx/redfall/releases/tag/v0.1.1) |
| Build provenance | Sigstore attestation and `SHA256SUMS` |
| Security policy | [SECURITY.md](https://github.com/DevAnimecx/redfall/blob/main/SECURITY.md) |

If a page or a README claim cannot be reproduced, open an issue with the command and the observed output. A correction with a real transcript is more useful than a disagreement about wording.

## What is the project status?

0.1.1 is a public release. It targets Windows, Linux and macOS, runs on Python 3.12+, and ships as a pure-Python wheel. The non-execution paths — ingestion, taint analysis, route extraction, SARIF export, the contract suite and the range replays — were measured. A full `redfall scan` needs Docker with gVisor, a provider key and PostgreSQL; the current development host has neither a container runtime nor a provider key. That is recorded on the [blocked page](/docs/blocked/).

The project does not claim production support, an SLA, a security certification or a guaranteed detection rate. It claims a working 0.1.1 with a specific evidence trail.

## What is the license?

0.1.1 does not declare a license file. The source is publicly readable on GitHub, but public readability is not a grant of reuse rights. A license decision is pending; until one is declared, do not assume that you may redistribute or incorporate the code. If you need a license to evaluate RedFall, open an issue and say so.

The font and brand assets have their own provenance; the repository's third-party notices, where present, apply.

## What does RedFall not claim?

- **No guaranteed rankings, backlinks or AI citations.** Those are external outcomes, not product capabilities.
- **No "virus free" or "unhackable" claim.** The release checks establish provenance and behaviour, not the absence of every vulnerability.
- **No simulated results.** A blocked capability is reported as blocked.
- **No complete coverage.** The supported languages, frameworks and categories are enumerated, and the exclusions are recorded.
- **No substitute for authorization.** Run scans only against systems you own or have written permission to test.

## How do you contact the maintainer?

For a bug or a documentation correction, open an issue in the [repository](https://github.com/DevAnimecx/redfall/issues). For a vulnerability in RedFall itself, use GitHub's private vulnerability reporting: **Security** → **Report a vulnerability**. Do not open a public issue for anything exploitable.

The [privacy page](/privacy/) explains what the site does and does not collect. It does not run analytics or set cookies.

## Frequently asked questions

### Is DevAnimecx a company?

No. It is the public GitHub identity used to maintain the project. There is no corporate entity, support contract or sales team behind this page.

### Can I use RedFall commercially?

The repository does not declare a license for 0.1.1, so do not assume commercial reuse rights. Open an issue if you need a license decision for evaluation.

### How do I know the maintainer is real?

The identity is the GitHub account, the commit history, the signed release attestation and the public issue tracker. That is the available evidence; the project does not invent a stronger credential.
