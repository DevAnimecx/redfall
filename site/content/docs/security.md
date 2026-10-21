---
title: Security and supply chain
seoTitle: "RedFall Security Policy and Supply Chain"
description: "RedFall's threat model, the deliberately vulnerable range targets, private vulnerability reporting, weekly dependency auditing and Sigstore-attested releases."
path: docs/security/
group: Trust and evidence
kind: cluster
pillar: evidence
order: 6
updated: 2026-10-21
keywords: RedFall security policy, vulnerability reporting, software supply chain security, Sigstore release
sources: https://github.com/DevAnimecx/redfall/blob/main/SECURITY.md, https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability
related: release-verification, blocked, install
---

**The threat RedFall manages is the target's, not the analyst's.** RedFall executes target code on purpose, inside a gVisor sandbox, against applications you are authorized to test. The range targets are deliberately vulnerable and must never be exposed. Vulnerabilities in RedFall itself go through GitHub's private reporting flow.

This page summarises the security policy in the repository. The [full SECURITY.md](https://github.com/DevAnimecx/redfall/blob/main/SECURITY.md) is the authoritative version.

## What is the threat model?

RedFall is a tool for running hostile input against a target. It is not a service that makes arbitrary code safe.

| Asset | Threat | Control |
| --- | --- | --- |
| The host | Target code escaping the sandbox | Docker + gVisor, capability drop, no-new-privileges, pid/memory/CPU caps |
| The target | Unauthorized testing | The operator must own or have written permission to test it |
| The analyst | Credential leakage in transcripts | Provider keys come from the environment; do not paste them into issues |
| The release | Tampered artifact | SHA256SUMS and Sigstore attestation |
| The dependency graph | A known vulnerable package | Weekly `pip-audit` in CI |

The sandbox limits blast radius; it does not make a hostile target benign. Run scans on a host you control and only against systems you are allowed to test.

## Why are the range targets dangerous?

`range/vulnbank`, `range/vulnbank-adaptive`, `range/chainbank` and `range/pythonbank` are applications built to contain known vulnerabilities. They exist to be exploited by the test suite.

- Never deploy a range target anywhere reachable.
- Keep the local scripts bound to loopback.
- Never point RedFall at a system you do not own or have written permission to test.

The targets are part of the test infrastructure, not a product you should expose. The [range targets page](/docs/ranges/) describes them.

## How do you report a vulnerability in RedFall?

Use GitHub's private vulnerability reporting: **Security** → **Report a vulnerability** on the [repository](https://github.com/DevAnimecx/redfall/security/advisories/new). Do not open a public issue for anything exploitable.

Include:

- the affected version or commit;
- a minimal reproduction;
- the impact you believe it has;
- whether a range target is needed to trigger it.

Reports about unintended execution of target code outside the sandbox, or the harness escaping its container, are especially welcome. The policy commits to acknowledgement within a few days, an honest triage (including "not a vulnerability" with reasoning), and credit in release notes when requested.

## Which versions are supported?

0.1.x receives security fixes. There is no back-porting policy before 1.0; fixes land on `main` and ship in the next release. A finding against an older commit should include the commit and the version.

## What does the supply chain look like?

The security policy makes several checkable claims:

- **Pure Python.** The wheel is `py3-none-any` and ships no compiled binaries, no post-install hooks and no vendored code.
- **Declared dependencies.** Runtime dependencies are in `pyproject.toml` with lower bounds.
- **Weekly audit.** `.github/workflows/security.yml` runs `pip-audit` weekly.
- **Attested builds.** Release artifacts are built by GitHub Actions from the tagged source and carry Sigstore attestations.
- **Published hashes.** Every release publishes `SHA256SUMS`.
- **Rebuildable.** A checkout can build the wheel, and `scripts/verify_wheel.py` proves an installed wheel behaves.

The [release verification page](/docs/release-verification/) gives the commands. No claim here says the software is free of vulnerabilities; the claim is that the artifact's provenance and behaviour can be checked.

## What does "secure" mean here?

It means the tool is small enough to audit, the execution boundary is explicit, the release is verifiable, and the project records what it cannot run. It does not mean the scanner is invulnerable or that a scanned target is safe.

The [no-mock contract](/docs/no-mock-contract/) is part of the security posture: a tool that fabricates a result is unsafe in a different way, because it creates false confidence. The [blocked page](/docs/blocked/) is the public record of the capabilities that are not exercised on the current host.

## What should you not put in an issue?

Do not paste provider keys, target credentials, customer data or a full exploit against a system you do not own. For a sensitive report, use the private advisory flow. For a documentation correction, a public issue is fine.

## Frequently asked questions

### Is RedFall safe to run against production?

Only with explicit authorization, a controlled host, and a clear understanding that it generates and executes exploits. The sandbox reduces risk; it does not grant permission.

### Does the sandbox protect the target from RedFall?

The target is the thing being exploited. The sandbox protects the host and limits the target's reach. The target's own data and availability are still affected by the scan.

### Where is the full policy?

[SECURITY.md](https://github.com/DevAnimecx/redfall/blob/main/SECURITY.md) in the repository.
