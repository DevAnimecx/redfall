---
title: RedFall documentation
seoTitle: "RedFall Documentation: Execution-Verified Scanning"
description: "How RedFall proves vulnerability findings by executing them: the verification guide, taint analysis, gVisor sandbox, adaptive scanning, fixes, install and reference."
path: docs/
group: Start here
kind: hub
order: 0
updated: 2026-10-21
keywords: RedFall documentation, execution-verified vulnerability scanner, vulnerability scanning guide
sources: https://github.com/DevAnimecx/redfall, https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md
---

RedFall is a vulnerability scanner that proves findings by executing them. It reads real TypeScript, JavaScript and Python source, tracks attacker-controlled data from a request surface to a sink, builds a candidate proof of concept, and runs it against the live application inside a Docker container on the gVisor `runsc` runtime. A candidate is reported only if it reproduces. Static analysis produces candidates; it never produces a finding on its own.

This documentation covers the mechanism, the evidence, the operating instructions and the limits. It is written for engineers who need to decide whether a finding is real before they spend a day triaging it, and for reviewers who want to check the claims against the source. The 0.1.1 release also exposes the same 44-tool registry to agents over MCP, HTTP/OpenAPI and A2A v1.0; the [interoperability page](/docs/interop/) documents those transports and their boundaries.

[[DOCS_INDEX]]

## How to use these docs

Start with [execution-verified vulnerability scanning](/docs/verified-findings/) if you want the argument, or [install RedFall](/docs/install/) if you want to run it. The architecture pillar explains how the pipeline is assembled; the trust pages record what was measured, what was skipped and what remains blocked.

Every page answers a question in the first paragraph, cites the primary source or the repository file behind a claim, and ends with related guides. There is no demo data on this site. Numbers come from commands that ran, and a missing number is described as missing rather than estimated.

## How this documentation is maintained

The pages are generated from Markdown in `site/content/` at build time. The same build emits the sitemap, `robots.txt`, `llms.txt` and the 404 page. A CI check fails the build if a page is missing a title, description, canonical URL, H1, structured data, or a working internal link.

The maintainer is [DevAnimecx](https://github.com/DevAnimecx). The source, tests, range targets and the full blocker ledger are public in the [RedFall repository](https://github.com/DevAnimecx/redfall). If a claim here cannot be reproduced, open an issue with the command and the observed output.
