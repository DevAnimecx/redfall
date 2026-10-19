// Shared landing-page content. The visible FAQ and the FAQPage JSON-LD are
// generated from the same array, so an answer cannot drift between the two.
// Every answer is short enough to be quoted by an answer engine and links to
// the page that carries the full mechanism and its limits.

export const FAQ = [
  {
    q: "What is RedFall?",
    a: "RedFall is a vulnerability scanner for TypeScript, JavaScript and Python that proves findings by execution. It traces attacker-controlled data to dangerous sinks, runs a candidate exploit against the real application inside a gVisor sandbox, and reports only what reproduces. Static analysis produces candidates; execution produces findings.",
    href: "/redfall/docs/verified-findings/",
    link: "How execution verification works",
  },
  {
    q: "How does RedFall verify a finding instead of guessing?",
    a: "A finding is kept only after its proof of concept runs against the real target and a defined predicate matches. The request, response and verdict are stored. SARIF also carries properties.redfall.verified on every result, so unproven candidates stay marked false and are never silently upgraded.",
    href: "/redfall/docs/output/",
    link: "See the SARIF contract",
  },
  {
    q: "Which languages and frameworks are covered?",
    a: "TypeScript, JavaScript and Python. Route extraction covers Express, Fastify, koa-router, NestJS, Flask and FastAPI, with mount and blueprint prefixes resolved. Taint analysis is intra- and interprocedural with return flow. It is not a full type checker or a general-purpose SAST platform.",
    href: "/redfall/docs/languages/",
    link: "Check language coverage",
  },
  {
    q: "What does a full scan require?",
    a: "Docker with a gVisor runsc runtime, one LLM provider key through LiteLLM, PostgreSQL and a target boot contract. Installing the CLI needs only Python 3.12+. redfall doctor reports what the host can actually run, and missing prerequisites fail loudly instead of producing a demo scan.",
    href: "/redfall/docs/install/",
    link: "Read the install guide",
  },
  {
    q: "How are fixes verified?",
    a: "The fix loop patches a scratch checkout, runs the target's own tests, and replays the original proof of concept. A fix is verified only when the tests pass and the PoC stops reproducing. After three attempts, the full transcript goes to a human. Nothing is committed or pushed automatically.",
    href: "/redfall/docs/verified-fixes/",
    link: "How verified fixes work",
  },
  {
    q: "Why are some tests skipped?",
    a: "Five sandbox tests require Docker plus gVisor and are skipped on the current development host. They run in CI where the runtime exists. The no-mock contract requires reporting them as skips, not passes; the blocker ledger names the missing prerequisite and the smallest real unblock.",
    href: "/redfall/docs/blocked/",
    link: "Read the blocker ledger",
  },
  {
    q: "Where is the source and are releases verifiable?",
    a: "The source, tests and range targets are public on GitHub. Releases are built by CI from the tagged commit, published with SHA256SUMS, and attested with Sigstore. Verify a wheel with gh attestation verify. That proves build provenance, not that the software is free of every vulnerability.",
    href: "/redfall/docs/release-verification/",
    link: "Verify a release",
  },
  {
    q: "Is RedFall free to use?",
    a: "RedFall 0.1.0 does not declare a license, so public source readability is not a grant of reuse rights. If you need a license for evaluation or redistribution, open an issue. The project is maintained by DevAnimecx and has no corporate support contract.",
    href: "/redfall/about/",
    link: "About the project",
  },
  {
    q: "Does RedFall replace static analysis?",
    a: "No. RedFall uses static analysis to find candidates and adds an execution gate for findings that need proof. A SAST or SCA platform still provides broader, faster coverage. Use execution verification when a false positive would block a release, trigger disclosure or cost a day of triage.",
    href: "/redfall/compare/static-analysis/",
    link: "Compare the approaches",
  },
];

export const EVIDENCE = [
  [
    "Test suite",
    "pytest against real artefacts, local + CI",
    "254 passed, 5 skipped (gVisor-only)",
  ],
  ["range/vulnbank", "76 tests, candidate exploits executed over real HTTP", "30/32 PoCs, 32/32 patches verified"],
  ["range/vulnbank-adaptive", "vulnbank plus 7 adaptive surfaces", "7/7 PoCs"],
  ["range/pythonbank", "real HTTP against Flask / FastAPI targets", "17/17 PoCs"],
  ["range/chainbank", "two-step exploit chains end to end", "6/6 chains reproduce"],
  ["Self-scan", "RedFall's own tree, both language parsers", "654 edges, 0 errors"],
  ["Release v0.1.0", "CI-built wheel and sdist, SHA256SUMS, Sigstore", "attestation verified"],
];

export const FEATURES = [
  {
    title: "Executed proofs only",
    body: "Static analysis produces candidates, never findings. A finding exists only if its exploit ran against the real application and its predicate matched. Every SARIF result carries a verified flag; the no-mock contract is enforced in CI.",
    href: "/redfall/docs/verified-findings/",
    link: "The verification model",
  },
  {
    title: "Taint that crosses functions",
    body: "Route extraction for Express, Fastify, koa-router, NestJS, Flask and FastAPI. Depth-one interprocedural taint in both language pairs, with return-flow summaries, over an inter-file call graph.",
    href: "/redfall/docs/taint-analysis/",
    link: "How taint analysis works",
  },
  {
    title: "Scans that grow mid-run",
    body: "Work is a tree of branches, not a fixed plan. Seven adaptive detectors open new surfaces when the target suggests them, and chaining composes confirmed steps into multi-step exploits.",
    href: "/redfall/docs/adaptive-scanning/",
    link: "The seven adaptive surfaces",
  },
  {
    title: "Fixes you can verify",
    body: "The repair loop patches on a branch, runs the target's own tests, and re-runs the original PoC. Verified means the suite passes and the PoC stops reproducing — three attempts, then a human sees the transcript.",
    href: "/redfall/docs/verified-fixes/",
    link: "How fixes are proved",
  },
];

export const STEPS = [
  {
    title: "Ingest",
    body: "tree-sitter parses the real tree; symbols, routes, dependencies and git state are extracted for TypeScript, JavaScript and Python.",
    href: "/redfall/docs/architecture/",
  },
  {
    title: "Taint",
    body: "Sources are tracked to sinks — intraprocedurally and across function boundaries with return-flow summaries — and an inter-file call graph connects the pieces.",
    href: "/redfall/docs/taint-analysis/",
  },
  {
    title: "Plan",
    body: "The orchestrator grows a tree of branches; seven adaptive detectors and agent categories decide where the next attempt goes, under a budget, with a bring-your-own LLM key.",
    href: "/redfall/docs/adaptive-scanning/",
  },
  {
    title: "Execute",
    body: "Each candidate becomes a generated exploit that runs inside Docker + gVisor against the live target. Its observable predicate decides — nothing else does.",
    href: "/redfall/docs/sandbox/",
  },
  {
    title: "Report",
    body: "Verified results export as SARIF 2.1.0 with per-result flags; the fix loop then patches, tests, and re-runs the PoC to prove the repair.",
    href: "/redfall/docs/output/",
  },
];

export const LAST_UPDATED = "October 19, 2026";
