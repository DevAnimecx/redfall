// Shared landing-page content. The visible FAQ and the FAQPage JSON-LD are
// generated from the same array, so an answer cannot drift between the two.
// Every answer is short enough to be quoted by an answer engine and links to
// the page that carries the full mechanism and its limits.

import { VERSION } from "./release.mjs";

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
    a: "TypeScript, JavaScript and Python are the certified pair-pairs: route extraction for Express, Fastify, koa-router, NestJS, Flask and FastAPI with prefixes resolved, and intra- plus interprocedural taint with return flow. Java/Kotlin and Go are read but not certified — Spring and JAX-RS annotations, and net/http, gorilla/chi and Gin/Echo registration are parsed and traced over real source, but no JVM or Go toolchain runs here, so no category has been reproduced against a running service. It is not a full type checker or a general-purpose SAST platform.",
    href: "/redfall/docs/languages/",
    link: "Check language coverage",
  },
  {
    q: "Does RedFall need an AI API key?",
    a: "No. From 0.2.0 the reasoning layer borrows an agent you already have installed — Claude Code, Codex, Gemini CLI, Aider, Cursor, Goose, OpenHands, Continue, Cline, Kilo, Qwen Code or Crush — or reads from an OpenAI-compatible endpoint such as Ollama, vLLM, LM Studio or OpenRouter. A provider key is one option among four, not a requirement. redfall agent detect names the agent it would use.",
    href: "/redfall/docs/agents/",
    link: "How bring-your-own-agent works",
  },
  {
    q: "How do I connect my own agent?",
    a: "Run redfall agent detect to see what is installed, then redfall agent certify <name> to prove the agent answers a real prompt with valid JSON from this host. Any agent that is not one of the twelve shipped drivers can be declared in redfall.toml under [agent] with a command, and RedFall will drive it the same way. Certification records the agent version and the run, and nothing else.",
    href: "/redfall/docs/agents/",
    link: "Certify an agent",
  },
  {
    q: "What does a full scan require?",
    a: "Docker with a gVisor runsc runtime, PostgreSQL and a target boot contract. Installing the CLI needs only Python 3.12+. From 0.2.0 the reasoning layer needs no AI API key — an installed agent, an OpenAI-compatible endpoint or a provider key all work. redfall doctor reports what the host can actually run, and missing prerequisites fail loudly instead of producing a demo scan.",
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
    q: "Is there a dashboard or a graphical interface?",
    a: "Yes. From 0.3.0, redfall dashboard starts a local console over the same tool registry the CLI uses — not a separate implementation. It streams a running scan over Server-Sent Events, lists findings with their evidence, replays a proof of concept, and proposes a fix inside a throwaway git worktree so your checkout is never written to. It binds loopback by default and refuses a non-loopback bind without a bearer token.",
    href: "/redfall/docs/dashboard/",
    link: "The dashboard guide",
  },
  {
    q: "Can a team run RedFall together?",
    a: "From 0.5.0. Enterprise tenancy puts teams behind isolation boundaries: a credential resolves to a tenant and the scope built from it is the only thing queries filter on, so no request field can widen it. Five roles carry explicit permission sets, operators write per-tenant policy rules that are evaluated before an action runs, and audit exports cover a timeline without a gap. It is off unless REDFALL_TENANCY is set. No OIDC or SAML provider is wired up yet — the identity half of SSO is stored, not enforced.",
    href: "/redfall/docs/enterprise/",
    link: "Tenancy, roles and policy",
  },
  {
    q: "Does RedFall learn from its own results?",
    a: "From 0.5.0, and only from reproduced ones. A lesson cites an E3/E4 evidence record — propose takes no grade argument, so a caller cannot declare its own claim verified — and then runs beside current behaviour in shadow, is compared against a holdout, and is promoted only if the *worst* holdout improved. Rejection and rollback both require a reason, and nothing is deleted. No holdout set exists on this host, so no promotion has been measured and no learning gain is claimed.",
    href: "/redfall/docs/learning/",
    link: "How the learning loop is gated",
  },
  {
    q: "Can different agents play different roles?",
    a: "Yes. The agent mesh names eight roles — recon, analyst, planner, exploit, runtime operator, critic, fixer, verifier — each with the smallest tool allowlist its job needs. The separation is the point: asking one agent to author an exploit and then judge whether it worked produces a report that looks identical to an independently verified one. A binding that puts the author and the critic on the same agent is refused. Most teams run one agent everywhere, so falling back to a shared default warns rather than failing.",
    href: "/redfall/docs/mesh/",
    link: "The agent mesh",
  },
  {
    q: "Is RedFall free to use?",
    a: `RedFall ${VERSION} does not declare a license, so public source readability is not a grant of reuse rights. If you need a license for evaluation or redistribution, open an issue. The project is maintained by DevAnimecx and has no corporate support contract.`,
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
    `pytest against real artefacts, local + CI`,
    `780 collected; 746 passed, 34 skipped on this host`,
  ],
  ["range/vulnbank", "76 tests, candidate exploits executed over real HTTP", "30/32 PoCs, 32/32 patches verified"],
  ["range/vulnbank-adaptive", "vulnbank plus 7 adaptive surfaces", "7/7 PoCs"],
  ["range/pythonbank", "real HTTP against Flask / FastAPI targets", "17/17 PoCs"],
  ["range/chainbank", "two-step exploit chains end to end", "6/6 chains reproduce"],
  ["Self-scan", "RedFall's own tree, all five language parsers", "0 parse errors"],
  [
    "Capacity plan, not a claim",
    "the microVM target computed against this host",
    "50 requested, 2 supported; refuses rather than guessing",
  ],
  [`Release v${VERSION}`, "CI-built wheel and sdist, SHA256SUMS, Sigstore", "verify with SHA256SUMS and Sigstore"],
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
    body: "Route extraction for Express, Fastify, koa-router, NestJS, Flask and FastAPI. Depth-one interprocedural taint in both language pairs, with return-flow summaries, over an inter-file call graph. Java/Kotlin and Go are read too, but not certified.",
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

// The platform surfaces added across 0.4.0 and 0.5.0. Each entry says what the
// thing is and what it does *not* claim, because the second half is what makes
// the first half believable.
export const PLATFORM = [
  {
    title: "Four languages, two of them certified",
    body: "Java/Kotlin and Go join TypeScript and Python. Spring and JAX-RS annotations are read, with the class prefix joined onto the method path; Go routes are read from the registration call, and its sinks are receiver-gated so a method named Command on someone's own type is not mistaken for process execution.",
    status: "Uncertified: no JVM or Go toolchain on the build host, so no service has been executed.",
    href: "/redfall/docs/languages/",
    link: "Language coverage and its limits",
  },
  {
    title: "Tenancy a team can be put behind",
    body: "A credential resolves to a tenant and the scope built from it is the only thing queries filter on. No request carries a tenant id a caller could choose, so reading another tenant's campaign by guessing its id is not a policy that can be misconfigured. Five roles, per-tenant policy rules, and an audit export whose resume point is the last record it wrote rather than the wall clock.",
    status: "Off unless REDFALL_TENANCY is set. No OIDC or SAML provider is wired up.",
    href: "/redfall/docs/enterprise/",
    link: "Tenancy, roles and policy",
  },
  {
    title: "A loop that learns only from proofs",
    body: "A lesson cites an E3/E4 evidence record and takes no grade argument, so a caller cannot declare its own claim verified. It then runs in shadow beside current behaviour, is compared on a holdout, and is promoted only when the worst holdout improved — with the gate re-checked at promotion and both rejection and rollback keeping their reason.",
    status: "No holdout exists on this host, so no promotion has been measured.",
    href: "/redfall/docs/learning/",
    link: "How the loop is gated",
  },
  {
    title: "A critic that is not the author",
    body: "Eight named roles, each with the smallest tool allowlist its job needs. The verifier holds no tool that writes a fix, and the fixer holds no tool that runs the proof. One agent authoring an exploit and then judging whether it worked produces a report that looks identical to an independently verified one — which is why the binding is refused.",
    status: "No multi-agent campaign has been run here; the refusals are tested, the gain is not claimed.",
    href: "/redfall/docs/mesh/",
    link: "The agent mesh",
  },
  {
    title: "An isolation ladder, and a plan that refuses",
    body: "Firecracker, gVisor and plain containers described as one ladder with a probe each, plus the arithmetic that says how many units of one a host holds. The 50-concurrent-microVM target computes to two on a 1982 MiB host, and the planner says so instead of a scheduler that starts fifty and runs out of memory.",
    status: "No KVM and no Docker here, so nothing boots: the plan is computed and refused, never demonstrated.",
    href: "/redfall/docs/sandbox/",
    link: "Tiers and capacity",
  },
  {
    title: "A deployment image",
    body: "An orchestrator image kept separate from the sandbox image it drives, a compose stack with its database and cache, and a healthcheck wired to redfall doctor --quiet — so a container that cannot scan reports unhealthy rather than merely busy.",
    status: "Manifests are verified; the image has never been built, because there is no Docker here.",
    href: "/redfall/docs/deploy/",
    link: "Deployment guide",
  },
];

// The twelve agents RedFall can drive today. One list feeds the landing page,
// the FAQ above and the docs, so the count cannot drift between them.
export const AGENTS = [
  ["Claude Code", "claude", "Anthropic"],
  ["Codex", "codex", "OpenAI"],
  ["Gemini CLI", "gemini", "Google"],
  ["Aider", "aider", "open source"],
  ["Cursor", "cursor-agent", "Cursor"],
  ["Goose", "goose", "Block"],
  ["OpenHands", "openhands", "open source"],
  ["Continue", "cn", "Continue"],
  ["Cline", "cline", "Cline"],
  ["Kilo", "kilo", "Kilo"],
  ["Qwen Code", "qwen", "Alibaba"],
  ["Crush", "crush", "Charm"],
];

export const REASONING_CHOICES = [
  {
    title: "Borrow an installed agent",
    body: "RedFall drives an agent already on your machine as a real subprocess, passing each prompt as data — never interpolated into a shell command. Twelve drivers ship today, and a custom command can be declared in redfall.toml.",
    href: "/redfall/docs/agents/",
    link: "The twelve agent drivers",
  },
  {
    title: "Point at a local endpoint",
    body: "Ollama, vLLM, LM Studio and OpenRouter speak the OpenAI wire format. Set a base URL and a model, and the engine talks to your own inference server with nothing leaving the machine.",
    href: "/redfall/docs/interop/",
    link: "Configure an endpoint",
  },
  {
    title: "Bring a provider key",
    body: "A hosted provider key still works, routed through LiteLLM exactly as before. Nothing about 0.2.0 removed it — the key just stopped being the only way in.",
    href: "/redfall/docs/install/",
    link: "The key path",
  },
  {
    title: "Route across several",
    body: "Split work by tier and require agreement: cheap models triage, a strong model decides, and consensus mode keeps the answer the majority reached. Spend is enforced before and after every call.",
    href: "/redfall/docs/architecture/",
    link: "How routing decides",
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
    body: "The orchestrator grows a tree of branches; seven adaptive detectors and agent categories decide where the next attempt goes, under a budget, using an agent or endpoint you already have.",
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

export const LAST_UPDATED = "October 21, 2026";
