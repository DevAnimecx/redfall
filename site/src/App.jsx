import { useState } from "react";

const GITHUB = "https://github.com/DevAnimecx/redfall";
const RELEASES = `${GITHUB}/releases`;
const RELEASE = `${RELEASES}/tag/v0.1.0`;

function Mark({ className = "" }) {
  return (
    <svg viewBox="0 0 256 256" className={className} aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="rd-red" x1="0.1" y1="0" x2="0.9" y2="1">
          <stop offset="0" stopColor="#ff5147" />
          <stop offset="0.55" stopColor="#e01b1b" />
          <stop offset="1" stopColor="#8c0202" />
        </linearGradient>
      </defs>
      <g fill="none" stroke="url(#rd-red)" strokeLinejoin="round" strokeLinecap="round">
        <path d="M46 26 H210 L234 50 V142 L128 236 L22 142 V50 Z" strokeWidth="16" />
        <circle cx="128" cy="118" r="42" strokeWidth="10" />
        <path d="M128 52 V68 M128 168 V184 M60 118 H76 M180 118 H196" strokeWidth="10" />
      </g>
      <circle cx="128" cy="118" r="12" fill="url(#rd-red)" />
    </svg>
  );
}

function Wordmark({ className = "" }) {
  return (
    <span className={`font-extrabold tracking-tight ${className}`}>
      <span className="text-brand">Red</span>
      <span className="text-white">Fall</span>
    </span>
  );
}

function CopyButton({ text, label }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(
          () => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1600);
          },
          () => {},
        );
      }}
      className="rounded-md border border-white/10 px-2.5 py-1 text-xs font-medium text-slate-300 transition hover:border-white/25 hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
      aria-label={`Copy ${label}`}
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function CodeBlock({ title, code }) {
  return (
    <figure className="rounded-xl border border-white/10 bg-ink-soft">
      <figcaption className="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</span>
        <CopyButton text={code} label={title} />
      </figcaption>
      <pre className="overflow-x-auto px-4 py-3.5 text-sm leading-relaxed text-slate-200">
        <code>{code}</code>
      </pre>
    </figure>
  );
}

function Card({ title, children }) {
  return (
    <article className="rounded-xl border border-white/10 bg-white/[0.03] p-6">
      <h3 className="mb-2 font-semibold text-white">{title}</h3>
      <p className="text-sm leading-relaxed text-slate-400">{children}</p>
    </article>
  );
}

function Step({ n, title, children }) {
  return (
    <li className="flex gap-4">
      <span
        className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-brand/30 bg-brand/10 text-sm font-bold text-brand"
        aria-hidden="true"
      >
        {n}
      </span>
      <div>
        <h3 className="font-semibold text-white">{title}</h3>
        <p className="mt-1 text-sm leading-relaxed text-slate-400">{children}</p>
      </div>
    </li>
  );
}

function Faq({ q, children }) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.02] p-6">
      <h3 className="font-semibold text-white">{q}</h3>
      <p className="mt-2 text-sm leading-relaxed text-slate-400">{children}</p>
    </div>
  );
}

const NAV = [
  ["#why", "Why"],
  ["#how", "How it works"],
  ["#evidence", "Evidence"],
  ["#install", "Install"],
  ["#faq", "FAQ"],
];

const EVIDENCE = [
  ["Test suite", "pytest against real artefacts, local + CI", "254 passed, 5 skipped (gVisor-only)"],
  ["range/vulnbank", "76 tests, candidate exploits executed over real HTTP", "30/32 PoCs, 32/32 patches verified"],
  ["range/vulnbank-adaptive", "vulnbank plus 7 adaptive surfaces", "7/7 PoCs"],
  ["range/pythonbank", "real HTTP against Flask / FastAPI targets", "17/17 PoCs"],
  ["range/chainbank", "two-step exploit chains end to end", "6/6 chains reproduce"],
  ["Self-scan", "Redfall's own tree, both language parsers", "654 edges, 0 errors"],
  ["Release v0.1.0", "CI-built wheel and sdist, SHA256SUMS, Sigstore", "attestation verified"],
];

const FAQ = [
  [
    "What is RedFall?",
    "RedFall is an autonomous vulnerability scanner that proves findings by execution. It ingests a target's real source with tree-sitter (TypeScript, JavaScript, Python), tracks attacker-controlled data from request surface to sink — across function boundaries, with return flow — generates a candidate exploit for each lead, runs it inside a gVisor sandbox against the running application, and reports only what reproduced. It then attempts a repair and verifies it against the target's own test suite.",
  ],
  [
    "How does RedFall verify a finding instead of guessing?",
    "Static analysis never produces findings, only candidates. A candidate becomes a finding only when its exploit ran inside the sandbox against the real application and its observable predicate matched. Every SARIF result carries properties.redfall.verified — true or false — and nothing is ever upgraded or dropped behind your back.",
  ],
  [
    "Which languages and frameworks are covered?",
    "TypeScript/TSX, JavaScript/JSX and Python. Route extraction covers Express, Fastify, koa-router and NestJS decorators, plus Flask and FastAPI with blueprint/router prefix resolution. Taint analysis has a depth-one interprocedural pass in both language pairs, including unseeded return-flow summaries, and an inter-file call graph.",
  ],
  [
    "What does a full scan require?",
    "Docker with a gVisor runtime and one LLM provider key (bring-your-own-key via LiteLLM). There is no dry-run mode: redfall doctor prints exactly what the current host can and cannot run, and refuses to guess. Anything unrunnable is listed in BLOCKED.md with its smallest real unblock.",
  ],
  [
    "How are fixes verified?",
    "The fix loop patches on a branch, runs the target's own tests, and re-runs the original PoC; a fix is verified only when the suite still passes and the PoC stops reproducing. Failure text is fed back into up to three attempts, then the transcripts go to a human. Nothing is committed or pushed for you.",
  ],
  [
    "Why are some tests skipped?",
    "The five skips are gVisor-dependent tests on the development host used for 0.1.0; they run in CI where the container runtime exists. The no-mock contract forbids simulating them locally, so they are reported as skips, not passes.",
  ],
  [
    "Where is the source and are releases verifiable?",
    "The full source, tests and ground-truth range targets are public in the GitHub repository. Releases are built by CI from the tagged commit, published with SHA256SUMS and attested with Sigstore, so gh attestation verify proves the wheel came from this repository's release workflow.",
  ],
];

export default function App() {
  return (
    <div className="min-h-screen bg-ink text-slate-200 antialiased">
      <a href="#main" className="skip-link">
        Skip to content
      </a>

      <header className="sticky top-0 z-40 border-b border-white/10 bg-ink/80 backdrop-blur">
        <nav className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3.5" aria-label="Main">
          <a href="#top" className="flex items-center gap-2.5">
            <Mark className="h-7 w-7" />
            <Wordmark className="text-lg" />
          </a>
          <div className="hidden items-center gap-6 md:flex">
            {NAV.map(([href, label]) => (
              <a key={href} href={href} className="text-sm text-slate-400 transition hover:text-white">
                {label}
              </a>
            ))}
          </div>
          <a
            href={GITHUB}
            className="rounded-lg bg-brand-deep px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-red-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
          >
            GitHub
          </a>
        </nav>
      </header>

      <main id="main">
        <section id="top" className="mx-auto max-w-6xl px-6 pb-16 pt-16 sm:pt-24">
          <p className="mb-4 inline-flex items-center gap-2 rounded-full border border-brand/30 bg-brand/10 px-3.5 py-1.5 text-xs font-semibold text-brand">
            <span aria-hidden="true">●</span> v0.1.0 — first release, Windows · Linux · macOS
          </p>
          <h1 className="max-w-3xl text-4xl font-extrabold leading-tight tracking-tight text-white sm:text-5xl">
            The vulnerability scanner that{" "}
            <span className="text-brand">proves every finding by executing it</span>.
          </h1>
          <p className="mt-6 max-w-3xl text-lg leading-relaxed text-slate-400">
            RedFall reads a target's real source (TypeScript, JavaScript, Python), tracks attacker-controlled data
            from request surface to sink — including across function boundaries — generates a candidate exploit for
            every lead, and runs it inside a gVisor sandbox against the live application. Only what reproduces is
            reported. Then it repairs, and calls the fix verified only when the target's own tests still pass{" "}
            <em>and</em> the original PoC stops working.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <a
              href="#install"
              className="rounded-lg bg-brand-deep px-5 py-3 text-sm font-semibold text-white transition hover:bg-red-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
            >
              Get started
            </a>
            <a
              href={GITHUB}
              className="rounded-lg border border-white/15 px-5 py-3 text-sm font-semibold text-slate-200 transition hover:border-white/35 hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
            >
              View source on GitHub
            </a>
          </div>
          <dl className="mt-10 grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-white/10 bg-white/10 text-sm sm:grid-cols-4">
            {[
              ["254", "tests passed"],
              ["6/6", "chains reproduce"],
              ["17/17", "pythonbank PoCs"],
              ["SARIF", "2.1.0 with verified flags"],
            ].map(([big, small]) => (
              <div key={small} className="flex flex-col bg-ink px-5 py-4">
                <dt className="order-2 text-xs text-slate-400">{small}</dt>
                <dd className="order-1 text-xl font-bold text-white">{big}</dd>
              </div>
            ))}
          </dl>
        </section>

        <section id="why" className="border-t border-white/10 bg-white/[0.015]">
          <div className="mx-auto max-w-6xl px-6 py-16 sm:py-20">
            <h2 className="text-2xl font-extrabold tracking-tight text-white sm:text-3xl">What makes it different</h2>
            <p className="mt-3 max-w-2xl text-slate-400">
              Most scanners hand you a list of suspicions. RedFall hands you executed proofs, on a public record of
              what could and could not be run.
            </p>
            <div className="mt-10 grid gap-5 md:grid-cols-2">
              <Card title="Executed proofs only">
                Static analysis produces candidates, never findings. A finding exists only if its exploit ran against
                the real application and its predicate matched; every SARIF result carries{" "}
                <code className="rounded bg-white/10 px-1.5 py-0.5 text-xs">verified: true/false</code> and nothing is
                upgraded behind your back. The no-mock contract is enforced in CI.
              </Card>
              <Card title="Taint that crosses functions">
                Route extraction for Express, Fastify, koa-router, NestJS, Flask and FastAPI (with blueprint prefix
                resolution). Taint analysis runs intraprocedurally plus a depth-one interprocedural pass in both
                language pairs — unseeded return-flow summaries included — over an inter-file call graph.
              </Card>
              <Card title="Scans that grow mid-run">
                Work is a tree of branches, not a fixed plan. Seven adaptive detectors open new surfaces when the
                target suggests them, and chaining composes confirmed steps into two-step exploits with compound CVSS
                scoring and operational narratives.
              </Card>
              <Card title="Fixes you can trust">
                The repair loop patches on a branch, runs the target's own tests, and re-runs the original PoC.
                Verified means the suite passes and the PoC stops reproducing — three attempts with the real failure
                text, then a human sees the full transcript.
              </Card>
            </div>
          </div>
        </section>

        <section id="how" className="border-t border-white/10">
          <div className="mx-auto max-w-6xl px-6 py-16 sm:py-20">
            <h2 className="text-2xl font-extrabold tracking-tight text-white sm:text-3xl">How a scan works</h2>
            <ol className="mt-10 grid gap-8 md:grid-cols-2">
              <Step n="1" title="Ingest">
                tree-sitter parses the real tree; symbols, routes, dependencies and git state are extracted for
                TypeScript, JavaScript and Python.
              </Step>
              <Step n="2" title="Taint">
                Sources are tracked to sinks — intraprocedurally and across function boundaries with return-flow
                summaries — and an inter-file call graph connects the pieces.
              </Step>
              <Step n="3" title="Plan">
                The orchestrator grows a tree of branches; adaptive detectors and agent categories decide where the
                next attempt goes, under a budget, with bring-your-own LLM key.
              </Step>
              <Step n="4" title="Execute">
                Each candidate becomes a generated exploit that runs inside Docker + gVisor against the live target.
                Its observable predicate decides — nothing else does.
              </Step>
              <Step n="5" title="Report">
                Verified results export as SARIF 2.1.0 with per-result flags; the fix loop then patches, tests, and
                re-runs the PoC to prove the repair.
              </Step>
            </ol>
          </div>
        </section>

        <section id="evidence" className="border-t border-white/10 bg-white/[0.015]">
          <div className="mx-auto max-w-6xl px-6 py-16 sm:py-20">
            <h2 className="text-2xl font-extrabold tracking-tight text-white sm:text-3xl">Evidence, not adjectives</h2>
            <p className="mt-3 max-w-3xl text-slate-400">
              Every number below came from a command that actually ran on a real host. What could not run there is
              listed in <span className="text-slate-200">BLOCKED.md</span> with the smallest real unblock for each
              item — no estimates in place of results.
            </p>
            <div className="mt-8 overflow-x-auto rounded-xl border border-white/10">
              <table className="w-full min-w-[40rem] text-left text-sm">
                <thead>
                  <tr className="border-b border-white/10 text-xs uppercase tracking-wider text-slate-400">
                    <th scope="col" className="px-5 py-3.5 font-semibold">Target</th>
                    <th scope="col" className="px-5 py-3.5 font-semibold">What ran</th>
                    <th scope="col" className="px-5 py-3.5 font-semibold">Result</th>
                  </tr>
                </thead>
                <tbody>
                  {EVIDENCE.map(([target, what, result]) => (
                    <tr key={target} className="border-b border-white/5 last:border-0">
                      <td className="px-5 py-3.5 font-medium text-white">{target}</td>
                      <td className="px-5 py-3.5 text-slate-400">{what}</td>
                      <td className="px-5 py-3.5 text-slate-200">{result}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <section id="install" className="border-t border-white/10">
          <div className="mx-auto max-w-6xl px-6 py-16 sm:py-20">
            <h2 className="text-2xl font-extrabold tracking-tight text-white sm:text-3xl">Install</h2>
            <p className="mt-3 max-w-3xl text-slate-400">
              Pure-Python wheel: no compiled extensions, no post-install hooks. The installers use{" "}
              <code className="rounded bg-white/10 px-1.5 py-0.5 text-xs">pipx</code> when present and a private
              virtualenv otherwise — never system-wide, never elevated — and finish with{" "}
              <code className="rounded bg-white/10 px-1.5 py-0.5 text-xs">redfall doctor</code>, the host's real
              capability report.
            </p>
            <div className="mt-8 grid gap-5 lg:grid-cols-2">
              <CodeBlock
                title="Windows (PowerShell)"
                code={"git clone https://github.com/DevAnimecx/redfall.git; cd redfall\n.\\scripts\\install.ps1"}
              />
              <CodeBlock
                title="Linux / macOS"
                code={"git clone https://github.com/DevAnimecx/redfall.git && cd redfall\n./scripts/install.sh"}
              />
              <CodeBlock
                title="Any package manager"
                code={"pipx install git+https://github.com/DevAnimecx/redfall\nredfall doctor"}
              />
              <CodeBlock
                title="Verify a release"
                code={"gh attestation verify redfall-0.1.0-py3-none-any.whl \\\n  --repo DevAnimecx/redfall"}
              />
            </div>
            <p className="mt-6 text-sm text-slate-400">
              The full README, the changelog and the honest BLOCKED.md live in the{" "}
              <a href={GITHUB} className="font-medium text-brand underline-offset-4 hover:underline">
                GitHub repository
              </a>
              .
            </p>
          </div>
        </section>

        <section id="faq" className="border-t border-white/10 bg-white/[0.015]">
          <div className="mx-auto max-w-6xl px-6 py-16 sm:py-20">
            <h2 className="text-2xl font-extrabold tracking-tight text-white sm:text-3xl">FAQ</h2>
            <div className="mt-10 grid gap-5 md:grid-cols-2">
              {FAQ.map(([q, a]) => (
                <Faq key={q} q={q}>
                  {a}
                </Faq>
              ))}
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-white/10">
        <div className="mx-auto flex max-w-6xl flex-col gap-8 px-6 py-12 sm:flex-row sm:items-start sm:justify-between">
          <div className="max-w-sm">
            <div className="flex items-center gap-2.5">
              <Mark className="h-7 w-7" />
              <Wordmark className="text-lg" />
            </div>
            <p className="mt-3 text-sm leading-relaxed text-slate-400">
              Autonomous vulnerability discovery and verified repair. Findings are executed proofs only — every
              number came from a command that ran.
            </p>
          </div>
          <nav aria-label="Project links" className="grid grid-cols-2 gap-x-12 gap-y-2 text-sm">
            <a href={GITHUB} className="text-slate-400 transition hover:text-white">GitHub repository</a>
            <a href={RELEASE} className="text-slate-400 transition hover:text-white">Release v0.1.0</a>
            <a href={`${GITHUB}/blob/main/CHANGELOG.md`} className="text-slate-400 transition hover:text-white">Changelog</a>
            <a href={`${GITHUB}/blob/main/CONTRIBUTING.md`} className="text-slate-400 transition hover:text-white">Contributing</a>
            <a href={`${GITHUB}/blob/main/SECURITY.md`} className="text-slate-400 transition hover:text-white">Security</a>
            <a href={`${GITHUB}/blob/main/BLOCKED.md`} className="text-slate-400 transition hover:text-white">What is blocked</a>
          </nav>
        </div>
        <div className="border-t border-white/10">
          <p className="mx-auto max-w-6xl px-6 py-5 text-xs text-slate-400">
            © 2026 RedFall contributors · Source available on GitHub · Built under the no-mock contract: nothing on
            this page is simulated.
          </p>
        </div>
      </footer>
    </div>
  );
}
