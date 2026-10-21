import { useCallback, useEffect, useId, useRef, useState } from "react";
import {
  ArrowRight,
  BadgeCheck,
  Check,
  ChevronDown,
  Copy,
  ExternalLink,
  GitBranch,
  Menu,
  Network,
  ShieldCheck,
  X,
} from "lucide-react";

import { EVIDENCE, FAQ, FEATURES, LAST_UPDATED, STEPS } from "../lib/content.mjs";
import { RELEASE_URL, VERSION } from "../lib/release.mjs";

const GITHUB = "https://github.com/DevAnimecx/redfall";
const DOCS = "/redfall/docs/";
const EVIDENCE_PAGE = "/redfall/evidence/";
const COMPARE = "/redfall/compare/static-analysis/";
const ABOUT = "/redfall/about/";
const PRIVACY = "/redfall/privacy/";
const SITEMAP = "/redfall/sitemap.xml";
const LLMS = "/redfall/llms.txt";

const NAV = [
  ["#why", "Why"],
  ["#how", "How it works"],
  ["#evidence", "Evidence"],
  ["#compare", "Compare"],
  ["#install", "Install"],
  ["#faq", "FAQ"],
];

function Mark({ className = "" }) {
  const gradientId = `rd-red-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  return (
    <svg viewBox="0 0 256 256" className={className} aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id={gradientId} x1="0.1" y1="0" x2="0.9" y2="1">
          <stop offset="0" stopColor="#ff5147" />
          <stop offset="0.55" stopColor="#ff0033" />
          <stop offset="1" stopColor="#8c0202" />
        </linearGradient>
      </defs>
      <g fill="none" stroke={`url(#${gradientId})`} strokeLinejoin="round" strokeLinecap="round">
        <path d="M46 26 H210 L234 50 V142 L128 236 L22 142 V50 Z" strokeWidth="16" />
        <circle cx="128" cy="118" r="42" strokeWidth="10" />
        <path d="M128 52 V68 M128 168 V184 M60 118 H76 M180 118 H196" strokeWidth="10" />
      </g>
      <circle cx="128" cy="118" r="12" fill={`url(#${gradientId})`} />
    </svg>
  );
}

function Wordmark({ className = "" }) {
  return (
    <span className={`font-bold tracking-tight ${className}`}>
      <span className="text-accent">Red</span>
      <span className="text-ink">Fall</span>
    </span>
  );
}

/* GitHub brand mark. Lucide 1.x dropped brand icons, and a traced logo path
   is more accurate than a stand-in icon. */
function GithubMark({ size = 20, className = "" }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="currentColor"
      className={className}
      aria-hidden="true"
      focusable="false"
    >
      <path d="M12 .5C5.73.5.5 5.73.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.55 0-.27-.01-1.17-.02-2.12-3.2.7-3.88-1.36-3.88-1.36-.52-1.33-1.28-1.68-1.28-1.68-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11.1 11.1 0 0 1 5.79 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.42-2.7 5.39-5.26 5.68.41.36.78 1.06.78 2.14 0 1.55-.01 2.8-.01 3.18 0 .3.2.67.8.55A11.51 11.51 0 0 0 23.5 12C23.5 5.73 18.27.5 12 .5Z" />
    </svg>
  );
}

/* Hero visual: abstract orbital system, pure SVG, no images. */
function HeroVisual() {
  const wrapRef = useRef(null);
  const innerRef = useRef(null);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const wrap = wrapRef.current;
    const inner = innerRef.current;
    if (!wrap || !inner) return;
    let frame = 0;
    const onMove = (event) => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const rect = wrap.getBoundingClientRect();
        const cx = rect.left + rect.width / 2;
        const cy = rect.top + rect.height / 2;
        const dx = Math.max(-20, Math.min(20, (event.clientX - cx) / 24));
        const dy = Math.max(-20, Math.min(20, (event.clientY - cy) / 24));
        inner.style.transform = `translate3d(${dx}px, ${dy}px, 0)`;
      });
    };
    window.addEventListener("pointermove", onMove, { passive: true });
    return () => {
      window.removeEventListener("pointermove", onMove);
      cancelAnimationFrame(frame);
    };
  }, []);

  return (
    <div ref={wrapRef} className="relative mx-auto mt-14 w-full max-w-[520px] select-none" aria-hidden="true">
      <div ref={innerRef} className="transition-transform duration-300 ease-out will-change-transform">
        <svg viewBox="0 0 520 520" className="h-auto w-full">
          <defs>
            <radialGradient id="hero-core" cx="50%" cy="50%" r="50%">
              <stop offset="0" stopColor="#ff0033" stopOpacity="0.30" />
              <stop offset="0.45" stopColor="#ff0033" stopOpacity="0.10" />
              <stop offset="1" stopColor="#ff0033" stopOpacity="0" />
            </radialGradient>
            <linearGradient id="ring-fade" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stopColor="#ff0033" stopOpacity="0.9" />
              <stop offset="0.6" stopColor="#ff0033" stopOpacity="0.15" />
              <stop offset="1" stopColor="#ff0033" stopOpacity="0.05" />
            </linearGradient>
          </defs>

          <circle cx="260" cy="260" r="230" fill="url(#hero-core)" />

          <g className="orbit">
            <g transform="rotate(-18 260 260)">
              <ellipse cx="260" cy="260" rx="212" ry="84" fill="none" stroke="url(#ring-fade)" strokeWidth="1.25" />
              <circle cx="472" cy="260" r="4" fill="#ff0033" />
              <circle cx="48" cy="260" r="2.5" fill="#ff0033" opacity="0.55" />
            </g>
            <g transform="rotate(28 260 260)">
              <ellipse cx="260" cy="260" rx="188" ry="66" fill="none" stroke="#ff003345" strokeWidth="1" />
              <circle cx="74" cy="260" r="3" fill="#ff0033" opacity="0.8" />
              <circle cx="446" cy="260" r="2" fill="#ff0033" opacity="0.4" />
            </g>
            <g transform="rotate(-62 260 260)">
              <ellipse cx="260" cy="260" rx="150" ry="150" fill="none" stroke="#1f1f1f" strokeWidth="1" strokeDasharray="2 8" />
            </g>
            <circle cx="260" cy="110" r="2" fill="#ff0033" opacity="0.45" />
            <circle cx="408" cy="330" r="2" fill="#ff0033" opacity="0.35" />
            <circle cx="120" cy="352" r="2" fill="#ff0033" opacity="0.35" />
          </g>

          <g opacity="0.9">
            <path
              d="M232 178 H288 L302 192 V240 L260 282 L218 240 V192 Z"
              fill="none"
              stroke="#ff0033"
              strokeWidth="7"
              strokeLinejoin="round"
            />
            <circle cx="260" cy="228" r="17" fill="none" stroke="#ff0033" strokeWidth="4" />
            <path d="M260 200 V207 M260 249 V256 M232 228 H239 M281 228 H288" stroke="#ff0033" strokeWidth="4" strokeLinecap="round" />
            <circle cx="260" cy="228" r="5" fill="#ff0033" />
          </g>
        </svg>
      </div>
      <span className="cue absolute inset-x-0 -bottom-2 mx-auto block w-fit text-muted">
        <ChevronDown size={20} strokeWidth={1.5} aria-hidden="true" />
      </span>
    </div>
  );
}

function CopyButton({ text, label }) {
  const [state, setState] = useState("idle");
  const copy = useCallback(() => {
    if (!navigator.clipboard) {
      setState("error");
      window.setTimeout(() => setState("idle"), 2000);
      return;
    }
    navigator.clipboard.writeText(text).then(
      () => {
        setState("copied");
        window.setTimeout(() => setState("idle"), 1600);
      },
      () => {
        setState("error");
        window.setTimeout(() => setState("idle"), 2000);
      },
    );
  }, [text]);

  return (
    <button
      type="button"
      onClick={copy}
      className={`inline-flex items-center gap-1.5 rounded-sm border px-2.5 py-1 text-xs font-medium transition-colors duration-200 ${
        state === "error"
          ? "border-error/60 text-error"
          : state === "copied"
            ? "border-success/60 text-success"
            : "border-line text-muted hover:border-line-accent hover:text-ink"
      }`}
      aria-label={`Copy ${label}`}
    >
      {state === "copied" ? (
        <Check size={13} strokeWidth={2} aria-hidden="true" />
      ) : state === "error" ? (
        <X size={13} strokeWidth={2} aria-hidden="true" />
      ) : (
        <Copy size={13} strokeWidth={1.5} aria-hidden="true" />
      )}
      <span aria-live="polite">{state === "copied" ? "Copied" : state === "error" ? "Copy failed" : "Copy"}</span>
    </button>
  );
}

function CodeBlock({ title, code }) {
  return (
    <figure className="card min-w-0 overflow-hidden">
      <figcaption className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <span className="caption text-muted">{title}</span>
        <CopyButton text={code} label={title} />
      </figcaption>
      <pre
        className="overflow-x-auto px-4 py-3.5 font-mono text-[0.8125rem] leading-relaxed text-ink/90"
        role="region"
        aria-label={`${title} command`}
        tabIndex={0}
      >
        <code>{code}</code>
      </pre>
    </figure>
  );
}

function Counter({ value, suffix = "", label }) {
  const ref = useRef(null);
  const [shown, setShown] = useState(value);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const el = ref.current;
    if (!el) return;

    let frame = 0;
    let started = false;
    const observer = new IntersectionObserver(
      (entries) => {
        if (!entries[0].isIntersecting || started) return;
        started = true;
        const start = performance.now();
        const duration = 1500;
        setShown(0);
        const tick = (now) => {
          const t = Math.min(1, (now - start) / duration);
          const eased = 1 - Math.pow(1 - t, 3);
          setShown(Math.round(value * eased));
          if (t < 1) frame = requestAnimationFrame(tick);
        };
        frame = requestAnimationFrame(tick);
        observer.disconnect();
      },
      { threshold: 0.4 },
    );
    observer.observe(el);
    return () => {
      observer.disconnect();
      cancelAnimationFrame(frame);
    };
  }, [value]);

  return (
    <div ref={ref} className="px-6 py-10 text-center sm:py-12">
      <div className="font-mono text-4xl font-bold leading-none tracking-tight tabular-nums text-ink sm:text-5xl">
        {shown}
        <span className="text-accent">{suffix}</span>
      </div>
      <div className="mt-2 text-sm text-muted">{label}</div>
    </div>
  );
}

export default function App() {
  const [scrolled, setScrolled] = useState(false);
  const [active, setActive] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef(null);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 80);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    const ids = ["top", ...NAV.map(([href]) => href.slice(1))];
    const sections = ids.map((id) => document.getElementById(id)).filter(Boolean);
    if (!sections.length) return;
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          setActive(entry.target.id === "top" ? "" : `#${entry.target.id}`);
        }
      },
      { rootMargin: "-40% 0px -55% 0px", threshold: 0 },
    );
    sections.forEach((section) => observer.observe(section));
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const elements = document.querySelectorAll("[data-reveal]");
    if (!elements.length) return;
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      },
      { threshold: 0.15, rootMargin: "0px 0px -40px 0px" },
    );
    elements.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (event) => {
      if (event.key === "Escape") setMenuOpen(false);
    };
    document.addEventListener("keydown", onKey);
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    menuRef.current?.querySelector("a")?.focus();
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = previous;
    };
  }, [menuOpen]);

  return (
    <div className="min-h-screen bg-bg text-ink antialiased">
      <a href="#main" className="skip-link">
        Skip to main content
      </a>

      <header className="nav-shell fixed inset-x-0 top-0 z-50" data-scrolled={scrolled}>
        <div className="container-rf flex h-[60px] items-center justify-between lg:h-[72px]">
          <a href="#top" className="flex items-center gap-2.5" aria-label="RedFall home">
            <Mark className="h-8 w-8 [filter:drop-shadow(0_0_10px_rgba(255,0,51,0.45))]" />
            <Wordmark className="text-lg" />
          </a>

          <nav aria-label="Main" className="hidden items-center gap-7 lg:flex">
            {NAV.map(([href, label]) => (
              <a key={href} href={href} className="nav-link" data-active={active === href} aria-current={active === href ? "location" : undefined}>
                {label}
              </a>
            ))}
            <a href={DOCS} className="nav-link">
              Docs
            </a>
          </nav>

          <div className="flex items-center gap-3">
            <div className="hidden sm:block">
              <a href="#install" className="btn btn-primary">
                Get Started
                <ArrowRight size={16} strokeWidth={2} aria-hidden="true" />
              </a>
            </div>

            <button
              type="button"
              className="inline-flex h-11 w-11 items-center justify-center rounded-sm border border-line text-ink lg:hidden"
              aria-label={menuOpen ? "Close menu" : "Open menu"}
              aria-expanded={menuOpen}
              aria-controls="mobile-menu"
              onClick={() => setMenuOpen((open) => !open)}
            >
              {menuOpen ? <X size={20} strokeWidth={1.5} aria-hidden="true" /> : <Menu size={20} strokeWidth={1.5} aria-hidden="true" />}
            </button>
          </div>
        </div>

        {menuOpen && (
          <div id="mobile-menu" ref={menuRef} className="fixed inset-0 top-[60px] z-40 overflow-y-auto bg-bg lg:hidden">
            <nav aria-label="Mobile" className="container-rf flex flex-col gap-1 py-8">
              {NAV.map(([href, label]) => (
                <a
                  key={href}
                  href={href}
                  className="menu-link border-b border-line py-4 text-2xl font-semibold text-ink"
                  onClick={() => setMenuOpen(false)}
                >
                  {label}
                </a>
              ))}
              {[
                [DOCS, "Documentation"],
                [EVIDENCE_PAGE, "Evidence ledger"],
                [COMPARE, "Compare static analysis"],
                [ABOUT, "About"],
              ].map(([href, label]) => (
                <a key={href} href={href} className="menu-link border-b border-line py-4 text-2xl font-semibold text-muted">
                  {label}
                </a>
              ))}
              <a href="#install" className="btn btn-primary btn-lg mt-8 w-full" onClick={() => setMenuOpen(false)}>
                Get Started
                <ArrowRight size={16} strokeWidth={2} aria-hidden="true" />
              </a>
            </nav>
          </div>
        )}
      </header>

      <main id="main">
        {/* Hero */}
        <section id="top" className="hero-glow relative flex min-h-screen flex-col justify-center pb-16 pt-28 sm:pt-32">
          <div className="container-rf">
            <div className="mx-auto max-w-[800px] text-center">
              <p className="pill rise">
                <span className="h-1.5 w-1.5 rounded-full bg-accent" aria-hidden="true" />
                v{VERSION} · Windows · Linux · macOS
              </p>

              <h1 className="display-xl rise rise-1 mt-7 text-ink">
                The vulnerability scanner that{" "}
                <span className="text-accent [text-shadow:0_0_28px_rgba(255,0,51,0.35)]">proves every finding by executing it</span>.
              </h1>

              <p className="rise rise-2 mx-auto mt-6 max-w-[560px] text-lg leading-relaxed text-muted">
                RedFall reads a target's real source, tracks attacker-controlled data from request surface to sink, and
                runs every candidate exploit inside a gVisor sandbox against the live application. Only what reproduces
                is reported — then it repairs, and verifies the fix against the target's own tests.
              </p>

              <div className="rise rise-3 mt-9 flex flex-col justify-center gap-3 sm:flex-row">
                <a href="#install" className="btn btn-primary btn-lg">
                  Get started
                  <ArrowRight size={16} strokeWidth={2} aria-hidden="true" />
                </a>
                <a href={GITHUB} className="btn btn-ghost btn-lg">
                  <GithubMark size={17} />
                  View source on GitHub
                </a>
              </div>

              <p className="rise rise-4 mt-5 text-sm text-muted">
                New to the model?{" "}
                <a
                  href={`${DOCS}verified-findings/`}
                  className="font-medium text-ink underline decoration-accent/50 underline-offset-4 hover:decoration-accent"
                >
                  Read how execution verification works
                </a>
                .
              </p>
            </div>

            <HeroVisual />
          </div>
        </section>

        {/* Features */}
        <section id="why" className="section border-t border-line">
          <div className="container-rf">
            <div className="mx-auto max-w-[640px] text-center" data-reveal>
              <span className="accent-rule mx-auto mb-5" aria-hidden="true" />
              <h2 className="h2 text-ink">What makes RedFall different?</h2>
              <p className="mt-3 text-muted">
                Most scanners hand you a list of suspicions. RedFall hands you executed proofs, on a public record of
                what could and could not be run.
              </p>
            </div>

            <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
              {FEATURES.map(({ title, body, href, link }, index) => {
                const Icon = [ShieldCheck, Network, GitBranch, BadgeCheck][index];
                return (
                  <article key={title} className="card card-hover flex flex-col p-8" data-reveal data-delay={index % 3}>
                    <Icon size={48} strokeWidth={1.25} className="text-accent" aria-hidden="true" />
                    <h3 className="mt-4 text-xl font-semibold text-ink">{title}</h3>
                    <p className="mt-2 text-sm leading-relaxed text-muted">{body}</p>
                    <a
                      href={href}
                      className="mt-4 inline-flex w-fit items-center gap-1.5 text-sm font-medium text-ink underline decoration-accent/50 underline-offset-4 hover:decoration-accent"
                    >
                      {link}
                      <ArrowRight size={14} strokeWidth={2} aria-hidden="true" />
                    </a>
                  </article>
                );
              })}
            </div>
          </div>
        </section>

        {/* Stats */}
        <section className="border-y border-line bg-surface" aria-labelledby="measured-title">
          <div className="container-rf">
            <div className="max-w-[720px] pt-12" data-reveal>
              <span className="accent-rule mb-5" aria-hidden="true" />
              <h2 id="measured-title" className="h2 text-ink">
                What has RedFall measured?
              </h2>
              <p className="mt-3 text-muted">
                These are counts from commands that ran, not estimates. The full ledger records the host, the date and
                the five gVisor-only tests that skip without a container runtime.
              </p>
            </div>
            <div className="mt-8 grid divide-y divide-line border-t border-line sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4">
              <div className="sm:border-b sm:border-line lg:border-b-0 lg:border-r">
                <Counter value={362} label="tests passed in CI" />
              </div>
              <div className="sm:border-b sm:border-line lg:border-b-0 lg:border-r">
                <Counter value={6} suffix="/6" label="chains reproduce" />
              </div>
              <div className="sm:border-r sm:border-line">
                <Counter value={17} suffix="/17" label="pythonbank PoCs" />
              </div>
              <div>
                <Counter value={32} suffix="/32" label="patches verified" />
              </div>
            </div>
            <p className="pb-10 pt-2 text-sm text-muted">
              Read the{" "}
              <a href={EVIDENCE_PAGE} className="footer-link underline decoration-accent/50 underline-offset-4">
                full evidence ledger
              </a>{" "}
              for the commands, dates and current gaps.
            </p>
          </div>
        </section>

        {/* How it works */}
        <section id="how" className="section">
          <div className="container-rf">
            <div className="max-w-[640px]" data-reveal>
              <span className="accent-rule mb-5" aria-hidden="true" />
              <h2 className="h2 text-ink">How does a RedFall scan work?</h2>
              <p className="mt-3 text-muted">
                Five stages, one rule: nothing counts until it ran. Static analysis only ever proposes candidates.
              </p>
            </div>

            <ol className="mt-12 grid gap-10 md:grid-cols-2">
              {STEPS.map(({ title, body, href }, index) => (
                <li key={title} className="flex gap-5" data-reveal data-delay={index % 2}>
                  <span
                    className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-line-accent bg-accent-subtle font-mono text-sm font-semibold text-accent"
                    aria-hidden="true"
                  >
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <div>
                    <h3 className="text-lg font-semibold text-ink">{title}</h3>
                    <p className="mt-1.5 text-sm leading-relaxed text-muted">{body}</p>
                    <a href={href} className="mt-2 inline-block text-sm font-medium text-accent hover:underline">
                      Read the {title.toLowerCase()} guide
                    </a>
                  </div>
                </li>
              ))}
            </ol>

            <p className="mt-10 text-sm text-muted">
              Start with the{" "}
              <a href={`${DOCS}architecture/`} className="footer-link underline decoration-accent/50 underline-offset-4">
                architecture guide
              </a>{" "}
              or see how the{" "}
              <a href={`${DOCS}sandbox/`} className="footer-link underline decoration-accent/50 underline-offset-4">
                gVisor sandbox
              </a>{" "}
              decides a finding.
            </p>
          </div>
        </section>

        {/* Evidence */}
        <section id="evidence" className="section border-t border-line bg-surface">
          <div className="container-rf">
            <div className="max-w-[720px]" data-reveal>
              <span className="accent-rule mb-5" aria-hidden="true" />
              <h2 className="h2 text-ink">What evidence backs RedFall?</h2>
              <p className="mt-3 text-muted">
                Every number below came from a command that actually ran on a real host. What could not run there is
                listed in BLOCKED.md with the smallest real unblock for each item — no estimates in place of results.
              </p>
            </div>

            <div
              className="mt-10 overflow-x-auto rounded-md border border-line"
              data-reveal
              role="region"
              aria-label="Measured results table"
              tabIndex={0}
            >
              <table className="w-full min-w-[40rem] text-left text-sm">
                <thead>
                  <tr className="border-b border-line">
                    <th scope="col" className="caption px-5 py-3.5 font-medium text-muted">
                      Target
                    </th>
                    <th scope="col" className="caption px-5 py-3.5 font-medium text-muted">
                      What ran
                    </th>
                    <th scope="col" className="caption px-5 py-3.5 font-medium text-muted">
                      Result
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {EVIDENCE.map(([target, what, result]) => (
                    <tr key={target} className="border-b border-line last:border-0">
                      <td className="px-5 py-3.5 font-medium text-ink">{target}</td>
                      <td className="px-5 py-3.5 text-muted">{what}</td>
                      <td className="px-5 py-3.5 font-mono text-[0.8125rem] text-ink/90">{result}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-6 flex flex-wrap gap-x-6 gap-y-2 text-sm">
              <a href={EVIDENCE_PAGE} className="footer-link underline decoration-accent/50 underline-offset-4">
                Full evidence ledger
              </a>
              <a href={`${DOCS}ranges/`} className="footer-link underline decoration-accent/50 underline-offset-4">
                Range targets and counts
              </a>
              <a
                href={`${GITHUB}/blob/main/BLOCKED.md`}
                className="footer-link underline decoration-accent/50 underline-offset-4"
                rel="noopener"
              >
                What is still blocked
              </a>
            </div>
          </div>
        </section>

        {/* Compare */}
        <section id="compare" className="section border-t border-line">
          <div className="container-rf">
            <div className="max-w-[760px]" data-reveal>
              <span className="accent-rule mb-5" aria-hidden="true" />
              <h2 className="h2 text-ink">How is RedFall different from static analysis?</h2>
              <p className="mt-3 text-muted">
                Static analysis asks whether a dangerous dataflow may exist. RedFall asks whether a specific request
                produced a specific effect against the running application. Both are useful; they prove different
                things.
              </p>
            </div>

            <div
              className="mt-10 overflow-x-auto rounded-md border border-line"
              data-reveal
              role="region"
              aria-label="Static analysis and execution verification comparison"
              tabIndex={0}
            >
              <table className="w-full min-w-[42rem] text-left text-sm">
                <caption className="sr-only">Comparison of static analysis and execution-verified scanning</caption>
                <thead>
                  <tr className="border-b border-line">
                    <th scope="col" className="caption px-5 py-3.5 font-medium text-muted">
                      Question
                    </th>
                    <th scope="col" className="caption px-5 py-3.5 font-medium text-muted">
                      Static analysis
                    </th>
                    <th scope="col" className="caption px-5 py-3.5 font-medium text-muted">
                      RedFall
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    ["What is the output?", "A candidate or alert", "A finding with a stored request, response and verdict"],
                    ["What proves it?", "A rule or dataflow model", "The PoC executed against the real app"],
                    ["What about false positives?", "Triaged or suppressed", "Rejected by the execution gate"],
                    ["When is it worth it?", "Broad, fast coverage", "When a false positive blocks a release or triggers disclosure"],
                  ].map(([question, sa, rf]) => (
                    <tr key={question} className="border-b border-line last:border-0">
                      <td className="px-5 py-3.5 font-medium text-ink">{question}</td>
                      <td className="px-5 py-3.5 text-muted">{sa}</td>
                      <td className="px-5 py-3.5 text-ink/90">{rf}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <p className="mt-6 text-sm text-muted">
              Read the{" "}
              <a href={COMPARE} className="footer-link underline decoration-accent/50 underline-offset-4">
                full comparison of static analysis, DAST and execution verification
              </a>
              . It includes when a broad SAST or SCA tool is the better choice.
            </p>
          </div>
        </section>

        {/* Install */}
        <section id="install" className="section border-t border-line">
          <div className="container-rf">
            <div className="max-w-[720px]" data-reveal>
              <span className="accent-rule mb-5" aria-hidden="true" />
              <h2 className="h2 text-ink">How do you install RedFall?</h2>
              <p className="mt-3 text-muted">
                Pure-Python wheel: no compiled extensions, no post-install hooks. The installers use pipx when present
                and a private virtualenv otherwise — never system-wide, never elevated — and finish with{" "}
                <code className="rounded-sm bg-elevated px-1.5 py-0.5 font-mono text-[0.8125rem] text-ink">redfall doctor</code>,
                the host's real capability report.
              </p>
              <p className="mt-3 text-sm text-muted">
                Installing needs Python 3.12+. A full scan additionally needs Docker with gVisor, an LLM provider key
                and PostgreSQL. The{" "}
                <a href={`${DOCS}install/`} className="footer-link underline decoration-accent/50 underline-offset-4">
                  install guide
                </a>{" "}
                lists every prerequisite and the unblock path.
              </p>
            </div>

            <div className="mt-10 grid gap-6 lg:grid-cols-2">
              <div className="min-w-0" data-reveal>
                <CodeBlock
                  title="Windows (PowerShell)"
                  code={"git clone https://github.com/DevAnimecx/redfall.git; cd redfall\n.\\scripts\\install.ps1"}
                />
              </div>
              <div className="min-w-0" data-reveal data-delay="1">
                <CodeBlock
                  title="Linux / macOS"
                  code={"git clone https://github.com/DevAnimecx/redfall.git && cd redfall\n./scripts/install.sh"}
                />
              </div>
              <div className="min-w-0" data-reveal>
                <CodeBlock
                  title="Any package manager"
                  code={"pipx install git+https://github.com/DevAnimecx/redfall\nredfall doctor"}
                />
              </div>
              <div className="min-w-0" data-reveal data-delay="1">
                <CodeBlock
                  title="Verify a release"
                  code={`gh attestation verify redfall-${VERSION}-py3-none-any.whl \\\n  --repo DevAnimecx/redfall`}
                />
              </div>
            </div>

            <p className="mt-6 text-sm text-muted">
              The release is built by CI from the tagged commit and carries a Sigstore attestation.{" "}
              <a
                href={`${DOCS}release-verification/`}
                className="footer-link underline decoration-accent/50 underline-offset-4"
              >
                Check the release-verification steps
              </a>{" "}
              and what the attestation does not prove.
            </p>
          </div>
        </section>

        {/* FAQ */}
        <section id="faq" className="section border-t border-line bg-surface">
          <div className="container-rf">
            <div className="max-w-[640px]" data-reveal>
              <span className="accent-rule mb-5" aria-hidden="true" />
              <h2 className="h2 text-ink">What do people ask about RedFall?</h2>
            </div>

            <div className="mt-10 grid gap-6 md:grid-cols-2">
              {FAQ.map(({ q, a, href, link }, index) => (
                <article key={q} className="card flex flex-col p-6" data-reveal data-delay={index % 2}>
                  <h3 className="font-semibold text-ink">{q}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-muted">{a}</p>
                  <a
                    href={href}
                    className="mt-4 inline-flex w-fit items-center gap-1.5 text-sm font-medium text-ink underline decoration-accent/50 underline-offset-4 hover:decoration-accent"
                  >
                    {link}
                    <ExternalLink size={13} strokeWidth={2} aria-hidden="true" />
                  </a>
                </article>
              ))}
            </div>

            <p className="mt-8 text-sm text-muted">
              The{" "}
              <a href={DOCS} className="footer-link underline decoration-accent/50 underline-offset-4">
                documentation
              </a>{" "}
              covers the mechanism, the evidence and the limits in detail.
            </p>
          </div>
        </section>

        {/* Final CTA */}
        <section className="cta-glow section border-t border-line">
          <div className="container-rf">
            <div className="mx-auto max-w-[600px] text-center" data-reveal>
              <h2 className="display text-ink">Ready to prove a finding?</h2>
              <p className="mx-auto mt-4 max-w-[520px] text-muted">
                Install RedFall, run <code className="font-mono text-[0.9375rem] text-ink">redfall doctor</code>, and see
                exactly what your host can prove. Nothing is simulated — if it cannot run, it says so.
              </p>
              <div className="mt-8 flex flex-col justify-center gap-3 sm:flex-row">
                <a href="#install" className="btn btn-primary btn-lg">
                  Get started
                  <ArrowRight size={16} strokeWidth={2} aria-hidden="true" />
                </a>
                <a href={`${GITHUB}/blob/main/BLOCKED.md`} className="btn btn-ghost btn-lg">
                  Read what is blocked
                </a>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-line">
        <div className="container-rf grid gap-10 py-12 sm:grid-cols-2 lg:grid-cols-4">
          <div className="sm:col-span-2 lg:col-span-1">
            <div className="flex items-center gap-2.5">
              <Mark className="h-8 w-8" />
              <Wordmark className="text-lg" />
            </div>
            <p className="mt-3 max-w-xs text-sm leading-relaxed text-muted">
              Execution-verified vulnerability discovery and verified repair. Findings are executed proofs only — every
              number came from a command that ran.
            </p>
            <p className="mt-4 text-sm text-muted">
              Maintained by{" "}
              <a href={ABOUT} rel="author" className="footer-link underline underline-offset-2">
                DevAnimecx
              </a>{" "}
              in public.
            </p>
          </div>

          <nav aria-label="Documentation" className="flex flex-col gap-2.5 text-sm">
            <p className="caption mb-1 text-muted">Documentation</p>
            <a href={DOCS} className="footer-link">
              All documentation
            </a>
            <a href={`${DOCS}verified-findings/`} className="footer-link">
              Execution verification
            </a>
            <a href={`${DOCS}architecture/`} className="footer-link">
              How it works
            </a>
            <a href={`${DOCS}install/`} className="footer-link">
              Install
            </a>
            <a href={EVIDENCE_PAGE} className="footer-link">
              Evidence ledger
            </a>
            <a href={COMPARE} className="footer-link">
              Compare static analysis
            </a>
            <a href={`${DOCS}glossary/`} className="footer-link">
              Glossary
            </a>
          </nav>

          <nav aria-label="Project links" className="flex flex-col gap-2.5 text-sm">
            <p className="caption mb-1 text-muted">Project</p>
            <a href={GITHUB} className="footer-link" rel="noopener">
              GitHub repository
            </a>
            <a href={RELEASE_URL} className="footer-link" rel="noopener">
              Release v{VERSION}
            </a>
            <a href={`${GITHUB}/blob/main/CHANGELOG.md`} className="footer-link" rel="noopener">
              Changelog
            </a>
            <a href={`${GITHUB}/blob/main/CONTRIBUTING.md`} className="footer-link" rel="noopener">
              Contributing
            </a>
            <a href={`${GITHUB}/blob/main/SECURITY.md`} className="footer-link" rel="noopener">
              Security
            </a>
            <a href={`${GITHUB}/blob/main/BLOCKED.md`} className="footer-link" rel="noopener">
              What is blocked
            </a>
            <a href={ABOUT} className="footer-link">
              About
            </a>
            <a href={PRIVACY} className="footer-link">
              Privacy
            </a>
          </nav>

          <div className="sm:justify-self-start lg:justify-self-end">
            <a
              href={GITHUB}
              aria-label="RedFall on GitHub"
              className="inline-flex h-11 w-11 items-center justify-center rounded-sm border border-line text-muted transition-colors duration-200 hover:border-line-accent hover:text-ink"
              rel="noopener"
            >
              <GithubMark size={20} />
            </a>
            <p className="mt-4 max-w-[16rem] text-xs leading-relaxed text-muted">
              No analytics, no cookies, no accounts. The site self-hosts its font and publishes an{" "}
              <a href={LLMS} className="footer-link underline underline-offset-2">
                llms.txt
              </a>
              .
            </p>
          </div>
        </div>
        <div className="border-t border-line">
          <p className="container-rf py-6 text-sm text-muted">
            © 2026 RedFall contributors · Maintained by{" "}
            <a href={ABOUT} className="footer-link underline underline-offset-2">
              DevAnimecx
            </a>{" "}
            · Last updated <time dateTime="2026-10-21">{LAST_UPDATED}</time> ·{" "}
            <a href={SITEMAP} className="footer-link underline underline-offset-2">
              sitemap
            </a>{" "}
            · Built under the no-mock contract: nothing on this page is simulated.
          </p>
        </div>
      </footer>
    </div>
  );
}
