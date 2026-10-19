# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Landing page + documentation** (`site/`) — a one-page React + Tailwind
  landing page, statically prerendered at build time, plus **22 docs/trust
  pages** generated from Markdown with zero client JavaScript. Deployed to
  <https://devanimecx.github.io/redfall/> by `.github/workflows/pages.yml`.
- **Technical SEO + GEO/AEO system** — one canonical per page, unique titles and
  descriptions, hreflang, a real 404, `sitemap.xml` (23 URLs), `robots.txt` with
  named AI crawlers, a byte-identical `llms.txt` at repo and site root,
  23 generated 1200×630 OG cards, JSON-LD graphs (Organization, Person, WebSite,
  SoftwareApplication, WebPage, FAQPage, BreadcrumbList, TechArticle), IndexNow
  key plus submission script, a weekly live SEO monitor workflow, and the
  operating manual in [`site/SEO.md`](site/SEO.md). Build gates:
  `check:seo`, `check:docs`, `check:layout`, `check:a11y`, `check:lighthouse`.
- **Brand assets** — `assets/` carries the vector lockups (dark, light, mark);
  `scripts/generate_brand_assets.py` renders the base social card and touch
  icons, and `scripts/generate_og_assets.py` renders a per-page 1200×630 card.
  `tests/test_brand_assets.py` pins the SVG path to the generator so the two
  cannot drift.
- **`llms.txt`** — machine-readable project summary for answer engines, generated
  from the same page manifest as the sitemap and copied byte-for-byte to the repo
  root; the build fails if the two drift.
- **Live deployment verified** — Pages run
  [39253506525](https://github.com/DevAnimecx/redfall/actions/runs/39253506525)
  completed build and deploy on 2026-10-19. The SEO gate passed, the live monitor
  passed all 23 pages, IndexNow accepted 23 URLs with **HTTP 202**, and a missing
  path returned **HTTP 404**. Live Lighthouse: landing **100/100/100/100**
  desktop and **98 performance / 100 accessibility / 100 best-practices / 100
  SEO** mobile; docs **100/100/100/100** desktop and **99 / 100 / 100 / 100**
  mobile. No ranking, backlink or AI-citation outcome is claimed.

### Fixed

- **Mobile layout overflow on the landing page** — the install code blocks are
  CSS-grid children, and grid items default to `min-width: auto`, so each
  `<pre>` forced its track to 554 px and the document was 578 px wide on a
  390 px phone (188 px of sideways scroll). Lighthouse's viewport audit only
  reads the meta tag, so it did not catch this; `site/scripts/mobile_check.mjs`
  now drives real Chrome at 390/768/1280 px and CI fails on any unclipped
  overflow.
- **Dark logo lockup** — the white "Fall" was invisible when the SVG was
  rendered on a light background; the dark variant now carries an opaque plate.

### Changed

- **Landing page rebuilt as a dark design system** — exact token layer
  (`#050505` / `#0d0d0d` / `#ff0033`), Inter self-hosted from a single 47 kB
  Latin variable font, SVG orbital hero with 20 s rotation and pointer
  parallax, IntersectionObserver reveals and count-ups, full-screen mobile
  menu, copy states, reduced-motion fallbacks, and a 1200 px content grid.
  The JavaScript bundle is **80.9 kB gzipped**; CSS is **8.22 kB gzipped** and
  inlined into the prerendered HTML with a font preload, while the static docs
  share it as one cached file.
- **Accessibility and layout are now CI contracts** — `axe-core` runs at 390,
  768 and 1280 px and must report zero violations; `mobile_check.mjs` drives
  real Chrome and fails on any unclipped horizontal overflow. Both found real
  bugs during this change (an unfocusable scrollable code block and a grid-track
  overflow), which are fixed.
- **Measured after the rebuild** (2026-10-19, local production build) — landing
  Lighthouse **100 / 100 / 100 / 100 desktop**, mobile **98–100 performance** with
  100 accessibility, best-practices and SEO on every run; docs page 100/100/100/100
  desktop and 99–100 performance mobile with 100 elsewhere. Landing mobile LCP
  1.5–1.7 s, CLS 0, TBT 0–10 ms; every category stays above the 95 gate. axe-core
  found 0 violations on the landing page at 390/768/1280 and on all 22 docs/trust
  routes at 390/1280; the SEO gate found 0 errors across 24 HTML routes and 23
  sitemap URLs.
- **Brand assets follow the new palette** — the dark lockup plate is now
  `#0d0d0d → #050505`, the red wordmark is `#ff0033`, and the OG card, touch
  icons and favicon are regenerated from the same geometry.
- Test suite: **254 passed, 5 skipped** (the four new brand-asset guard tests;
  `pillow` added to the dev extras so CI runs them).
- CI: the `check` job now builds the site from a clean lockfile, runs the SEO
  gate, and drives real Chrome for layout, axe, docs and Lighthouse checks; site
  builds use Node 22 (vite 8 requires `^20.19 || >=22.12`). The Pages workflow
  runs `check:seo` before upload and submits the deployed sitemap to IndexNow,
  then re-checks the live surface.

## [0.1.0] — 2026-10-19

The first release. Everything below was verified on the development host with a
real Postgres, real target applications over real HTTP, and a built wheel
installed into a fresh virtualenv. What could not run there (gVisor sandbox
execution, live LLM calls) refuses loudly and is listed in
[`BLOCKED.md`](BLOCKED.md) with the exact unblock.

### Added

- **Ingestion** — tree-sitter parsing for TS/TSX/JS/JSX/MJS and Python;
  symbols, imports (named, aliased, namespace, CommonJS `require`, Python
  relative imports), dependency and git facts.
- **Taint analysis** — intraprocedural source→sink flow per function, plus a
  depth-one interprocedural pass in both languages: parameters seeded to prove
  what a caller's taint can reach, **return flow** proving what a callee's
  sources hand back, and a **call graph** that route attribution follows across
  files. Ambiguity is dropped, never guessed. Sanitisers are recorded and never
  silently clear taint.
- **Route frameworks** — Express, Fastify, koa-router and NestJS decorators;
  Flask/FastAPI blueprints with prefix resolution through imports.
- **Adaptive branching** — a recursive branch tree with seven spawn triggers
  detected from real source (dynamic imports, dynamic routes, plugin systems,
  DB-stored code, webhooks, feature flags, env conditionals).
- **Cross-branch chaining** — attack graph over discovered findings, compound
  CVSS, and the chain narrative; `range/chainbank` reproduces 6/6 chains.
- **Sandbox validation** — Docker + gVisor executor and an in-box exploit
  harness that runs Node and Python targets (venv boot with a
  `redfall.target.json` contract, `app.py` fallback, `target-missing` otherwise).
- **Verified fix loop** — patch application on branches with verification; never
  auto-merged.
- **Range targets with ground truth** — `vulnbank` (32 seeded vulns),
  `vulnbank-adaptive` (7 adaptive surfaces), `chainbank` (6 chains),
  `pythonbank` (17 seeded vulns, real HTTP PoC replay 17/17).
- **Range-runner gate** — deterministic scorer: 5 core metrics plus 3 chain
  metrics over scan and fix outputs.
- **SARIF 2.1.0 export** — `redfall report <scan-id> --format sarif`; every
  result carries `properties.redfall.verified`, so unproven candidates stay
  visible and nothing is upgraded or dropped.
- **Packaging** — pure-Python wheel (`py3-none-any`) with the sandbox harness,
  prompts and Dockerfile included; `scripts/verify_wheel.py` proves an installed
  wheel from outside the checkout; CI packaging matrix on Ubuntu, Windows and
  macOS across Python 3.12/3.13.
- **Installers** — `scripts/install.sh` (Linux, macOS) and
  `scripts/install.ps1` (Windows) with a `redfall doctor` report at the end.
- **Contracts** — no-mock, version, orphan and clean-tree checkers, all run by
  `make check` and CI.

### Verified

- `python -m pytest tests/ -q` → **254 passed, 5 skipped** (the five gVisor
  skips), against a real Postgres.
- pythonbank: **17/17** PoCs reproduced over real HTTP; **18** target tests.
- vulnbank: **32/32** patches verified; 76 tests. vulnbank-adaptive: 91 tests,
  7/7 PoCs. chainbank: 8 tests, 6/6 chains.
- `scripts/verify_wheel.py` → `WHEEL VERIFY: PASS` from a fresh virtualenv,
  with the interprocedural taint found through the installed wheel.
- vulnbank scan parity after the return-flow work: 27 routes, 20 taint paths,
  11 call edges, 0 over-claims; self-scan: 51 files, 0 parse errors.

[0.1.0]: https://github.com/DevAnimecx/redfall/releases/tag/v0.1.0
