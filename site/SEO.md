# RedFall SEO, GEO and AEO operating manual

This document describes what is implemented in the repository, how to verify it,
and which tasks require a human account. It deliberately separates the two.
Nothing here promises a ranking, a backlink, an AI citation or a traffic number:
those outcomes are not controlled by the site and are not fabricated to make a
dashboard look complete.

Canonical site: <https://devanimecx.github.io/redfall/>
Repository: <https://github.com/DevAnimecx/redfall>
Public author identity: `DevAnimecx` (<https://github.com/DevAnimecx>)
Last technical review: 2026-10-21

---

## 1. What is implemented

| Area | Implementation | Verification |
| --- | --- | --- |
| Rendering | The landing page is React + Tailwind, built by Vite and **prerendered to static HTML** by `site/scripts/prerender.mjs`. All documentation, comparison, evidence, about and privacy pages are static HTML generated from Markdown by `site/scripts/build_docs.mjs`, with **zero client JavaScript**. | `npm run build`; `node scripts/docs_check.mjs` asserts `script[src]` is empty on every docs route and that the H1 is readable with JavaScript disabled. |
| URLs and canonicals | Absolute self-referencing `<link rel="canonical">` on every indexable page. Trailing-slash routes. One HTML page per URL. `hreflang="en"` and `x-default`. A real custom `404.html` with `noindex`. | `site/scripts/seo_check.mjs`: canonical must equal the production URL; 404 must not be in the sitemap; 24 sitemap URLs must match the built pages exactly. |
| Indexing | `sitemap.xml` with `lastmod`, `changefreq` and `priority`; `robots.txt` that allows the site and the named AI crawlers; no accidental `noindex` on indexable pages; `llms.txt` for answer engines. | `npm run check:seo`; weekly `seo-monitor` workflow against the live site. |
| Metadata | Unique title and description per page; Open Graph and Twitter cards; per-page 1200×630 PNG cards generated from the page title; `og:image:alt`; author, theme colour and colour scheme. | `seo_check.mjs` enforces length, uniqueness, required tags, image alt text and PNG existence; `scripts/generate_og_assets.py` regenerates the cards. |
| Structured data | JSON-LD graph: `Organization`, `Person`, `WebSite`, `WebPage`, `SoftwareApplication`, `FAQPage` and `BreadcrumbList` on the landing page; `Organization`, `Person`, `WebSite`, page/article type and `BreadcrumbList` on documentation pages. FAQ schema is generated from the same `site/lib/content.mjs` object as the visible FAQ. | `seo_check.mjs` parses every JSON-LD block and checks required types and FAQ answers; the live monitor checks the deployed graph again. |
| E-E-A-T | A visible named maintainer, an About page that states what is and is not claimed, visible `Last updated` dates, primary-source links on technical pages, a dated evidence ledger, release-verification instructions and the blocker ledger. No invented credentials, employers, testimonials or review counts. | `seo_check.mjs` requires a visible `time[datetime]` and an author link; manual review of `site/content/about.md` and `site/content/evidence.md`. |
| Internal linking | Persistent documentation sidebar, breadcrumbs, related-reading blocks, landing-page paths into each cluster, footer links to documentation/evidence/about/privacy, and links from every docs page back to the hub. | `seo_check.mjs` resolves every internal link and fragment against the built HTML; `docs_check.mjs` verifies the static pages render. |
| Accessibility | Semantic landmarks, one H1 per page, skip link, visible focus, keyboard-scrollable code and tables, reduced-motion support. | axe-core at 390/768/1280 on the landing page and at 390/1280 on all 23 documentation/trust pages. |
| Performance | Inlined landing CSS, self-hosted 47 KB Inter subset with metric-matched fallback, prerendered HTML, deferred hydration, no analytics, no third-party requests. Docs share one externally cached CSS file and ship no JavaScript. | Lighthouse 13.5, desktop and mobile, threshold ≥95 for all four categories; plus the real Chrome layout gate. |
| Security | SHA-256 hash-based CSP delivered as a `<meta http-equiv>` (GitHub Pages cannot set response headers), `object-src 'none'`, `base-uri 'self'`, `form-action` restricted. HSTS comes from the `github.io` parent host. | Browser console is checked by Lighthouse (`errors-in-console`), the docs gate and axe runs. `frame-ancestors`/`X-Frame-Options` are impossible on Pages and are documented as such, not faked. |
| Supply chain | Release wheel built by CI from the tagged commit, Sigstore attestation, `SHA256SUMS`, weekly `pip-audit`. | `gh attestation verify ...`; `docs/release-verification/`. |

### Current measured results (2026-10-21, local 0.1.1 production build)

```text
npm run build        landing prerendered; 23 docs pages; 24 sitemap URLs
npm run check:seo    SEO GATE: PASS — 25 HTML routes, 0 errors
node scripts/docs_check.mjs
                     PASS — 23 routes × 2 viewports, axe clean,
                     no horizontal overflow, zero client JS
Lighthouse desktop   100 performance / 100 accessibility / 100 best-practices / 100 SEO
Lighthouse mobile    100 performance / 100 accessibility / 100 best-practices / 100 SEO
Lighthouse docs      100 / 100 / 100 / 100 desktop
Live deploy          0.1.1: build + deploy PASS; live monitor PASS (24 pages)
IndexNow             0.1.1: HTTP 200, 24 URLs
Live landing (0.1.1) desktop 97–98 performance; mobile 93–99; 100 accessibility/best-practices/SEO in both runs
Live docs (0.1.0)    100/100/100/100 desktop; 99 performance, 100 elsewhere mobile (not re-run for 0.1.1)
Live 404             HTTP 404
```

The local and live numbers are kept separate; a local measurement is never
presented as a live one. The last live deploy run is
[39616295475](https://github.com/DevAnimecx/redfall/actions/runs/39616295475),
and the full evidence is in `BLOCKED.md` and `RELEASE.md`. One of the two live
mobile Lighthouse runs scored 93, below the 95 performance gate; that miss is
recorded rather than averaged into a pass.

---

## 2. Content architecture: pillars and clusters

The site is intentionally small. It is one landing page plus 23 documentation and
trust pages, not a programme of filler pages. Every page answers a real question
that the repository can support with code, a command or a recorded result.

| Pillar | Cluster pages | Search / answer intent |
| --- | --- | --- |
| Execution verification | `/docs/verified-findings/`, `/docs/architecture/`, `/docs/taint-analysis/`, `/docs/sandbox/`, `/docs/adaptive-scanning/`, `/docs/exploit-chaining/`, `/docs/verified-fixes/`, `/docs/no-mock-contract/` | “What does execution-verified scanning mean?”, “How does a scanner prove a finding?”, “How does a gVisor sandbox run a PoC?” |
| Evidence and trust | `/evidence/`, `/docs/ranges/`, `/docs/output/`, `/docs/release-verification/`, `/docs/blocked/`, `/docs/security/` | “What results has RedFall actually measured?”, “How do I verify the release?”, “What cannot it run?” |
| Adoption | `/docs/install/`, `/docs/cli/`, `/docs/languages/` | “How do I install RedFall?”, “Which languages/frameworks?”, “What commands exist?” |
| Comparison | `/compare/static-analysis/` | “Execution verification vs static analysis”, “Is DAST better than SAST?” |
| Orientation | `/docs/`, `/docs/glossary/` | “RedFall documentation”, “What is a verified finding / taint / predicate?” |
| Project identity | `/about/`, `/privacy/` | “Who maintains RedFall?”, “Does the site track me?” |

Rules used when adding a page:

1. It must answer a question a user would actually type or ask an assistant.
2. It must link to at least one primary source (repository file, release,
   changelog, evidence entry) or show a command that can be run.
3. It must not invent a benchmark, a customer, a review, a date or a credential.
4. It must have a unique title, a unique description, one H1, at least one
   question-shaped or specific H2, a visible update date and an author link.
5. It must join an existing cluster and receive at least one contextual internal
   link from a related page. No orphan pages.

### Internal-linking map

- Landing hero → execution-verification guide.
- Landing “Why” cards → one cluster page each.
- Landing “How” steps → architecture, taint, sandbox, adaptive and fix guides.
- Landing evidence table → evidence ledger, range targets, BLOCKED.md.
- Landing comparison → full comparison page.
- Landing install → install guide and release verification.
- Landing FAQ → install, no-mock contract, sandbox, languages, evidence.
- Docs sidebar → every docs page, grouped by pillar.
- Docs breadcrumbs → `/docs/` and landing.
- Docs “Related” blocks → sibling pages in the same cluster.
- Docs article CTA → install and GitHub source.
- Footer (landing and docs) → docs hub, evidence, comparison, about, privacy,
  sitemap, `llms.txt`.

The gate checks the links; it does not guess whether they are useful. Usefulness
is a review item in the 90-day calendar.

---

## 3. Technical SEO details

### Sitemap and robots

`sitemap.xml` is generated from the same page manifest as the HTML, so a page
cannot exist without being in the sitemap (or being deliberately excluded, as the
404 is). It contains the landing page plus 23 docs/trust URLs.

`robots.txt` allows all crawlers and explicitly names GPTBot, OAI-SearchBot,
ChatGPT-User, ClaudeBot, Claude-Web, PerplexityBot, Google-Extended,
Applebot-Extended, CCBot, meta-externalagent and Bytespider. It declares the
sitemap. It does not hide content: if a page is public HTML, it is meant to be
read and cited.

### IndexNow

The public key is `465631c0f24944dcc1adf9325287a357` and is served at:

```text
https://devanimecx.github.io/redfall/465631c0f24944dcc1adf9325287a357.txt
```

`site/scripts/indexnow.mjs` derives every URL from the built sitemap, waits for
the deployed key file to be readable, and POSTs the list to
`https://api.indexnow.org/indexnow`. The Pages deploy workflow runs it after a
successful deployment. IndexNow is used by Bing, Yandex, Seznam and other
participating engines; Google does not consume it.

Manual operation:

```bash
cd site
npm run build
node scripts/indexnow.mjs --dry-run    # prints the exact URL list, sends nothing
node scripts/indexnow.mjs --wait=180   # production submission after deploy
```

### Canonicals, hreflang and 404s

- Every indexable page has one canonical URL with a trailing slash.
- The sitemap and canonical use the same production origin; there is no
  `www`/non-`www` split and no alternate staging origin in the output.
- `hreflang="en"` and `x-default` point to the same English page. There is no
  machine-translated duplicate content.
- `404.html` is excluded from the sitemap, carries `noindex, nofollow`, links to
  the landing page and docs, and returns HTTP 404 on GitHub Pages. The local Vite
  preview cannot reproduce the 404 status (it falls back to `index.html`), so the
  live monitor performs that check only against production.

### Structured data design

Landing graph:

- `Organization` with the public GitHub profile as `sameAs`
- `Person` for `DevAnimecx`, linked to `/about/`
- `WebSite` with the site name and language
- `SoftwareApplication` for RedFall 0.1.1, with licence, operating systems,
  application category, release date, code repository and download URL
- `WebPage` for the landing page
- `FAQPage` generated from the same FAQ array rendered in the visible cards
- `BreadcrumbList` for the landing page

Docs graph:

- `Organization`, `Person`, `WebSite`
- `TechArticle` for technical guides (with author, dates, sources and section)
- `CollectionPage`/`AboutPage`/`WebPage` where appropriate
- `BreadcrumbList` for every docs/trust page

No aggregate ratings, review counts, prices, addresses, employers or awards are
invented. The schema describes only facts present on the page or in the public
repository.

### Open Graph and social cards

`site/public/og/` contains a real 1200×630 PNG for each page. The build fails if
a page has no card. Cards are generated from the page title by
`scripts/generate_og_assets.py`; they are not screenshots of a page that does not
exist. `twitter:image:alt` and `og:image:alt` are required.

Regenerate after changing titles:

```bash
python scripts/generate_og_assets.py
cd site && npm run build && npm run check:seo
```

### Security-header limits on GitHub Pages

GitHub Pages cannot set arbitrary response headers. The site therefore uses a
meta CSP with SHA-256 hashes of every inline script. The docs pages have no client
script at all; their JSON-LD hash is the only script hash. `frame-ancestors` and
`X-Frame-Options` are ignored or unavailable through meta tags and are **not
claimed**. HSTS is supplied by the `github.io` parent domain. The page does not
frame external content, and a future host with header control is the correct
place to add the missing framing protection.

---

## 4. GEO / AEO: being answerable, not gaming answers

GEO (generative engine optimisation) and AEO (answer engine optimisation) are
treated as clarity and citability work, not tricks.

Implemented:

- Definition-first copy: the H1 and opening paragraph say what RedFall is, what
  it does and what it refuses to do.
- Question-shaped H2s on the landing page and docs: “What makes RedFall
  different?”, “How does a RedFall scan work?”, “What evidence backs RedFall?”,
  “How do you install RedFall?”, “What do people ask about RedFall?”.
- FAQ answers that are complete enough to quote and short enough to be a snippet.
- A `llms.txt` with the canonical summary, page map, primary-source links and
  verification commands.
- Explicit dates, named author, repository links and citations to the code and
  evidence rather than unsourced claims.
- AI crawler directives in `robots.txt` that allow reading and indexing.
- Static HTML that does not require JavaScript, so an agent that does not execute
  JS can read the whole docs surface.

Not implemented, because it would be dishonest or account-bound:

- No “guaranteed ChatGPT ranking”, no paid AI-placement service, no fake
  third-party listicles, no manufactured citations.
- No claim that an AI answer currently cites RedFall. Citation monitoring is a
  manual observation log, not a metric the site can prove.

### Manual AI-citation observation log

Once a month, a human records the following in a private log (do not publish a
fake count):

| Date | Engine/model | Exact prompt | Answer mentions RedFall? | URL cited? | Notes |
| --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |

Prompts worth tracking:

1. “What is execution-verified vulnerability scanning?”
2. “What tools prove a vulnerability by executing it?”
3. “RedFall vulnerability scanner review”
4. “How does a gVisor sandbox verify an exploit?”
5. “SAST vs DAST vs execution verification”

Do not claim an answer engine cites the site unless the answer actually did so
and the URL is visible. Do not seed fake forum questions to manufacture
citations.

---

## 5. E-E-A-T without invented expertise

The public identity is `DevAnimecx`; the site does not claim a legal name,
employer, certification, security clearance, customer or years of experience.
That is intentional. What the site can prove:

- **Experience:** the dated range runs, the 367-test suite and the 17/17
  pythonbank PoCs in `/evidence/`.
- **Expertise:** mechanism-level pages that explain source, sink, taint,
  interprocedural return flow, predicates, gVisor, adaptive triggers and verified
  repair, with links to the corresponding code.
- **Authoritativeness:** release attestations, `SHA256SUMS`, CI checks and a
  public source tree. Authority here means “can be checked”, not “claims to be
  famous”.
- **Trust:** a blocker ledger that names what did **not** run, a privacy page,
  a security policy, a no-mock contract and visible update dates.

Human-only E-E-A-T tasks:

- A real author bio would require the maintainer's consent and, if used, accurate
  facts. The public handle is used until then.
- External reviews or testimonials must be real and attributable; none are
  displayed now.
- Third-party audits must be commissioned by a human; none are claimed.

---

## 6. Backlink and citation strategy (no manufacturing)

The only durable link-earning assets are the real ones:

1. **The evidence ledger** (`/evidence/`) — dated commands and limits.
2. **The no-mock contract** (`/docs/no-mock-contract/`) — a clear, unusual rule
   with mechanical enforcement.
3. **Release verification** (`/docs/release-verification/`) — a reproducible
   supply-chain check.
4. **The comparison** (`/compare/static-analysis/`) — a fair explanation of when
   RedFall is the wrong tool.
5. **The blocker ledger** (`/docs/blocked/`) — a rare public account of what does
   not run.

Outreach rules:

- Link only where the page genuinely answers the community's question. Do not
  post the same link to unrelated threads.
- Disclose that you maintain the project.
- Do not buy links, join link exchanges, use private blog networks, pay for
  “guest posts” with keyword anchors, or accept “SEO package” guarantees.
- Do not fabricate directory listings, review sites, awards or user quotes.
- Prefer primary-source citations: GitHub, release notes, changelogs, security
  advisories, conference talks, maintainers' own posts, relevant awesome-lists
  with contribution rules.
- Accept that a link may be removed, marked `nofollow` or never appear. That is
  a normal outcome, not a failure to hide.

Realistic targets to investigate, with human judgment:

| Target type | Example | Rule |
| --- | --- | --- |
| GitHub | Repository README, release notes, topic tags | Already first-party; keep the README canonical. |
| Curated lists | Security tooling / vulnerability scanner lists | Read the contribution guide; one honest entry; no astroturfing. |
| Practitioner communities | Hacker News, Reddit r/netsec, security Discords | Follow each community's self-promotion rules; disclose; answer questions, don't drop links. |
| OSS projects | Projects that need a verification harness | Offer the technique, not a drive-by link; contribute code if useful. |
| Conferences / CFPs | Local security meetups, OSS conferences | Submit a real talk with reproducible evidence; no invented credentials. |
| Maintainer profiles | GitHub profile, personal site | Link the project from an owned profile. |

Measurement that is actually available:

- GitHub repository traffic and referrers (maintainer-only).
- Google Search Console “Links” report (after human verification).
- Bing Webmaster Tools backlinks report (after human verification).
- Manual notes for direct outreach.
- No affiliate/UTM analytics are added, because the site promises no analytics and
  no cookies. Do not silently add GA4; if that changes, update the privacy page
  and obtain consent where required.

There is no “20 backlinks in 30 days” target. Volume targets create pressure to
manufacture links, which violates the project's honesty rule.

---

## 7. Search-engine activation (human-only)

The following cannot be completed from this repository alone. They require the
owner of the GitHub account or a domain/DNS control panel.

### Google Search Console

1. Add a **URL-prefix** property: `https://devanimecx.github.io/redfall/`.
2. Verify with the HTML file method: download the Google verification file,
   commit it to `site/public/` with the exact filename Google gives, rebuild and
   deploy, then click Verify. A DNS TXT record is not available because
   `devanimecx.github.io` is not a domain this project controls.
3. Submit `https://devanimecx.github.io/redfall/sitemap.xml`.
4. Use URL Inspection → Request indexing for the landing page and the five most
   important docs pages. Do not repeatedly request the same URL.
5. Record the property, verification date, sitemap submission date and any
   coverage errors in the private operations log.

Do not commit a fake verification file or claim verification before Google
confirms it.

### Bing Webmaster Tools

1. Add `https://devanimecx.github.io/redfall/`.
2. Verify via the HTML meta tag or XML file method. Commit the real token to
   `site/index.html` or `site/public/` only after Bing issues it.
3. Import from Google Search Console if that property is already verified.
4. Confirm the sitemap and IndexNow submissions appear in the dashboard.
5. Optionally add Yandex Webmaster and Seznam; both consume IndexNow.

### Analytics decision

The public site intentionally has no analytics, cookies or accounts. Search
Console and Bing Webmaster Tools provide query/index data without adding client
tracking. Do not add GA4, heatmaps or session replay without changing the
privacy page and the consent posture. If analytics are added later, they are a
human product decision, not an SEO “must”.

---

## 8. Monitoring

### Repository gates (every push / PR)

```bash
cd site
npm ci
npm run build
npm run check:seo          # metadata, schema, links, sitemap, robots, llms, OG, no-JS docs
npm run check:layout -- http://localhost:4173/redfall/
npm run check:a11y  -- http://localhost:4173/redfall/
npm run check:docs  -- http://localhost:4173/redfall/
npm run check:lighthouse -- http://localhost:4173/redfall/
```

CI runs the same commands with a real Chrome on Ubuntu. The Lighthouse threshold
is 95 for each category; the current local 0.1.1 build scores 100/100/100/100 on
both desktop and mobile. The live deployment is more variable: two mobile runs
scored 93 and 99, so the live score is not certified at 100.

### Weekly live monitor

`.github/workflows/seo-monitor.yml` runs every Monday at 06:30 UTC and can be
started manually. It checks:

- HTTP 200 and HTML content type for all 24 sitemap URLs
- self-referencing canonical and one H1 per page
- title and description present
- no `noindex` in meta robots or `X-Robots-Tag`
- valid JSON-LD with Organization, WebSite, BreadcrumbList and a page type
- landing FAQPage
- OG image resolves
- internal links present
- `robots.txt` sitemap directive and AI-agent directives
- IndexNow key file content
- `llms.txt` exists and links the core pages
- production 404 returns HTTP 404 with the custom page

It writes `build/seo-monitor-report.json` and uploads it as a workflow artifact.
A failure means the live surface changed; it does not prove a ranking loss.

### Human review cadence

| Frequency | Task | Account |
| --- | --- | --- |
| Weekly | Read the live monitor artifact; inspect Search Console coverage and Bing sitemap status | GSC / Bing |
| Weekly | Check GitHub release/README links and any broken links reported by users | GitHub |
| Monthly | Review queries in Search Console; identify pages with impressions but no clicks; improve the page that already exists | GSC |
| Monthly | Manual AI-citation observation log (five fixed prompts) | Human |
| Quarterly | Re-run the full technical gates, regenerate OG cards if titles changed, review the 90-day plan | Repo + human |
| Quarterly | Audit backlinks for spam or accidental low-quality links; disavow only with evidence and caution | GSC / Bing |

### KPI table (leading indicators, not promises)

| KPI | Source | Why it is measurable |
| --- | --- | --- |
| Indexed pages / discovered pages | GSC, Bing | A count reported by the engine, not a guess |
| Sitemap errors | GSC, Bing | Concrete error list |
| Core Web Vitals field data | CrUX/GSC (once enough traffic) | Field data; may be “no data” |
| Lighthouse lab scores | CI | Reproducible on the build |
| Organic impressions / clicks | GSC | Engine-reported |
| Referring pages | GSC/Bing | Engine-reported |
| AI citations | Manual log | Only what was observed |

Never report “ranking #1”, “guaranteed page 1”, “viral”, “20 backlinks” or an
AI-citation count without a dated source. If a metric has no data, say “no data”.

---

## 9. 90-day calendar

The calendar starts on the first day the SEO redesign is deployed. It assumes one
maintainer and is deliberately modest. Completing fewer, better tasks is the
goal; the dates are a cadence, not a promise of results.

### Days 1–7: ship and verify

- [ ] Merge the redesign after CI passes: `check:seo`, layout, axe, docs check,
      Lighthouse.
- [ ] Confirm the Pages workflow succeeds and the deploy job records the IndexNow
      HTTP response.
- [ ] Run `node site/scripts/seo_monitor.mjs` against production; save the
      artifact. Do not edit the report to make it pass.
- [ ] Verify live canonical, title, description, OG image, JSON-LD, robots,
      sitemap, `llms.txt`, IndexNow key and custom 404 in a browser and with
      `curl`.
- [ ] Add the Google Search Console URL-prefix property and verify with the real
      HTML file if the owner wants Google indexing data.
- [ ] Add Bing Webmaster Tools, verify, submit the sitemap, confirm IndexNow.
- [ ] Record the baseline (indexed count, impressions, clicks, any errors) in the
      private log. No ranking claim.

### Days 8–21: technical cleanup

- [ ] Read the first live monitor report end to end and fix every error.
- [ ] Check Search Console “Page indexing” and “Sitemaps”; resolve real errors.
- [ ] Crawl the site with a human browser and a crawler (Screaming Frog free tier
      is optional) to spot orphan pages, duplicate titles and redirect chains.
- [ ] Review all 24 URLs in the sitemap: is each page still accurate, dated and
      linked from at least one other page?
- [ ] Check mobile rendering at 390 px and keyboard navigation through the docs
      sidebar, code blocks and tables.
- [ ] Confirm the custom 404 on production returns 404, not a soft 200.
- [ ] Do not add pages yet.

### Days 22–45: usefulness and internal links

- [ ] Use Search Console queries to find pages with impressions but weak clicks.
      Rewrite the title/description or add the missing answer to the existing
      page; do not create a near-duplicate.
- [ ] Improve the five highest-value pages first: execution verification,
      architecture, sandbox, install, evidence.
- [ ] Add at most **two** genuinely missing pages, and only if they answer a
      question the existing pages cannot. Each must join a cluster and pass the
      build gates.
- [ ] Re-check all internal links from the landing page into the clusters.
- [ ] Update the visible `Last updated` date only when the content actually
      changed.
- [ ] Regenerate OG cards if any title changed.

### Days 46–60: earned distribution

- [ ] Prepare one honest technical write-up (e.g. “what execution verification
      actually proves” or “verifying a release with Sigstore”) from existing
      evidence. Draft it in the repo or a personal site; no fake author.
- [ ] Identify five communities/lists where the write-up genuinely fits. Read
      each rule before posting. Disclose maintainership.
- [ ] Submit one conference/meetup CFP if there is a relevant event; use only real
      credentials.
- [ ] Ask two knowledgeable engineers for technical review of specific claims.
      Record their feedback; do not invent endorsements.
- [ ] Do not buy links or use automated outreach blasts.

### Days 61–75: measurement and pruning

- [ ] Export GSC/Bing data; compare to the day-1 baseline. Record absolute
      numbers and the date range, not a percentage without a denominator.
- [ ] Identify pages with zero impressions and zero internal clicks. Decide:
      improve, merge or remove. Removing a thin page is better than padding it.
- [ ] Check for keyword cannibalisation between the landing page and docs pages;
      consolidate if two pages target the same question.
- [ ] Re-run the manual AI-citation log. Record “not cited” honestly.
- [ ] Audit backlinks for spam; document any disavow decision.

### Days 76–90: stabilise and plan the next quarter

- [ ] Re-run all gates and the live monitor.
- [ ] Review Core Web Vitals field data; if there is no field data, say so and use
      lab data.
- [ ] Update the evidence page with the latest measured results and dates.
- [ ] Update `BLOCKED.md` if a human-only task is still blocked.
- [ ] Write a one-page quarter review: what shipped, what was measured, what was
      not, what will be tested next. No invented wins.
- [ ] Choose the next quarter's two or three content bets from real user
      questions, not from a keyword-volume spreadsheet alone.

### Weekly cadence after day 90

- Monday: read the monitor artifact and Search Console/Bing errors.
- Wednesday: improve one existing page or one internal link.
- Friday: record one observation (query, citation, referral, broken link) with a
  date and source. No metric is invented to fill the row.

---

## 10. Known limits and stop conditions

- **No guaranteed rankings.** Search engines decide. The site can be crawlable,
  fast, structured and honest; it cannot guarantee position.
- **No guaranteed AI citations.** Assistants may ignore `llms.txt`, summarise
  incorrectly or cite a competitor. The observation log records what happened.
- **No fake authorship.** The maintainer is `DevAnimecx`; no legal identity,
  employer or certification is claimed.
- **No manufactured backlinks.** Outreach must be relevant and disclosed.
- **No analytics by default.** Search Console/Bing provide enough for a small
  site; adding GA4 requires a privacy update.
- **GitHub Pages header limits.** HSTS comes from `github.io`; framing protection
  cannot be set from this repo and is documented rather than faked.
- **Postgres is required for the full test suite.** The site gates are independent
  of it; the recorded 367-test result and the current host limitation are in
  `BLOCKED.md`.
- **A full product scan still needs Docker + gVisor and an LLM key.** SEO cannot
  unblock that; do not imply it does.

If a proposed SEO tactic requires inventing evidence, a fake reviewer, a paid
link, a misleading schema field or a guaranteed outcome, stop. It is outside the
no-mock contract and this document.
