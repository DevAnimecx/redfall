// Static documentation generator.
//
// The landing page is React + a prerender pass. Everything under /docs/,
// /compare/, /evidence/, /about/ and /privacy/ is generated here as plain HTML
// with zero client JavaScript. That keeps documentation pages fast, crawlable
// and cheap to render, while the shared CSS is the same design system as the
// landing page.
//
// Source of truth: site/content/**/*.md (frontmatter + Markdown).
// Outputs: dist/**/index.html, dist/sitemap.xml, dist/robots.txt,
//          dist/llms.txt, dist/404.html.

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import MarkdownIt from "markdown-it";
import markdownItAnchor from "markdown-it-anchor";
import {
  AUTHOR_NAME,
  AUTHOR_PATH,
  AUTHOR_URL,
  BASE,
  FONT_PATH,
  GITHUB_USER_URL,
  REPO_URL,
  RELEASE_URL,
  SITE_NAME,
  SITE_URL,
  UPDATED,
  VERSION,
  abs,
} from "../lib/site.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SITE_ROOT = path.resolve(HERE, "..");
const CONTENT_DIR = path.join(SITE_ROOT, "content");
const DIST_DIR = path.join(SITE_ROOT, "dist");
const BUILD_DIR = path.resolve(SITE_ROOT, "..", "build");

const GROUPS = ["Start here", "How it works", "Trust and evidence", "Reference", "Project"];
const GROUP_ORDER = new Map(GROUPS.map((g, i) => [g, i]));

const md = new MarkdownIt({
  html: false,
  linkify: true,
  typographer: true,
  breaks: false,
});

md.use(markdownItAnchor, {
  level: [2, 3],
  permalink: false,
  slugify: (s) =>
    s
      .toLowerCase()
      .trim()
      .replace(/<[^>]+>/g, "")
      .replace(/[^\w\s-]/g, "")
      .replace(/\s+/g, "-")
      .replace(/-+/g, "-"),
});

// Fenced code becomes a labelled, keyboard-scrollable region. The landing page
// had to fix exactly this with axe; documentation must not reintroduce it.
md.renderer.rules.fence = (tokens, idx, _options, env) => {
  const token = tokens[idx];
  const lang = token.info.trim().split(/\s+/)[0];
  const cls = lang ? ` class="language-${escapeHtml(lang)}"` : "";
  env.codeIndex = (env.codeIndex ?? 0) + 1;
  return `<div class="code-scroll" role="region" aria-label="Code example ${env.codeIndex}" tabindex="0"><pre><code${cls}>${escapeHtml(
    token.content,
  )}</code></pre></div>\n`;
};

md.renderer.rules.table_open = (_tokens, _idx, _options, env) => {
  env.tableIndex = (env.tableIndex ?? 0) + 1;
  return `<div class="table-scroll" role="region" aria-label="Data table ${env.tableIndex}" tabindex="0"><table>`;
};
md.renderer.rules.table_close = () => "</table></div>";

const defaultLinkOpen =
  md.renderer.rules.link_open ??
  ((tokens, idx, options, _env, self) => self.renderToken(tokens, idx, options));
md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
  const href = tokens[idx].attrGet("href");
  if (href && /^https?:\/\//.test(href)) {
    tokens[idx].attrSet("rel", "noopener");
  }
  return defaultLinkOpen(tokens, idx, options, env, self);
};

function sha256Inline(value) {
  const normalized = value.replace(/\r\n?/g, "\n");
  return `'sha256-${createHash("sha256").update(normalized, "utf8").digest("base64")}'`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function escapeXml(value) {
  return escapeHtml(value).replace(/'/g, "&apos;");
}

function stripTags(value) {
  return String(value)
    .replace(/<[^>]*>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .trim();
}

function parseList(value) {
  if (!value) return [];
  return value
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
}

function parseFrontmatter(source, file) {
  const match = source.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (!match) throw new Error(`${file}: missing frontmatter`);
  const meta = {};
  for (const line of match[1].split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const key = line.slice(0, colon).trim();
    let value = line.slice(colon + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    meta[key] = value;
  }
  const body = source.slice(match[0].length).trimStart();
  return { meta, body };
}

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (entry.isFile() && entry.name.endsWith(".md")) out.push(full);
  }
  return out;
}

function loadPages() {
  if (!fs.existsSync(CONTENT_DIR)) throw new Error(`content directory missing: ${CONTENT_DIR}`);
  const pages = walk(CONTENT_DIR).map((file) => {
    const source = fs.readFileSync(file, "utf8");
    const { meta, body } = parseFrontmatter(source, path.relative(SITE_ROOT, file));
    const id = path.basename(file, ".md");
    const route = (meta.path ?? `docs/${id}/`).replace(/^\/+|\/+$/g, "");
    if (!meta.title) throw new Error(`${file}: title is required`);
    if (!meta.description) throw new Error(`${file}: description is required`);
    const words = stripTags(body).split(/\s+/).filter(Boolean).length;
    // Search-result titles must identify the brand. An explicit seoTitle may
    // already include it; otherwise append it once. The SEO gate enforces the
    // final length bound after this transform.
    const seoTitleBase = meta.seoTitle || meta.title;
    const seoTitle = seoTitleBase.includes(SITE_NAME) ? seoTitleBase : `${seoTitleBase} | ${SITE_NAME}`;
    return {
      id,
      file,
      body,
      path: `${route}/`,
      title: meta.title,
      seoTitle,
      description: meta.description,
      group: meta.group || "Reference",
      kind: meta.kind || "cluster",
      pillar: meta.pillar || "",
      order: Number(meta.order || 100),
      updated: meta.updated || UPDATED,
      published: meta.published || meta.updated || UPDATED,
      keywords: parseList(meta.keywords),
      sources: parseList(meta.sources),
      related: parseList(meta.related),
      hideFromNav: String(meta.hideFromNav).toLowerCase() === "true",
      noindex: String(meta.noindex).toLowerCase() === "true",
      words,
      readingMinutes: Math.max(1, Math.ceil(words / 220)),
      url: abs(`${route}/`),
      html: "",
      toc: [],
    };
  });

  const paths = new Set();
  for (const page of pages) {
    if (paths.has(page.path)) throw new Error(`duplicate page path: ${page.path}`);
    paths.add(page.path);
  }
  pages.sort((a, b) => {
    if (a.path === "docs/") return -1;
    if (b.path === "docs/") return 1;
    const group = (GROUP_ORDER.get(a.group) ?? 99) - (GROUP_ORDER.get(b.group) ?? 99);
    if (group !== 0) return group;
    if (a.kind === "pillar" && b.kind !== "pillar") return -1;
    if (b.kind === "pillar" && a.kind !== "pillar") return 1;
    return a.order - b.order || a.title.localeCompare(b.title);
  });
  return pages;
}

function rewriteInternal(html) {
  return html.replace(/(href|src)="\/(?!\/)([^"]*)"/g, (_match, attr, value) => {
    if (value.startsWith("redfall/")) return `${attr}="/${value}"`;
    return `${attr}="${BASE}${value}"`;
  });
}

function renderPage(page) {
  const html = rewriteInternal(md.render(page.body, { codeIndex: 0, tableIndex: 0 }));
  const toc = [];
  for (const match of html.matchAll(/<h2 id="([^"]+)">([\s\S]*?)<\/h2>/g)) {
    toc.push({ id: match[1], text: stripTags(match[2]) });
  }
  page.html = html;
  page.toc = toc;
  return page;
}

function formatDate(iso) {
  const date = new Date(`${iso}T12:00:00Z`);
  if (Number.isNaN(date.valueOf())) throw new Error(`invalid date: ${iso}`);
  return new Intl.DateTimeFormat("en-US", {
    month: "long",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  }).format(date);
}

function byId(pages) {
  return new Map(pages.map((page) => [page.id, page]));
}

function navActive(page) {
  if (page.path.startsWith("docs/install/")) return "install";
  if (page.path.startsWith("docs/")) return "docs";
  if (page.path.startsWith("compare/")) return "compare";
  if (page.path.startsWith("evidence/")) return "evidence";
  if (page.path.startsWith("about/")) return "about";
  return "";
}

function markSvg(idSuffix = "header") {
  const gradientId = `rf-docs-mark-${idSuffix}`;
  return `<svg viewBox="0 0 256 256" class="h-8 w-8" aria-hidden="true" focusable="false">
<defs><linearGradient id="${gradientId}" x1="0.1" y1="0" x2="0.9" y2="1"><stop offset="0" stop-color="#ff5147"/><stop offset="0.55" stop-color="#ff0033"/><stop offset="1" stop-color="#8c0202"/></linearGradient></defs>
<g fill="none" stroke="url(#${gradientId})" stroke-linejoin="round" stroke-linecap="round"><path d="M46 26 H210 L234 50 V142 L128 236 L22 142 V50 Z" stroke-width="16"/><circle cx="128" cy="118" r="42" stroke-width="10"/><path d="M128 52 V68 M128 168 V184 M60 118 H76 M180 118 H196" stroke-width="10"/></g>
<circle cx="128" cy="118" r="12" fill="url(#${gradientId})"/></svg>`;
}

function githubSvg() {
  return `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" aria-hidden="true" focusable="false"><path d="M12 .5C5.73.5.5 5.73.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.55 0-.27-.01-1.17-.02-2.12-3.2.7-3.88-1.36-3.88-1.36-.52-1.33-1.28-1.68-1.28-1.68-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11.1 11.1 0 0 1 5.79 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.42-2.7 5.39-5.26 5.68.41.36.78 1.06.78 2.14 0 1.55-.01 2.8-.01 3.18 0 .3.2.67.8.55A11.51 11.51 0 0 0 23.5 12C23.5 5.73 18.27.5 12 .5Z"/></svg>`;
}

function wordmark() {
  return `<span class="font-bold tracking-tight text-lg"><span class="text-accent">Red</span><span class="text-ink">Fall</span></span>`;
}

function header(page) {
  const active = navActive(page);
  const nav = [
    ["docs", `${BASE}docs/`, "Docs"],
    ["evidence", `${BASE}evidence/`, "Evidence"],
    ["compare", `${BASE}compare/static-analysis/`, "Compare"],
    ["install", `${BASE}docs/install/`, "Install"],
  ];
  const links = nav
    .map(
      ([key, href, label]) =>
        `<a href="${href}" class="nav-link" data-active="${active === key}"${
          active === key ? ' aria-current="page"' : ""
        }>${label}</a>`,
    )
    .join("\n");
  return `<a href="#main" class="skip-link">Skip to main content</a>
<header class="nav-shell fixed inset-x-0 top-0 z-50" data-scrolled="true">
  <div class="container-rf flex h-[60px] items-center justify-between lg:h-[72px]">
    <a href="${BASE}" class="flex items-center gap-2.5" aria-label="RedFall home">${markSvg()}${wordmark()}</a>
    <nav aria-label="Main" class="hidden items-center gap-7 lg:flex">${links}
      <a href="${REPO_URL}" class="nav-link" rel="noopener">GitHub</a>
    </nav>
    <div class="flex items-center gap-3">
      <div class="hidden sm:block"><a href="${BASE}#install" class="btn btn-primary">Get started</a></div>
      <details class="docs-menu">
        <summary aria-label="Open menu">${"<svg width=\"20\" height=\"20\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" stroke-linecap=\"round\" aria-hidden=\"true\"><path d=\"M3 6h18M3 12h18M3 18h18\"/></svg>"}</summary>
        <div class="docs-menu-panel">
          <p class="docs-menu-label">RedFall</p>
          ${nav.map(([, href, label]) => `<a href="${href}">${label}</a>`).join("")}
          <a href="${BASE}about/">About</a>
          <a href="${REPO_URL}" rel="noopener">GitHub repository</a>
          <a href="${BASE}#install" class="mt-2 btn btn-primary">Get started</a>
        </div>
      </details>
    </div>
  </div>
</header>`;
}

function sidebar(pages, current) {
  const groups = new Map();
  for (const page of pages) {
    if (page.hideFromNav || page.kind === "project") continue;
    if (!groups.has(page.group)) groups.set(page.group, []);
    groups.get(page.group).push(page);
  }
  const ordered = GROUPS.filter((group) => groups.has(group));
  const groupHtml = ordered
    .map((group) => {
      const items = groups
        .get(group)
        .map(
          (page) =>
            `<a href="${BASE}${page.path}"${
              page.path === current.path ? ' aria-current="page"' : ""
            }>${escapeHtml(page.title)}</a>`,
        )
        .join("\n");
      return `<p class="docs-group-label">${escapeHtml(group)}</p>\n${items}`;
    })
    .join("\n");
  return `<aside class="docs-sidebar" aria-label="Documentation"><div class="docs-sidebar-inner">
<a href="${BASE}docs/"${current.path === "docs/" ? ' aria-current="page"' : ""}>All documentation</a>
${groupHtml}
</div></aside>`;
}

function mobileIndex(pages) {
  const groups = new Map();
  for (const page of pages) {
    if (page.hideFromNav || page.kind === "project" || page.path === "docs/") continue;
    if (!groups.has(page.group)) groups.set(page.group, []);
    groups.get(page.group).push(page);
  }
  const body = GROUPS.filter((group) => groups.has(group))
    .map((group) => {
      const links = groups
        .get(group)
        .map((page) => `<a href="${BASE}${page.path}">${escapeHtml(page.title)}</a>`)
        .join("");
      return `<p class="docs-group-label">${escapeHtml(group)}</p>${links}`;
    })
    .join("");
  return `<details class="docs-mobile-index"><summary>Browse all guides</summary><div class="docs-mobile-index-panel">${body}</div></details>`;
}

function breadcrumb(page) {
  const items = [{ name: "Home", href: BASE }];
  if (page.path.startsWith("docs/") && page.path !== "docs/") {
    items.push({ name: "Docs", href: `${BASE}docs/` });
  }
  if (page.path.startsWith("compare/")) {
    items.push({ name: "Compare", href: `${BASE}compare/static-analysis/` });
  }
  if (page.path.startsWith("docs/") && page.path === "docs/") {
    // The hub is its own crumb.
  }
  items.push({ name: page.title, current: true });
  const rendered = items
    .map((item, i) => {
      const isLast = i === items.length - 1;
      if (isLast) return `<span aria-current="page">${escapeHtml(item.name)}</span>`;
      return `<a href="${item.href}">${escapeHtml(item.name)}</a><span aria-hidden="true">/</span>`;
    })
    .join("");
  return `<nav class="breadcrumbs" aria-label="Breadcrumb">${rendered}</nav>`;
}

function breadcrumbSchema(page) {
  const items = [{ name: "Home", url: abs("") }];
  if (page.path.startsWith("docs/") && page.path !== "docs/") {
    items.push({ name: "Docs", url: abs("docs/") });
  }
  if (page.path.startsWith("compare/")) {
    items.push({ name: "Compare", url: abs("compare/static-analysis/") });
  }
  items.push({ name: page.title, url: page.url });
  return {
    "@type": "BreadcrumbList",
    "@id": `${page.url}#breadcrumb`,
    itemListElement: items.map((item, i) => ({
      "@type": "ListItem",
      position: i + 1,
      name: item.name,
      item: item.url,
    })),
  };
}

function jsonLd(page) {
  const org = {
    "@type": "Organization",
    "@id": `${SITE_URL}/#organization`,
    name: SITE_NAME,
    url: abs(""),
    logo: {
      "@type": "ImageObject",
      url: abs("android-chrome-512.png"),
      width: 512,
      height: 512,
    },
    sameAs: [REPO_URL, RELEASE_URL],
    description:
      "RedFall builds execution-verified vulnerability scanning and verified repair for TypeScript, JavaScript and Python.",
  };
  const person = {
    "@type": "Person",
    "@id": `${AUTHOR_URL}#person`,
    name: AUTHOR_NAME,
    url: AUTHOR_URL,
    sameAs: [GITHUB_USER_URL],
    description: "Maintainer of RedFall.",
    knowsAbout: [
      "Vulnerability research",
      "Static and dynamic analysis",
      "TypeScript",
      "Python",
      "gVisor",
      "SARIF",
    ],
  };
  const website = {
    "@type": "WebSite",
    "@id": `${SITE_URL}/#website`,
    url: abs(""),
    name: SITE_NAME,
    publisher: { "@id": `${SITE_URL}/#organization` },
    inLanguage: "en",
  };

  let pageType = "TechArticle";
  if (page.path === "docs/") pageType = "CollectionPage";
  else if (page.path === "about/") pageType = "AboutPage";
  else if (page.path === "privacy/") pageType = "WebPage";
  else if (page.kind === "page") pageType = "WebPage";

  const mainEntity = {
    "@type": pageType,
    "@id": `${page.url}#page`,
    url: page.url,
    name: page.title,
    headline: page.title,
    description: page.description,
    inLanguage: "en",
    isPartOf: { "@id": `${SITE_URL}/#website` },
    about: { "@id": `${SITE_URL}/#organization` },
    mainEntityOfPage: { "@type": "WebPage", "@id": page.url },
    author: { "@id": `${AUTHOR_URL}#person` },
    publisher: { "@id": `${SITE_URL}/#organization` },
    datePublished: page.published,
    dateModified: page.updated,
    image: {
      "@type": "ImageObject",
      url: page.ogUrl ?? abs("og.png"),
      width: 1200,
      height: 630,
    },
  };
  if (pageType === "TechArticle") {
    mainEntity.articleSection = page.group;
    mainEntity.keywords = page.keywords.join(", ");
    mainEntity.wordCount = page.words;
    mainEntity.timeRequired = `PT${page.readingMinutes}M`;
    if (page.sources.length) mainEntity.citation = page.sources;
  }
  if (page.path === "about/") {
    mainEntity.mainEntity = { "@id": `${AUTHOR_URL}#person` };
  }
  if (page.path === "docs/") {
    mainEntity.hasPart = page.hasPart ?? [];
  }

  const graph = [org, person, website, mainEntity, breadcrumbSchema(page)];
  return `<script type="application/ld+json">${JSON.stringify({
    "@context": "https://schema.org",
    "@graph": graph,
  }).replace(/</g, "\\u003c")}</script>`;
}

function head(page) {
  const ogType = page.kind === "page" || page.kind === "hub" ? "website" : "article";
  const image = page.ogUrl ?? abs("og.png");
  const canonical = page.noindex ? "" : `<link rel="canonical" href="${page.url}">`;
  const robots = page.noindex
    ? "noindex, nofollow"
    : "index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1";
  const ld = page.noindex ? "" : jsonLd(page);
  const ldContent = ld ? ld.slice(ld.indexOf(">") + 1, ld.lastIndexOf("</script>")) : "";
  const csp = page.noindex
    ? "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-src 'none'; upgrade-insecure-requests"
    : `default-src 'self'; script-src ${sha256Inline(ldContent)}; script-src-attr 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-src 'none'; upgrade-insecure-requests`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<title>${escapeHtml(page.seoTitle)}</title>
<meta name="description" content="${escapeHtml(page.description)}">
<meta name="robots" content="${robots}">
${canonical}
<meta name="theme-color" content="#050505">
<meta name="color-scheme" content="dark">
<meta name="referrer" content="strict-origin-when-cross-origin">
<meta name="author" content="${AUTHOR_NAME}">
<meta name="application-name" content="${SITE_NAME}">
<link rel="sitemap" type="application/xml" href="${BASE}sitemap.xml">
<link rel="alternate" type="text/plain" href="${BASE}llms.txt" title="LLM-readable summary">
${page.noindex ? "" : `<link rel="alternate" hreflang="en" href="${page.url}">\n<link rel="alternate" hreflang="x-default" href="${page.url}">`}
<link rel="author" href="${BASE}about/">
<link rel="icon" href="${BASE}favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="${BASE}apple-touch-icon.png">
<link rel="preload" href="${FONT_PATH}" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="${page.cssHref}">
<meta property="og:type" content="${ogType}">
<meta property="og:site_name" content="${SITE_NAME}">
<meta property="og:locale" content="en_US">
<meta property="og:title" content="${escapeHtml(page.title)}">
<meta property="og:description" content="${escapeHtml(page.description)}">
<meta property="og:url" content="${page.url}">
<meta property="og:image" content="${image}">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="${escapeHtml(`${page.title} — RedFall`)}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${escapeHtml(page.title)}">
<meta name="twitter:description" content="${escapeHtml(page.description)}">
<meta name="twitter:image" content="${image}">
<meta name="twitter:image:alt" content="${escapeHtml(`${page.title} — RedFall`)}">
${ogType === "article" ? `<meta property="article:published_time" content="${page.published}">\n<meta property="article:modified_time" content="${page.updated}">\n<meta property="article:author" content="${AUTHOR_URL}">\n<meta property="article:section" content="${escapeHtml(page.group)}">` : ""}
${ld}
</head>`;
}

function footer() {
  const docs = [
    ["Docs", `${BASE}docs/`],
    ["Verified findings", `${BASE}docs/verified-findings/`],
    ["Architecture", `${BASE}docs/architecture/`],
    ["Install", `${BASE}docs/install/`],
    ["Evidence", `${BASE}evidence/`],
    ["Compare", `${BASE}compare/static-analysis/`],
    ["About", `${BASE}about/`],
    ["Privacy", `${BASE}privacy/`],
  ];
  return `<footer class="border-t border-line">
  <div class="container-rf grid gap-10 py-12 md:grid-cols-3">
    <div>
      <a href="${BASE}" class="flex w-fit items-center gap-2.5" aria-label="RedFall home">${markSvg("footer")}${wordmark()}</a>
      <p class="mt-3 max-w-xs text-sm leading-relaxed text-muted">Execution-verified vulnerability discovery and verified repair. Findings are proofs, not candidates.</p>
    </div>
    <nav aria-label="Documentation" class="grid grid-cols-2 gap-x-8 gap-y-2.5 text-sm">
      ${docs.map(([label, href]) => `<a href="${href}" class="footer-link">${label}</a>`).join("\n")}
    </nav>
    <div class="md:justify-self-end">
      <a href="${REPO_URL}" aria-label="RedFall on GitHub" class="inline-flex h-11 w-11 items-center justify-center rounded-sm border border-line text-muted transition-colors duration-200 hover:border-line-accent hover:text-ink" rel="noopener">${githubSvg()}</a>
    </div>
  </div>
  <div class="border-t border-line">
    <p class="container-rf py-6 text-sm text-muted">© 2026 RedFall contributors · Maintained by <a href="${BASE}${AUTHOR_PATH}" class="footer-link underline underline-offset-2">${AUTHOR_NAME}</a> · Last updated <time datetime="${UPDATED}">${formatDate(UPDATED)}</time> · <a href="${BASE}llms.txt" class="footer-link underline underline-offset-2">llms.txt</a></p>
  </div>
</footer>`;
}

function relatedFor(page, pages) {
  const map = byId(pages);
  const picked = [];
  const add = (candidate) => {
    if (!candidate || candidate.id === page.id || picked.some((p) => p.id === candidate.id)) return;
    if (candidate.noindex || candidate.path === "docs/") return;
    picked.push(candidate);
  };
  for (const id of page.related) add(map.get(id));
  for (const candidate of pages) if (candidate.pillar === page.pillar) add(candidate);
  for (const candidate of pages) if (candidate.group === page.group) add(candidate);
  add(map.get("install"));
  add(map.get("evidence"));
  return picked.slice(0, 3);
}

function relatedBlock(page, pages) {
  const related = relatedFor(page, pages);
  if (!related.length) return "";
  return `<nav class="related" aria-label="Related guides">
<h2>Related guides</h2>
<div class="related-grid">
${related
  .map(
    (item) =>
      `<a class="related-card" href="${BASE}${item.path}"><span>${escapeHtml(item.group)}</span><strong>${escapeHtml(item.title)}</strong></a>`,
  )
  .join("\n")}
</div>
</nav>`;
}

function pillarGuides(page, pages) {
  if (page.kind !== "pillar") return "";
  const guides = pages.filter((p) => p.pillar === page.id && p.id !== page.id && p.kind !== "pillar");
  if (!guides.length) return "";
  return `<nav class="related" aria-label="Guides in this pillar">
<h2>Guides in this pillar</h2>
<div class="related-grid">
${guides
  .map(
    (item) =>
      `<a class="related-card" href="${BASE}${item.path}"><span>${escapeHtml(item.group)}</span><strong>${escapeHtml(item.title)}</strong></a>`,
  )
  .join("\n")}
</div>
</nav>`;
}

function articleMeta(page, pages) {
  const pillar = page.pillar && page.kind !== "pillar" ? byId(pages).get(page.pillar) : null;
  return `<div class="article-meta">
<a href="${BASE}${AUTHOR_PATH}" rel="author">${AUTHOR_NAME}</a><span class="dot" aria-hidden="true">·</span>
<span>Last updated <time datetime="${page.updated}">${formatDate(page.updated)}</time></span><span class="dot" aria-hidden="true">·</span>
<span>${page.readingMinutes} min read</span>
${pillar ? `<span class="dot" aria-hidden="true">·</span><span>Part of <a href="${BASE}${pillar.path}">${escapeHtml(pillar.title)}</a></span>` : ""}
</div>`;
}

function tocBlock(page) {
  if (page.toc.length < 2) return "";
  return `<nav class="toc" aria-label="On this page">
<p class="toc-title">On this page</p>
<ol>${page.toc.map((item) => `<li><a href="#${item.id}">${escapeHtml(item.text)}</a></li>`).join("")}</ol>
</nav>`;
}

function articleCta() {
  return `<div class="article-cta">
<p><strong>Run it yourself.</strong> Install RedFall, run <code>redfall doctor</code>, then scan a target you own. The evidence page records what was measured and what still needs a runtime.</p>
<div class="article-cta-actions"><a href="${BASE}docs/install/" class="btn btn-primary">Install RedFall</a><a href="${BASE}evidence/" class="btn btn-ghost">See the evidence</a></div>
</div>`;
}

function docsFooterNote() {
  return `<p class="docs-footer-note">This page is part of the RedFall documentation and is maintained in the <a href="${REPO_URL}" rel="noopener">public repository</a>. Corrections and reproducible counterexamples are welcome via GitHub Issues. Read the <a href="${BASE}about/">maintainer note</a>.</p>`;
}

function layout(page, pages) {
  const titleTag = page.path === "docs/" ? `<h1 class="docs-title">${escapeHtml(page.title)}</h1>` : `<h1 class="docs-title">${escapeHtml(page.title)}</h1>`;
  return `${head(page)}
<body class="min-h-screen bg-bg text-ink antialiased">
${header(page)}
<main id="main">
<div class="docs-shell container-rf">
${sidebar(pages, page)}
<div class="docs-main">
${breadcrumb(page)}
${titleTag}
${articleMeta(page, pages)}
${mobileIndex(pages)}
${tocBlock(page)}
<article class="prose-rf">${page.html}</article>
${pillarGuides(page, pages)}
${relatedBlock(page, pages)}
${articleCta()}
${docsFooterNote()}
</div>
</div>
</main>
${footer()}
</body>
</html>
`;
}

function docsIndex(pages) {
  const groups = new Map();
  for (const page of pages) {
    if (page.path === "docs/" || page.noindex || page.kind === "project") continue;
    if (!groups.has(page.group)) groups.set(page.group, []);
    groups.get(page.group).push(page);
  }
  return GROUPS.filter((group) => groups.has(group))
    .map((group) => {
      const cards = groups
        .get(group)
        .map(
          (page) =>
            `<a class="docs-card" href="${BASE}${page.path}"><strong>${escapeHtml(page.title)}</strong><span>${escapeHtml(page.description)}</span></a>`,
        )
        .join("\n");
      return `<h2>${escapeHtml(group)}</h2>\n<div class="docs-index-grid">${cards}</div>`;
    })
    .join("\n");
}

function buildPages(pages) {
  const cssAssets = fs
    .readdirSync(path.join(DIST_DIR, "assets"))
    .filter((name) => name.endsWith(".css"));
  if (cssAssets.length !== 1) {
    throw new Error(`expected exactly one built CSS asset, found: ${cssAssets.join(", ") || "none"}`);
  }
  const cssHref = `${BASE}assets/${cssAssets[0]}`;

  const map = byId(pages);
  for (const page of pages) {
    page.cssHref = cssHref;
    const ogRel = page.og ?? `og/${page.id}.png`;
    const ogPath = path.join(DIST_DIR, ogRel);
    if (!fs.existsSync(ogPath)) {
      throw new Error(`missing social card ${ogRel}; run python scripts/generate_og_assets.py`);
    }
    page.ogUrl = abs(ogRel);
  }

  const hub = pages.find((page) => page.path === "docs/");
  if (hub) {
    hub.html = hub.html.replace(
      /<p>\[\[DOCS_INDEX\]\]<\/p>/,
      docsIndex(pages),
    );
    if (hub.html.includes("[[DOCS_INDEX]]")) throw new Error("docs hub placeholder was not replaced");
  } else {
    throw new Error("docs hub page (path: docs/) is missing");
  }

  for (const page of pages) {
    if (page.path === "docs/") {
      page.hasPart = pages
        .filter((p) => p.path !== "docs/" && !p.noindex && p.kind !== "project")
        .map((p) => ({ "@type": "TechArticle", "@id": `${p.url}#page`, name: p.title, url: p.url }));
    }
    const targetDir = path.join(DIST_DIR, page.path);
    fs.mkdirSync(targetDir, { recursive: true });
    fs.writeFileSync(path.join(targetDir, "index.html"), layout(page, pages), "utf8");
  }
}

function build404(pages) {
  const page = {
    id: "404",
    path: "404.html",
    title: "Page not found",
    seoTitle: "Page not found | RedFall",
    description: "That URL does not exist. Browse the RedFall documentation, evidence page, or install guide.",
    group: "Reference",
    kind: "page",
    pillar: "",
    updated: UPDATED,
    published: UPDATED,
    keywords: [],
    sources: [],
    related: [],
    words: 0,
    readingMinutes: 1,
    url: abs("404.html"),
    html: "",
    toc: [],
    noindex: true,
    cssHref: pages[0].cssHref,
    ogUrl: abs("og/landing.png"),
  };
  const body = `<div class="docs-shell container-rf"><div class="docs-main">
<nav class="breadcrumbs" aria-label="Breadcrumb"><a href="${BASE}">Home</a><span aria-hidden="true">/</span><span aria-current="page">404</span></nav>
<h1 class="docs-title">Page not found</h1>
<div class="article-meta"><span>HTTP 404</span><span class="dot" aria-hidden="true">·</span><span>Last updated <time datetime="${UPDATED}">${formatDate(UPDATED)}</time></span></div>
<article class="prose-rf">
<p>That URL does not exist. It may have moved, or the link may be mistyped. Nothing was redirected silently.</p>
<h2>Where to go next</h2>
<ul>
<li><a href="${BASE}docs/">Documentation</a> — the verification guide, architecture, install steps and reference pages.</li>
<li><a href="${BASE}evidence/">Evidence</a> — what was measured, on which host, and what remains blocked.</li>
<li><a href="${BASE}compare/static-analysis/">Comparison</a> — execution-verified scanning versus static analysis.</li>
<li><a href="${BASE}docs/install/">Install</a> — Windows, Linux and macOS instructions.</li>
</ul>
<p>If a link on this site is broken, <a href="${REPO_URL}/issues" rel="noopener">open an issue</a> with the URL and the page you came from.</p>
</article>
${articleCta()}
</div></div>`;
  const html = `${head(page)}
<body class="min-h-screen bg-bg text-ink antialiased">
${header(page)}
<main id="main">${body}</main>
${footer()}
</body>
</html>`;
  fs.writeFileSync(path.join(DIST_DIR, "404.html"), html, "utf8");
}

function buildSitemap(pages) {
  const today = UPDATED;
  const urls = [
    { loc: abs(""), updated: today, priority: "1.0", freq: "weekly" },
    ...pages
      .filter((page) => !page.noindex)
      .map((page) => ({
        loc: page.url,
        updated: page.updated,
        priority:
          page.path === "docs/"
            ? "0.9"
            : page.kind === "pillar"
              ? "0.9"
              : page.kind === "page"
                ? "0.5"
                : "0.7",
        freq: page.kind === "page" ? "yearly" : "monthly",
      })),
  ];
  const seen = new Set();
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls
  .filter((item) => {
    if (seen.has(item.loc)) return false;
    seen.add(item.loc);
    return true;
  })
  .map(
    (item) =>
      `  <url>\n    <loc>${escapeXml(item.loc)}</loc>\n    <lastmod>${item.updated}</lastmod>\n    <changefreq>${item.freq}</changefreq>\n    <priority>${item.priority}</priority>\n  </url>`,
  )
  .join("\n")}
</urlset>
`;
  fs.writeFileSync(path.join(DIST_DIR, "sitemap.xml"), xml, "utf8");
}

function buildRobots() {
  const ai = [
    "GPTBot",
    "OAI-SearchBot",
    "ChatGPT-User",
    "ClaudeBot",
    "Claude-Web",
    "PerplexityBot",
    "Google-Extended",
    "Applebot-Extended",
    "CCBot",
    "meta-externalagent",
    "Bytespider",
  ];
  const robots = `# RedFall — execution-verified vulnerability scanning
# All public documentation is readable by search engines and answer engines.

User-agent: *
Allow: /

${ai.map((bot) => `User-agent: ${bot}\nAllow: /`).join("\n\n")}

Sitemap: ${abs("sitemap.xml")}
`;
  fs.writeFileSync(path.join(DIST_DIR, "robots.txt"), robots, "utf8");
}

function buildLlms(pages) {
  const groups = new Map();
  for (const page of pages) {
    if (page.noindex || page.kind === "project") continue;
    if (!groups.has(page.group)) groups.set(page.group, []);
    groups.get(page.group).push(page);
  }
  const lines = [
    "# RedFall",
    "",
    "> RedFall is an execution-verified vulnerability scanner for TypeScript, JavaScript and Python. It ingests real source with tree-sitter, tracks attacker-controlled data from request surface to sink, runs candidate exploits against the live application inside a Docker container on the gVisor `runsc` runtime, and reports only findings that reproduced. It then attempts a repair and verifies it against the target's own tests. Static analysis produces candidates; a finding exists only if it executed. This is enforced in CI by the no-mock contract.",
    "",
    "Key facts:",
    `- Site: ${abs("")}`,
    `- Source: ${REPO_URL}`,
    `- Release: ${RELEASE_URL}`,
    `- Maintainer: ${AUTHOR_NAME} (${GITHUB_USER_URL})`,
    `- Version: ${VERSION}; Python 3.12+; Windows, Linux and macOS`,
    "- Full scans require Docker with a gVisor runtime and one LLM provider key through LiteLLM.",
    `- Last updated: ${UPDATED}`,
    "",
    "## Start here",
    "",
    ...["docs/", "docs/verified-findings/", "docs/install/", "docs/no-mock-contract/"].map((p) => {
      const page = pages.find((x) => x.path === p);
      return page ? `- [${page.title}](${page.url}): ${page.description}` : null;
    }).filter(Boolean),
    "",
  ];
  for (const group of GROUPS) {
    if (group === "Start here" || !groups.has(group)) continue;
    lines.push(`## ${group}`, "");
    for (const page of groups.get(group)) {
      lines.push(`- [${page.title}](${page.url}): ${page.description}`);
    }
    lines.push("");
  }
  lines.push(
    "## Source and verification",
    "",
    `- [README](${REPO_URL}): full description, status table and the source for every claim.`,
    `- [CHANGELOG](${REPO_URL}/blob/main/CHANGELOG.md): what shipped in ${VERSION}, with measured numbers.`,
    `- [BLOCKED.md](${REPO_URL}/blob/main/BLOCKED.md): what cannot run on the release host, with the smallest real unblock for each item.`,
    `- [SECURITY.md](${REPO_URL}/blob/main/SECURITY.md): vulnerability reporting, supply-chain verification and the range-target warning.`,
    `- [CONTRIBUTING.md](${REPO_URL}/blob/main/CONTRIBUTING.md): the no-mock rule, stage ownership and the PR contract.`,
    "",
    "Verification commands:",
    "",
    `- \`gh attestation verify redfall-${VERSION}-py3-none-any.whl --repo DevAnimecx/redfall\` proves the release wheel was built by this repository's release workflow from the tagged commit.`,
    "- `redfall doctor` prints exactly what the current host can and cannot run.",
    "- `python scripts/check_no_mock.py` is the mechanical part of the no-mock contract.",
    "",
    "## Citation",
    "",
    `Cite the specific page you used, not the home page. Every documentation page carries a visible last-updated date, a named maintainer and links to the primary sources it relies on. The canonical URL is the one in the page's <link rel="canonical"> tag.`,
    "",
    `Machine-readable index: ${abs("sitemap.xml")}`,
    "",
  );
  fs.writeFileSync(path.join(DIST_DIR, "llms.txt"), lines.join("\n"), "utf8");
}

function main() {
  if (!fs.existsSync(DIST_DIR)) {
    throw new Error("dist/ does not exist; run `vite build` and `prerender.mjs` first");
  }
  fs.mkdirSync(BUILD_DIR, { recursive: true });
  const pages = loadPages().map(renderPage);
  if (!pages.some((p) => p.path === "docs/")) throw new Error("missing docs/ hub page (site/content/docs/index.md)");
  buildPages(pages);
  build404(pages);
  buildSitemap(pages);
  buildRobots();
  buildLlms(pages);

  const manifest = pages.map((page) => ({
    id: page.id,
    path: page.path,
    title: page.title,
    description: page.description,
    group: page.group,
    kind: page.kind,
    updated: page.updated,
    words: page.words,
    url: page.url,
  }));
  fs.writeFileSync(path.join(BUILD_DIR, "docs-manifest.json"), JSON.stringify(manifest, null, 2), "utf8");
  console.log(`docs: generated ${pages.length} pages, sitemap, robots.txt, llms.txt and 404.html`);
}

main();
