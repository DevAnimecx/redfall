// Prerender the React app into dist/index.html so crawlers and answer engines
// get the full page as static HTML (no JavaScript required to read it).
//
// Runs after:  vite build  &&  vite build --ssr src/entry-server.jsx
// The client bundle hydrates the same markup in main.jsx.
//
// Build-time steps:
//   1. Render the React tree into the HTML template.
//   2. Generate the site graph (Organization, Person, WebSite, SoftwareApplication,
//      WebPage, FAQPage, BreadcrumbList) from shared content so the FAQ schema
//      cannot drift from the visible answers.
//   3. Inline the built stylesheet into <head> (removes a render-blocking
//      round trip).
//   4. Preload the Inter woff2 that paints the hero headline.
//   5. Add a hash-based CSP. GitHub Pages cannot set response headers, so a
//      meta CSP is the strongest control available; frame-ancestors is included
//      for documentation but is ignored in meta CSP by browsers.
//
// The documentation routes are built separately by scripts/build_docs.mjs.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { FAQ, LAST_UPDATED } from "../lib/content.mjs";
import {
  AUTHOR_NAME,
  AUTHOR_PATH,
  AUTHOR_URL,
  BASE,
  GITHUB_USER_URL,
  REPO_URL,
  RELEASE_URL,
  SITE_NAME,
  SITE_URL,
  UPDATED,
  abs,
} from "../lib/site.mjs";

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distDir = path.join(siteRoot, "dist");
const distIndex = path.join(distDir, "index.html");
const serverEntry = path.join(siteRoot, "dist-server", "entry-server.js");
const marker = "<!--app-html-->";

const ORG_ID = `${SITE_URL}/#organization`;
const PERSON_ID = `${AUTHOR_URL}#person`;
const WEBSITE_ID = `${SITE_URL}/#website`;
const SOFTWARE_ID = `${SITE_URL}/#software`;
const WEBPAGE_ID = `${SITE_URL}/#webpage`;
const FAQ_ID = `${SITE_URL}/#faq`;

function sha256Inline(value) {
  // HTML normalizes CRLF to LF before the script is handed to the CSP check;
  // hash the same bytes the browser hashes or every Windows checkout fails.
  const normalized = value.replace(/\r\n?/g, "\n");
  return `'sha256-${createHash("sha256").update(normalized, "utf8").digest("base64")}'`;
}

function siteGraph() {
  const image = {
    "@type": "ImageObject",
    url: abs("og/landing.png"),
    width: 1200,
    height: 630,
  };
  const organization = {
    "@type": "Organization",
    "@id": ORG_ID,
    name: SITE_NAME,
    url: abs(""),
    logo: {
      "@type": "ImageObject",
      url: abs("android-chrome-512.png"),
      width: 512,
      height: 512,
    },
    description:
      "RedFall builds execution-verified vulnerability scanning and verified repair for TypeScript, JavaScript and Python.",
    sameAs: [GITHUB_USER_URL],
  };
  const person = {
    "@type": "Person",
    "@id": PERSON_ID,
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
    "@id": WEBSITE_ID,
    url: abs(""),
    name: SITE_NAME,
    description:
      "Execution-verified vulnerability scanning for TypeScript, JavaScript and Python. Every finding reproduces in a gVisor sandbox.",
    publisher: { "@id": ORG_ID },
    inLanguage: "en",
  };
  const software = {
    "@type": "SoftwareApplication",
    "@id": SOFTWARE_ID,
    name: SITE_NAME,
    url: abs(""),
    description:
      "Execution-verified vulnerability scanner for TypeScript, JavaScript and Python. tree-sitter ingestion, source-to-sink taint analysis, exploit verification in a Docker + gVisor sandbox, verified repair and SARIF 2.1.0 export.",
    applicationCategory: "SecurityApplication",
    applicationSubCategory: "Vulnerability scanner",
    operatingSystem: "Windows, Linux, macOS",
    softwareVersion: "0.1.0",
    programmingLanguage: "Python",
    codeRepository: REPO_URL,
    downloadUrl: RELEASE_URL,
    releaseNotes: `${REPO_URL}/blob/main/CHANGELOG.md`,
    softwareHelp: `${abs("docs/")}`,
    installUrl: `${abs("docs/install/")}`,
    author: { "@id": PERSON_ID },
    maintainer: { "@id": PERSON_ID },
    publisher: { "@id": ORG_ID },
    screenshot: image,
    featureList: [
      "Execution-verified findings",
      "Taint analysis with an interprocedural pass and return flow",
      "Seven adaptive runtime-surface detectors",
      "Exploit chaining over reproduced findings",
      "Verified repair against the target's own tests",
      "SARIF 2.1.0 with a verified flag on every result",
    ],
    softwareRequirements:
      "Python 3.12+; Docker with the gVisor runsc runtime, PostgreSQL and an LLM provider key for a full scan",
    datePublished: "2026-10-18",
    dateModified: "2026-10-18",
  };
  const webpage = {
    "@type": "WebPage",
    "@id": WEBPAGE_ID,
    url: abs(""),
    name: "RedFall — Execution-Verified Vulnerability Scanner",
    description:
      "RedFall proves vulnerability findings by executing them: real taint analysis, a gVisor sandbox, verified fixes and SARIF 2.1.0.",
    isPartOf: { "@id": WEBSITE_ID },
    about: { "@id": SOFTWARE_ID },
    primaryImageOfPage: image,
    author: { "@id": PERSON_ID },
    publisher: { "@id": ORG_ID },
    datePublished: "2026-10-19",
    dateModified: UPDATED,
    inLanguage: "en",
    breadcrumb: { "@id": `${SITE_URL}/#breadcrumb` },
  };
  const faq = {
    "@type": "FAQPage",
    "@id": FAQ_ID,
    url: abs(""),
    name: "RedFall frequently asked questions",
    isPartOf: { "@id": WEBSITE_ID },
    mainEntity: FAQ.map(({ q, a }) => ({
      "@type": "Question",
      name: q,
      acceptedAnswer: { "@type": "Answer", text: a },
    })),
    dateModified: UPDATED,
  };
  const breadcrumb = {
    "@type": "BreadcrumbList",
    "@id": `${SITE_URL}/#breadcrumb`,
    itemListElement: [
      {
        "@type": "ListItem",
        position: 1,
        name: "Home",
        item: abs(""),
      },
    ],
  };
  return {
    "@context": "https://schema.org",
    "@graph": [organization, person, website, software, webpage, faq, breadcrumb],
  };
}

function injectCsp(template) {
  const inlineScripts = [
    ...template.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g),
  ].map((match) => match[1]);
  const hashes = [...new Set(inlineScripts.map(sha256Inline))];
  const csp = [
    "default-src 'self'",
    `script-src 'self' ${hashes.join(" ")}`,
    "script-src-attr 'none'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-src 'none'",
    // frame-ancestors is intentionally omitted: browsers ignore it in a meta
    // CSP and log a console error, which breaks the best-practices score. The
    // Pages host cannot send X-Frame-Options or a header CSP; see SECURITY.md.
    "upgrade-insecure-requests",
  ].join("; ");
  const meta = `<meta http-equiv="Content-Security-Policy" content="${csp}">`;
  if (!template.includes("<!--csp-->")) {
    throw new Error("prerender: CSP placeholder not found in index.html");
  }
  return template.replace("<!--csp-->", meta);
}

let template = readFileSync(distIndex, "utf8");
if (!template.includes(marker)) {
  console.error(`prerender: marker ${marker} not found in dist/index.html`);
  process.exit(1);
}
if (!template.includes("<!--jsonld-->")) {
  console.error("prerender: JSON-LD placeholder not found in index.html");
  process.exit(1);
}

const { render } = await import(pathToFileURL(serverEntry).href);
const html = render();
if (!html || html.length < 10_000) {
  console.error(`prerender: rendered HTML is suspiciously small (${html.length} chars)`);
  process.exit(1);
}

template = template.replace(marker, html);

// 1. Inject the shared site graph.
const graph = JSON.stringify(siteGraph()).replace(/</g, "\\u003c").replace(/\u2028|\u2029/g, "");
template = template.replace(
  "<!--jsonld-->",
  `<script type="application/ld+json">${graph}</script>`,
);

// 2. Inline the stylesheet.
const linkRe = /<link rel="stylesheet"[^>]*href="([^"]+\.css)"[^>]*>/g;
const cssHrefs = [...template.matchAll(linkRe)].map((m) => m[1]);
for (const href of cssHrefs) {
  const cssPath = path.join(distDir, href.replace(/^\//, "").replace(/^redfall\//, ""));
  const css = readFileSync(cssPath, "utf8");
  template = template.replace(
    new RegExp(`<link rel="stylesheet"[^>]*href="${href.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"[^>]*>`),
    `<style>${css}</style>`,
  );
}

// 3. Preload the Inter woff2 that paints the hero headline.
const inter = template.match(/\/redfall\/fonts\/inter-latin\.woff2/);
if (inter) {
  const preload = `<link rel="preload" href="${inter[0]}" as="font" type="font/woff2" crossorigin>`;
  template = template.replace("</head>", `  ${preload}\n  </head>`);
}

// 4. Add the hash-based CSP after all inline scripts are in place.
template = injectCsp(template);

// 5. Record what was built so the SEO gate can check the result without
//    re-parsing the React source.
const meta = {
  url: abs(""),
  title: "RedFall — Execution-Verified Vulnerability Scanner",
  description:
    "RedFall proves vulnerability findings by executing them: real taint analysis, a gVisor sandbox, verified fixes and SARIF 2.1.0.",
  lastUpdated: UPDATED,
  lastUpdatedLabel: LAST_UPDATED,
  ogImage: abs("og/landing.png"),
};
const buildDir = path.join(siteRoot, "..", "build");
mkdirSync(buildDir, { recursive: true });
writeFileSync(path.join(buildDir, "landing-meta.json"), JSON.stringify(meta, null, 2));

writeFileSync(distIndex, template);
rmSync(path.join(siteRoot, "dist-server"), { recursive: true, force: true });

const size = Buffer.byteLength(template, "utf8");
console.log(
  `prerender: dist/index.html ${(size / 1024).toFixed(1)} kB — ${html.length.toLocaleString("en-US")} rendered chars, ` +
    `${cssHrefs.length} stylesheet(s) inlined, font preload ${inter ? "added" : "SKIPPED"}, CSP hashes applied`,
);
