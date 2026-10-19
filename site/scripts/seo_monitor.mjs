// Live SEO monitor. Run weekly against production, or manually against a
// preview origin. It checks what a crawler actually receives, not what the
// repository says should be there.
//
//   node scripts/seo_monitor.mjs [origin]
//
// Default origin: https://devanimecx.github.io/redfall/
// The sitemap always contains production URLs; `origin` only changes where the
// monitor fetches the bytes (useful for a local preview before deployment).
//
// This monitor does not call Google Search Console, Bing Webmaster Tools or any
// analytics API. Those require account access and are documented as human-only
// tasks in site/SEO.md. It also never reports a ranking, a backlink or an AI
// citation: those cannot be measured from the site alone.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "node-html-parser";

import { INDEXNOW_KEY, SITE_URL, abs } from "../lib/site.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BUILD = path.resolve(HERE, "..", "..", "build");
const FETCH_BASE = `${(process.argv[2] ?? `${SITE_URL}/`).replace(/\/$/, "")}/`;
const errors = [];
const warnings = [];

function fail(message) {
  errors.push(message);
}
function warn(message) {
  warnings.push(message);
}
function norm(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}
function relativeToSite(loc) {
  return loc.startsWith(`${SITE_URL}/`) ? loc.slice(SITE_URL.length + 1) : loc;
}
function fetchUrl(loc) {
  return new URL(relativeToSite(loc), FETCH_BASE).href;
}

async function get(url, method = "GET", timeout = 20_000) {
  const response = await fetch(url, {
    method,
    redirect: "follow",
    headers: { "user-agent": "RedFall-SEO-Monitor/0.1 (+https://github.com/DevAnimecx/redfall)" },
    signal: AbortSignal.timeout(timeout),
  });
  const text = method === "HEAD" ? "" : await response.text();
  return { status: response.status, finalUrl: response.url, headers: response.headers, text };
}

async function checkAsset(url, label) {
  const result = await get(url, "HEAD");
  if (result.status !== 200) fail(`${label}: HTTP ${result.status} (${url})`);
  return result;
}

async function checkPage(loc) {
  const url = fetchUrl(loc);
  const result = await get(url);
  if (result.status !== 200) {
    fail(`${loc}: HTTP ${result.status} at ${url}`);
    return;
  }
  if (result.finalUrl !== url) fail(`${loc}: unexpected redirect to ${result.finalUrl}`);
  const contentType = result.headers.get("content-type") ?? "";
  if (!contentType.includes("text/html")) fail(`${loc}: content-type is ${contentType || "missing"}`);
  if ((result.headers.get("x-robots-tag") ?? "").toLowerCase().includes("noindex")) {
    fail(`${loc}: X-Robots-Tag contains noindex`);
  }
  if (result.text.includes('http-equiv="refresh"')) fail(`${loc}: meta refresh found`);

  const root = parse(result.text, { comment: true });
  const title = norm(root.querySelector("title")?.textContent);
  const description = norm(root.querySelector('meta[name="description"]')?.getAttribute("content"));
  const canonical = root.querySelector('link[rel="canonical"]')?.getAttribute("href") ?? "";
  const robots = norm(root.querySelector('meta[name="robots"]')?.getAttribute("content"));
  const h1 = root.querySelectorAll("h1");
  if (!title) fail(`${loc}: title missing`);
  if (!description) fail(`${loc}: description missing`);
  if (h1.length !== 1) fail(`${loc}: expected one h1, found ${h1.length}`);
  if (canonical !== loc) fail(`${loc}: canonical is ${canonical || "missing"}, expected ${loc}`);
  if (robots.includes("noindex")) fail(`${loc}: meta robots contains noindex`);

  const jsonLd = root.querySelectorAll('script[type="application/ld+json"]');
  if (!jsonLd.length) fail(`${loc}: JSON-LD missing`);
  const graph = [];
  for (const script of jsonLd) {
    try {
      const data = JSON.parse(script.textContent);
      graph.push(...(Array.isArray(data["@graph"]) ? data["@graph"] : [data]));
    } catch (error) {
      fail(`${loc}: invalid JSON-LD (${error.message})`);
    }
  }
  const types = new Set(graph.flatMap((node) => (Array.isArray(node["@type"]) ? node["@type"] : [node["@type"]])));
  for (const type of ["Organization", "WebSite", "BreadcrumbList"]) {
    if (!types.has(type)) fail(`${loc}: JSON-LD missing ${type}`);
  }
  if (loc === `${SITE_URL}/` && !types.has("FAQPage")) fail(`${loc}: FAQPage missing`);
  if (
    loc !== `${SITE_URL}/` &&
    !["TechArticle", "CollectionPage", "AboutPage", "WebPage"].some((type) => types.has(type))
  ) {
    fail(`${loc}: JSON-LD has no page/article type`);
  }

  const ogImage = root.querySelector('meta[property="og:image"]')?.getAttribute("content") ?? "";
  if (!ogImage) fail(`${loc}: og:image missing`);
  else {
    const imageUrl = fetchUrl(ogImage);
    await checkAsset(imageUrl, `${loc}: og:image`);
  }

  if (root.querySelectorAll('a[href^="/redfall/"]').length < 5) fail(`${loc}: too few internal links`);
  if (result.text.includes("[[DOCS_INDEX]]") || result.text.includes("<!--jsonld-->")) {
    fail(`${loc}: unresolved build placeholder`);
  }
}

async function main() {
  fs.mkdirSync(BUILD, { recursive: true });
  const started = new Date().toISOString();
  console.log(`seo monitor: fetching ${FETCH_BASE}`);

  const home = await get(FETCH_BASE);
  if (home.status !== 200) fail(`home: HTTP ${home.status}`);

  const robots = await get(new URL("robots.txt", FETCH_BASE).href);
  if (robots.status !== 200) fail(`robots.txt: HTTP ${robots.status}`);
  else {
    if (!robots.text.includes(`Sitemap: ${abs("sitemap.xml")}`)) fail("robots.txt: sitemap declaration missing");
    if (!robots.text.includes("User-agent: GPTBot")) fail("robots.txt: GPTBot directive missing");
    if (/Disallow:\s*\/\s*$/m.test(robots.text)) fail("robots.txt: whole site disallowed");
  }

  const keyFile = await get(new URL(`${INDEXNOW_KEY}.txt`, FETCH_BASE).href);
  if (keyFile.status !== 200) fail(`IndexNow key: HTTP ${keyFile.status}`);
  else if (keyFile.text.trim() !== INDEXNOW_KEY) fail("IndexNow key file content does not match site constant");

  const sitemap = await get(new URL("sitemap.xml", FETCH_BASE).href);
  if (sitemap.status !== 200) {
    fail(`sitemap.xml: HTTP ${sitemap.status}`);
  } else {
    const locs = [...sitemap.text.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].trim());
    if (locs.length < 20) fail(`sitemap.xml: only ${locs.length} URLs`);
    if (new Set(locs).size !== locs.length) fail("sitemap.xml: duplicate URLs");
    for (const loc of locs) {
      if (!loc.startsWith(`${SITE_URL}/`)) fail(`sitemap.xml: URL outside production origin: ${loc}`);
      await checkPage(loc);
    }
    console.log(`seo monitor: checked ${locs.length} sitemap pages`);
  }

  const llms = await get(new URL("llms.txt", FETCH_BASE).href);
  if (llms.status !== 200) fail(`llms.txt: HTTP ${llms.status}`);
  else {
    if (!llms.text.startsWith("# RedFall")) fail("llms.txt: heading missing");
    for (const route of ["docs/", "docs/verified-findings/", "docs/install/", "evidence/"]) {
      if (!llms.text.includes(abs(route))) fail(`llms.txt: missing ${abs(route)}`);
    }
  }

  const isLocal = ["localhost", "127.0.0.1", "::1"].includes(new URL(FETCH_BASE).hostname);
  if (isLocal) {
    console.log("seo monitor: local preview — 404 status check skipped (Vite preview falls back to index.html)");
  } else {
    const missingUrl = new URL("seo-monitor-missing-page/", FETCH_BASE).href;
    const notFound = await get(missingUrl);
    if (notFound.status !== 404) fail(`404 handling: expected HTTP 404 at ${missingUrl}, got ${notFound.status}`);
    else if (!notFound.text.includes("Page not found")) fail("404 handling: custom Page not found content missing");
  }

  const report = {
    started,
    finished: new Date().toISOString(),
    fetchBase: FETCH_BASE,
    errors,
    warnings,
  };
  fs.writeFileSync(path.join(BUILD, "seo-monitor-report.json"), JSON.stringify(report, null, 2), "utf8");
  for (const warning of warnings) console.warn(`WARN ${warning}`);
  if (errors.length) {
    for (const error of errors) console.error(`FAIL ${error}`);
    console.error(`seo monitor: FAIL (${errors.length} error(s))`);
    process.exit(1);
  }
  console.log("seo monitor: PASS");
}

await main();
