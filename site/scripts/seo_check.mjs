// Technical SEO gate for the generated RedFall site.
//
// Run after `npm run build` (which writes dist/ and the docs pages):
//   node scripts/seo_check.mjs
//
// The gate treats the built output as the source of truth. It checks metadata,
// structure, structured data, internal links, anchors, sitemap/robots/llms.txt,
// social-image existence and the "no React on docs" rule. It writes a JSON
// report to build/seo-report.json and exits non-zero on any error.
//
// This is deliberately stricter than a typical SEO plugin: a link to a route
// that does not exist, a canonical that disagrees with the sitemap, or a FAQ
// answer that drifted from its JSON-LD is a build failure.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "node-html-parser";

import { BASE, INDEXNOW_KEY, SITE_URL, abs } from "../lib/site.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SITE_ROOT = path.resolve(HERE, "..");
const DIST = path.join(SITE_ROOT, "dist");
const REPO_ROOT = path.resolve(SITE_ROOT, "..");
const BUILD = path.join(REPO_ROOT, "build");
const SITE_ORIGIN = SITE_URL;
const INTERNAL_PREFIXES = [SITE_URL, BASE];

const errors = [];
const warnings = [];
const pages = new Map();
const routes = new Set();

function fail(message) {
  errors.push(message);
}
function warn(message) {
  warnings.push(message);
}
function norm(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}
function textOf(node) {
  return norm(node?.textContent ?? "");
}

function findHtmlFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...findHtmlFiles(full));
    else if (entry.isFile() && entry.name === "index.html") out.push(full);
  }
  return out;
}

function routeForFile(file) {
  const rel = path.relative(DIST, file).replaceAll("\\", "/");
  if (rel === "index.html") return "/";
  if (rel === "404.html") return "/404.html";
  return `/${rel.replace(/\/index\.html$/, "/")}`;
}

function fileForRoute(route) {
  const clean = route.replace(SITE_URL, "").replace(BASE, "/");
  if (clean === "/" || clean === "") return path.join(DIST, "index.html");
  if (clean === "/404.html") return path.join(DIST, "404.html");
  if (clean.endsWith("/")) return path.join(DIST, clean.slice(1), "index.html");
  const direct = path.join(DIST, clean.slice(1));
  if (fs.existsSync(direct) && fs.statSync(direct).isFile()) return direct;
  if (fs.existsSync(path.join(direct, "index.html"))) return path.join(direct, "index.html");
  return null;
}

function meta(root, selector) {
  return norm(root.querySelector(selector)?.getAttribute("content") ?? "");
}

function isInternal(href) {
  return INTERNAL_PREFIXES.some((prefix) => href === prefix || href.startsWith(prefix)) || href.startsWith("/redfall/") || href === "/redfall";
}

function localRoute(href) {
  if (href.startsWith(SITE_URL)) return href.slice(SITE_URL.length) || "/";
  if (href.startsWith(BASE)) return href.slice(BASE.length - 1);
  if (href === "/redfall") return "/";
  return null;
}

function checkAnchor(targetFile, anchor, sourceRoute, href) {
  if (!anchor) return;
  if (!targetFile) return;
  const target = pages.get(targetFile);
  if (!target) return;
  if (!target.root.querySelector(`#${cssEscape(anchor)}`)) {
    fail(`${sourceRoute}: link ${href} points to missing anchor #${anchor}`);
  }
}

function cssEscape(value) {
  return value.replace(/[^a-zA-Z0-9_-]/g, "\\$&");
}

function collectJsonLd(root, route) {
  const scripts = root.querySelectorAll('script[type="application/ld+json"]');
  const graphs = [];
  for (const script of scripts) {
    try {
      const data = JSON.parse(script.textContent);
      if (Array.isArray(data["@graph"])) graphs.push(...data["@graph"]);
      else graphs.push(data);
    } catch (error) {
      fail(`${route}: invalid JSON-LD (${error.message})`);
    }
  }
  return graphs;
}

function typesOf(graph) {
  return new Set(graph.flatMap((node) => (Array.isArray(node["@type"]) ? node["@type"] : [node["@type"]])));
}

function checkFaq(graph, root, route) {
  const faq = graph.find((node) => node["@type"] === "FAQPage");
  if (!faq) return;
  if (!Array.isArray(faq.mainEntity) || faq.mainEntity.length < 3) {
    fail(`${route}: FAQPage must contain at least three questions`);
    return;
  }
  const visible = textOf(root.querySelector("main") ?? root);
  for (const question of faq.mainEntity) {
    const q = norm(question.name);
    if (!q) {
      fail(`${route}: FAQPage question has no name`);
      continue;
    }
    if (!root.querySelectorAll("h3").some((node) => textOf(node) === q)) {
      fail(`${route}: FAQPage question is not visible as an h3: ${q}`);
    }
    const answer = norm(question.acceptedAnswer?.text);
    if (!answer) {
      fail(`${route}: FAQPage question has no answer: ${q}`);
    } else if (!visible.includes(answer.slice(0, 80))) {
      fail(`${route}: FAQPage answer does not match visible text: ${q}`);
    }
  }
}

function checkStructuredData(graph, route, isLanding, is404) {
  if (is404) return;
  const types = typesOf(graph);
  const required = ["Organization", "Person", "WebSite", "BreadcrumbList"];
  for (const type of required) {
    if (!types.has(type)) fail(`${route}: JSON-LD is missing ${type}`);
  }
  if (isLanding) {
    for (const type of ["SoftwareApplication", "WebPage", "FAQPage"]) {
      if (!types.has(type)) fail(`${route}: JSON-LD is missing ${type}`);
    }
    const software = graph.find((node) => node["@type"] === "SoftwareApplication");
    if (software) {
      if (software.softwareVersion !== "0.1.0") fail(`${route}: SoftwareApplication version is not 0.1.0`);
      if (!software.codeRepository) fail(`${route}: SoftwareApplication has no codeRepository`);
      if (!software.author) fail(`${route}: SoftwareApplication has no author`);
      if (!software.dateModified) fail(`${route}: SoftwareApplication has no dateModified`);
    }
  } else {
    const article = graph.find((node) => ["TechArticle", "CollectionPage", "AboutPage", "WebPage"].includes(node["@type"]));
    if (!article) fail(`${route}: JSON-LD has no page/article node`);
    else {
      if (!article.dateModified) fail(`${route}: article node has no dateModified`);
      if (!article.author) fail(`${route}: article node has no author`);
      if (!article.isPartOf) fail(`${route}: article node has no isPartOf`);
      if (article["@type"] === "TechArticle" && !article.articleSection) {
        fail(`${route}: TechArticle has no articleSection`);
      }
    }
  }
}

function checkPage(route, root, isLanding) {
  const html = root.querySelector("html");
  const is404 = route === "/404.html";
  const title = textOf(root.querySelector("title"));
  const description = meta(root, 'meta[name="description"]');
  const canonical = root.querySelector('link[rel="canonical"]')?.getAttribute("href") ?? "";
  const robots = meta(root, 'meta[name="robots"]');
  const h1 = root.querySelectorAll("h1");
  const headings = root.querySelectorAll("h1, h2, h3, h4, h5, h6");
  const anchors = root.querySelectorAll("a[href]");
  const bodyText = textOf(root.querySelector("main") ?? root);
  const words = bodyText.split(/\s+/).filter(Boolean).length;
  const domNodes = root.querySelectorAll("*").length;

  if (!html || html.getAttribute("lang") !== "en") fail(`${route}: <html lang="en"> is missing`);
  if (!meta(root, 'meta[name="viewport"]')) fail(`${route}: viewport meta is missing`);
  if (!meta(root, 'meta[name="author"]')) fail(`${route}: author meta is missing`);
  if (!title) fail(`${route}: title is missing`);
  else if (title.length < 12 || title.length > 68) {
    fail(`${route}: title length ${title.length} is outside 12–68: ${title}`);
  }
  if (!description) fail(`${route}: meta description is missing`);
  else if (description.length < 50 || description.length > 170) {
    fail(`${route}: description length ${description.length} is outside 50–170`);
  }
  if (h1.length !== 1) fail(`${route}: expected exactly one h1, found ${h1.length}`);
  if (!textOf(h1[0])) fail(`${route}: h1 is empty`);
  if (domNodes > 1400) fail(`${route}: DOM has ${domNodes} nodes, above the 1400-node budget`);

  // Heading order: no skipped level and no duplicate h1.
  let previous = 0;
  for (const heading of headings) {
    const level = Number(heading.tagName.slice(1));
    if (previous && level > previous + 1) {
      fail(`${route}: heading jumps from h${previous} to h${level}: ${textOf(heading)}`);
    }
    previous = level;
  }

  if (is404) {
    if (!robots.includes("noindex")) fail(`${route}: 404 must be noindex`);
    if (canonical) fail(`${route}: 404 must not declare a canonical URL`);
  } else {
    if (!canonical) fail(`${route}: canonical is missing`);
    const expectedCanonical = abs(route.replace(/^\//, ""));
    if (canonical && canonical !== expectedCanonical) {
      fail(`${route}: canonical ${canonical} does not equal ${expectedCanonical}`);
    }
    for (const lang of ["en", "x-default"]) {
      const alternate = root
        .querySelectorAll('link[rel="alternate"][hreflang]')
        .find((node) => node.getAttribute("hreflang") === lang);
      if (!alternate) fail(`${route}: hreflang ${lang} is missing`);
      else if (alternate.getAttribute("href") !== expectedCanonical) {
        fail(`${route}: hreflang ${lang} does not point to the canonical URL`);
      }
    }
    if (meta(root, 'meta[property="og:url"]') !== expectedCanonical) {
      fail(`${route}: og:url does not equal the canonical URL`);
    }
    if (robots.includes("noindex")) fail(`${route}: indexable page is marked noindex`);
    if (!meta(root, 'meta[property="og:image"]')) fail(`${route}: og:image is missing`);
    if (!meta(root, 'meta[name="twitter:card"]')) fail(`${route}: twitter:card is missing`);
    if (!meta(root, 'meta[property="og:image:alt"]')) fail(`${route}: og:image:alt is missing`);
  }

  if (!is404 && words < (isLanding ? 700 : 350)) {
    fail(`${route}: only ${words} words of main content`);
  }
  if (anchors.length < (isLanding ? 20 : 20)) {
    fail(`${route}: only ${anchors.length} links; internal linking budget is 20`);
  }

  // No placeholder tokens or unresolved template markers.
  const raw = root.toString();
  for (const token of ["[[DOCS_INDEX]]", "<!--app-html-->", "<!--jsonld-->", "<!--csp-->", "%BASE_URL%", "TODO", "lorem ipsum"]) {
    if (raw.includes(token)) fail(`${route}: unresolved token ${token}`);
  }

  // Docs must ship no application JavaScript.
  if (!isLanding && !is404) {
    if (root.querySelectorAll("script[src]").length) fail(`${route}: documentation must not load client JavaScript`);
    if (root.querySelectorAll('link[rel="stylesheet"]').length !== 1) {
      fail(`${route}: documentation must link exactly one stylesheet`);
    }
    if (!root.querySelector('link[rel="author"]')) fail(`${route}: rel=author link is missing`);
    if (!root.querySelector("time[datetime]")) fail(`${route}: visible date without <time datetime>`);
    if (!bodyText.includes("Last updated")) fail(`${route}: visible last-updated date is missing`);
  }

  // Images need alt text.
  for (const image of root.querySelectorAll("img")) {
    if (image.getAttribute("alt") === undefined) fail(`${route}: image without alt: ${image.getAttribute("src")}`);
  }

  // Duplicate IDs break fragment links and anchor semantics.
  const ids = new Map();
  for (const node of root.querySelectorAll("[id]")) {
    const id = node.getAttribute("id");
    if (!id) continue;
    if (ids.has(id)) fail(`${route}: duplicate id #${id}`);
    ids.set(id, true);
  }

  // Internal links and anchors.
  for (const anchor of anchors) {
    const href = anchor.getAttribute("href") ?? "";
    if (!href) {
      fail(`${route}: empty link`);
      continue;
    }
    if (href.startsWith("#")) {
      checkAnchor(fileForRoute(route) ?? path.join(DIST, "index.html"), href.slice(1), route, href);
      continue;
    }
    if (href.startsWith("mailto:") || href.startsWith("tel:")) continue;
    if (isInternal(href)) {
      const withoutHash = href.split("#")[0].split("?")[0];
      const targetRoute = localRoute(withoutHash);
      if (targetRoute === null) {
        fail(`${route}: internal link is outside the site base: ${href}`);
        continue;
      }
      const cleanRoute = targetRoute === "" ? "/" : targetRoute;
      const targetFile = fileForRoute(cleanRoute);
      if (!targetFile) {
        fail(`${route}: broken internal link ${href}`);
        continue;
      }
      const hash = href.split("#")[1];
      checkAnchor(targetFile, hash, route, href);
    } else if (!/^https:\/\//.test(href)) {
      fail(`${route}: insecure or relative external link ${href}`);
    }
  }

  // Social image must exist locally.
  const ogImage = meta(root, 'meta[property="og:image"]');
  if (ogImage && isInternal(ogImage)) {
    const imageRoute = localRoute(ogImage);
    const imageFile = imageRoute ? fileForRoute(imageRoute) : null;
    if (!imageFile) fail(`${route}: og:image does not resolve to a built file: ${ogImage}`);
  } else if (ogImage && !ogImage.startsWith(SITE_URL)) {
    fail(`${route}: og:image is not absolute: ${ogImage}`);
  }

  // JSON-LD is required on every indexable page.
  const graph = collectJsonLd(root, route);
  if (!is404 && graph.length === 0) fail(`${route}: no JSON-LD graph`);
  checkStructuredData(graph, route, isLanding, is404);
  checkFaq(graph, root, route);

  pages.set(path.join(DIST, route === "/" ? "index.html" : route === "/404.html" ? "404.html" : `${route.slice(1)}index.html`), {
    route,
    root,
    title,
    description,
    canonical,
    words,
    domNodes,
    graph,
  });
  routes.add(route);
  return { route, title, description, words, domNodes, links: anchors.length };
}

function checkSitemap(expectedRoutes) {
  const file = path.join(DIST, "sitemap.xml");
  if (!fs.existsSync(file)) {
    fail("sitemap.xml is missing");
    return;
  }
  const xml = fs.readFileSync(file, "utf8");
  const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].trim());
  const unique = new Set(locs);
  if (unique.size !== locs.length) fail("sitemap.xml contains duplicate URLs");
  const expected = new Set([...expectedRoutes].filter((route) => route !== "/404.html").map((route) => abs(route.replace(/^\//, ""))));
  for (const loc of locs) {
    if (!expected.has(loc)) fail(`sitemap.xml contains an unexpected URL: ${loc}`);
    if (!loc.startsWith(SITE_URL)) fail(`sitemap URL is not absolute: ${loc}`);
    if (!loc.endsWith("/")) fail(`sitemap URL must be a directory URL: ${loc}`);
  }
  for (const loc of expected) {
    if (!unique.has(loc)) fail(`sitemap.xml is missing ${loc}`);
  }
  const lastmods = [...xml.matchAll(/<lastmod>([^<]+)<\/lastmod>/g)].map((match) => match[1]);
  if (!lastmods.length) fail("sitemap.xml has no lastmod values");
  for (const lastmod of lastmods) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(lastmod)) fail(`sitemap lastmod is not ISO date: ${lastmod}`);
  }
  return { urls: locs.length };
}

function checkRobots() {
  const file = path.join(DIST, "robots.txt");
  if (!fs.existsSync(file)) {
    fail("robots.txt is missing");
    return {};
  }
  const text = fs.readFileSync(file, "utf8");
  if (!text.includes(`Sitemap: ${abs("sitemap.xml")}`)) fail("robots.txt does not declare the sitemap");
  if (!text.includes("User-agent: GPTBot") || !text.includes("User-agent: ClaudeBot")) {
    fail("robots.txt does not allow the documented AI crawlers");
  }
  if (/Disallow:\s*\/\s*$/m.test(text)) fail("robots.txt disallows the whole site");
  return { bytes: fs.statSync(file).size };
}

function checkLlms(expectedRoutes) {
  const file = path.join(DIST, "llms.txt");
  if (!fs.existsSync(file)) {
    fail("llms.txt is missing");
    return {};
  }
  const text = fs.readFileSync(file, "utf8");
  if (!text.startsWith("# RedFall")) fail("llms.txt does not start with the site name");
  for (const route of expectedRoutes) {
    if (route === "/404.html") continue;
    const url = abs(route.replace(/^\//, ""));
    if (!text.includes(url)) fail(`llms.txt does not link ${url}`);
  }
  if (text.includes("[[") || text.includes("TODO")) fail("llms.txt contains an unresolved placeholder");

  // The repository-root copy is what GitHub crawlers and humans see outside
  // the Pages build. It must be byte-for-byte the served file.
  const rootFile = path.join(REPO_ROOT, "llms.txt");
  if (!fs.existsSync(rootFile)) {
    fail("repository-root llms.txt is missing");
  } else {
    const rootText = fs.readFileSync(rootFile, "utf8");
    if (rootText.replace(/\r\n?/g, "\n") !== text.replace(/\r\n?/g, "\n")) {
      fail("repository-root llms.txt is stale; copy site/dist/llms.txt to llms.txt");
    }
  }
  return { bytes: fs.statSync(file).size };
}

function checkIndexNow() {
  const file = path.join(DIST, `${INDEXNOW_KEY}.txt`);
  if (!fs.existsSync(file)) {
    fail(`IndexNow key file ${INDEXNOW_KEY}.txt is missing from dist`);
    return {};
  }
  const value = fs.readFileSync(file, "utf8").trim();
  if (value !== INDEXNOW_KEY) fail("IndexNow key file does not match site/lib/site.mjs");
  return { key: INDEXNOW_KEY };
}

function checkManifest() {
  const file = path.join(BUILD, "docs-manifest.json");
  if (!fs.existsSync(file)) {
    fail("build/docs-manifest.json is missing; did build_docs.mjs run?");
    return {};
  }
  const manifest = JSON.parse(fs.readFileSync(file, "utf8"));
  if (manifest.length !== 22) fail(`docs manifest has ${manifest.length} pages, expected 22`);
  const ids = new Set(manifest.map((page) => page.id));
  if (ids.size !== manifest.length) fail("docs manifest contains duplicate IDs");
  return { pages: manifest.length };
}

function main() {
  if (!fs.existsSync(DIST)) {
    console.error("seo: dist/ is missing; run `npm run build` first");
    process.exit(1);
  }
  fs.mkdirSync(BUILD, { recursive: true });

  const files = [...findHtmlFiles(DIST), path.join(DIST, "404.html")].filter((file) => fs.existsSync(file));
  const metrics = [];
  for (const file of files) {
    const route = routeForFile(file);
    const html = fs.readFileSync(file, "utf8");
    const root = parse(html, { comment: true });
    pages.set(file, { route, root });
    metrics.push(checkPage(route, root, route === "/"));
  }

  // Re-check anchors now that every page is parsed and in the map.
  for (const file of files) {
    const route = routeForFile(file);
    const root = pages.get(file).root;
    for (const anchor of root.querySelectorAll("a[href]")) {
      const href = anchor.getAttribute("href") ?? "";
      if (!href || href.startsWith("#") || !isInternal(href)) continue;
      const targetRoute = localRoute(href.split("#")[0].split("?")[0]);
      const targetFile = targetRoute === null ? null : fileForRoute(targetRoute || "/");
      checkAnchor(targetFile, href.split("#")[1], route, href);
    }
  }

  const sitemap = checkSitemap(routes);
  const robots = checkRobots();
  const llms = checkLlms(routes);
  const indexnow = checkIndexNow();
  const manifest = checkManifest();

  const report = {
    generatedAt: new Date().toISOString(),
    site: SITE_URL,
    pages: metrics,
    sitemap,
    robots,
    llms,
    indexnow,
    manifest,
    errors,
    warnings,
  };
  fs.writeFileSync(path.join(BUILD, "seo-report.json"), JSON.stringify(report, null, 2), "utf8");

  const titleCounts = new Map();
  const descCounts = new Map();
  for (const page of metrics) {
    titleCounts.set(page.title, (titleCounts.get(page.title) ?? 0) + 1);
    descCounts.set(page.description, (descCounts.get(page.description) ?? 0) + 1);
  }
  for (const [title, count] of titleCounts) if (count > 1) fail(`duplicate title (${count}): ${title}`);
  for (const [description, count] of descCounts) if (count > 1) fail(`duplicate description (${count}): ${description}`);

  console.log(`SEO: ${metrics.length} HTML routes checked; ${sitemap.urls ?? 0} sitemap URLs; ${errors.length} error(s)`);
  for (const page of metrics) {
    console.log(
      `  ${page.route.padEnd(38)} ${String(page.words).padStart(4)} words  ${String(page.links).padStart(2)} links  ${String(page.domNodes).padStart(4)} DOM`,
    );
  }
  for (const warning of warnings) console.warn(`WARN ${warning}`);
  if (errors.length) {
    for (const error of errors) console.error(`FAIL ${error}`);
    process.exit(1);
  }
  console.log("SEO GATE: PASS");
}

main();
