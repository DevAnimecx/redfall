// Documentation gate: axe + layout + console-error checks on every generated
// documentation/trust route at phone and laptop widths.
//
//   node scripts/docs_check.mjs [origin]
//
// The origin must include the base path, e.g.
//   http://localhost:4173/redfall/
//
// Docs are static HTML with zero React JS. This gate proves the static pages
// are accessible and that the hash-based CSP does not block their JSON-LD.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer-core";

const require = createRequire(import.meta.url);
const axeSource = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const HERE = path.dirname(fileURLToPath(import.meta.url));
const BUILD = path.resolve(HERE, "..", "..", "build");

const CANDIDATES = [
  process.env.CHROME_PATH,
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
].filter(Boolean);

const chrome = CANDIDATES.find((candidate) => existsSync(candidate));
if (!chrome) {
  console.error("docs check: no Chrome/Chromium found; set CHROME_PATH");
  process.exit(2);
}

const origin = new URL(process.argv[2] ?? "http://localhost:4173/redfall/");
const manifestPath = path.join(BUILD, "docs-manifest.json");
if (!existsSync(manifestPath)) {
  console.error("docs check: build/docs-manifest.json is missing; run npm run build");
  process.exit(2);
}
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const routes = [...new Set(manifest.map((page) => page.path))];

const VIEWPORTS = [
  { label: "phone", width: 390, height: 844, isMobile: true, hasTouch: true, deviceScaleFactor: 2 },
  { label: "laptop", width: 1280, height: 800, isMobile: false, hasTouch: false, deviceScaleFactor: 1 },
];

const browser = await puppeteer.launch({
  executablePath: chrome,
  headless: true,
  args: ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
});

let failed = false;
const results = [];
try {
  for (const route of routes) {
    const url = new URL(route, origin).href;
    for (const viewport of VIEWPORTS) {
      const { label, ...emulation } = viewport;
      const page = await browser.newPage();
      await page.setViewport(emulation);
      const consoleErrors = [];
      const requestFailures = [];
      page.on("console", (message) => {
        if (message.type() === "error") consoleErrors.push(message.text());
      });
      page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${error.message}`));
      page.on("requestfailed", (request) =>
        requestFailures.push(`${request.url()} — ${request.failure()?.errorText ?? "request failed"}`),
      );

      try {
        const response = await page.goto(url, { waitUntil: "networkidle0", timeout: 60000 });
        const status = response?.status() ?? 0;
        if (!response || (status >= 400 && status !== 304)) {
          failed = true;
          console.error(`FAIL ${route} ${label}: HTTP ${status || "no response"}`);
          results.push({ route, viewport: label, status, errors: ["HTTP"] });
          continue;
        }

        await page.evaluate(axeSource);
        const axe = await page.evaluate(async () =>
          axe.run(document, {
            runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
          }),
        );
        const metrics = await page.evaluate(() => {
          const doc = document.documentElement;
          return {
            width: doc.clientWidth,
            scrollWidth: doc.scrollWidth,
            overflow: Math.max(0, doc.scrollWidth - doc.clientWidth),
            h1: document.querySelectorAll("h1").length,
            scripts: [...document.querySelectorAll("script[src]")].map((script) => script.src),
            title: document.title,
          };
        });

        const violations = axe.violations.map((violation) => ({
          id: violation.id,
          impact: violation.impact,
          nodes: violation.nodes.map((node) => node.target.join(" ")),
        }));
        const pageErrors = [
          ...consoleErrors,
          ...requestFailures,
          ...(metrics.overflow > 0 ? [`horizontal overflow ${metrics.overflow}px`] : []),
          ...(metrics.h1 !== 1 ? [`expected one h1, found ${metrics.h1}`] : []),
          ...(metrics.scripts.length ? [`client scripts loaded: ${metrics.scripts.join(", ")}`] : []),
        ];
        const ok = violations.length === 0 && pageErrors.length === 0;
        if (!ok) failed = true;
        console.log(
          `${ok ? "PASS" : "FAIL"} ${route.padEnd(32)} ${label.padEnd(6)} axe=${violations.length} overflow=${metrics.overflow}px h1=${metrics.h1}`,
        );
        for (const violation of violations) {
          console.error(
            `     [${violation.impact}] ${violation.id}: ${violation.nodes.slice(0, 3).join(" | ")}`,
          );
        }
        for (const error of pageErrors) console.error(`     ${error}`);
        results.push({ route, viewport: label, status: 200, violations, pageErrors });
      } catch (error) {
        failed = true;
        console.error(`FAIL ${route} ${label}: ${error.message}`);
        results.push({ route, viewport: label, error: error.message });
      } finally {
        await page.close();
      }
    }
  }

  // Prove the docs do not depend on JavaScript to expose their content.
  const noJs = await browser.newPage();
  await noJs.setJavaScriptEnabled(false);
  await noJs.goto(new URL("docs/verified-findings/", origin).href, { waitUntil: "networkidle0", timeout: 60000 });
  const noJsTitle = await noJs.evaluate(() => document.querySelector("h1")?.textContent?.trim() ?? "");
  if (!noJsTitle) {
    failed = true;
    console.error("FAIL docs/verified-findings/: h1 is not readable with JavaScript disabled");
  } else {
    console.log(`PASS no-JS render: ${noJsTitle}`);
  }
  await noJs.close();
} finally {
  await browser.close();
}

writeFileSync(path.join(BUILD, "docs-check.json"), JSON.stringify(results, null, 2), "utf8");
if (failed) {
  console.error("docs check: FAIL");
  process.exit(1);
}
console.log(`docs check: PASS - ${routes.length} routes × ${VIEWPORTS.length} viewports, axe clean, no overflow, zero client JS`);
