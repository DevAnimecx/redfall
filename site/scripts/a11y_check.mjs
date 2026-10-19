// Accessibility gate: inject axe-core into the real page at three widths and
// fail on any violation. Complements the Lighthouse a11y score, which samples
// a narrower rule set.
//
// Usage:  node scripts/a11y_check.mjs [url]

import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import puppeteer from "puppeteer-core";

const require = createRequire(import.meta.url);
const axeSource = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");

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

const chrome = CANDIDATES.find((path) => existsSync(path));
if (!chrome) {
  console.error("a11y check: no Chrome/Chromium found; set CHROME_PATH");
  process.exit(2);
}

const URL = process.argv[2] ?? "https://devanimecx.github.io/redfall/";
const VIEWPORTS = [
  { width: 390, height: 844, label: "phone" },
  { width: 768, height: 1024, label: "tablet" },
  { width: 1280, height: 800, label: "laptop" },
];

const browser = await puppeteer.launch({
  executablePath: chrome,
  headless: true,
  args: ["--no-sandbox", "--disable-gpu"],
});

let failed = false;
try {
  for (const viewport of VIEWPORTS) {
    const page = await browser.newPage();
    await page.setViewport({ width: viewport.width, height: viewport.height });
    await page.goto(URL, { waitUntil: "networkidle0", timeout: 60000 });
    await page.evaluate(axeSource);
    const result = await page.evaluate(async () =>
      axe.run(document, {
        runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
      }),
    );

    const violations = result.violations;
    console.log(
      `${violations.length === 0 ? "PASS" : "FAIL"} axe ${viewport.label} ${viewport.width}px: ${violations.length} violation(s)`,
    );
    for (const v of violations) {
      failed = true;
      console.error(`     [${v.impact}] ${v.id}: ${v.help}`);
      for (const node of v.nodes.slice(0, 3)) {
        console.error(`       ${node.target.join(" ")}`);
      }
    }
    await page.close();
  }
  console.log(failed ? "a11y check: FAIL" : "a11y check: PASS - axe-core clean at all widths");
  if (failed) process.exitCode = 1;
} finally {
  await browser.close();
}
