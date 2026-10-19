// Lighthouse gate for the production build. Runs the real page in Chrome at
// desktop and mobile presets and fails if any category drops below 95.
//
//   node scripts/lighthouse_check.mjs [url]
//
// The site is prerendered, so run this against `vite preview` (or the live
// Pages URL), never the dev server. Reports are written to build/.
//
// Lighthouse 13 is used directly. @lhci/cli was rejected because its dependency
// tree carried 17 npm advisories; this keeps `npm audit` at zero.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import lighthouse from "lighthouse";
import * as chromeLauncher from "chrome-launcher";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BUILD = path.resolve(HERE, "..", "..", "build");
const URL = process.argv[2] ?? "http://localhost:4173/redfall/";
const MIN = Number(process.env.LIGHTHOUSE_MIN ?? 95);
const CATEGORIES = ["performance", "accessibility", "best-practices", "seo"];

fs.mkdirSync(BUILD, { recursive: true });

const chrome = await chromeLauncher.launch({
  chromeFlags: ["--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
});

const profiles = [
  {
    name: "desktop",
    flags: {
      formFactor: "desktop",
      screenEmulation: {
        mobile: false,
        width: 1350,
        height: 940,
        deviceScaleFactor: 1,
        disabled: false,
      },
      throttling: {
        rttMs: 40,
        throughputKbps: 10 * 1024,
        cpuSlowdownMultiplier: 1,
        requestLatencyMs: 0,
        downloadThroughputKbps: 0,
        uploadThroughputKbps: 0,
      },
    },
  },
  { name: "mobile", flags: {} },
];

let failed = false;
const summary = { url: URL, min: MIN, runs: {} };

try {
  for (const profile of profiles) {
    const result = await lighthouse(URL, {
      port: chrome.port,
      output: "json",
      logLevel: "error",
      onlyCategories: CATEGORIES,
      ...profile.flags,
    });
    if (!result || !result.lhr) throw new Error("lighthouse returned no report");

    const { lhr } = result;
    const scores = Object.fromEntries(
      CATEGORIES.map((category) => [category, Math.round((lhr.categories[category]?.score ?? 0) * 100)]),
    );
    const audits = {
      lcp: lhr.audits["largest-contentful-paint"]?.displayValue ?? null,
      cls: lhr.audits["cumulative-layout-shift"]?.displayValue ?? null,
      tbt: lhr.audits["total-blocking-time"]?.displayValue ?? null,
      fcp: lhr.audits["first-contentful-paint"]?.displayValue ?? null,
      speedIndex: lhr.audits["speed-index"]?.displayValue ?? null,
    };
    const line = CATEGORIES.map((category) => `${category} ${scores[category]}`).join(" · ");
    console.log(`${profile.name.padEnd(7)} ${line}`);
    console.log(
      `        LCP ${audits.lcp} · CLS ${audits.cls} · TBT ${audits.tbt} · FCP ${audits.fcp} · SI ${audits.speedIndex}`,
    );

    for (const category of CATEGORIES) {
      if (scores[category] < MIN) {
        failed = true;
        console.error(`FAIL ${profile.name}: ${category} ${scores[category]} < ${MIN}`);
      }
    }
    if (lhr.runtimeError) {
      failed = true;
      console.error(`FAIL ${profile.name}: ${lhr.runtimeError.code} ${lhr.runtimeError.message}`);
    }

    summary.runs[profile.name] = { scores, audits, runtimeError: lhr.runtimeError ?? null };
    const reportPath = path.join(BUILD, `lighthouse-${profile.name}.json`);
    fs.writeFileSync(reportPath, result.report, "utf8");
    console.log(`        report -> ${reportPath}`);
  }
} finally {
  await chrome.kill();
}

fs.writeFileSync(path.join(BUILD, "lighthouse-summary.json"), JSON.stringify(summary, null, 2), "utf8");
if (failed) {
  console.error(`lighthouse check: FAIL (minimum ${MIN})`);
  process.exit(1);
}
console.log(`lighthouse check: PASS (all categories >= ${MIN})`);
