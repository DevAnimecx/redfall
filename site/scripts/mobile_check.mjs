// Layout gate: emulate real viewports and fail if the document is wider than
// the viewport (horizontal scrolling) or an unclipped element overflows it.
// Lighthouse's "viewport" audit only checks the meta tag, so this catches
// layout regressions it misses.
//
// Usage:  node scripts/mobile_check.mjs [url] [screenshot-path]
// Chrome: CHROME_PATH, or a known Windows/macOS/Linux install location.

import { existsSync } from "node:fs";
import puppeteer from "puppeteer-core";

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
  console.error("layout check: no Chrome/Chromium found; set CHROME_PATH");
  process.exit(2);
}

const URL = process.argv[2] ?? "https://devanimecx.github.io/redfall/";
const OUT = process.argv[3] ?? null;

// iPhone 12 width, iPad portrait, and a small laptop. 390 is the narrowest
// layout the site claims to support.
const VIEWPORTS = [
  { width: 390, height: 844, deviceScaleFactor: 2, isMobile: true, hasTouch: true, label: "phone" },
  { width: 768, height: 1024, deviceScaleFactor: 2, isMobile: true, hasTouch: true, label: "tablet" },
  { width: 1280, height: 800, deviceScaleFactor: 1, isMobile: false, hasTouch: false, label: "laptop" },
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
    const { label, ...emulation } = viewport;
    await page.setViewport(emulation);
    if (emulation.isMobile) {
      await page.setUserAgent(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
      );
    }
    await page.goto(URL, { waitUntil: "networkidle0", timeout: 60000 });
    await new Promise((resolve) => setTimeout(resolve, 300));

    const metrics = await page.evaluate(() => {
      const doc = document.documentElement;
      const vw = doc.clientWidth;

      const clippedByAncestor = (el) => {
        for (let p = el.parentElement; p; p = p.parentElement) {
          const s = getComputedStyle(p);
          if (["auto", "scroll", "hidden", "clip"].includes(s.overflowX)) return p;
        }
        return null;
      };

      const offenders = [];
      for (const el of document.querySelectorAll("body *")) {
        const r = el.getBoundingClientRect();
        if (r.width <= 0 || r.right <= vw + 1) continue;
        if (clippedByAncestor(el)) continue;
        offenders.push({
          tag: el.tagName.toLowerCase(),
          cls: (el.className || "").toString().slice(0, 70),
          right: Math.round(r.right),
        });
      }

      return { vw, scrollWidth: doc.scrollWidth, overflowX: doc.scrollWidth - vw, offenders: offenders.slice(0, 10) };
    });

    const verdict = metrics.overflowX > 0 ? "FAIL" : "PASS";
    console.log(
      `${verdict} ${label} ${metrics.vw}px: document ${metrics.scrollWidth}px (overflow ${metrics.overflowX}px)`,
    );
    if (metrics.overflowX > 0) {
      failed = true;
      for (const o of metrics.offenders) {
        console.error(`     <${o.tag}> right=${o.right}px ${o.cls}`);
      }
    }

    if (label === "phone" && OUT) {
      await page.screenshot({ path: OUT, fullPage: false });
      console.log(`     screenshot -> ${OUT}`);
    }
    await page.close();
  }

  console.log(failed ? "layout check: FAIL" : "layout check: PASS - no horizontal overflow at any width");
  if (failed) process.exitCode = 1;
} finally {
  await browser.close();
}
