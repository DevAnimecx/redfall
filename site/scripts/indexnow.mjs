// Submit the sitemap URLs to IndexNow after a Pages deployment.
//
//   node scripts/indexnow.mjs [--dry-run] [--wait=60]
//
// IndexNow is used by Bing, Yandex, Seznam and other participating engines.
// Google does not consume IndexNow; Google discovers the site through the
// sitemap and search-console verification. The key is public by design and is
// served from the site root so the endpoint can verify ownership.
//
// No URL is invented here: every submitted URL comes from the built sitemap.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { INDEXNOW_KEY, SITE_URL, abs } from "../lib/site.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SITE_ROOT = path.resolve(HERE, "..");
const args = new Set(process.argv.slice(2));
const dryRun = args.has("--dry-run");
const waitArg = process.argv.find((arg) => arg.startsWith("--wait="));
const waitSeconds = Number(waitArg?.split("=")[1] ?? 60);
const ENDPOINT = "https://api.indexnow.org/indexnow";
const HOST = new URL(SITE_URL).host;
const KEY_URL = abs(`${INDEXNOW_KEY}.txt`);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function getText(url, timeout = 20_000) {
  const response = await fetch(url, {
    headers: { "user-agent": "RedFall-IndexNow/0.1 (+https://github.com/DevAnimecx/redfall)" },
    signal: AbortSignal.timeout(timeout),
  });
  return { status: response.status, text: await response.text() };
}

async function loadSitemap() {
  if (dryRun) return readFileSync(path.join(SITE_ROOT, "dist", "sitemap.xml"), "utf8");
  const deadline = Date.now() + Math.max(0, waitSeconds) * 1000;
  let last = "not fetched";
  while (Date.now() <= deadline) {
    try {
      const live = await getText(abs("sitemap.xml"));
      const count = [...live.text.matchAll(/<loc>/g)].length;
      last = `HTTP ${live.status}, ${count} URLs`;
      // Do not submit a stale one-URL sitemap while Pages is still serving the
      // previous deployment. The current architecture has 23 indexable URLs.
      if (live.status === 200 && live.text.includes("<urlset") && count >= 20) return live.text;
    } catch (error) {
      last = error.message;
    }
    console.log(`indexnow: waiting for the deployed sitemap (${last})`);
    await sleep(5000);
  }
  throw new Error(`indexnow: live sitemap did not reach 20 URLs within ${waitSeconds}s (${last})`);
}

async function verifyKey() {
  if (dryRun) return;
  const deadline = Date.now() + Math.max(0, waitSeconds) * 1000;
  let last = "";
  while (Date.now() <= deadline) {
    try {
      const result = await getText(KEY_URL);
      last = `HTTP ${result.status}`;
      if (result.status === 200 && result.text.trim() === INDEXNOW_KEY) {
        console.log(`indexnow: key verified at ${KEY_URL}`);
        return;
      }
    } catch (error) {
      last = error.message;
    }
    console.log(`indexnow: waiting for ${KEY_URL} (${last})`);
    await sleep(5000);
  }
  throw new Error(`indexnow key was not readable at ${KEY_URL} after ${waitSeconds}s (${last})`);
}

const xml = await loadSitemap();
const urls = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].trim());
if (!urls.length) throw new Error("indexnow: sitemap contains no URLs");
if (urls.length > 10_000) throw new Error(`indexnow: sitemap has ${urls.length} URLs, above the 10,000 limit`);
for (const url of urls) {
  if (!url.startsWith(`${SITE_URL}/`)) throw new Error(`indexnow: sitemap URL is outside the site: ${url}`);
}

console.log(`indexnow: ${urls.length} URLs from ${abs("sitemap.xml")}`);
console.log(`indexnow: key ${INDEXNOW_KEY}, keyLocation ${KEY_URL}`);
if (dryRun) {
  console.log("indexnow: dry run — no request sent");
  for (const url of urls) console.log(`  ${url}`);
  process.exit(0);
}

await verifyKey();

const response = await fetch(ENDPOINT, {
  method: "POST",
  headers: { "content-type": "application/json; charset=utf-8" },
  body: JSON.stringify({ host: HOST, key: INDEXNOW_KEY, keyLocation: KEY_URL, urlList: urls }),
  signal: AbortSignal.timeout(30_000),
});
const body = await response.text();
console.log(`indexnow: POST ${ENDPOINT} -> HTTP ${response.status} ${response.statusText}`);
if (body) console.log(body.slice(0, 2000));
if (response.status !== 200 && response.status !== 202) {
  throw new Error(`indexnow submission rejected (HTTP ${response.status})`);
}
console.log(`indexnow: accepted ${urls.length} URLs (HTTP ${response.status})`);
