// Visual check: full-page screenshots at desktop/tablet/phone, plus the open
// mobile menu. Not a gate — an inspection aid.
import { existsSync } from "node:fs";
import puppeteer from "puppeteer-core";

const CANDIDATES = [
  process.env.CHROME_PATH,
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "/usr/bin/google-chrome",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
].filter(Boolean);
const chrome = CANDIDATES.find((p) => existsSync(p));
const URL = process.argv[2] ?? "http://localhost:4173/redfall/";
const OUT = process.argv[3] ?? "C:\\Users\\india\\AppData\\Local\\Temp\\opencode";

const browser = await puppeteer.launch({ executablePath: chrome, headless: true, args: ["--no-sandbox", "--disable-gpu"] });

async function shot(width, height, name, fullPage = true) {
  const page = await browser.newPage();
  await page.setViewport({ width, height, deviceScaleFactor: 1 });
  await page.goto(URL, { waitUntil: "networkidle0", timeout: 60000 });
  await page.evaluate(() => {
    document.querySelectorAll(".reveal").forEach((el) => el.classList.add("is-visible"));
  });
  await new Promise((r) => setTimeout(r, 900));
  await page.screenshot({ path: `${OUT}\\${name}.png`, fullPage });
  console.log(name, await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.scrollHeight]));
  await page.close();
}

await shot(1440, 900, "redesign-desktop");
await shot(768, 1024, "redesign-tablet");
await shot(390, 844, "redesign-phone");

// Mobile menu open.
const page = await browser.newPage();
await page.setViewport({ width: 390, height: 844 });
await page.goto(URL, { waitUntil: "networkidle0", timeout: 60000 });
await page.click('button[aria-controls="mobile-menu"]');
await new Promise((r) => setTimeout(r, 600));
await page.screenshot({ path: `${OUT}\\redesign-menu.png` });
console.log("redesign-menu");
await page.close();

await browser.close();
