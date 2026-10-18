// Prerender the React app into dist/index.html so crawlers and answer engines
// get the full page as static HTML (no JavaScript required to read it).
//
// Runs after:  vite build  &&  vite build --ssr src/entry-server.jsx
// The client bundle hydrates the same markup in main.jsx.

import { readFileSync, writeFileSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distIndex = path.join(siteRoot, "dist", "index.html");
const serverEntry = path.join(siteRoot, "dist-server", "entry-server.js");
const marker = "<!--app-html-->";

const template = readFileSync(distIndex, "utf8");
if (!template.includes(marker)) {
  console.error(`prerender: marker ${marker} not found in dist/index.html`);
  process.exit(1);
}

const { render } = await import(pathToFileURL(serverEntry).href);
const html = render();
if (!html || html.length < 10_000) {
  console.error(`prerender: rendered HTML is suspiciously small (${html.length} chars)`);
  process.exit(1);
}

writeFileSync(distIndex, template.replace(marker, html));
rmSync(path.join(siteRoot, "dist-server"), { recursive: true, force: true });
console.log(`prerender: dist/index.html now ${html.length.toLocaleString("en-US")} rendered chars`);
