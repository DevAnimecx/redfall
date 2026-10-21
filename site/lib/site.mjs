// Shared site identity. Every generated page, sitemap entry and JSON-LD node
// reads from here so the canonical URL, base path and author cannot drift.

import { RELEASE_DATE, RELEASE_URL, REPO_URL, VERSION } from "./release.mjs";

export { RELEASE_DATE, RELEASE_URL, REPO_URL, VERSION };

export const SITE_URL = (process.env.SITE_URL ?? "https://devanimecx.github.io/redfall").replace(/\/$/, "");
export const BASE = process.env.SITE_BASE ?? "/redfall/";
export const GITHUB_USER_URL = "https://github.com/DevAnimecx";
export const SITE_NAME = "RedFall";
export const AUTHOR_NAME = "DevAnimecx";
export const AUTHOR_PATH = "about/";
export const AUTHOR_URL = `${SITE_URL}/${AUTHOR_PATH}`;
export const UPDATED = RELEASE_DATE;
// Public by design: IndexNow verifies ownership by fetching this key from the
// site root. It is not a secret and must match site/public/<key>.txt.
export const INDEXNOW_KEY = "465631c0f24944dcc1adf9325287a357";
export const FONT_PATH = `${BASE}fonts/inter-latin.woff2`;
export const DESCRIPTION =
  "RedFall is an execution-verified vulnerability scanner for TypeScript, JavaScript and Python. Every finding reproduces in a gVisor sandbox.";

/** Absolute production URL for a site-root path (no base, no leading slash). */
export function abs(path = "") {
  return `${SITE_URL}/${String(path).replace(/^\/+/, "")}`;
}

/** URL path including the GitHub Pages base (no leading slash). */
export function withBase(path = "") {
  return `${BASE}${String(path).replace(/^\/+/, "")}`;
}
