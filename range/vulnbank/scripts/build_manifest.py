#!/usr/bin/env python3
"""Regenerates manifest.yaml with line numbers read from the actual source files.

Run from the vulnbank root:  python3 scripts/build_manifest.py
Keeps the manifest honest: location.lines always points at a real line.
"""
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# (vuln_id, file, regex for the anchor line, symbol)
ANCHORS = {
    "VULN-001": ("src/routes/auth.ts", r"const lookup = ", "loginHandler"),
    "VULN-002": ("src/routes/auth.ts", r"router\.post\('/login'", "loginHandler"),
    "VULN-003": ("src/routes/auth.ts", r"error: 'no such user'", "loginHandler"),
    "VULN-004": ("src/routes/auth.ts", r"verifyPassword\(password", "loginHandler"),
    "VULN-005": ("src/middleware/jwt.ts", r"jwt\.verify\(token, JWT_SECRET\)", "verifyToken"),
    "VULN-006": ("src/middleware/jwt.ts", r"jwt\.sign\(payload, JWT_SECRET\)", "signToken"),
    "VULN-007": ("src/routes/auth.ts", r"router\.post\('/register'", "register"),
    "VULN-008": ("src/routes/users.ts", r"router\.get\('/:id'", "getUserById"),
    "VULN-009": ("src/routes/users.ts", r"ORDER BY id LIMIT \$1", "listUsers"),
    "VULN-010": ("src/routes/users.ts", r"Search results for", "searchUsers"),
    "VULN-011": ("src/routes/profile.ts", r'class="bio"', "getProfile"),
    "VULN-012": ("src/routes/profile.ts", r"stack: e\.stack", "getProfile"),
    "VULN-013": ("src/routes/tx.ts", r"await sleep\(120\)", "transfer"),
    "VULN-014": ("src/routes/tx.ts", r"!Number\.isFinite\(amount\)", "transfer"),
    "VULN-015": ("src/routes/tx.ts", r"router\.get\('/:id'", "getTransaction"),
    "VULN-016": ("src/routes/upload.ts", r"path\.join\(UPLOAD_DIR", "uploadFile"),
    "VULN-017": ("src/routes/upload.ts", r"const upload = multer\(", "uploadFile"),
    "VULN-018": ("src/routes/fetch.ts", r"await fetch\(url", "proxyFetch"),
    "VULN-019": ("src/routes/fetch.ts", r"await fetch\(url", "proxyFetch"),
    "VULN-020": ("src/routes/redirect.ts", r"res\.redirect\(302", "redirect"),
    "VULN-021": ("src/routes/comments.ts", r"router\.post\('/'", "createComment"),
    "VULN-022": ("src/app.ts", r"export function createApp", "createApp"),
    "VULN-023": ("src/routes/admin.ts", r"exec\(`psql", "execSql"),
    "VULN-024": ("src/routes/export.ts", r"lines\.push", "exportCsv"),
    "VULN-025": ("src/routes/webhook.ts", r"router\.post\('/stripe'", "stripeWebhook"),
    "VULN-026": ("src/routes/config.ts", r"const extra = \{", "getConfig"),
    "VULN-027": ("src/middleware/jwt.ts", r"const JWT_SECRET = ", "JWT_SECRET"),
    "VULN-028": ("src/db.ts", r"password: '", "pool"),
    "VULN-029": ("src/auth/hash.ts", r"createHash\('md5'\)", "hashPassword"),
    "VULN-030": ("src/routes/settings.ts", r"function merge", "merge"),
    "VULN-031": ("src/routes/import.ts", r"serialize\.unserialize", "importBatch"),
    "VULN-032": ("src/app.ts", r"Access-Control-Allow-Credentials", "createApp"),
}


def anchor_line(rel_path: str, pattern: str) -> int:
    path = os.path.join(ROOT, rel_path)
    with open(path, encoding="utf-8") as handle:
        for index, line in enumerate(handle, start=1):
            if re.search(pattern, line):
                return index
    raise SystemExit(f"anchor not found: {rel_path} :: {pattern}")


def main() -> None:
    for vuln_id, (rel_path, pattern, _symbol) in sorted(ANCHORS.items()):
        line = anchor_line(rel_path, pattern)
        print(f"{vuln_id}\t{rel_path}:{line}")

    manifest_path = os.path.join(ROOT, "manifest.yaml")
    with open(manifest_path, encoding="utf-8") as handle:
        text = handle.read()

    for vuln_id, (rel_path, pattern, _symbol) in ANCHORS.items():
        line = anchor_line(rel_path, pattern)
        block = re.search(
            rf"(  - id: {vuln_id}\n(?:.*\n)*?      lines: )\[[^\]]*\]",
            text,
        )
        if not block:
            raise SystemExit(f"manifest has no lines entry for {vuln_id}")
        text = text[: block.start()] + f"{block.group(1)}[{line}]" + text[block.end():]

    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(f"\nmanifest.yaml line anchors refreshed: {manifest_path}")


if __name__ == "__main__":
    sys.exit(main())
