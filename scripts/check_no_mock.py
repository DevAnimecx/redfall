#!/usr/bin/env python3
"""Enforce the no-mock contract (§1). Exits 0 only when `src/` is clean.

Run as:  python scripts/check_no_mock.py

This checks the code that ships, not the tests. The banned patterns are the ones
that let a scanner look like it works without ever executing anything.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

BANNED_PATTERNS: list[tuple[str, str]] = [
    (r"\bTODO\b", "TODO"),
    (r"\bFIXME\b", "FIXME"),
    (r"\bXXX\b", "XXX marker"),
    (r"\bNotImplementedError\b", "NotImplementedError"),
    (r"^\s*pass\s*(#.*)?$", "bare `pass` placeholder"),
    (r"\.\.\.\s*$", "ellipsis placeholder body"),
    (r'return\s*\{\s*"(mock|fake|placeholder|dummy)"', "hardcoded mock/fake/placeholder return"),
    (r'"\s*(mock|fake|placeholder|dummy)_', "mock/fake/placeholder/dummy identifier"),
    (r"\bMOCK_MODE\b", "MOCK_MODE switch"),
    (r"if\s+os\.getenv\(\s*[\"']MOCK", "MOCK env switch"),
    (r"\bDEBUG_MOCK\b", "DEBUG_MOCK switch"),
    (r"\bif\s+TESTING\b", "TESTING branch"),
    (r"\bos\.system\s*\(", "os.system (host execution)"),
    (r"\bsubprocess\.(run|Popen|call|check_output|check_call)\s*\(\s*[\"'](curl|wget)", "shell curl/wget"),
    (r"""\bexec\s*\(\s*["']""", "exec() of a string"),
    (r"\beval\s*\(", "eval()"),
    (r"\btime\.sleep\s*\(", "sleep to wait for a result"),
    (r"""\bVULN-\d{3}\b""", "hardcoded range vuln id in src/"),
    (r"\bmock\.patch\b", "mock.patch in shipped code"),
    (r"\bMagicMock\b", "MagicMock in shipped code"),
    (r"--dry-run", "--dry-run is banned"),
    (r"\bdry_run\b", "dry_run flag is banned"),
]

# Compiled once. The `pass` and ellipsis rules are line-anchored so legitimate
# code containing those characters is not flagged.
COMPILED = [(re.compile(pattern, re.MULTILINE), label) for pattern, label in BANNED_PATTERNS]

# `pass` is legal in an `except` handler that genuinely has nothing to do, but
# only when the handler body is exactly that. Everything else is a stub.
LEGAL_PASS = re.compile(r"except[^\n]*:\n\s+pass\n", re.MULTILINE)

SCAN_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".mjs", ".jsx"}


def iter_sources(root: Path) -> list[Path]:
    return sorted(
        p
        for p in root.rglob("*")
        if p.is_file() and p.suffix in SCAN_EXTENSIONS and "__pycache__" not in p.parts
    )


def check_file(path: Path) -> list[str]:
    text = path.read_text(errors="replace")
    violations: list[str] = []

    for regex, label in COMPILED:
        if label == "bare `pass` placeholder":
            # Only flag `pass` that is not a complete except-handler body.
            for match in regex.finditer(text):
                window = text[max(0, match.start() - 200) : match.end()]
                if not LEGAL_PASS.search(window):
                    line_no = text.count("\n", 0, match.start()) + 1
                    violations.append(f"{path}:{line_no}: {label}")
            continue
        for match in regex.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            violations.append(f"{path}:{line_no}: {label}")
    return violations


def main() -> int:
    if not SRC.exists():
        print(f"no source tree at {SRC}", file=sys.stderr)
        return 2

    sources = iter_sources(SRC)
    violations: list[str] = []
    for path in sources:
        violations.extend(check_file(path))

    print(f"check_no_mock: scanned {len(sources)} file(s) under {SRC.relative_to(ROOT)}/")
    if violations:
        print(f"NO-MOCK CONTRACT: FAIL ({len(violations)} violation(s))")
        for violation in violations:
            print(f"  {violation}")
        return 1

    print("NO-MOCK CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
