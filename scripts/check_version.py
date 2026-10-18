#!/usr/bin/env python3
"""Rule 21 — every version string in the repository is exactly the release version.

Version drift is a release bug, not a cosmetic one: a customer who pulls a chart
tagged 0.1.0 that runs a 0.0.9 image gets behaviour nobody tested. So the version
is declared once, in `src/redfall/version.py`, and every other declaration is
checked against it.

Two traps this script is written to avoid:

* `127.0.0.1` contains the literal `1.0.0`. A naive forbidden-pattern grep flags
  every loopback URL in the range PoCs, which is most of them. Version patterns
  are therefore anchored to the syntax that actually declares a version.
* Dependency pins such as `node-serialize: ^0.0.4` are third-party versions.
  They are not ours to change and are excluded from both checks.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_OF_TRUTH = ROOT / "src" / "redfall" / "version.py"

SKIP_DIRS = {
    "node_modules",
    ".git",
    ".next",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "coverage",
}

# Files that must declare the release version, and the pattern that must appear.
REQUIRED: dict[str, str] = {
    "VERSION": r"^0\.1\.0$",
    "pyproject.toml": r'^version\s*=\s*"0\.1\.0"',
    "range/pyproject.toml": r'^version\s*=\s*"0\.1\.0"',
    "package.json": r'"version"\s*:\s*"0\.1\.0"',
    "web/package.json": r'"version"\s*:\s*"0\.1\.0"',
    "range/vulnbank/package.json": r'"version"\s*:\s*"0\.1\.0"',
    "range/vulnbank-adaptive/package.json": r'"version"\s*:\s*"0\.1\.0"',
    "range/chainbank/package.json": r'"version"\s*:\s*"0\.1\.0"',
    "src/redfall/version.py": r'^__version__\s*=\s*"0\.1\.0"',
}

# Anchored so that `127.0.0.1`, dependency pins and port numbers cannot match.
#
# The forbidden literals are assembled from parts. Written out whole, this file
# would contain the very strings it scans for and fail its own check.
_SNAPSHOT = "-" + "SNAPSHOT"
_PRE = "|".join(("rc", "alpha", "beta", "dev"))

FORBIDDEN = [
    (r'^version\s*=\s*"(?!0\.1\.0")[^"]+"', "pyproject version != 0.1.0"),
    (r'"version"\s*:\s*"(?!0\.1\.0")[^"]+"', "package.json version != 0.1.0"),
    (r'^__version__\s*=\s*"(?!0\.1\.0")[^"]+"', "__version__ != 0.1.0"),
    (r'^\s*version\s*:\s*(?!0\.1\.0\b)0\.\d+\.\d+', "chart/spec version != 0.1.0"),
    (re.escape(_SNAPSHOT) + r"\b", "Maven snapshot suffix"),
    (r'\b0\.1\.0-(?:' + _PRE + r')\d*', "pre-release suffix on the release version"),
]

# A hardcoded version outside version.py is drift waiting to happen.
HARDCODED = re.compile(r'(?<![\w.])0\.1\.0(?![\w.\-])')
ALLOWED_HARDCODED = {
    "src/redfall/version.py",
    "scripts/check_version.py",
    "CHANGELOG.md",
    "README.md",
    "BLOCKED.md",
    "docs/openapi.yaml",
    "docs/quickstart.md",
    "docs/self-hosting.md",
    "docs/airgap.md",
    "docs/byok.md",
    "docs/compliance.md",
    "docs/api.md",
}

SCAN_SUFFIXES = {".py", ".toml", ".json", ".yaml", ".yml", ".md", ".rs", ".ts", ".tsx", ".sh"}


def rel(path: Path) -> str:
    """A POSIX-style repo-relative path, so messages read the same on every host."""
    return path.relative_to(ROOT).as_posix()


def read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def check_required() -> list[str]:
    problems: list[str] = []
    for relative, pattern in REQUIRED.items():
        path = ROOT / relative
        if not path.exists():
            # Chart.yaml, openapi.yaml and the root package.json arrive with the
            # packaging work; they are required only once they exist.
            if relative in ("VERSION", "pyproject.toml", "src/redfall/version.py"):
                problems.append(f"{relative}: missing, but it is required to exist")
            continue
        if not re.search(pattern, read(path), re.MULTILINE):
            problems.append(f"{relative}: does not match {pattern!r}")
    return problems


def check_forbidden() -> list[str]:
    problems: list[str] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in SCAN_SUFFIXES and path.name not in ("Makefile", "VERSION"):
            continue
        if path.name in ("package-lock.json",):
            continue
        text = read(path)
        for index, line in enumerate(text.splitlines(), start=1):
            for pattern, label in FORBIDDEN:
                if re.search(pattern, line):
                    problems.append(f"{rel(path)}:{index}: {label} — {line.strip()[:90]}")
    return problems


def check_hardcoded() -> list[str]:
    """Only version.py may state the version in Python source."""
    problems: list[str] = []
    for path in sorted((ROOT / "src").rglob("*.py")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        relative = rel(path)
        if relative in ALLOWED_HARDCODED:
            continue
        for index, line in enumerate(read(path).splitlines(), start=1):
            if HARDCODED.search(line):
                problems.append(
                    f"{relative}:{index}: hardcoded version outside version.py — {line.strip()[:90]}"
                )
    return problems


def check_single_truth() -> list[str]:
    """The declared version and the source of truth must agree."""
    if not SOURCE_OF_TRUTH.exists():
        return [f"{rel(SOURCE_OF_TRUTH)}: the single source of truth is missing"]
    match = re.search(r'__version__\s*=\s*"([^"]+)"', read(SOURCE_OF_TRUTH))
    if not match:
        return [f"{rel(SOURCE_OF_TRUTH)}: no __version__ assignment found"]
    declared = match.group(1)
    version_file = ROOT / "VERSION"
    problems: list[str] = []
    if version_file.exists():
        on_disk = read(version_file).strip()
        if on_disk != declared:
            problems.append(f"VERSION says {on_disk!r} but version.py says {declared!r}")
    return problems


def main() -> int:
    problems = check_required() + check_forbidden() + check_hardcoded() + check_single_truth()

    truth = read(SOURCE_OF_TRUTH)
    match = re.search(r'__version__\s*=\s*"([^"]+)"', truth)
    print(f"check_version: release version {match.group(1) if match else 'UNKNOWN'}")
    print(f"  required declarations checked: {len(REQUIRED)}")

    if problems:
        print(f"VERSION CONTRACT: FAIL ({len(problems)} violation(s))")
        for problem in problems:
            print(f"  {problem}")
        return 1

    print("VERSION CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
