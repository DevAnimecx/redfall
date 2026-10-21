#!/usr/bin/env python3
"""Rule 21 — every version string in the repository is exactly the release version.

Version drift is a release bug, not a cosmetic one: a customer who pulls a chart
tagged 0.1.1 that runs a 0.0.9 image gets behaviour nobody tested. So the version
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


def read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def _declared_version() -> str:
    match = re.search(r'__version__\s*=\s*"([^"]+)"', read(SOURCE_OF_TRUTH))
    if not match:
        raise SystemExit(f"{SOURCE_OF_TRUTH}: no __version__ assignment found")
    return match.group(1)


VERSION = _declared_version()
V = re.escape(VERSION)

# Files that must declare the release version, and the pattern that must appear.
REQUIRED: dict[str, str] = {
    "VERSION": rf"^{V}$",
    "pyproject.toml": rf'^version\s*=\s*"{V}"',
    "range/pyproject.toml": rf'^version\s*=\s*"{V}"',
    "package.json": rf'"version"\s*:\s*"{V}"',
    "site/package.json": rf'"version"\s*:\s*"{V}"',
    "web/package.json": rf'"version"\s*:\s*"{V}"',
    "range/vulnbank/package.json": rf'"version"\s*:\s*"{V}"',
    "range/vulnbank-adaptive/package.json": rf'"version"\s*:\s*"{V}"',
    "range/chainbank/package.json": rf'"version"\s*:\s*"{V}"',
    "src/redfall/version.py": rf'^__version__\s*=\s*"{V}"',
    "site/lib/release.mjs": rf'^export const VERSION = "{V}";$',
}

REQUIRED_EXISTENCE = {
    "VERSION",
    "pyproject.toml",
    "src/redfall/version.py",
    "site/package.json",
    "site/lib/release.mjs",
}

LOCKFILES = [
    "site/package-lock.json",
    "web/package-lock.json",
    "range/vulnbank/package-lock.json",
    "range/vulnbank-adaptive/package-lock.json",
    "range/chainbank/package-lock.json",
]

# Anchored so that `127.0.0.1`, dependency pins and port numbers cannot match.
#
# The forbidden literals are assembled from parts. Written out whole, this file
# would contain the very strings it scans for and fail its own check.
_SNAPSHOT = "-" + "SNAPSHOT"
_PRE = "|".join(("rc", "alpha", "beta", "dev"))

FORBIDDEN = [
    (rf'^version\s*=\s*"(?!{V}")[^"]+"', f"pyproject version != {VERSION}"),
    (rf'"version"\s*:\s*"(?!{V}")[^"]+"', f"package.json version != {VERSION}"),
    (rf'^__version__\s*=\s*"(?!{V}")[^"]+"', f"__version__ != {VERSION}"),
    (rf'^\s*version\s*:\s*(?!{V}\b)0\.\d+\.\d+', f"chart/spec version != {VERSION}"),
    (re.escape(_SNAPSHOT) + r"\b", "Maven snapshot suffix"),
    (rf'\b{V}-(?:{_PRE})\d*', "pre-release suffix on the release version"),
]

# A hardcoded version outside version.py is drift waiting to happen.
HARDCODED = re.compile(rf'(?<![\w.]){V}(?![\w.\-])')
ALLOWED_HARDCODED = {"src/redfall/version.py"}

SCAN_SUFFIXES = {".py", ".toml", ".json", ".yaml", ".yml", ".md", ".rs", ".ts", ".tsx", ".sh"}


def rel(path: Path) -> str:
    """A POSIX-style repo-relative path, so messages read the same on every host."""
    return path.relative_to(ROOT).as_posix()


def check_required() -> list[str]:
    problems: list[str] = []
    for relative, pattern in REQUIRED.items():
        path = ROOT / relative
        if not path.exists():
            if relative in REQUIRED_EXISTENCE:
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


def check_lockfiles() -> list[str]:
    """npm lockfile roots must agree with the package manifest and version.py."""
    problems: list[str] = []
    for relative in LOCKFILES:
        path = ROOT / relative
        if not path.exists():
            continue
        try:
            data = json.loads(read(path))
        except json.JSONDecodeError as error:
            problems.append(f"{relative}: invalid JSON ({error})")
            continue
        declared = data.get("version")
        if declared != VERSION:
            problems.append(f"{relative}: root version says {declared!r}, expected {VERSION!r}")
        package = data.get("packages", {}).get("", {})
        if package.get("version") != VERSION:
            problems.append(
                f"{relative}: packages[''] version says {package.get('version')!r}, expected {VERSION!r}"
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
    problems = (
        check_required()
        + check_forbidden()
        + check_hardcoded()
        + check_lockfiles()
        + check_single_truth()
    )

    print(f"check_version: release version {VERSION}")
    print(f"  required declarations checked: {len(REQUIRED)}")
    print(f"  lockfile roots checked: {len(LOCKFILES)}")

    if problems:
        print(f"VERSION CONTRACT: FAIL ({len(problems)} violation(s))")
        for problem in problems:
            print(f"  {problem}")
        return 1

    print("VERSION CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
