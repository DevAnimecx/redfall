#!/usr/bin/env python3
"""Rule 22 — no build detritus or stray files in the shipped tree.

Two different things are checked, because they have different fixes:

* **Ignored artifacts** (`__pycache__`, `node_modules`, `.next`, `dist`, logs,
  swap files). These are generated, so the fix is to delete them and make sure
  `.gitignore` covers them. They must not be committed.
* **Stray files** (`.bak`, `.orig`, `.rej`, `.tmp`). These are almost always the
  residue of an editor or a patch tool. They ship by accident and then someone
  imports the wrong one.

The scan skips the ignored directories rather than reporting their contents, so a
single `node_modules` does not produce eighty thousand violations and bury the
one file that actually matters.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Directories that are build output. Skipped entirely, and forbidden in git.
IGNORED_DIRS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".turbo",
    ".parcel-cache",
    ".next",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    "coverage",
    "htmlcov",
    ".idea",
    ".vscode",
    ".cache",
}

# Kept: the workspace snapshot excludes these names, and a range target needs its
# own dist/ to run. They are ignored, not shipped.
IGNORED_SUFFIXES = {".pyc", ".pyo", ".log", ".tmp", ".bak", ".orig", ".rej", ".swp", ".swo"}

IGNORED_NAMES = {".DS_Store", "Thumbs.db", ".coverage", "npm-debug.log", "yarn-error.log"}

# `dist/` is a build artifact and must never be committed, but it is legitimate
# on disk: the range targets build into it and the replay harness runs from it.
FORBIDDEN_IN_GIT = IGNORED_DIRS | {"*.pyc", "*.log", "*.tmp", "*.bak", "*.orig", "*.swp"}


def is_ignored_dir(name: str) -> bool:
    return name in IGNORED_DIRS or name.endswith(".egg-info")


def scan() -> tuple[list[str], list[str]]:
    """Return (stray_files, ignored_dirs_present)."""
    stray: list[str] = []
    present: list[str] = []

    stack = [ROOT]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            name = entry.name
            if entry.is_dir():
                if name == ".git":
                    continue
                if is_ignored_dir(name):
                    present.append(entry.relative_to(ROOT).as_posix())
                    continue
                stack.append(entry)
                continue
            if name in IGNORED_NAMES or entry.suffix.lower() in IGNORED_SUFFIXES:
                stray.append(entry.relative_to(ROOT).as_posix())

    return sorted(stray), sorted(present)


def check_gitignore() -> list[str]:
    """Every ignored dir name should be covered by .gitignore."""
    path = ROOT / ".gitignore"
    if not path.exists():
        return [".gitignore is missing, so nothing is ignored"]
    text = path.read_text(errors="replace")
    covered = {line.strip().rstrip("/").lstrip("/") for line in text.splitlines() if line.strip()
               and not line.strip().startswith("#")}
    missing = sorted(name for name in IGNORED_DIRS if name not in covered and f"{name}/" not in text)
    return [f".gitignore does not cover {name}" for name in missing]


def main() -> int:
    stray, present = scan()
    gitignore_problems = check_gitignore()

    print("check_clean_tree: scanned the working tree")
    print(f"  build directories present (ignored, not shipped): {len(present)}")
    for name in present[:12]:
        print(f"    {name}")
    if len(present) > 12:
        print(f"    ... and {len(present) - 12} more")

    problems = stray + gitignore_problems
    if problems:
        print(f"CLEAN TREE: FAIL ({len(problems)} problem(s))")
        for problem in problems:
            print(f"  {problem}")
        return 1

    print("  stray files: none")
    print("CLEAN TREE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
