#!/usr/bin/env python3
"""Rule 24 — every shipped file is reachable from an entrypoint.

An orphan file is worse than dead weight. It is code nobody runs, so nobody
tests it, so it rots — and then a future import picks it up and the shipped
behaviour changes. The fix is deletion, not an ignore list.

Reachability is computed by following imports from the real entrypoints, not by
grepping filenames. A file mentioned in a comment is still an orphan.

Only `src/` is walked. `tests/`, `range/` and `web/` have their own runners and
are not part of the Python import graph.
"""

from __future__ import annotations

import ast
import sys
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

ENTRYPOINTS = [
    SRC / "redfall" / "cli.py",
    SRC / "redfall" / "orchestrator.py",
    SRC / "redfall" / "__init__.py",
]

SKIP_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}


def module_name(path: Path) -> str:
    """`src/redfall/chain/graph.py` -> `redfall.chain.graph`."""
    relative = path.relative_to(SRC).with_suffix("")
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def all_modules() -> dict[str, Path]:
    out: dict[str, Path] = {}
    for path in sorted(SRC.rglob("*.py")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        out[module_name(path)] = path
    return out


def imported_names(path: Path) -> set[str]:
    """Every module name this file imports, in absolute form where resolvable."""
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except (SyntaxError, OSError):
        return set()

    names: set[str] = set()
    package = module_name(path).rsplit(".", 1)[0] if path.name != "__init__.py" else module_name(path)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # Relative import: climb `level` packages from the importer.
                base_parts = package.split(".")
                if path.name != "__init__.py":
                    base_parts = module_name(path).split(".")[:-1]
                climbed = base_parts[: len(base_parts) - (node.level - 1)]
                base = ".".join(climbed)
            else:
                base = node.module or ""
            if node.module and node.level:
                names.add(f"{base}.{node.module}" if base else node.module)
            elif base:
                names.add(base)
            # `from pkg import module` also imports a submodule.
            for alias in node.names:
                names.add(f"{base}.{alias.name}" if base else alias.name)
    return names


def reachable_from(entrypoints: list[Path], modules: dict[str, Path]) -> set[str]:
    seen: set[str] = set()
    queue: deque[Path] = deque(entrypoints)

    while queue:
        path = queue.popleft()
        if not path.exists():
            continue
        name = module_name(path)
        if name in seen:
            continue
        seen.add(name)

        # Importing a submodule executes every package __init__ above it, so a
        # package is reachable whenever anything inside it is. Without this, a
        # package whose modules are all imported still shows as an orphan even
        # though Python has already run its __init__.
        parent = name.rsplit(".", 1)[0] if "." in name else ""
        while parent:
            if parent in modules and parent not in seen:
                queue.append(modules[parent])
            parent = parent.rsplit(".", 1)[0] if "." in parent else ""

        for imported in imported_names(path):
            # Match the longest known module that this import refers to, so that
            # `redfall.chain.graph` and `redfall.chain` both resolve.
            if imported in modules and imported not in seen:
                queue.append(modules[imported])
                continue
            parent = imported.rsplit(".", 1)[0]
            while parent:
                if parent in modules and parent not in seen:
                    queue.append(modules[parent])
                    break
                parent = parent.rsplit(".", 1)[0] if "." in parent else ""

        # A package's modules are reachable through its __init__ only if it
        # imports them; do not assume the whole package is live.
    return seen


def main() -> int:
    modules = all_modules()
    missing = [str(e.relative_to(ROOT)) for e in ENTRYPOINTS if not e.exists()]
    if missing:
        print(f"ORPHAN CHECK: FAIL — entrypoint(s) missing: {', '.join(missing)}")
        return 1

    seen = reachable_from(ENTRYPOINTS, modules)
    orphans = sorted(name for name in modules if name not in seen)

    print(f"check_orphans: {len(modules)} module(s) under src/, "
          f"{len(ENTRYPOINTS)} entrypoint(s)")
    print(f"  reachable: {len(seen)}")

    if orphans:
        print(f"ORPHAN CHECK: FAIL ({len(orphans)} unreachable file(s))")
        for name in orphans:
            print(f"  {modules[name].relative_to(ROOT).as_posix()}")
        print("  Delete these, or import them from something that is reachable.")
        return 1

    print("ORPHAN CHECK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
