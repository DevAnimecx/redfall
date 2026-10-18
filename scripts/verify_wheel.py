"""Verify an *installed* redfall wheel, from outside the repository.

The point of this script is that it must not be able to reach the source tree:
run it with an interpreter that has the wheel installed, with a working
directory that is not the checkout. If anything the package needs at runtime
was left out of the wheel — the sandbox harness, the prompts, the Dockerfile —
this fails loudly instead of silently importing from `src/`.

Usage:

    python -m pip wheel . --no-deps -w dist
    python -m venv --system-site-packages /tmp/redfall-wheel-verify
    /tmp/redfall-wheel-verify/bin/pip install dist/redfall-*.whl
    cd /tmp && /tmp/redfall-wheel-verify/bin/python <repo>/scripts/verify_wheel.py

What it proves, in order:

1. The console script's package (redfall.validation) ships `harness.mjs` and
   `harness_internals.mjs`, and the agent prompts ship with it.
2. A real ingest runs through the installed code on a synthetic two-file
   TypeScript tree, and the interprocedural pass — not the intraprocedural one,
   because `term` is a parameter, not a source — finds the SQL sink reached
   through the import binding.
"""

from __future__ import annotations

import argparse
import importlib.resources as resources
import tempfile
from pathlib import Path

import redfall
from redfall.ingestion.ingest import ingest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workdir",
        type=Path,
        default=None,
        help="Directory to build the synthetic tree in (default: a fresh temp dir).",
    )
    args = parser.parse_args()

    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="redfall-wheel-verify-"))
    workdir.mkdir(parents=True, exist_ok=True)

    # 1. Runtime files ship inside the installed package.
    for package, relative in (
        ("redfall.validation", "harness.mjs"),
        ("redfall.validation", "harness_internals.mjs"),
        ("redfall.agent", "prompts/analyzer.md"),
    ):
        assert (resources.files(package) / relative).is_file(), f"{package}:{relative} missing"

    # 2. A real interprocedural ingest through the installed code.
    root = workdir / "synthetic"
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "core.ts").write_text(
        "export function lookup(pool: any, term: string) {\n"
        "  return pool.query('SELECT ' + term);\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "src" / "routes.ts").write_text(
        "import { lookup } from './core';\n"
        "export function handler(req: any, pool: any) {\n"
        "  const t = req.query.q;\n"
        "  return lookup(pool, t);\n"
        "}\n",
        encoding="utf-8",
    )

    result = ingest("wheel-verify", root)
    assert not result.parse_errors, result.parse_errors
    print(f"installed redfall {redfall.__version__}")
    print(f"files={len(result.files)} routes={len(result.routes)} edges={len(result.call_edges)}")

    found = []
    for file in result.files:
        for taint in file.taints:
            found.append(
                (file.path, taint.line, taint.sink, taint.symbol, taint.via[-1] if taint.via else "")
            )
    for row in found:
        print("taint:", row)

    # `term` is a parameter, so a taint in core.ts can only come from the
    # interprocedural pass, reached through the import binding.
    assert found, "no taint found through the installed wheel"
    assert any(row[0].endswith("core.ts") and row[2] == "pool.query" for row in found), found
    assert all(row[4] for row in found), found  # every taint carries an auditable via chain
    print("WHEEL VERIFY: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
