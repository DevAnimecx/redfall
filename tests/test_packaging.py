"""The package must install and stay self-contained wherever it lands.

These tests chain to reality: the entry point and version come from the real
installed distribution metadata, the shipped files are read through the
installed package (importlib.resources), and the built wheel is inspected when
one is present. A src-only checkout with no built wheel skips only the wheel
check — never the install contract.
"""

from __future__ import annotations

import importlib.metadata
import importlib.resources
import zipfile
from pathlib import Path

import redfall

ROOT = Path(__file__).resolve().parent.parent

RUNTIME_FILES = [
    ("redfall.validation", "harness.mjs"),
    ("redfall.validation", "harness_internals.mjs"),
    ("redfall.agent", "prompts/_common.md"),
    ("redfall.agent", "prompts/planner.md"),
    ("redfall.agent", "prompts/analyzer.md"),
    ("redfall.agent", "prompts/poc_generator.md"),
    ("redfall.agent", "prompts/fixer.md"),
    ("redfall.agent", "prompts/chain_analyst.md"),
    ("redfall.sandbox", "images/redfall-sandbox/Dockerfile"),
]


def test_console_entry_point_is_declared():
    entries = [e for e in importlib.metadata.entry_points(group="console_scripts") if e.name == "redfall"]
    assert entries, "no `redfall` console script in the installed distribution"
    assert entries[0].value == "redfall.cli:main"
    # The entry point must resolve to a callable.
    assert callable(entries[0].load())


def test_version_is_single_sourced_from_metadata():
    assert importlib.metadata.version("redfall") == redfall.__version__


def test_runtime_files_ship_with_the_package():
    for package, relative in RUNTIME_FILES:
        resource = importlib.resources.files(package) / relative
        assert resource.is_file(), f"{package}:{relative} is missing from the installed package"
        assert resource.read_text(encoding="utf-8").strip(), f"{package}:{relative} is empty"


def test_built_wheel_contains_the_runtime_files(tmp_path):
    """Inspect a real wheel: the one in dist/ if present, otherwise build one.

    Building here keeps the contract honest on a clean checkout — and in CI —
    without depending on a prior manual build step.
    """
    wheels = sorted((ROOT / "dist").glob("redfall-*.whl"), key=lambda p: p.stat().st_mtime)
    if not wheels:
        import subprocess
        import sys

        built = subprocess.run(
            [sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "--no-build-isolation", "-w", str(tmp_path), "--quiet"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert built.returncode == 0, built.stderr
        wheels = sorted(tmp_path.glob("redfall-*.whl"))
    assert wheels, "no wheel could be produced"
    names = zipfile.ZipFile(wheels[-1]).namelist()
    for package, relative in RUNTIME_FILES:
        member = f"{package.replace('.', '/')}/{relative}"
        assert member in names, f"wheel is missing {member}"
