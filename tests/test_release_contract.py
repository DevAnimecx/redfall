"""The release metadata must agree across every public surface.

These tests are intentionally version-agnostic: they read the single source of
truth and compare the declarations that a release actually publishes. The
version checker is the mechanical gate; these tests make the same failure visible
inside the normal pytest run.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import redfall

ROOT = Path(__file__).resolve().parent.parent
VERSION = redfall.__version__


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_version_surfaces_agree():
    assert read("VERSION").strip() == VERSION
    assert re.search(rf'^version\s*=\s*"{re.escape(VERSION)}"', read("pyproject.toml"), re.M)
    assert re.search(rf'^version\s*=\s*"{re.escape(VERSION)}"', read("range/pyproject.toml"), re.M)

    for relative in (
        "site/package.json",
        "web/package.json",
        "range/vulnbank/package.json",
        "range/vulnbank-adaptive/package.json",
        "range/chainbank/package.json",
    ):
        assert json.loads(read(relative))["version"] == VERSION, relative

    assert f'export const VERSION = "{VERSION}";' in read("site/lib/release.mjs")
    assert f"Redfall {VERSION} ·" in read("web/app/layout.tsx")
    assert f"- Version: {VERSION};" in read("llms.txt")

    for relative in (
        "site/package-lock.json",
        "web/package-lock.json",
        "range/vulnbank/package-lock.json",
        "range/vulnbank-adaptive/package-lock.json",
        "range/chainbank/package-lock.json",
    ):
        data = json.loads(read(relative))
        assert data["version"] == VERSION, relative
        assert data["packages"][""]["version"] == VERSION, relative


def test_changelog_records_current_release():
    changelog = read("CHANGELOG.md")
    heading = re.search(
        rf"^## \[{re.escape(VERSION)}\] [-—] (\d{{4}}-\d{{2}}-\d{{2}})$",
        changelog,
        re.M,
    )
    assert heading, f"CHANGELOG.md has no dated [{VERSION}] section"
    assert re.search(
        rf"^\[{re.escape(VERSION)}\]: https://github\.com/DevAnimecx/redfall/releases/tag/v{re.escape(VERSION)}$",
        changelog,
        re.M,
    )


def test_current_release_docs_use_current_artifacts():
    wheel = f"redfall-{VERSION}-py3-none-any.whl"
    sdist = f"redfall-{VERSION}.tar.gz"
    for relative in (
        "README.md",
        "SECURITY.md",
        "llms.txt",
        "site/content/docs/install.md",
        "site/content/docs/release-verification.md",
    ):
        text = read(relative)
        assert wheel in text, f"{relative}: missing {wheel}"
    assert sdist in read("site/content/docs/release-verification.md")
    assert f"releases/tag/v{VERSION}" in read("llms.txt")


def test_version_contract_checker_passes():
    result = subprocess.run(
        [sys.executable, "scripts/check_version.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VERSION CONTRACT: PASS" in result.stdout
