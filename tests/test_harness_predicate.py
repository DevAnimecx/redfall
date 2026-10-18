"""Run the harness's real request/predicate code against live HTTP traffic.

The harness normally executes inside a gVisor container, which this host cannot
provide. The pure parts — raw request parsing, chunked-transfer decoding, CSV
parsing and predicate evaluation — are what decide whether an exploit worked, so
they are verified here against a real Node HTTP server using the real PoC from
the range manifest.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
HARNESS_TEST = ROOT / "tests" / "harness" / "verify_harness.mjs"
PYTHON_TARGET_TEST = ROOT / "tests" / "harness" / "verify_python_target.mjs"

requires_node = pytest.mark.skipif(shutil.which("node") is None, reason="node is required")


def _vuln_001_poc() -> dict:
    manifest = yaml.safe_load((ROOT / "range" / "vulnbank" / "manifest.yaml").read_text())
    for entry in manifest["vulns"]:
        if entry["id"] == "VULN-001":
            return entry["poc"]
    raise AssertionError("VULN-001 missing from the range manifest")


@requires_node
def test_real_manifest_predicate_holds_over_live_http():
    """The ground-truth predicate must pass on a vulnerable response and fail on a patched one."""
    poc = _vuln_001_poc()
    assert "expect_expr" in poc and "request" in poc

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(poc, handle)
        poc_path = handle.name

    try:
        proc = subprocess.run(
            ["node", str(HARNESS_TEST), "--poc", poc_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        Path(poc_path).unlink(missing_ok=True)

    assert proc.returncode == 0, f"harness verification failed:\n{proc.stdout}\n{proc.stderr}"
    assert "ALL HARNESS CHECKS PASSED" in proc.stdout, proc.stdout


@requires_node
def test_python_target_boot_contract_boots_the_real_target():
    """pythonbank's real redfall.target.json must resolve to a command line that
    really boots the app on this host (the host Python stands in for the
    sandbox's virtualenv Python; argv/cwd/env semantics are identical)."""
    proc = subprocess.run(
        ["node", str(PYTHON_TARGET_TEST)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"python target verification failed:\n{proc.stdout}\n{proc.stderr}"
    assert "ALL PYTHON TARGET CHECKS PASSED" in proc.stdout, proc.stdout
