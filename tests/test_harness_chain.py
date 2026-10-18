"""Run the multi-step chain runner against live HTTP traffic.

A chain verdict is what admits an edge into the attack graph, so the code that
produces it is verified here the same way the single-request harness is: the
real substitution/extraction/step-loop code, driven over real sockets against a
server that behaves like the one under test.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CHAIN_TEST = ROOT / "tests" / "harness" / "verify_chain_steps.mjs"

requires_node = pytest.mark.skipif(shutil.which("node") is None, reason="node is required")


@requires_node
def test_real_chain_runner_over_live_http():
    proc = subprocess.run(
        ["node", str(CHAIN_TEST)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"chain harness verification failed:\n{proc.stdout}\n{proc.stderr}"
    assert "ALL CHAIN HARNESS CHECKS PASSED" in proc.stdout, proc.stdout
