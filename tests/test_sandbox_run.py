"""Scoring RedFall against real, third-party vulnerable applications.

The runner itself is small; what matters is that it measures the *engine* and
not a convenient subset of it. The bug it was written to catch bit three times
during development — a stage left out of the pipeline, and a sink→category map
that silently dropped findings the engine had actually produced — so the tests
below pin both.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def test_the_ground_truth_is_well_formed():
    from redfall.sandbox_run import load_ground_truth

    data = load_ground_truth()
    targets = data.get("targets")
    assert targets, "no targets in the sandbox ground truth"
    for name, entry in targets.items():
        assert entry.get("repo", "").startswith("https://github.com/"), name
        assert len(entry.get("commit", "")) == 40, f"{name}: commit is not a full sha"
        expected = entry.get("expected") or []
        assert expected, f"{name} has no expected findings"
        ids = [e["id"] for e in expected]
        assert len(ids) == len(set(ids)), f"{name} has duplicate ids"


def test_every_expected_entry_names_a_file_and_a_category():
    from redfall.sandbox_run import load_ground_truth

    data = load_ground_truth()
    for name, entry in data["targets"].items():
        for item in entry["expected"]:
            assert item.get("category"), f"{name}/{item.get('id')} has no category"
            assert item.get("file"), f"{name}/{item.get('id')} has no file"
            assert not str(item["file"]).startswith("/"), (
                f"{name}/{item['id']}: the path must be relative to the app root"
            )


def test_matching_is_by_file_and_category_not_line():
    """The ground truth for a third-party app names where a class lives, not
    the line its authors would have chosen."""
    from redfall.sandbox_run import Expected

    expectation = Expected("X", "sqli", "core/appHandler.js", note="")
    assert expectation.matches({"category": "sqli", "file": "core/appHandler.js"})
    assert expectation.matches({"category": "sqli", "file": "/abs/core/appHandler.js"})
    assert not expectation.matches({"category": "xss", "file": "core/appHandler.js"})
    assert not expectation.matches({"category": "sqli", "file": "other.js"})


def test_vendored_and_generated_files_are_not_scanned(tmp_path, monkeypatch):
    """Scanning jQuery would bury the app's own findings."""
    from redfall.sandbox_run import source_files

    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "route.js").write_text("x", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text("x", encoding="utf-8")
    (tmp_path / "app" / "vendor").mkdir()
    (tmp_path / "app" / "vendor" / "jquery.js").write_text("x", encoding="utf-8")
    (tmp_path / "app" / "bundle.min.js").write_text("x", encoding="utf-8")

    found = {p.name for p in source_files(tmp_path)}
    assert found == {"route.js"}


def test_a_missing_challenge_is_reported_not_fetched(tmp_path, monkeypatch):
    """A host that has not cloned the apps scores nothing, not zero."""
    from redfall import sandbox_run

    monkeypatch.setattr(sandbox_run, "CHALLENGES", tmp_path / "challenges")
    result = sandbox_run.scan_target("definitely-not-here")
    assert result.fetched is False
    assert result.recall is None


def test_the_engine_reports_through_both_stages():
    """Scoring only the detectors measured half the engine.

    A SQL injection is a flow, not a shape, so the detector suite cannot see
    one — and an earlier version of this runner scored detector output alone,
    which reported every injection as a miss while the taint stage had found
    them.
    """
    from redfall.sandbox_run import _taint_findings

    root = ROOT / "range" / "pythonbank" / "src" / "pythonbank" / "routes"
    target = root / "tools.py"
    if not target.is_file():
        pytest.skip("pythonbank not present")
    rows = _taint_findings(target, "routes/tools.py")
    assert rows, "the taint stage produced nothing for a file with a known flow"
    assert all("category" in row and "file" in row for row in rows)


def test_a_command_injection_sink_kind_maps_to_its_category():
    """The mapping bug that cost 15 points twice.

    The taint engine emits the sink *kind* (`exec`), and the corpus names the
    *class* (`cmd_injection`). Mapping the bare kind through the fallback
    returned the string "exec", which matched no category — so a bug the engine
    had found scored as a miss on both the held-out corpus and the real apps.
    """
    from redfall.cli_bench import _category_for_sink

    assert _category_for_sink("exec") == "cmd_injection"
    assert _category_for_sink("eval") == "cmd_injection"
    assert _category_for_sink("os.system") == "cmd_injection"
    assert _category_for_sink("child_process.exec") == "cmd_injection"


def test_the_runner_reports_both_stages_together(monkeypatch, tmp_path):
    """findings from one file include detector hits and taint paths."""
    from redfall import sandbox_run

    app = tmp_path / "challenges" / "fake"
    app.mkdir(parents=True)
    (app / "app.py").write_text(
        "import os\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/run')\n"
        "def run():\n"
        "    cmd = request.args.get('cmd')\n"
        "    os.system(cmd)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sandbox_run, "CHALLENGES", tmp_path / "challenges")
    monkeypatch.setattr(
        sandbox_run, "expected_for", lambda name: []
    )
    result = sandbox_run.scan_target("fake")
    categories = {row["category"] for row in result.findings}
    # The flow stage finds the injection; both stages contribute.
    assert "cmd_injection" in categories, (
        f"only the detector stage ran; got {sorted(categories)}"
    )
