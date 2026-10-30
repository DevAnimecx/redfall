"""The `redfall learn` commands, driven end to end.

The property under test is that the CLI cannot promote past the gate: a lesson
with no evaluation, or with a negative delta, must exit nonzero and say why.
A command that printed `"ok": true` regardless would make the gate decorative.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    db_path = tmp_path / "learn.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    from redfall.store import db

    db.init_engine(f"sqlite:///{db_path}")
    with db.session_scope() as session:
        from redfall.store.models import Campaign

        session.add(Campaign(id="cmp-1", repo="/srv/app", tenant_id=""))
    return CliRunner(), db_path


def _run(runner, *args):
    from redfall.cli import main

    return runner.invoke(main, ["learn", *args], catch_exceptions=False)


def _json(output: str) -> dict:
    start = output.index("{")
    return json.loads(output[start:])


def _evidence_id(db_path) -> str:
    from redfall.evidence.ledger import EvidenceLedger
    from redfall.store import db

    with db.session_scope() as session:
        record = EvidenceLedger(session).append(
            "cmp-1",
            grade="E4",
            kind="execution",
            claim="IDOR lets A read B's invoice",
            payload={
                "execution_id": "exe-1",
                "observable": "status 200",
                "impact": "cross-tenant read",
            },
            reproduce_command="redfall reproduce fnd-1",
            environment_digest="sha256:abc",
        )
        return record.id


def test_kinds_prints_the_kinds_and_the_gate(env):
    runner, _ = env
    payload = _json(_run(runner, "kinds").output)
    assert "route_shape" in payload["kinds"]
    assert payload["learnable_grades"] == ["E3", "E4"]
    assert payload["gate"]["min_holdout_n"] > 0


def test_propose_from_a_verified_record_succeeds(env):
    runner, db_path = env
    result = _run(
        runner,
        "propose",
        "--kind",
        "route_shape",
        "--evidence",
        _evidence_id(db_path),
        "--summary",
        "Spring joins the class prefix",
        "--payload-json",
        '{"framework": "spring"}',
    )
    assert result.exit_code == 0
    payload = _json(result.output)
    assert payload["created"] is True
    assert payload["lesson"]["status"] == "candidate"


def test_propose_refuses_when_the_evidence_grade_is_a_hypothesis(env):
    runner, db_path = env
    from redfall.evidence.ledger import EvidenceLedger
    from redfall.store import db

    with db.session_scope() as session:
        static = EvidenceLedger(session).append(
            "cmp-1",
            grade="E1",
            kind="static",
            claim="a path may exist",
            payload={"path": "src/app.py"},
        )
        evidence_id = static.id

    result = _run(
        runner,
        "propose",
        "--kind",
        "sink",
        "--evidence",
        evidence_id,
        "--summary",
        "from a hypothesis",
    )
    assert result.exit_code != 0
    assert "only E3/E4" in result.output


def test_promote_refuses_a_lesson_with_no_evaluation(env):
    runner, db_path = env
    created = _json(
        _run(
            runner,
            "propose",
            "--kind",
            "sink",
            "--evidence",
            _evidence_id(db_path),
            "--summary",
            "s",
        ).output
    )
    result = _run(runner, "promote", created["lesson"]["id"])
    assert result.exit_code != 0
    assert "no holdout evaluation" in result.output


def test_the_full_loop_reaches_promoted_and_then_rolls_back(env):
    runner, db_path = env
    lesson_id = _json(
        _run(
            runner,
            "propose",
            "--kind",
            "sink",
            "--evidence",
            _evidence_id(db_path),
            "--summary",
            "exec.Command is reachable",
        ).output
    )["lesson"]["id"]

    ev = _json(
        _run(
            runner,
            "evaluate",
            lesson_id,
            "--holdout",
            "arena-v1",
            "--baseline",
            "0.80",
            "--candidate",
            "0.90",
            "--baseline-n",
            "25",
            "--candidate-n",
            "25",
        ).output
    )
    assert ev["gate"]["ok"] is True

    _run(runner, "shadow", lesson_id, "--agreement", "0.95")
    promoted = _json(_run(runner, "promote", lesson_id).output)
    assert promoted["ok"] is True

    active = _json(_run(runner, "active").output)
    assert [row["id"] for row in active["active"]] == [lesson_id]

    _run(runner, "rollback", lesson_id, "--reason", "precision dropped")
    assert _json(_run(runner, "active").output)["active"] == []


def test_a_negative_delta_blocks_promotion(env):
    runner, db_path = env
    lesson_id = _json(
        _run(
            runner,
            "propose",
            "--kind",
            "sink",
            "--evidence",
            _evidence_id(db_path),
            "--summary",
            "s",
        ).output
    )["lesson"]["id"]
    _run(
        runner,
        "evaluate",
        lesson_id,
        "--holdout",
        "arena",
        "--baseline",
        "0.90",
        "--candidate",
        "0.60",
        "--baseline-n",
        "30",
        "--candidate-n",
        "30",
    )
    result = _run(runner, "promote", lesson_id)
    assert result.exit_code != 0
    assert "below the" in result.output


def test_show_prints_the_trail_and_the_gate(env):
    runner, db_path = env
    lesson_id = _json(
        _run(
            runner,
            "propose",
            "--kind",
            "sink",
            "--evidence",
            _evidence_id(db_path),
            "--summary",
            "s",
        ).output
    )["lesson"]["id"]
    payload = _json(_run(runner, "show", lesson_id).output)
    assert payload["lesson"]["id"] == lesson_id
    assert payload["history"][0]["to_status"] == "candidate"
    assert payload["gate"]["ok"] is False
    assert "rollback_plan" in payload


def test_reject_requires_a_reason(env):
    runner, db_path = env
    lesson_id = _json(
        _run(
            runner,
            "propose",
            "--kind",
            "sink",
            "--evidence",
            _evidence_id(db_path),
            "--summary",
            "s",
        ).output
    )["lesson"]["id"]
    result = _run(runner, "reject", lesson_id, "--reason", "")
    assert result.exit_code != 0


def test_list_filters_by_status(env):
    runner, db_path = env
    _run(
        runner,
        "propose",
        "--kind",
        "sink",
        "--evidence",
        _evidence_id(db_path),
        "--summary",
        "s",
    )
    candidates = _json(_run(runner, "list", "--status", "candidate").output)
    promoted = _json(_run(runner, "list", "--status", "promoted").output)
    assert candidates["count"] == 1
    assert promoted["count"] == 0
