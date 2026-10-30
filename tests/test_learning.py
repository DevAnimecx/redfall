"""The learning loop: provenance, dedup, gating, shadow, promotion, rollback.

The tests that carry the doctrine are the refusals. A learning loop that works
when it is fed good input is not the hard part; the hard part is that a model's
plausible-sounding output cannot become durable practice, and most of what
follows checks exactly that.

Everything runs against a real SQLite database and real evidence rows written
through the real ledger.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture()
def session(tmp_path):
    from redfall.store import db

    db.init_engine(f"sqlite:///{tmp_path / 'learning.db'}")
    with db.session_scope() as s:
        yield s


def _campaign(session, campaign_id: str = "cmp-1"):
    from redfall.store.models import Campaign

    existing = session.get(Campaign, campaign_id)
    if existing is not None:
        return existing
    row = Campaign(id=campaign_id, repo="/srv/app", tenant_id="ten-1")
    session.add(row)
    session.flush()
    return row


def _evidence(session, *, grade: str = "E4", campaign_id: str = "cmp-1") -> str:
    """Write a real evidence record of a given grade and return its id.

    The payload carries what the ledger's own validation demands for the grade,
    so these rows are the same shape a real reproduction produces. A test that
    fabricated an E4 record by bypassing that check would be testing the
    learning loop against evidence the ledger would never have accepted.
    """
    from redfall.evidence.ledger import EvidenceLedger

    _campaign(session, campaign_id)
    ledger = EvidenceLedger(session)
    payload: dict = {
        "status": 200,
        "execution_id": f"exe-{campaign_id}",
        "observable": "status 200 with body containing invoice-b",
    }
    if grade == "E4":
        payload["impact"] = "cross-tenant read of another principal's invoice"
    if grade == "E1":
        payload = {"path": "src/routes/invoices.py", "sink": "exec"}
    if grade == "E2":
        payload = {"observation": "the endpoint accepts an unvalidated id parameter"}

    record = ledger.append(
        campaign_id,
        grade=grade,
        kind="execution" if grade in {"E3", "E4"} else "static",
        claim="IDOR lets principal A read principal B's invoice",
        payload=payload,
        finding_id="fnd-1",
        artifacts=["response.http"],
        reproduce_command="redfall reproduce fnd-1",
        environment_digest="sha256:abc",
    )
    return record.id


# -- provenance: only verified outcomes may be learned from ------------------

def test_a_lesson_can_be_proposed_from_e4_evidence(session):
    from redfall.learning import registry

    evidence_id = _evidence(session, grade="E4")
    row, created = registry.propose(
        session,
        kind="route_shape",
        evidence_id=evidence_id,
        summary="Spring joins the class prefix onto the method path",
        payload={"framework": "spring", "shape": "class+method"},
    )
    assert created is True
    assert row.status == "candidate"
    assert row.evidence_id == evidence_id
    assert row.campaign_id == "cmp-1"


def test_a_lesson_can_be_proposed_from_e3_evidence(session):
    from redfall.learning import registry

    evidence_id = _evidence(session, grade="E3")
    row, created = registry.propose(
        session, kind="sink", evidence_id=evidence_id, summary="exec.Command is reachable"
    )
    assert created is True
    assert row.evidence_id == evidence_id


def test_a_hypothesis_grade_cannot_become_a_lesson(session):
    """E0/E1/E2 are hypotheses. Learning from them is how a guess hardens."""
    from redfall.learning import LearningError, registry

    for grade in ("E1", "E2"):
        evidence_id = _evidence(session, grade=grade)
        with pytest.raises(LearningError, match="only E3/E4"):
            registry.propose(
                session, kind="sink", evidence_id=evidence_id, summary="from a hypothesis"
            )


def test_a_lesson_without_an_evidence_id_is_refused(session):
    from redfall.learning import LearningError, registry

    with pytest.raises(LearningError, match="cite the evidence"):
        registry.propose(session, kind="sink", evidence_id="", summary="trust me")


def test_a_lesson_for_a_missing_evidence_record_is_refused(session):
    from redfall.learning import LearningError, registry

    with pytest.raises(LearningError, match="no such evidence record"):
        registry.propose(
            session, kind="sink", evidence_id="ev-does-not-exist", summary="invented"
        )


def test_a_caller_cannot_assert_a_grade(session):
    """The grade is read from the ledger; `propose` takes no grade argument."""
    import inspect

    from redfall.learning import registry

    params = set(inspect.signature(registry.propose).parameters)
    assert "grade" not in params, "a caller must not be able to declare its own evidence grade"


def test_an_unknown_lesson_kind_is_refused(session):
    from redfall.learning import LearningError, registry

    evidence_id = _evidence(session)
    with pytest.raises(LearningError, match="unknown lesson kind"):
        registry.propose(
            session, kind="vibes", evidence_id=evidence_id, summary="not a real kind"
        )


def test_a_lesson_with_an_empty_summary_is_refused(session):
    from redfall.learning import LearningError, registry

    evidence_id = _evidence(session)
    with pytest.raises(LearningError, match="must have a summary"):
        registry.propose(session, kind="sink", evidence_id=evidence_id, summary="   ")


# -- dedup and confidence ---------------------------------------------------

def test_the_same_lesson_twice_reinforces_one_row(session):
    from redfall.learning import registry

    first_ev = _evidence(session, campaign_id="cmp-1")
    _campaign(session, "cmp-2")
    second_ev = _evidence(session, campaign_id="cmp-2")

    payload = {"framework": "gin", "shape": "r.GET"}
    first, created_a = registry.propose(
        session, kind="route_shape", evidence_id=first_ev, summary="gin registers by call", payload=payload
    )
    second, created_b = registry.propose(
        session, kind="route_shape", evidence_id=second_ev, summary="gin registers by call", payload=payload
    )
    assert created_a is True
    assert created_b is False
    assert first.id == second.id
    assert second.occurrences == 2
    assert len(registry.list_learnings(session, kind="route_shape")) == 1


def test_payload_key_order_does_not_defeat_dedup(session):
    """A dict built in a different order is the same lesson."""
    from redfall.learning import registry

    ev_a = _evidence(session, campaign_id="cmp-1")
    _campaign(session, "cmp-2")
    ev_b = _evidence(session, campaign_id="cmp-2")

    registry.propose(
        session, kind="sink", evidence_id=ev_a, summary="s", payload={"a": 1, "b": 2}
    )
    _, created = registry.propose(
        session, kind="sink", evidence_id=ev_b, summary="s", payload={"b": 2, "a": 1}
    )
    assert created is False


def test_a_second_campaign_sighting_is_recorded(session):
    from redfall.learning import registry

    ev_a = _evidence(session, campaign_id="cmp-1")
    _campaign(session, "cmp-2")
    ev_b = _evidence(session, campaign_id="cmp-2")

    registry.propose(session, kind="sink", evidence_id=ev_a, summary="s", payload={"x": 1})
    row, _ = registry.propose(
        session, kind="sink", evidence_id=ev_b, summary="s", payload={"x": 1}
    )
    assert sorted(row.payload["sighted_in"]) == ["cmp-1", "cmp-2"]


def test_confidence_rises_with_occurrences_and_saturates():
    from redfall.learning import CONFIDENCE_SATURATION, confidence_for

    assert confidence_for(0) == 0.0
    assert confidence_for(1) < confidence_for(3)
    assert confidence_for(CONFIDENCE_SATURATION) == 1.0
    assert confidence_for(CONFIDENCE_SATURATION + 100) == 1.0


# -- the promotion gate -----------------------------------------------------

def test_a_candidate_with_no_evaluation_cannot_be_promoted(session):
    from redfall.learning import promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    decision = promotion.promote(session, learning_id=row.id)
    assert decision.ok is False
    assert "no holdout evaluation" in decision.reason
    assert registry.get(session, row.id).status == "candidate"


def test_a_holdout_that_is_too_small_cannot_promote(session):
    from redfall.learning import promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    promotion.record_evaluation(
        session,
        learning_id=row.id,
        holdout="arena-v1",
        baseline_metric=0.80,
        candidate_metric=0.95,
        baseline_n=3,
        candidate_n=3,
    )
    decision = promotion.promote(session, learning_id=row.id)
    assert decision.ok is False
    assert "cases" in decision.reason


def test_a_candidate_with_no_improvement_cannot_be_promoted(session):
    from redfall.learning import promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    promotion.record_evaluation(
        session,
        learning_id=row.id,
        holdout="arena-v1",
        baseline_metric=0.90,
        candidate_metric=0.90,
        baseline_n=20,
        candidate_n=20,
    )
    decision = promotion.promote(session, learning_id=row.id)
    assert decision.ok is False
    assert "below the" in decision.reason


def test_the_worst_holdout_decides_not_the_best(session):
    """A lesson that helped once and hurt once is not ready."""
    from redfall.learning import promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    promotion.record_evaluation(
        session,
        learning_id=row.id,
        holdout="arena-v1",
        baseline_metric=0.80,
        candidate_metric=0.95,
        baseline_n=20,
        candidate_n=20,
    )
    promotion.record_evaluation(
        session,
        learning_id=row.id,
        holdout="arena-v2",
        baseline_metric=0.90,
        candidate_metric=0.70,  # a regression on the second holdout
        baseline_n=20,
        candidate_n=20,
    )
    decision = promotion.promote(session, learning_id=row.id)
    assert decision.ok is False
    assert decision.delta < 0


def test_a_lesson_that_clears_the_gate_is_promoted(session):
    from redfall.learning import promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    promotion.record_evaluation(
        session,
        learning_id=row.id,
        holdout="arena-v1",
        baseline_metric=0.80,
        candidate_metric=0.90,
        baseline_n=25,
        candidate_n=25,
    )
    decision = promotion.promote(session, learning_id=row.id)
    assert decision.ok is True
    promoted = registry.get(session, row.id)
    assert promoted.status == "promoted"
    assert promoted.version == 2
    assert promoted.promoted_at is not None


def test_an_evaluation_metric_outside_zero_to_one_is_refused(session):
    from redfall.learning import LearningError, promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    with pytest.raises(LearningError, match="fractions in"):
        promotion.record_evaluation(
            session,
            learning_id=row.id,
            holdout="arena",
            baseline_metric=0.0,
            candidate_metric=1.5,
        )


# -- shadow -----------------------------------------------------------------

def test_a_candidate_enters_shadow_when_it_agrees_with_the_incumbent(session):
    from redfall.learning import promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    decision = promotion.shadow(session, learning_id=row.id, agreement=0.95)
    assert decision.ok is True
    assert registry.get(session, row.id).status == "shadow"


def test_a_lesson_that_disagrees_with_current_behaviour_is_not_shadowed(session):
    """Noise should not consume evaluation budget."""
    from redfall.learning import promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    decision = promotion.shadow(session, learning_id=row.id, agreement=0.4)
    assert decision.ok is False
    assert "agreement" in decision.reason
    assert registry.get(session, row.id).status == "candidate"


def test_a_promoted_lesson_cannot_enter_shadow_again(session):
    from redfall.learning import promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    promotion.record_evaluation(
        session,
        learning_id=row.id,
        holdout="arena",
        baseline_metric=0.8,
        candidate_metric=0.9,
        baseline_n=20,
        candidate_n=20,
    )
    promotion.promote(session, learning_id=row.id)
    decision = promotion.shadow(session, learning_id=row.id, agreement=0.99)
    assert decision.ok is False


# -- rejection and rollback -------------------------------------------------

def test_a_rejection_must_state_a_reason(session):
    from redfall.learning import LearningError, promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    with pytest.raises(LearningError, match="must state a reason"):
        promotion.reject(session, learning_id=row.id, reason="   ")


def test_a_rejection_keeps_the_reason_and_blocks_promotion(session):
    from redfall.learning import promotion, registry

    row, _ = registry.propose(
        session, kind="false_positive", evidence_id=_evidence(session), summary="s"
    )
    promotion.record_evaluation(
        session,
        learning_id=row.id,
        holdout="arena",
        baseline_metric=0.8,
        candidate_metric=0.95,
        baseline_n=20,
        candidate_n=20,
    )
    promotion.reject(
        session, learning_id=row.id, reason="the holdout leaked into training"
    )
    decision = promotion.promote(session, learning_id=row.id)
    assert decision.ok is False
    assert "leaked into training" in decision.reason


def test_a_rollback_must_state_a_reason(session):
    from redfall.learning import LearningError, promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    with pytest.raises(LearningError, match="must state a reason"):
        promotion.rollback(session, learning_id=row.id, reason="")


def test_only_a_promoted_lesson_can_be_rolled_back(session):
    from redfall.learning import promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    decision = promotion.rollback(session, learning_id=row.id, reason="changed my mind")
    assert decision.ok is False
    assert "only a promoted lesson" in decision.reason


def test_a_rolled_back_lesson_leaves_force_and_keeps_its_reason(session):
    from redfall.learning import promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    promotion.record_evaluation(
        session,
        learning_id=row.id,
        holdout="arena",
        baseline_metric=0.8,
        candidate_metric=0.9,
        baseline_n=20,
        candidate_n=20,
    )
    promotion.promote(session, learning_id=row.id)
    assert [r.id for r in registry.active_lessons(session, kind="sink")] == [row.id]

    promotion.rollback(
        session, learning_id=row.id, reason="precision dropped in production"
    )
    rolled = registry.get(session, row.id)
    assert rolled.status == "rolled_back"
    assert registry.active_lessons(session, kind="sink") == []


def test_rollback_plan_names_what_it_would_revert_to(session):
    from redfall.learning import promotion, registry

    older, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="first"
    )
    promotion.record_evaluation(
        session, learning_id=older.id, holdout="a", baseline_metric=0.8, candidate_metric=0.9,
        baseline_n=20, candidate_n=20,
    )
    promotion.promote(session, learning_id=older.id)

    newer, _ = registry.propose(
        session,
        kind="sink",
        evidence_id=_evidence(session, campaign_id="cmp-2"),
        summary="second",
        payload={"different": True},
    )
    plan = promotion.rollback_plan(session, learning_id=newer.id)
    assert plan["rollback_to"]["id"] == older.id


# -- the audit trail of state changes ---------------------------------------

def test_every_state_change_is_recorded_in_order(session):
    from redfall.learning import promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    promotion.shadow(session, learning_id=row.id, agreement=0.9)
    promotion.record_evaluation(
        session, learning_id=row.id, holdout="a", baseline_metric=0.8, candidate_metric=0.9,
        baseline_n=20, candidate_n=20,
    )
    promotion.promote(session, learning_id=row.id)
    promotion.rollback(session, learning_id=row.id, reason="regression")

    trail = [(e.from_status, e.to_status) for e in registry.history(session, row.id)]
    assert trail == [
        ("", "candidate"),
        ("candidate", "shadow"),
        ("shadow", "promoted"),
        ("promoted", "rolled_back"),
    ]


def test_the_gate_constants_are_reported_not_hidden():
    from redfall.learning import gate_constants

    constants = gate_constants()
    assert set(constants) == {"min_agreement", "min_delta", "min_holdout_n"}
    assert constants["min_holdout_n"] > 0


# -- isolation between tenants ----------------------------------------------

def test_lessons_are_scoped_by_tenant(session):
    from redfall.learning import registry

    ev = _evidence(session)
    registry.propose(
        session, kind="sink", evidence_id=ev, summary="acme lesson", tenant_id="ten-1", payload={"p": 1}
    )
    registry.propose(
        session, kind="sink", evidence_id=ev, summary="globex lesson", tenant_id="ten-2", payload={"p": 1}
    )
    assert len(registry.list_learnings(session, tenant_id="ten-1")) == 1
    assert len(registry.list_learnings(session, tenant_id="ten-2")) == 1


def test_active_lessons_never_expose_a_rejected_one(session):
    from redfall.learning import promotion, registry

    row, _ = registry.propose(
        session, kind="sink", evidence_id=_evidence(session), summary="s"
    )
    promotion.reject(session, learning_id=row.id, reason="no basis")
    assert registry.active_lessons(session, kind="sink") == []
