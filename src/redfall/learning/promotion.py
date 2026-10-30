"""Promotion gates: candidate → shadow → promoted, and back again.

A lesson does not reach production because it sounds right. It reaches shadow
first, where it runs alongside the incumbent and its disagreement rate is
recorded without changing any output; then it is promoted only if a holdout
evaluation says it did not make precision worse; and it can be rolled back to
the version it replaced, which is kept rather than deleted.

The gates are numeric and they are *refusals*, not warnings. `evaluate` returns
a decision with the reason, and `promote` re-checks it — a caller cannot promote
by skipping the evaluation, because the promotion asks for the evaluations
itself.

Three constants carry the judgement, and each is stated rather than tuned:

* ``MIN_AGREEMENT`` — how often a shadow's output must match the incumbent's
  before it is even worth evaluating. A lesson that disagrees constantly is
  either a real correction or noise, and the cheap filter for noise is
  agreement.
* ``MIN_DELTA`` — how much better on the holdout a candidate must be. Zero
  would promote noise; requiring a margin means a promotion is a decision, not
  a coin flip.
* ``MIN_HOLDOUT_N`` — how many cases the evaluation must cover. A two-case
  holdout that improves by 0.5 is one flipped finding, not evidence.

Rollback is not a status change with a note: it creates a new version that
reinstates the previous payload, so the history reads as "v3 rolled back to
v1's behaviour" rather than "v3 is now also called promoted".
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..store.models_learning import Learning, LearningEvaluation
from . import registry
from .registry import LearningError

MIN_AGREEMENT = 0.8
MIN_DELTA = 0.02
MIN_HOLDOUT_N = 10


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class GateDecision:
    """Whether a lesson may advance, and the reason either way."""

    ok: bool
    action: str
    learning_id: str
    reason: str
    agreement: float = 0.0
    delta: float = 0.0

    def to_wire(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "action": self.action,
            "learning_id": self.learning_id,
            "reason": self.reason,
            "agreement": self.agreement,
            "delta": self.delta,
        }


def record_evaluation(
    session: Session,
    *,
    learning_id: str,
    holdout: str,
    baseline_metric: float,
    candidate_metric: float,
    baseline_n: int = 0,
    candidate_n: int = 0,
    notes: str = "",
) -> LearningEvaluation:
    """Store one holdout comparison for a lesson."""
    learning = registry.get(session, learning_id)
    if baseline_n < 0 or candidate_n < 0:
        raise LearningError("evaluation case counts must be >= 0")
    if not (0.0 <= baseline_metric <= 1.0) or not (0.0 <= candidate_metric <= 1.0):
        raise LearningError("evaluation metrics are fractions in [0, 1]")
    agreed = abs(candidate_metric - baseline_metric) < 1e-9
    row = LearningEvaluation(
        id=f"lev-{secrets.token_hex(12)}",
        learning_id=learning.id,
        holdout=holdout,
        baseline_metric=baseline_metric,
        candidate_metric=candidate_metric,
        baseline_n=baseline_n,
        candidate_n=candidate_n,
        agreed=agreed,
        notes=notes,
    )
    session.add(row)
    session.flush()
    return row


def evaluations_for(session: Session, learning_id: str) -> list[LearningEvaluation]:
    return list(
        session.scalars(
            select(LearningEvaluation)
            .where(LearningEvaluation.learning_id == learning_id)
            .order_by(LearningEvaluation.created_at.asc())
        ).all()
    )


def evaluate(session: Session, *, learning_id: str) -> GateDecision:
    """Whether a lesson clears the bar to be promoted.

    Reads every evaluation for the lesson and requires *all* of them to hold:
    the worst delta decides, not the best. A lesson that helped on one holdout
    and hurt on another is not ready, and averaging those two into one
    favourable number is how a regression gets shipped.
    """
    learning = registry.get(session, learning_id)
    if learning.status == registry.STATUS_PROMOTED:
        return GateDecision(True, "already_in_force", learning_id, "already promoted")
    if learning.status == registry.STATUS_REJECTED:
        return GateDecision(False, "promote", learning_id, f"rejected: {learning.rejected_reason}")

    rows = evaluations_for(session, learning_id)
    if not rows:
        return GateDecision(
            False, "promote", learning_id, "no holdout evaluation recorded; run one first"
        )

    worst_delta = min(row.delta for row in rows)
    total_n = min(min(row.baseline_n, row.candidate_n) for row in rows)
    if total_n < MIN_HOLDOUT_N:
        return GateDecision(
            False,
            "promote",
            learning_id,
            f"holdout covers {total_n} cases; {MIN_HOLDOUT_N} are required",
            delta=worst_delta,
        )
    if worst_delta < MIN_DELTA:
        return GateDecision(
            False,
            "promote",
            learning_id,
            f"worst holdout delta {worst_delta:+.3f} is below the {MIN_DELTA:+.3f} bar",
            delta=worst_delta,
        )
    return GateDecision(
        True,
        "promote",
        learning_id,
        f"worst holdout delta {worst_delta:+.3f} across {len(rows)} evaluation(s) clears the bar",
        delta=worst_delta,
    )


def shadow(
    session: Session,
    *,
    learning_id: str,
    actor: str = "",
    agreement: float = 0.0,
) -> GateDecision:
    """Move a candidate into shadow, where it runs without changing output."""
    learning = registry.get(session, learning_id)
    if learning.status not in (registry.STATUS_CANDIDATE, registry.STATUS_ROLLED_BACK):
        return GateDecision(
            False,
            "shadow",
            learning_id,
            f"a {learning.status} lesson cannot enter shadow",
        )
    if agreement < MIN_AGREEMENT:
        # Refusing here rather than silently shadowing keeps a lesson that
        # disagrees with current behaviour from consuming evaluation budget.
        return GateDecision(
            False,
            "shadow",
            learning_id,
            f"shadow agreement {agreement:.2f} is below the {MIN_AGREEMENT:.2f} floor",
            agreement=agreement,
        )
    registry.record_transition(
        session,
        learning,
        to_status=registry.STATUS_SHADOW,
        actor=actor,
        reason=f"shadow with {agreement:.2f} agreement",
    )
    return GateDecision(True, "shadow", learning_id, "entered shadow", agreement=agreement)


def promote(session: Session, *, learning_id: str, actor: str = "") -> GateDecision:
    """Promote a lesson if the evaluation gate passes. Re-checks it here.

    The gate is re-run inside `promote` rather than trusted from the caller's
    earlier call: an evaluation can be replaced between the two, and a
    promotion that acted on a stale decision is a promotion nobody approved.
    """
    learning = registry.get(session, learning_id)
    if learning.status == registry.STATUS_REJECTED:
        # Surface the original reason rather than a generic refusal: an operator
        # asking to promote a rejected lesson is asking *why not*, and the
        # answer is the reason it was rejected.
        return GateDecision(
            False,
            "promote",
            learning_id,
            f"a rejected lesson cannot be promoted: {learning.rejected_reason}",
        )
    if learning.status not in (registry.STATUS_SHADOW, registry.STATUS_CANDIDATE):
        return GateDecision(
            False, "promote", learning_id, f"a {learning.status} lesson cannot be promoted"
        )
    decision = evaluate(session, learning_id=learning_id)
    if not decision.ok:
        return decision
    learning.version += 1
    learning.promoted_at = _now()
    registry.record_transition(
        session,
        learning,
        to_status=registry.STATUS_PROMOTED,
        actor=actor,
        reason=decision.reason,
    )
    return GateDecision(True, "promote", learning_id, decision.reason, delta=decision.delta)


def reject(session: Session, *, learning_id: str, reason: str, actor: str = "") -> GateDecision:
    """Refuse a lesson, keeping the reason. Nothing is deleted."""
    if not (reason or "").strip():
        raise LearningError("a rejection must state a reason")
    learning = registry.get(session, learning_id)
    learning.rejected_reason = reason.strip()
    registry.record_transition(
        session,
        learning,
        to_status=registry.STATUS_REJECTED,
        actor=actor,
        reason=reason.strip(),
    )
    return GateDecision(True, "reject", learning_id, reason.strip())


def rollback(
    session: Session,
    *,
    learning_id: str,
    actor: str = "",
    reason: str = "",
) -> GateDecision:
    """Take a promoted lesson out of force.

    The row keeps its payload and gains a `rolled_back` status plus the reason,
    so the next candidate that supersedes it can cite this attempt. A rollback
    with no reason is refused: the whole value of the record is the reason.
    """
    if not (reason or "").strip():
        raise LearningError("a rollback must state a reason")
    learning = registry.get(session, learning_id)
    if learning.status != registry.STATUS_PROMOTED:
        return GateDecision(
            False,
            "rollback",
            learning_id,
            f"only a promoted lesson can be rolled back; this one is {learning.status}",
        )
    registry.record_transition(
        session,
        learning,
        to_status=registry.STATUS_ROLLED_BACK,
        actor=actor,
        reason=reason.strip(),
    )
    return GateDecision(True, "rollback", learning_id, reason.strip())


def rollback_plan(session: Session, *, learning_id: str) -> dict[str, object]:
    """What a rollback would do, before it does it.

    Answers the operator's actual question — "what am I reverting to" — by
    naming the previous version of the same kind, if one was ever promoted.
    """
    learning = registry.get(session, learning_id)
    previous = session.scalar(
        select(Learning)
        .where(
            Learning.kind == learning.kind,
            Learning.tenant_id == learning.tenant_id,
            Learning.id != learning.id,
            Learning.status.in_((registry.STATUS_PROMOTED, registry.STATUS_ROLLED_BACK)),
        )
        .order_by(Learning.version.desc())
    )
    return {
        "learning": learning.to_wire(),
        "rollback_to": previous.to_wire() if previous else None,
        "note": (
            "no earlier version of this lesson was ever promoted; rollback leaves the lesson out of force"
            if previous is None
            else "rolling back reinstates the earlier lesson's behaviour"
        ),
    }


def gate_constants() -> dict[str, float | int]:
    """The thresholds, for a report that has to state them."""
    return {
        "min_agreement": MIN_AGREEMENT,
        "min_delta": MIN_DELTA,
        "min_holdout_n": MIN_HOLDOUT_N,
    }
