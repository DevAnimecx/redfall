"""Turning verified campaign outcomes into stored lessons.

The one rule this module exists to hold: **a lesson is derived from a
reportable evidence record, or it is not created.** `propose` reads the evidence
row itself, checks its grade, and refuses anything below E3. A caller cannot
pass a grade in — the grade is read from the record, not asserted by the
proposer, so a caller who believes their finding is solid cannot say so; the
ledger says so or nobody does.

That is the difference between a learning loop and a model that tells itself it
did well. Every lesson in the database can be walked back to an execution that
actually happened.

Deduplication is by content fingerprint over the lesson's *meaning* — kind plus
a normalised view of the payload — so the same lesson derived from two campaigns
raises `occurrences` on one row rather than creating two. `occurrences` is
therefore the honest evidence for how often a pattern was really observed, and
`confidence` is computed from it rather than declared.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..store.models import EvidenceRecord
from ..store.models_learning import Learning, LearningEvent

# What a lesson can be about. A closed set: a typo must not create a lesson
# that no consumer will ever read.
LESSON_KINDS = frozenset(
    {
        "route_shape",  # how a framework registers a route
        "sanitiser",  # a sanitiser that did or did not stop a flow
        "source",  # an input surface that carried attacker data
        "sink",  # a call that turned out to be exploitable
        "prompt",  # a hypothesis that led to a reproduction
        "payload",  # an exploit shape that worked
        "environment",  # a recipe fact that made a target boot
        "false_positive",  # a claim that did not reproduce, and why
    }
)

STATUS_CANDIDATE = "candidate"
STATUS_SHADOW = "shadow"
STATUS_PROMOTED = "promoted"
STATUS_REJECTED = "rejected"
STATUS_ROLLED_BACK = "rolled_back"
STATUSES = (STATUS_CANDIDATE, STATUS_SHADOW, STATUS_PROMOTED, STATUS_REJECTED, STATUS_ROLLED_BACK)

# Only these grades may be learned from. E0/E1/E2 are hypotheses; learning from
# them would let an unverified guess become durable policy.
LEARNABLE_GRADES = frozenset({"E3", "E4"})

# The number of independent observations at which confidence saturates. Chosen
# rather than derived: it says "five separate campaigns seeing the same thing is
# as sure as this loop gets without a holdout".
CONFIDENCE_SATURATION = 5


class LearningError(RuntimeError):
    """A lesson cannot be proposed, promoted or rolled back."""

    code = "learning_error"


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Bookkeeping keys that `propose` maintains on a lesson but which are not part
# of what the lesson *means*. Excluding them from the fingerprint is what lets
# a second campaign's sighting reinforce the first row instead of forking it.
_META_KEYS = frozenset({"sighted_in"})


def _fingerprint(kind: str, payload: dict[str, Any]) -> str:
    """A stable digest of what a lesson means.

    Sorted keys and a normalised value set, so a payload that differs only in
    list order fingerprints the same. Two campaigns observing the same route
    shape must land on one row, or `occurrences` counts nothing.

    Keys in `_META_KEYS` are stripped: they record who has seen the lesson, not
    what it says, and folding them in would make every new sighting a different
    lesson.
    """
    content = {key: value for key, value in payload.items() if key not in _META_KEYS}
    canonical = json.dumps(content, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(f"{kind}\x00{canonical}".encode("utf-8")).hexdigest()


def confidence_for(occurrences: int) -> float:
    """Confidence as a function of how many times a lesson was observed.

    A ratio rather than a curve with free parameters: one observation is 0.2,
    five saturate at 1.0, and the value is monotone so more evidence never
    reads as less certainty.
    """
    if occurrences <= 0:
        return 0.0
    return min(1.0, occurrences / CONFIDENCE_SATURATION)


@dataclass(frozen=True)
class Proposal:
    """What a caller hands to `propose`, before provenance is checked."""

    kind: str
    evidence_id: str
    summary: str
    payload: dict[str, Any]


def propose(
    session: Session,
    *,
    kind: str,
    evidence_id: str,
    summary: str,
    payload: dict[str, Any] | None = None,
    tenant_id: str = "",
    actor: str = "",
) -> tuple[Learning, bool]:
    """Create or reinforce a lesson. Returns ``(row, created)``.

    The evidence record is read here and its grade checked. A caller cannot
    supply a grade, and an evidence id that does not resolve is refused — which
    means a lesson in this table always has a real, reportable record behind it.
    """
    clean_kind = (kind or "").strip().lower()
    if clean_kind not in LESSON_KINDS:
        raise LearningError(
            f"unknown lesson kind {kind!r}; known: {', '.join(sorted(LESSON_KINDS))}"
        )
    clean_summary = (summary or "").strip()
    if not clean_summary:
        raise LearningError("a lesson must have a summary")
    clean_evidence = (evidence_id or "").strip()
    if not clean_evidence:
        raise LearningError("a lesson must cite the evidence it came from")

    record = session.get(EvidenceRecord, clean_evidence)
    if record is None:
        raise LearningError(f"no such evidence record: {clean_evidence}")
    if record.grade not in LEARNABLE_GRADES:
        raise LearningError(
            f"evidence {clean_evidence} is {record.grade}; only "
            f"{'/'.join(sorted(LEARNABLE_GRADES))} outcomes may be learned from"
        )

    data = dict(payload or {})
    try:
        json.dumps(data, ensure_ascii=False, default=str)
    except (TypeError, ValueError) as exc:
        raise LearningError(f"lesson payload is not serialisable: {exc}") from exc

    # Seed the sighting list from the first proposal, so "which campaigns saw
    # this" is complete from the start rather than listing only the campaigns
    # that happened to reinforce it after the first.
    if record.campaign_id:
        seen = list(data.get("sighted_in", []))
        if record.campaign_id not in seen:
            seen.append(record.campaign_id)
        data["sighted_in"] = seen

    fingerprint = _fingerprint(clean_kind, data)
    existing = session.scalar(
        select(Learning).where(
            Learning.tenant_id == tenant_id, Learning.fingerprint == fingerprint
        )
    )
    if existing is not None:
        existing.occurrences += 1
        existing.confidence = confidence_for(existing.occurrences)
        existing.updated_at = _now()
        # A second sighting from a second campaign is the strongest signal the
        # loop gets short of a holdout, so it is recorded, not averaged away.
        if record.campaign_id:
            seen = list((existing.payload or {}).get("sighted_in", []))
            if record.campaign_id not in seen:
                seen.append(record.campaign_id)
                existing.payload = {**(existing.payload or {}), "sighted_in": seen}
        session.flush()
        return existing, False

    row = Learning(
        id=f"lrn-{secrets.token_hex(12)}",
        tenant_id=tenant_id,
        kind=clean_kind,
        evidence_id=clean_evidence,
        campaign_id=record.campaign_id or "",
        finding_id=record.finding_id,
        fingerprint=fingerprint,
        summary=clean_summary,
        payload=data,
        status=STATUS_CANDIDATE,
        confidence=confidence_for(1),
        occurrences=1,
    )
    session.add(row)
    session.flush()
    _event(
        session,
        learning_id=row.id,
        from_status="",
        to_status=STATUS_CANDIDATE,
        actor=actor,
        reason=f"proposed from {record.grade} evidence {clean_evidence}",
    )
    return row, True


def _event(
    session: Session,
    *,
    learning_id: str,
    from_status: str,
    to_status: str,
    actor: str,
    reason: str,
) -> LearningEvent:
    row = LearningEvent(
        id=f"lev-{secrets.token_hex(12)}",
        learning_id=learning_id,
        from_status=from_status,
        to_status=to_status,
        actor=actor,
        reason=reason,
    )
    session.add(row)
    session.flush()
    return row


def record_transition(
    session: Session,
    learning: Learning,
    *,
    to_status: str,
    actor: str = "",
    reason: str = "",
) -> Learning:
    """Move a lesson to a new status, keeping the previous one in the log."""
    if to_status not in STATUSES:
        raise LearningError(f"unknown status {to_status!r}; known: {', '.join(STATUSES)}")
    previous = learning.status
    learning.status = to_status
    learning.updated_at = _now()
    if to_status == STATUS_REJECTED and not learning.rejected_reason:
        learning.rejected_reason = reason
    session.flush()
    _event(
        session,
        learning_id=learning.id,
        from_status=previous,
        to_status=to_status,
        actor=actor,
        reason=reason,
    )
    return learning


def get(session: Session, learning_id: str) -> Learning:
    row = session.get(Learning, learning_id)
    if row is None:
        raise LearningError(f"no such lesson: {learning_id}")
    return row


def list_learnings(
    session: Session,
    *,
    tenant_id: str = "",
    kind: str = "",
    status: str = "",
    limit: int = 200,
) -> list[Learning]:
    stmt = select(Learning).order_by(Learning.occurrences.desc(), Learning.created_at.desc()).limit(limit)
    if tenant_id:
        stmt = stmt.where(Learning.tenant_id == tenant_id)
    if kind:
        stmt = stmt.where(Learning.kind == kind.strip().lower())
    if status:
        stmt = stmt.where(Learning.status == status.strip().lower())
    return list(session.scalars(stmt).all())


def history(session: Session, learning_id: str) -> list[LearningEvent]:
    return list(
        session.scalars(
            select(LearningEvent)
            .where(LearningEvent.learning_id == learning_id)
            .order_by(LearningEvent.created_at.asc(), LearningEvent.id.asc())
        ).all()
    )


def active_lessons(
    session: Session,
    *,
    tenant_id: str = "",
    kind: str = "",
) -> list[Learning]:
    """The lessons currently in force, for a consumer to apply."""
    return list_learnings(session, tenant_id=tenant_id, kind=kind, status=STATUS_PROMOTED)
