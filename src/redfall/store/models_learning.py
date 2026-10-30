"""Learning-loop rows: what was learned, from which verified outcome, and why.

The doctrine this schema enforces: **a lesson cites the E3/E4 evidence that
produced it.** There is no column for "model said so". A `Learning` row whose
`evidence_id` does not resolve to a reportable record cannot be promoted, and
`redfall.learning.registry` refuses to create one in the first place.

Three states, mirroring the rollout in `redfall.learning.promotion`:

* ``candidate`` — proposed from a verified outcome, not yet affecting anything.
* ``shadow`` — being evaluated alongside the incumbent, its effect recorded but
  not applied. A shadow that disagrees with the incumbent is a finding.
* ``promoted`` — in force. Promotion is versioned and a previous version is kept
  so a rollback has somewhere to go.

Nothing here is deleted. A rolled-back lesson keeps its row and its rejection
reason, because "we tried this and it made precision worse" is the most useful
thing the loop can remember.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Learning(Base):
    """One lesson, traced to the verified outcome that produced it.

    ``kind`` names what the lesson is about — a framework's route shape, a
    sanitiser that does work, a prompt that produced a better hypothesis. It is
    a string rather than an enum so a new kind does not need a migration, but
    ``redfall.learning.registry`` validates it against a known set so a typo
    cannot create a lesson nothing will ever read.
    """

    __tablename__ = "learnings"
    __table_args__ = (
        Index("ix_learnings_kind_status", "kind", "status"),
        UniqueConstraint("tenant_id", "fingerprint", name="uq_learnings_tenant_fingerprint"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    # The verified outcome this came from. Not nullable: a lesson with no
    # provenance is exactly the thing the doctrine forbids.
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    campaign_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Content-addressed so the same lesson proposed twice is the same row.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    summary: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)

    status: Mapped[str] = mapped_column(String(16), default="candidate", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)

    version: Mapped[int] = mapped_column(Integer, default=1)
    rollback_of: Mapped[str | None] = mapped_column(String(64), nullable=True)

    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_reason: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "kind": self.kind,
            "evidence_id": self.evidence_id,
            "campaign_id": self.campaign_id,
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "summary": self.summary,
            "payload": self.payload or {},
            "status": self.status,
            "confidence": self.confidence,
            "occurrences": self.occurrences,
            "version": self.version,
            "rollback_of": self.rollback_of,
            "promoted_at": self.promoted_at.isoformat() if self.promoted_at else None,
            "rejected_reason": self.rejected_reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class LearningEvaluation(Base):
    """One evaluation of one lesson, on one holdout.

    A promotion decision reads the evaluations, never a single number. Storing
    them separately means an operator can see that a lesson was promoted on two
    runs that agreed, or on five that were mixed — the difference matters and
    one averaged float would hide it.
    """

    __tablename__ = "learning_evaluations"
    __table_args__ = (Index("ix_learning_evaluations_learning", "learning_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    learning_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    holdout: Mapped[str] = mapped_column(String(128), default="")
    baseline_metric: Mapped[float] = mapped_column(Float, default=0.0)
    candidate_metric: Mapped[float] = mapped_column(Float, default=0.0)
    baseline_n: Mapped[int] = mapped_column(Integer, default=0)
    candidate_n: Mapped[int] = mapped_column(Integer, default=0)
    agreed: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    @property
    def delta(self) -> float:
        return self.candidate_metric - self.baseline_metric

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "learning_id": self.learning_id,
            "holdout": self.holdout,
            "baseline_metric": self.baseline_metric,
            "candidate_metric": self.candidate_metric,
            "delta": self.delta,
            "baseline_n": self.baseline_n,
            "candidate_n": self.candidate_n,
            "agreed": self.agreed,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class LearningEvent(Base):
    """An append-only record of every state change a lesson went through.

    Separate from the row's own status so a rollback, a re-promotion and a
    rejection are all visible in order. The `Learning` row says where a lesson
    is now; this says how it got there.
    """

    __tablename__ = "learning_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    learning_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    from_status: Mapped[str] = mapped_column(String(16), default="")
    to_status: Mapped[str] = mapped_column(String(16), default="")
    actor: Mapped[str] = mapped_column(String(128), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "learning_id": self.learning_id,
            "from_status": self.from_status,
            "to_status": self.to_status,
            "actor": self.actor,
            "reason": self.reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
