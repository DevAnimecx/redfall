"""Append-only, hash-chained evidence records.

A record is not a finding by itself. The grade says what kind of claim it
supports:

``E0`` model assertion, ``E1`` static path, ``E2`` dynamic observation,
``E3`` reproduction, ``E4`` reproduction with impact and regression evidence.

Only E3/E4 are reportable. The ledger refuses an E3/E4 record without the
execution id, observable, reproduction command and environment digest that make
it replayable. That is the mechanical part of the no-mock contract.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..store.models import Campaign, EvidenceRecord

EVIDENCE_GRADES = ("E0", "E1", "E2", "E3", "E4")
EVIDENCE_KINDS = frozenset(
    {"static", "dynamic", "execution", "artifact", "human", "environment", "tool", "test", "review"}
)
GENESIS_HASH = "0" * 64


class EvidenceError(RuntimeError):
    """An evidence record cannot be appended or the chain cannot be trusted."""


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    checked: int
    first_bad_id: str | None
    reason: str

    def to_wire(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "checked": self.checked,
            "first_bad_id": self.first_bad_id,
            "reason": self.reason,
        }


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _canonical(payload: dict[str, Any]) -> bytes:
    try:
        text = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
    except (TypeError, ValueError) as exc:
        raise EvidenceError(f"evidence payload is not JSON serialisable: {exc}") from exc
    return text.encode("utf-8")


def _hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(record)).hexdigest()


class EvidenceLedger:
    """Read and append evidence for a campaign.

    The ledger locks the campaign row on Postgres while appending. That makes
    ``seq`` and ``previous_hash`` a single serialized chain even when several
    workers finish at once. SQLite serializes writers itself; its dialect does
    not support ``FOR UPDATE``, so tests use the same code path without the
    clause.
    """

    def __init__(self, session: Session, *, clock: Callable[[], datetime] | None = None) -> None:
        self.session = session
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _dialect(self) -> str:
        try:
            return self.session.get_bind().dialect.name
        except Exception:
            return ""

    def _lock_campaign(self, campaign_id: str) -> Campaign:
        statement = select(Campaign).where(Campaign.id == campaign_id)
        if self._dialect() not in {"sqlite", ""}:
            statement = statement.with_for_update()
        campaign = self.session.execute(statement).scalar_one_or_none()
        if campaign is None:
            raise EvidenceError(f"no such campaign: {campaign_id}")
        return campaign

    def _require_campaign(self, campaign_id: str) -> None:
        exists = self.session.execute(
            select(Campaign.id).where(Campaign.id == campaign_id)
        ).scalar_one_or_none()
        if exists is None:
            raise EvidenceError(f"no such campaign: {campaign_id}")

    def append(
        self,
        campaign_id: str,
        *,
        grade: str,
        kind: str,
        claim: str,
        payload: dict[str, Any] | None = None,
        finding_id: str | None = None,
        artifacts: Sequence[str] | None = None,
        reproduce_command: str = "",
        environment_digest: str = "",
    ) -> EvidenceRecord:
        normalized_grade = self._grade(grade)
        normalized_kind = str(kind).strip().lower()
        if normalized_kind not in EVIDENCE_KINDS:
            raise EvidenceError(
                f"unknown evidence kind {kind!r}; valid: {', '.join(sorted(EVIDENCE_KINDS))}"
            )
        claim = str(claim).strip()
        if not claim:
            raise EvidenceError("evidence claim must not be empty")
        if payload is not None and not isinstance(payload, dict):
            raise EvidenceError("evidence payload must be an object")
        data = dict(payload or {})
        if artifacts is not None and (
            isinstance(artifacts, (str, bytes)) or not isinstance(artifacts, Sequence)
        ):
            raise EvidenceError("evidence artifacts must be a sequence of strings")
        artifact_list = [str(item) for item in (artifacts or [])]
        try:
            json.dumps(data, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise EvidenceError(f"evidence payload is not JSON serialisable: {exc}") from exc
        reproduce_command = str(reproduce_command).strip()
        environment_digest = str(environment_digest).strip()
        self._validate_grade(
            normalized_grade,
            data,
            reproduce_command=reproduce_command,
            environment_digest=environment_digest,
        )
        if finding_id is not None:
            finding_id = str(finding_id).strip() or None

        self._lock_campaign(campaign_id)
        last = self.session.execute(
            select(EvidenceRecord)
            .where(EvidenceRecord.campaign_id == campaign_id)
            .order_by(EvidenceRecord.seq.desc())
            .limit(1)
        ).scalar_one_or_none()
        seq = (last.seq if last is not None else 0) + 1
        previous_hash = last.content_hash if last is not None else GENESIS_HASH
        created_at = _utc(self._clock())
        body = {
            "campaign_id": campaign_id,
            "seq": seq,
            "finding_id": finding_id,
            "grade": normalized_grade,
            "kind": normalized_kind,
            "claim": claim,
            "payload": data,
            "artifacts": artifact_list,
            "reproduce_command": reproduce_command,
            "environment_digest": environment_digest,
            "previous_hash": previous_hash,
            "created_at": created_at.isoformat(),
        }
        record = EvidenceRecord(
            id=f"ev-{uuid.uuid4().hex}",
            campaign_id=campaign_id,
            seq=seq,
            finding_id=finding_id,
            grade=normalized_grade,
            kind=normalized_kind,
            claim=claim,
            payload=data,
            artifacts=artifact_list,
            reproduce_command=reproduce_command,
            environment_digest=environment_digest,
            previous_hash=previous_hash,
            content_hash=_hash(body),
            created_at=created_at,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def list(
        self,
        campaign_id: str,
        *,
        reportable_only: bool = False,
    ) -> list[EvidenceRecord]:
        self._require_campaign(campaign_id)
        statement = select(EvidenceRecord).where(EvidenceRecord.campaign_id == campaign_id)
        if reportable_only:
            statement = statement.where(EvidenceRecord.grade.in_(("E3", "E4")))
        statement = statement.order_by(EvidenceRecord.seq.asc())
        return list(self.session.execute(statement).scalars().all())

    def reportable(self, campaign_id: str) -> list[EvidenceRecord]:
        return self.list(campaign_id, reportable_only=True)

    def require_reportable(self, campaign_id: str) -> list[EvidenceRecord]:
        chain = self.verify(campaign_id)
        if not chain.ok:
            raise EvidenceError(f"evidence chain is broken: {chain.reason}")
        records = self.reportable(campaign_id)
        if not records:
            raise EvidenceError("no E3/E4 evidence is available for a report")
        return records

    def verify(self, campaign_id: str) -> ChainVerification:
        records = self.list(campaign_id)
        previous = GENESIS_HASH
        expected_seq = 1
        for record in records:
            if record.seq != expected_seq:
                return ChainVerification(
                    False,
                    expected_seq - 1,
                    record.id,
                    f"sequence gap: expected {expected_seq}, found {record.seq}",
                )
            if record.previous_hash != previous:
                return ChainVerification(
                    False,
                    expected_seq - 1,
                    record.id,
                    "previous hash does not match the preceding record",
                )
            body = {
                "campaign_id": record.campaign_id,
                "seq": record.seq,
                "finding_id": record.finding_id,
                "grade": record.grade,
                "kind": record.kind,
                "claim": record.claim,
                "payload": record.payload or {},
                "artifacts": list(record.artifacts or []),
                "reproduce_command": record.reproduce_command,
                "environment_digest": record.environment_digest,
                "previous_hash": record.previous_hash,
                "created_at": _utc(record.created_at).isoformat(),
            }
            if _hash(body) != record.content_hash:
                return ChainVerification(
                    False,
                    expected_seq - 1,
                    record.id,
                    "content hash does not match the record",
                )
            previous = record.content_hash
            expected_seq += 1
        return ChainVerification(True, len(records), None, "")

    @staticmethod
    def _grade(grade: str) -> str:
        normalized = str(grade).strip().upper()
        if normalized not in EVIDENCE_GRADES:
            raise EvidenceError(
                f"unknown evidence grade {grade!r}; valid: {', '.join(EVIDENCE_GRADES)}"
            )
        return normalized

    @staticmethod
    def _validate_grade(
        grade: str,
        payload: dict[str, Any],
        *,
        reproduce_command: str,
        environment_digest: str,
    ) -> None:
        if grade == "E1":
            useful = ("path", "file", "source", "symbol", "query")
            if not any(str(payload.get(key) or "").strip() for key in useful):
                raise EvidenceError("E1 evidence needs a path, file, source, symbol or query")
        if grade == "E2":
            observation = payload.get("observation")
            observations = payload.get("observations")
            if not str(observation or "").strip() and not observations:
                raise EvidenceError("E2 evidence needs a non-empty observation")
        if grade in {"E3", "E4"}:
            if not str(payload.get("execution_id") or "").strip():
                raise EvidenceError(f"{grade} evidence needs payload.execution_id")
            observable = payload.get("observable") or payload.get("expected_observable")
            if not str(observable or "").strip():
                raise EvidenceError(f"{grade} evidence needs an observable or expected_observable")
            if not reproduce_command:
                raise EvidenceError(f"{grade} evidence needs a reproduce_command")
            if not environment_digest:
                raise EvidenceError(f"{grade} evidence needs an environment_digest")
            if grade == "E4" and not str(payload.get("impact") or "").strip():
                raise EvidenceError("E4 evidence needs payload.impact")
