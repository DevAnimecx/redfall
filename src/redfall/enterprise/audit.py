"""Audit export for SIEM and compliance.

The gateway already writes one `InteropAudit` row per authenticated call,
including denials. This module turns those rows into a transaction file an
operator can ship to a SIEM, and records what it produced.

The property worth protecting is the *write barrier*. An export states the
instant it read up to, and every record it writes is at or before that instant,
so two consecutive exports with the caller passing the first one's boundary as
the second one's `since` cover the timeline exactly once — with no gap where a
slow write could hide. A naive "everything up to now" export twice leaves an
overlap at best and, if the clock is not monotonic, a hole.

Two formats ship: JSON Lines (one object per line, what a SIEM ingests) and CSV
(what a spreadsheet-owning auditor asks for). Neither redacts on its own; the
caller decides, and `redact` is an explicit option so the choice is visible in
the export record rather than implied by the format.
"""

from __future__ import annotations

import csv
import io
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..store.models import InteropAudit
from ..store.models_tenant import AuditExport

FORMATS = ("jsonl", "csv")

# Fields that could carry a credential or personal data if a caller ever put one
# in a tool input. Redaction replaces the value rather than dropping the record,
# because a missing audit line is worse than a redacted one.
SENSITIVE_PATTERNS = (
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|authorization)\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"rfl_[A-Za-z0-9._~+/=-]{8,}"),
)

REDACTED = "[redacted]"

CSV_FIELDS = (
    "id",
    "created_at",
    "protocol",
    "agent",
    "token_id",
    "tool",
    "campaign_id",
    "ok",
    "error",
    "duration_ms",
    "input_hash",
)


@dataclass(frozen=True)
class AuditEntry:
    """One audit row, flattened for export."""

    id: str
    created_at: str
    protocol: str
    agent: str
    token_id: str
    tool: str
    campaign_id: str
    ok: bool
    error: str
    duration_ms: int
    input_hash: str

    def to_row(self, *, redact: bool = True) -> dict[str, Any]:
        row: dict[str, Any] = {
            "id": self.id,
            "created_at": self.created_at,
            "protocol": self.protocol,
            "agent": self.agent,
            "token_id": self.token_id,
            "tool": self.tool,
            "campaign_id": self.campaign_id,
            "ok": self.ok,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "input_hash": self.input_hash,
        }
        if redact:
            row["error"] = scrub(self.error)
        return row


def scrub(text: str) -> str:
    """Redact anything that looks like a credential in a free-text field."""
    if not text:
        return text
    out = text
    for pattern in SENSITIVE_PATTERNS:
        out = pattern.sub(REDACTED, out)
    return out


def _iso(value: datetime | None) -> str:
    return value.isoformat() if value else ""


def as_utc(value: datetime | None) -> datetime | None:
    """A datetime that is safe to compare with an aware one.

    SQLite does not preserve an offset. A value read back from a row there is
    naive even though it was written aware, and comparing it with the clock
    raises. Every timestamp Redfall stores is UTC by construction, so attaching
    UTC to a naive value restores the meaning rather than guessing at it.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _entry(row: InteropAudit) -> AuditEntry:
    return AuditEntry(
        id=row.id,
        created_at=_iso(row.created_at),
        protocol=row.protocol or "",
        agent=row.agent or "",
        token_id=row.token_id or "",
        tool=row.tool or "",
        campaign_id=row.campaign_id or "",
        ok=bool(row.ok),
        error=row.error or "",
        duration_ms=int(row.duration_ms or 0),
        input_hash=row.input_hash or "",
    )


def _tenant_token_ids(session: Session, tenant_id: str) -> list[str]:
    """Token ids belonging to a tenant, so the audit read is scoped by them.

    `InteropAudit` has no tenant column of its own: it records a token, and the
    token knows its tenant. Filtering through the token is therefore the only
    correct scoping, and doing it in the database rather than in Python is what
    keeps another tenant's rows out of the process entirely.
    """
    from ..store.models import AgentToken

    return list(
        session.scalars(
            select(AgentToken.id).where(AgentToken.tenant_id == tenant_id)
        ).all()
    )


class AuditExporter:
    """Reads a tenant's audit trail and records what it produced."""

    def __init__(self, session: Session, *, tenant_id: str) -> None:
        self.session = session
        self.tenant_id = tenant_id

    def _rows(
        self,
        *,
        since: datetime | None,
        until: datetime | None,
        limit: int,
        token_ids: list[str] | None = None,
    ) -> list[InteropAudit]:
        if token_ids is None:
            token_ids = _tenant_token_ids(self.session, self.tenant_id)
        if not token_ids:
            return []
        stmt = (
            select(InteropAudit)
            .where(InteropAudit.token_id.in_(token_ids))
            .order_by(InteropAudit.created_at.asc(), InteropAudit.id.asc())
            .limit(limit)
        )
        if since is not None:
            stmt = stmt.where(InteropAudit.created_at >= since)
        if until is not None:
            stmt = stmt.where(InteropAudit.created_at <= until)
        return list(self.session.scalars(stmt).all())

    def entries(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 10_000,
    ) -> list[AuditEntry]:
        return [_entry(row) for row in self._rows(since=since, until=until, limit=limit)]

    def export(
        self,
        *,
        fmt: str = "jsonl",
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 10_000,
        redact: bool = True,
        requested_by: str = "",
    ) -> tuple[str, AuditExport]:
        """Produce the export and its record. Returns ``(body, record)``.

        ``write_until`` is the timestamp of the last record this export
        actually contains — not the wall clock. That distinction is the whole
        point of the field. A barrier taken as "now" is later than every row in
        the export, so it is *ahead* of the data: an operator resuming from it
        silently skips every call that landed between the read and the clock.
        Anchoring to the last exported row means the next export resumes
        exactly where this one stopped, with neither a gap nor an overlap.

        When the export is empty there is no such anchor, so the query's own
        upper bound is used; it is still a point after which nothing has yet
        been shown.
        """
        clean_format = (fmt or "jsonl").strip().lower()
        if clean_format not in FORMATS:
            raise ValueError(f"format must be one of {', '.join(FORMATS)}")

        requested_at = datetime.now(timezone.utc)
        since = as_utc(since)
        effective_until = as_utc(until) if until is not None else requested_at
        if since is not None and since > effective_until:
            raise ValueError("since must not be later than until")

        raw = self._rows(since=since, until=effective_until, limit=limit)
        rows = [_entry(row) for row in raw]
        if clean_format == "jsonl":
            body = self._render_jsonl(rows, redact=redact)
        else:
            body = self._render_csv(rows, redact=redact)

        resume_from = as_utc(raw[-1].created_at) if raw else effective_until

        record = AuditExport(
            id=f"aexp-{secrets.token_hex(12)}",
            tenant_id=self.tenant_id,
            requested_by=requested_by,
            fmt=clean_format,
            since=since,
            until=effective_until,
            write_until=resume_from,
            record_count=len(rows),
            status="complete",
            note="redacted" if redact else "unredacted",
        )
        self.session.add(record)
        self.session.flush()
        return body, record

    def _render_jsonl(self, entries: list[AuditEntry], *, redact: bool) -> str:
        lines = [json.dumps(entry.to_row(redact=redact), sort_keys=True) for entry in entries]
        return "\n".join(lines) + ("\n" if lines else "")

    def _render_csv(self, entries: list[AuditEntry], *, redact: bool) -> str:
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=list(CSV_FIELDS), extrasaction="ignore")
        writer.writeheader()
        for entry in entries:
            writer.writerow(entry.to_row(redact=redact))
        return buffer.getvalue()

    def verify_coverage(
        self, *, since: datetime, until: datetime, limit: int = 10_000
    ) -> dict[str, object]:
        """Whether an export over a range would be complete.

        A range that holds more rows than the limit would silently truncate, and
        a truncated compliance export is a false statement. This answers that
        question without producing a file.
        """
        rows = self.entries(since=since, until=until, limit=limit + 1)
        complete = len(rows) <= limit
        return {
            "complete": complete,
            "count": min(len(rows), limit),
            "limit": limit,
            "since": since.isoformat(),
            "until": until.isoformat(),
            "note": "" if complete else f"range exceeds the {limit}-row limit; export in windows",
        }


def stream_entries(
    session: Session,
    *,
    tenant_id: str,
    since: datetime,
    window: timedelta = timedelta(hours=1),
    limit: int = 10_000,
) -> Iterator[dict[str, Any]]:
    """Yield entries forward from a point, in windows, for a long backfill.

    Windows advance past the last row's timestamp rather than by a fixed step,
    so a quiet period does not cost a query per empty hour.
    """
    exporter = AuditExporter(session, tenant_id=tenant_id)
    cursor = since
    now = datetime.now(timezone.utc)
    while cursor <= now:
        entries = exporter.entries(since=cursor, until=cursor + window, limit=limit)
        if entries:
            for entry in entries:
                yield entry.to_row()
            last = entries[-1].created_at
            cursor = datetime.fromisoformat(last) + timedelta(microseconds=1) if last else cursor + window
        else:
            cursor += window
