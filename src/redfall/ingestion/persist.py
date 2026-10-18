"""Persistence of the ingestion graph."""

from __future__ import annotations

import hashlib
from pathlib import Path

from sqlalchemy.orm import Session

from ..store.models import Dep, FileRow, Symbol, TaintPath
from .ingest import IngestResult


def _sid(*parts: object) -> str:
    """Stable 16-hex id from a tuple of discriminating values."""
    joined = "|".join(str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def _language_of(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix in (".py", ".pyw"):
        return "python"
    if suffix in (".ts", ".tsx"):
        return "typescript"
    return "javascript"


def persist(result: IngestResult, session: Session) -> None:
    """Write the ingestion graph for one scan. Callers own the transaction.

    Ids include a per-kind ordinal so two identical calls on the same line (for
    example `fs.existsSync(p); fs.readFileSync(p)`) cannot collide on the PK.
    """
    for f in result.files:
        session.add(
            FileRow(
                id=f.id,
                scan_id=result.scan_id,
                path=f.path,
                language=_language_of(f.path),
                size_bytes=f.size_bytes,
                line_count=f.line_count,
            )
        )

        for i, r in enumerate(f.symbols.routes):
            session.add(
                Symbol(
                    id=_sid(f.id, "route", i, r.method, r.path, r.line),
                    scan_id=result.scan_id,
                    file_id=f.id,
                    kind="route",
                    name=f"{r.method} {r.path}",
                    line=r.line,
                    end_line=r.end_line,
                    method=r.method,
                    route=(result.mount_prefixes.get(f.path, "") + r.path),
                    middleware=r.middleware,
                    detail={"handler": r.handler, "receiver": r.receiver},
                )
            )
        for i, fn in enumerate(f.symbols.functions):
            session.add(
                Symbol(
                    id=_sid(f.id, "fn", i, fn.name, fn.line),
                    scan_id=result.scan_id,
                    file_id=f.id,
                    kind="function",
                    name=fn.name,
                    line=fn.line,
                    end_line=fn.end_line,
                    detail={"exported": fn.is_exported},
                )
            )
        for i, call in enumerate(f.symbols.calls):
            session.add(
                Symbol(
                    id=_sid(f.id, "call", i, call.kind, call.callee, call.line),
                    scan_id=result.scan_id,
                    file_id=f.id,
                    kind=f"call:{call.kind}",
                    name=call.callee,
                    line=call.line,
                    end_line=call.line,
                    detail={"enclosing": call.enclosing_function, "arg": call.arg_text[:400]},
                )
            )
        for i, imp in enumerate(f.symbols.imports):
            session.add(
                Symbol(
                    id=_sid(f.id, "imp", i, imp.name, imp.line),
                    scan_id=result.scan_id,
                    file_id=f.id,
                    kind="import",
                    name=imp.name,
                    line=imp.line,
                    detail={"source": imp.source, "default": imp.is_default},
                )
            )
        for i, mount in enumerate(f.symbols.mounts):
            session.add(
                Symbol(
                    id=_sid(f.id, "mount", i, mount.prefix, mount.line),
                    scan_id=result.scan_id,
                    file_id=f.id,
                    kind="mount",
                    name=f"{mount.prefix} -> {mount.local_name}",
                    line=mount.line,
                    end_line=mount.line,
                    detail={"local_name": mount.local_name, "prefix": mount.prefix},
                )
            )
        for i, t in enumerate(f.taints):
            session.add(
                TaintPath(
                    id=_sid(f.id, "taint", i, t.dedupe_key),
                    scan_id=result.scan_id,
                    file_id=f.id,
                    source=t.source,
                    sink=t.sink,
                    line=t.line,
                    symbol=t.symbol,
                    via=t.via,
                )
            )

    for d in result.dependencies:
        session.add(
            Dep(
                id=_sid(result.scan_id, "dep", d.name, d.is_dev),
                scan_id=result.scan_id,
                name=d.name,
                version=d.declared,
                resolved=d.resolved,
                is_dev=d.is_dev,
            )
        )
