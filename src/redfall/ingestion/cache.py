"""Reuse the parse of a file that has not changed since the last ingest.

Re-indexing a repository whose source barely moved should not re-parse
everything. The parse of a file is a pure function of its bytes and its path,
so it can be keyed on a hash of those and reused safely.

The key includes the path as well as the content: two files with identical bytes
at different paths can produce different symbols, because a route's mount prefix
and an import's resolution both depend on where the file sits.

Only the *parsed* result is cached, never a decision made from it. A cached
entry carries the same `FileSymbols` and `Taint` the parser would produce now,
so a cache hit and a cache miss are indistinguishable downstream. If the parser
changes — a new release, a patched grammar — the stored version stops matching
and everything is reparsed, rather than mixing two parsers' output in one
result.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .symbols import (
    CallSymbol,
    FileSymbols,
    FunctionSymbol,
    ImportSymbol,
    MountSymbol,
    RouteSymbol,
)
from .taint import Taint

# Bump when a parser's output shape changes. A stored entry from an older
# version is ignored rather than trusted, so an upgrade cannot serve a stale
# parse. This is the whole invalidation story, and it is deliberate: guessing
# which parser changes matter would eventually serve a wrong result.
CACHE_VERSION = 1


def content_key(path: str, source: bytes, *, language: str) -> str:
    """A stable identity for one file's parse.

    Path is part of the key because symbols are path-dependent: the same bytes
    mounted at a different prefix yield a different route table.
    """
    digest = hashlib.sha256()
    digest.update(f"v{CACHE_VERSION}\x00{language}\x00{path}\x00".encode("utf-8"))
    digest.update(source)
    return digest.hexdigest()


@dataclass(frozen=True)
class CachedParse:
    """What a previous ingest computed for one file's content."""

    language: str
    symbols: FileSymbols
    taints: list[Taint]
    line_count: int
    size_bytes: int


class ParseCache:
    """A file-backed cache of parse results, safe to use from worker threads.

    SQLite because the cache must survive the process: the point is to make the
    *next* scan cheaper, and an in-memory cache dies with the run that filled
    it. WAL lets the parallel ingest pass read while another writes.

    A cache that cannot be read is not an error. The parse is recomputed, which
    is what would have happened without a cache at all — refusing to scan because
    a cache file is corrupt would turn an optimisation into a dependency.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS parses (
                key TEXT PRIMARY KEY,
                language TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        self._conn.commit()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> CachedParse | None:
        """Return a stored parse, or None if absent or unreadable."""
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT language, payload FROM parses WHERE key = ?", (key,)
                ).fetchone()
        except sqlite3.Error:
            # A closed, locked or corrupt cache is treated as an empty one. The
            # scan reparses, which is what it would have done without a cache —
            # failing the ingest here would make the cache load-bearing.
            self.misses += 1
            return None
        if row is None:
            self.misses += 1
            return None
        try:
            language, payload = row
            data = json.loads(payload)
            parsed = _decode(language, data)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            # A entry we cannot read is treated as absent. The parse is redone.
            self.misses += 1
            return None
        self.hits += 1
        return parsed

    def put(self, key: str, parsed: CachedParse) -> None:
        """Store a parse. A failure to write never fails the ingest."""
        payload = json.dumps(_encode(parsed), separators=(",", ":"))
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO parses (key, language, payload) VALUES (?, ?, ?)",
                    (key, parsed.language, payload),
                )
                self._conn.commit()
        except sqlite3.Error:
            # Read-only filesystem, a locked database, a full disk: none of
            # these should stop a scan that has already parsed the file.
            return

    def prune(self, keep: int = 20000) -> int:
        """Bound the cache so it cannot grow without limit. Returns rows removed."""
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM parses").fetchone()[0]
            excess = total - keep
            if excess <= 0:
                return 0
            self._conn.execute(
                "DELETE FROM parses WHERE key IN (SELECT key FROM parses LIMIT ?)", (excess,)
            )
            self._conn.commit()
        return excess

    def stats(self) -> dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "entries": self._conn.execute("SELECT COUNT(*) FROM parses").fetchone()[0],
            "version": CACHE_VERSION,
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# -- serialisation ---------------------------------------------------------
#
# The cache stores plain JSON, not pickle. A cache file is data written by an
# earlier run and read back by a later one, and unpickling an arbitrary file is
# how a corrupted cache becomes arbitrary code execution.


def _encode(parsed: CachedParse) -> dict[str, Any]:
    symbols = parsed.symbols
    return {
        "line_count": parsed.line_count,
        "size_bytes": parsed.size_bytes,
        "path": symbols.path,
        "routes": [dataclasses.asdict(r) for r in symbols.routes],
        "functions": [dataclasses.asdict(f) for f in symbols.functions],
        "calls": [dataclasses.asdict(c) for c in symbols.calls],
        "imports": [dataclasses.asdict(i) for i in symbols.imports],
        "mounts": [dataclasses.asdict(m) for m in symbols.mounts],
        "taints": [dataclasses.asdict(t) for t in parsed.taints],
    }


def _decode(language: str, data: dict[str, Any]) -> CachedParse:
    """Rebuild the parsed types. Unknown keys are a version mismatch, not data.

    A field added to one of these dataclasses by a later release will not be in
    an older payload, so the entry is treated as absent and the file is
    reparsed — mixing generations of the type in one run would be worse than
    paying for the parse again.
    """
    try:
        symbols = FileSymbols(
            path=data["path"],
            routes=[RouteSymbol(**r) for r in data["routes"]],
            functions=[FunctionSymbol(**f) for f in data["functions"]],
            calls=[CallSymbol(**c) for c in data["calls"]],
            imports=[ImportSymbol(**i) for i in data["imports"]],
            mounts=[MountSymbol(**m) for m in data["mounts"]],
        )
        taints = [Taint(**t) for t in data["taints"]]
    except TypeError as err:
        raise ValueError(f"cached entry does not match the current types: {err}") from err
    return CachedParse(
        language=language,
        symbols=symbols,
        taints=taints,
        line_count=int(data["line_count"]),
        size_bytes=int(data["size_bytes"]),
    )
