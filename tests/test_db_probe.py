"""The diagnostic database probe must fail fast, not inherit an indefinite wait.

`redfall doctor` calls `store.db.ping()` on every host. libpq has no default
connect timeout, so a database address that silently drops packets otherwise
freezes the command for the operating system's TCP timeout. The reserved
TEST-NET-1 address below is a real, unmodified socket attempt; no mock stands in
for a database.
"""

from __future__ import annotations

import time

from redfall.store.db import ping


def test_postgres_ping_fails_promptly_without_a_server():
    started = time.monotonic()
    ok, detail = ping("postgresql+psycopg://redfall:redfall@192.0.2.1:5432/redfall")
    elapsed = time.monotonic() - started

    assert ok is False
    assert detail
    assert elapsed < 10, f"probe took {elapsed:.1f}s instead of failing fast: {detail}"
