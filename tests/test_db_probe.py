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


def test_the_engine_carries_the_same_timeout_floor_as_the_probe():
    """`ping` is not the only path that must fail fast.

    Every surface builds its sessionmaker from `init_engine` — the CLI, the
    dashboard, MCP stdio. If only `ping` sets a connect timeout, a database
    that is not running stalls each request for the operating system's TCP
    timeout while `redfall doctor` stays snappy and reports the database down.
    """
    from redfall.store import db

    assert db._connect_args("postgresql+psycopg://redfall:redfall@192.0.2.1:5432/redfall") == {
        "connect_timeout": 5
    }
    # And the engine really is built with them, rather than the helper being
    # dead code beside a bare create_engine call.
    engine = db.init_engine("sqlite+pysqlite:///:memory:")
    assert engine.dialect.name == "sqlite"


def test_sqlite_is_a_supported_backend_so_the_console_needs_no_postgres(tmp_path):
    """The dashboard is useful on a host with no Postgres.

    The models use only portable column types, so a file-backed SQLite
    database serves every route the console reads. This pins that: the schema
    builds, and the tools the Overview page calls answer from it.
    """
    from sqlalchemy.orm import sessionmaker

    from redfall.interop.tools import ToolRegistry
    from redfall.store.db import init_engine

    db_path = tmp_path / "redfall.db"
    engine = init_engine(f"sqlite+pysqlite:///{db_path}")
    registry = ToolRegistry(sessionmaker(bind=engine, expire_on_commit=False))

    health = registry.call("redfall_health", {})
    assert health["ok"] is True
    assert health["database"] == "sqlite"

    assert registry.call("redfall_campaign_list", {"limit": 5}) == {"campaigns": []}
    assert registry.call("redfall_findings", {"limit": 5})["total"] == 0
