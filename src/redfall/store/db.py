"""Postgres access for Redfall state.

The engine is created once per process. `create_all` is idempotent, so a fresh
database is provisioned on first use without a migration tool.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

_engine: Engine | None = None
_sessionmaker: sessionmaker[Session] | None = None


def _connect_args(database_url: str) -> dict[str, Any]:
    """Per-dialect connection arguments, kept separate so they can be asserted.

    A bounded connect timeout, for the same reason `ping` sets one: libpq waits
    for the operating system's TCP timeout otherwise, so a database that is
    simply not running makes every request hang for ~30s and then report a
    generic connection error. Any surface built on this engine — the CLI, the
    dashboard, MCP stdio — would stall instead of saying the database is down.
    """
    if database_url.startswith("postgresql"):
        return {"connect_timeout": 5}
    if database_url.startswith("sqlite"):
        # The console opens more than one connection; the default thread-bound
        # check rejects the one that did not create the table.
        return {"check_same_thread": False}
    return {}


def init_engine(database_url: str, *, echo: bool = False) -> Engine:
    """Create (or replace) the global engine and ensure the schema exists."""
    global _engine, _sessionmaker
    _engine = create_engine(
        database_url,
        pool_pre_ping=True,
        echo=echo,
        future=True,
        connect_args=_connect_args(database_url),
    )
    if database_url.startswith("sqlite"):
        # WAL lets the dashboard read while a scan writes; without it a
        # concurrent writer returns "database is locked" to the console.
        from sqlalchemy import event

        @event.listens_for(_engine, "connect")
        def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    _sessionmaker = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    Base.metadata.create_all(_engine)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("database engine not initialised; call init_engine(database_url) first")
    return _engine


@contextmanager
def session_scope() -> Iterator[Session]:
    """A transaction-scoped session: commit on success, roll back on error."""
    if _sessionmaker is None:
        raise RuntimeError("database engine not initialised; call init_engine(database_url) first")
    session = _sessionmaker()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def ping(database_url: str) -> tuple[bool, str]:
    """Check connectivity without touching the global engine.

    A diagnostic probe must not inherit libpq's indefinite wait. Without a
    connect timeout a host whose database address silently drops packets hangs
    `redfall doctor` for the operating system's TCP timeout (minutes), which
    makes a missing prerequisite look like a frozen command.
    """
    connect_args = {"connect_timeout": 3} if database_url.startswith("postgresql") else {}
    try:
        engine = create_engine(database_url, future=True, connect_args=connect_args)
        with engine.connect() as conn:
            version = conn.execute(text("SELECT version()")).scalar_one()
        engine.dispose()
        return True, str(version)
    except Exception as err:  # noqa: BLE001 - connectivity probes report, not raise
        return False, f"{type(err).__name__}: {err}"
