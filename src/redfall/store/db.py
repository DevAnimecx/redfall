"""Postgres access for Redfall state.

The engine is created once per process. `create_all` is idempotent, so a fresh
database is provisioned on first use without a migration tool.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

_engine: Engine | None = None
_sessionmaker: sessionmaker[Session] | None = None


def init_engine(database_url: str, *, echo: bool = False) -> Engine:
    """Create (or replace) the global engine and ensure the schema exists."""
    global _engine, _sessionmaker
    _engine = create_engine(database_url, pool_pre_ping=True, echo=echo, future=True)
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
    """Check connectivity without touching the global engine."""
    try:
        engine = create_engine(database_url, future=True)
        with engine.connect() as conn:
            version = conn.execute(text("SELECT version()")).scalar_one()
        engine.dispose()
        return True, str(version)
    except Exception as err:  # noqa: BLE001 - connectivity probes report, not raise
        return False, f"{type(err).__name__}: {err}"
