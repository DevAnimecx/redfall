import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "range"))

TARGET = ROOT / "range" / "vulnbank"


@pytest.fixture(scope="session")
def postgres_url() -> str:
    """The explicit CI test database, or an honest skip.

    These tests create and drop tables. They must never fall back to a
    developer's default database just because a PostgreSQL service happens to
    be running. CI exports ``REDFALL_TEST_DATABASE_URL``; without it, a local
    run skips the database-backed tests instead of waiting on connection
    timeouts.
    """
    url = os.getenv("REDFALL_TEST_DATABASE_URL")
    if not url:
        pytest.skip("REDFALL_TEST_DATABASE_URL is not set; PostgreSQL test skipped")
    return url


@pytest.fixture(scope="session")
def redis_url() -> str:
    """A reachable Redis, or an honest skip.

    `StateStore` is built on Redis transactions, so its concurrency behaviour
    cannot be exercised against a stand-in. Without a server this skips rather
    than asserting against a fake that would pass whatever the test expected.
    """
    from redfall.store.state import StateStore

    url = os.getenv("REDFALL_REDIS_URL", "redis://localhost:6379/0")
    ok, detail = StateStore(url).ping()
    if not ok:
        pytest.skip(f"no Redis at {url} ({detail}); StateStore tests skipped")
    return url


@pytest.fixture(scope="session")
def vulnbank() -> Path:
    if not TARGET.exists():
        pytest.skip(f"range target missing at {TARGET}")
    return TARGET


@pytest.fixture(scope="session")
def ingest_result(vulnbank):
    """One real ingestion of the real target, shared by every test that needs it."""
    from redfall.ingestion.ingest import ingest

    return ingest("test-scan", vulnbank)
