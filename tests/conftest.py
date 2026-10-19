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
def vulnbank() -> Path:
    if not TARGET.exists():
        pytest.skip(f"range target missing at {TARGET}")
    return TARGET


@pytest.fixture(scope="session")
def ingest_result(vulnbank):
    """One real ingestion of the real target, shared by every test that needs it."""
    from redfall.ingestion.ingest import ingest

    return ingest("test-scan", vulnbank)
