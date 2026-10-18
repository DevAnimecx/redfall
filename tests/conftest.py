import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "range"))

TARGET = ROOT / "range" / "vulnbank"


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
