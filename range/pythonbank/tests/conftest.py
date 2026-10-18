"""pythonbank's own suite: a freshly seeded app per test."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

BANK_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BANK_ROOT / "src"))


@pytest.fixture()
def db_file(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "pythonbank-test.sqlite3"
    monkeypatch.setenv("PYTHONBANK_DB", str(path))
    return path


@pytest.fixture()
def app(db_file):
    from pythonbank.app import create_app

    application = create_app()
    application.config.update(TESTING=True)
    return application


@pytest.fixture()
def client(app):
    with app.test_client() as test_client:
        yield test_client
