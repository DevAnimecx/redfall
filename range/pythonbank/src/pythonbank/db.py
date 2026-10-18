"""SQLite storage for pythonbank. Recreated from scratch at every boot.

The database lives outside the bank directory (in the system temp dir by
default, or `PYTHONBANK_DB`) so a run never leaves an artefact in the tree.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
from pathlib import Path

DEFAULT_DB = Path(tempfile.gettempdir()) / "pythonbank.sqlite3"

SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    department TEXT NOT NULL,
    balance REAL NOT NULL
);
CREATE TABLE transactions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    note TEXT NOT NULL
);
"""

SEED_USERS = (
    ("alice", "Alice!Passw0rd1", "alice@pythonbank.test", "user", "retail", 2500.0),
    ("bob", "Bob!Passw0rd22", "bob@pythonbank.test", "user", "retail", 1200.0),
    ("admin", "Adm1n!Passw0rd", "admin@pythonbank.test", "admin", "operations", 99999.0),
)


def db_path() -> Path:
    return Path(os.environ.get("PYTHONBANK_DB", str(DEFAULT_DB)))


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    return conn


def md5_hex(text: str) -> str:
    """The password hash this target uses. See VULN-004 in manifest.yaml."""
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def seed() -> None:
    path = db_path()
    if path.exists():
        path.unlink()
    conn = connect()
    conn.executescript(SCHEMA)
    for username, password, email, role, department, balance in SEED_USERS:
        conn.execute(
            "INSERT INTO users (username, password_hash, email, role, department, balance) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (username, md5_hex(password), email, role, department, balance),
        )
    conn.execute(
        "INSERT INTO transactions (user_id, amount, note) VALUES (1, 10.0, 'opening balance')"
    )
    conn.commit()
    conn.close()
