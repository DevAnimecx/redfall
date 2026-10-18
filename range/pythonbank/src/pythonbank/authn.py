"""Who is calling: the bearer token resolved to a user row."""

from __future__ import annotations

from typing import Any

from flask import request

from . import db
from .tokens import parse_token


def current_user() -> dict[str, Any] | None:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    claims = parse_token(header[len("Bearer ") :])
    if claims is None:
        return None
    conn = db.connect()
    row = conn.execute(
        "SELECT id, username, role, email, balance FROM users WHERE username = ?",
        (str(claims.get("username") or ""),),
    ).fetchone()
    conn.close()
    return dict(row) if row is not None else None
