"""Registration and login. Sees VULN-001..004 in manifest.yaml."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from .. import db
from ..tokens import sign_token

bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@bp.post("/register")
def register():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    email = str(payload.get("email") or "")
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    conn = db.connect()
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing is not None:
        conn.close()
        return jsonify({"error": "user exists"}), 409
    # VULN-004: the password is stored as an unsalted MD5.
    password_hash = db.md5_hex(password)
    conn.execute(
        "INSERT INTO users (username, password_hash, email, role, department, balance) "
        "VALUES (?, ?, ?, 'user', 'retail', 0.0)",
        (username, password_hash, email),
    )
    conn.commit()
    conn.close()
    return jsonify({"created": username}), 201


@bp.post("/login")
def login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username") or "")
    password = str(payload.get("password") or "")
    password_hash = db.md5_hex(password)

    conn = db.connect()
    # VULN-001: the username is concatenated into the SQL string, so
    # `x' UNION SELECT ... -- ` authenticates as any seeded account.
    query = (
        "SELECT id, username, role, email FROM users "
        "WHERE username = '" + username + "' AND password_hash = '" + password_hash + "'"
    )
    row = conn.execute(query).fetchone()
    known = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if row is None:
        # VULN-003: unknown user and wrong password are distinguishable.
        if known is None:
            return jsonify({"error": "no such user"}), 404
        return jsonify({"error": "wrong password", "field": "password"}), 401

    # VULN-002: nothing throttles repeated attempts before they reach the query above.
    return jsonify(
        {
            "token": sign_token(row["username"], row["role"]),
            "user": {
                "id": row["id"],
                "username": row["username"],
                "role": row["role"],
                "email": row["email"],
            },
        }
    )
