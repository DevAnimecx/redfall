"""Account reads. Sees VULN-016 (missing object-level authorisation)."""

from __future__ import annotations

from flask import Blueprint, jsonify

from .. import db
from ..authn import current_user

bp = Blueprint("users", __name__, url_prefix="/api/users")


@bp.get("/me")
def me():
    user = current_user()
    if user is None:
        return jsonify({"error": "authentication required"}), 401
    return jsonify(user)


@bp.get("/<int:user_id>")
def get_user(user_id: int):
    user = current_user()
    if user is None:
        return jsonify({"error": "authentication required"}), 401
    conn = db.connect()
    # VULN-016: any authenticated user can read any account by changing the id.
    row = conn.execute(
        "SELECT id, username, email, role, balance FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "no such user"}), 404
    return jsonify(dict(row))
