"""Transactions, used by the CSV export proof."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from .. import db
from ..authn import current_user

bp = Blueprint("transactions", __name__, url_prefix="/api")


@bp.post("/transactions")
def create_transaction():
    user = current_user()
    if user is None:
        return jsonify({"error": "authentication required"}), 401
    payload = request.get_json(silent=True) or {}
    recipient_id = int(payload.get("to") or 0)
    amount = float(payload.get("amount") or 0)
    note = str(payload.get("note") or "")
    if recipient_id <= 0 or amount <= 0:
        return jsonify({"error": "to and amount must be positive"}), 400

    conn = db.connect()
    recipient = conn.execute("SELECT id FROM users WHERE id = ?", (recipient_id,)).fetchone()
    if recipient is None:
        conn.close()
        return jsonify({"error": "no such recipient"}), 404
    conn.execute(
        "INSERT INTO transactions (user_id, amount, note) VALUES (?, ?, ?)",
        (recipient_id, amount, note),
    )
    conn.commit()
    conn.close()
    return jsonify({"created": True}), 201
