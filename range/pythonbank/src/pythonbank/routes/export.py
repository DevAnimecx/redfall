"""CSV export. Sees VULN-014 (formula injection)."""

from __future__ import annotations

from flask import Blueprint, Response, jsonify

from .. import db
from ..authn import current_user

bp = Blueprint("export", __name__, url_prefix="/api/export")


@bp.get("/transactions.csv")
def export_csv():
    user = current_user()
    if user is None:
        return jsonify({"error": "authentication required"}), 401
    conn = db.connect()
    rows = conn.execute(
        "SELECT transactions.id AS id, users.username AS username, "
        "transactions.amount AS amount, transactions.note AS note "
        "FROM transactions JOIN users ON users.id = transactions.user_id "
        "ORDER BY transactions.id"
    ).fetchall()
    conn.close()

    lines = ["id,username,amount,note"]
    for row in rows:
        # VULN-014: fields are concatenated without CSV escaping, so a note
        # beginning `=` reaches the spreadsheet as a live formula.
        lines.append(f"{row['id']},{row['username']},{row['amount']},{row['note']}")
    return Response("\n".join(lines) + "\n", mimetype="text/csv")
