"""Department reporting. Sees VULN-017 (the SQL is built in core.reports)."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from .. import db
from ..authn import current_user
from ..core import reports

bp = Blueprint("reports", __name__, url_prefix="/api/reports")


@bp.get("/summary")
def summary():
    user = current_user()
    if user is None:
        return jsonify({"error": "authentication required"}), 401
    department = request.args.get("department", "")
    conn = db.connect()
    rows = reports.department_summary(conn, department)
    conn.close()
    return jsonify({"rows": [dict(row) for row in rows]})
