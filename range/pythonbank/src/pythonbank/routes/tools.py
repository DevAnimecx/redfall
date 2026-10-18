"""Admin tooling. Sees VULN-007 (command injection)."""

from __future__ import annotations

import subprocess

from flask import Blueprint, jsonify, request

from ..authn import current_user

bp = Blueprint("tools", __name__, url_prefix="/api/admin")


@bp.post("/exec")
def admin_exec():
    user = current_user()
    if user is None:
        return jsonify({"error": "authentication required"}), 401
    if user["role"] != "admin":
        return jsonify({"error": "admin required"}), 403
    payload = request.get_json(silent=True) or {}
    cmd = str(payload.get("cmd") or "")
    # VULN-007: the request body becomes a shell command line.
    completed = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    return jsonify(
        {"stdout": completed.stdout, "stderr": completed.stderr, "code": completed.returncode}
    )
