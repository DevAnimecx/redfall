"""Failure diagnostics. Sees VULN-015 (verbose error disclosure)."""

from __future__ import annotations

import json
import traceback

from flask import Blueprint, jsonify, request

bp = Blueprint("diagnostics", __name__, url_prefix="/api")


@bp.get("/debug")
def debug_echo():
    payload = request.args.get("payload", "{}")
    try:
        data = json.loads(payload)
        return jsonify({"value": data["nested"]["missing"]})
    except Exception:
        # VULN-015: the full traceback — paths, query fragments, internals — goes
        # back to whoever caused the failure.
        return jsonify({"error": traceback.format_exc()}), 500
