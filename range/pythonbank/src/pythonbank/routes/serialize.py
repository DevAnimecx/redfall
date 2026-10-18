"""Batch import. Sees VULN-008 (pickle over attacker-supplied bytes)."""

from __future__ import annotations

import base64
import pickle

from flask import Blueprint, jsonify, request

bp = Blueprint("imports", __name__, url_prefix="/api")


@bp.post("/import")
def import_object():
    payload = (request.get_json(silent=True) or {}).get("payload") or ""
    try:
        raw = base64.b64decode(str(payload))
    except (ValueError, TypeError):
        return jsonify({"error": "payload must be base64"}), 400
    # VULN-008: the bytes are unpickled, so the payload chooses the code that runs.
    obj = pickle.loads(raw)
    return jsonify({"result": repr(obj)[:200]})
