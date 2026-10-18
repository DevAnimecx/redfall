"""URL fetch proxy. Sees VULN-011 (SSRF) and VULN-012 (SSRF to metadata)."""

from __future__ import annotations

import requests
from flask import Blueprint, jsonify, request

bp = Blueprint("proxy", __name__, url_prefix="/api")


@bp.post("/fetch")
def proxy_fetch():
    payload = request.get_json(silent=True) or {}
    url = str(payload.get("url") or "")
    try:
        # VULN-011/012: no scheme, host or address restrictions; the link-local
        # metadata range included, so the response chooses what the server reads.
        response = requests.get(url, timeout=5)
    except requests.RequestException as exc:
        return jsonify({"error": str(exc)}), 502
    return jsonify({"status": response.status_code, "body": response.text[:2000]})
