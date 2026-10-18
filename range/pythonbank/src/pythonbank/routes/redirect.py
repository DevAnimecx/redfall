"""Redirects. Sees VULN-013 (open redirect)."""

from __future__ import annotations

from flask import Blueprint, redirect, request

bp = Blueprint("redirects", __name__, url_prefix="/api")


@bp.get("/redirect")
def open_redirect():
    target = request.args.get("next", "/")
    # VULN-013: the destination comes from the query string with no allowlist.
    return redirect(target, code=302)
