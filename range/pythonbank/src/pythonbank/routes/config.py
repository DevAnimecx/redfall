"""Configuration endpoint. Sees VULN-006 (secret exposure)."""

from __future__ import annotations

import os

from flask import Blueprint, jsonify

from ..tokens import TOKEN_SECRET

bp = Blueprint("config", __name__, url_prefix="/api")


@bp.get("/config")
def get_config():
    # VULN-006: the signing secret — and anything PYTHONBANK_* in the
    # environment — is served without any check.
    return jsonify(
        {
            "token_secret": TOKEN_SECRET,
            "env": {k: v for k, v in os.environ.items() if k.startswith("PYTHONBANK_")},
            "bank_version": "pythonbank 1.0",
        }
    )
