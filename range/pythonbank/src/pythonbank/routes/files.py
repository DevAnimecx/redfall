"""Upload and download. Sees VULN-009 (path traversal) and VULN-010 (file type)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from flask import Blueprint, Response, jsonify, request

from ..paths import PUBLIC_DIR

bp = Blueprint("files", __name__, url_prefix="/api/files")
# Uploads land in a runtime directory, not in the tree: a bank run must never
# leave an artefact behind for the next run (or the clean-tree checker) to find.
UPLOAD_DIR = Path(tempfile.gettempdir()) / "pythonbank-uploads"


@bp.post("/upload")
def upload():
    file = request.files.get("file")
    if file is None or not file.filename:
        return jsonify({"error": "file is required"}), 400
    target = UPLOAD_DIR / file.filename
    target.parent.mkdir(parents=True, exist_ok=True)
    # VULN-010: extension and content type are never checked.
    file.save(target)
    return jsonify({"stored": file.filename}), 201


@bp.get("/")
def download():
    name = request.args.get("name", "")
    # VULN-009: the name is joined onto the public dir and opened as-is, so
    # `../private/flag.txt` walks out of the intended directory.
    path = os.path.join(PUBLIC_DIR, name)
    with open(path, "rb") as handle:
        data = handle.read()
    return Response(data, mimetype="application/octet-stream")
