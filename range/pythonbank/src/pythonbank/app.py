"""pythonbank's application factory.

Deliberately vulnerable; see manifest.yaml for the seeded weaknesses. Boot with:

    PYTHONPATH=src python -m pythonbank.app          # listens on :4003
"""

from __future__ import annotations

import os

from flask import Flask, jsonify

from . import db
from .routes import (
    auth,
    config,
    diagnostics,
    export,
    files,
    proxy,
    redirect,
    reports,
    serialize,
    tools,
    transactions,
    users,
)

BLUEPRINTS = (
    auth,
    config,
    diagnostics,
    export,
    files,
    proxy,
    redirect,
    reports,
    serialize,
    tools,
    transactions,
    users,
)


def create_app() -> Flask:
    db.seed()
    app = Flask(__name__)
    for module in BLUEPRINTS:
        app.register_blueprint(module.bp)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "bank": "pythonbank"}), 200

    return app


def main() -> None:
    port = int(os.environ.get("PYTHONBANK_PORT", "4003"))
    create_app().run(
        host="127.0.0.1",
        port=port,
        threaded=True,
        debug=False,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
