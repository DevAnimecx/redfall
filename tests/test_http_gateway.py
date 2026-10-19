"""The HTTP/OpenAPI gateway: auth, scopes, quota, audit, artifacts and trust."""

from __future__ import annotations

import json
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from redfall.interop import artifacts
from redfall.interop.auth import create_token, revoke_token
from redfall.interop.http_server import InteropHTTPServer
from redfall.interop.tools import ToolRegistry
from redfall.store.models import Base


def request(
    base_url: str,
    method: str,
    path: str,
    *,
    body: dict | None = None,
    token: str = "",
    timeout: float = 20.0,
) -> tuple[int, dict, dict[str, str]]:
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    target = path if path.startswith(("http://", "https://")) else base_url + path
    req = Request(target, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=timeout) as response:
            raw = response.read()
            return int(response.status), json.loads(raw) if raw else {}, {
                key.lower(): value for key, value in response.headers.items()
            }
    except HTTPError as exc:
        raw = exc.read()
        return int(exc.code), json.loads(raw) if raw else {}, {
            key.lower(): value for key, value in exc.headers.items()
        }


@pytest.fixture()
def gateway(tmp_path, monkeypatch):
    monkeypatch.setenv("REDFALL_ALLOWED_ROOTS", str(tmp_path))
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'gateway.db'}",
        future=True,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    registry = ToolRegistry(Session)
    server = InteropHTTPServer(
        ("127.0.0.1", 0),
        registry=registry,
        session_factory=Session,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    with Session() as session:
        admin, admin_token = create_token(
            session, name="admin", scopes=["read", "execute", "admin"]
        )
        reader, reader_token = create_token(session, name="reader", scopes=["read"])
        quota, quota_token = create_token(
            session, name="quota", scopes=["read"], quota_per_hour=1
        )
        session.commit()
        tokens = {
            "admin": admin_token,
            "reader": reader_token,
            "quota": quota_token,
            "admin_id": admin.id,
            "reader_id": reader.id,
            "quota_id": quota.id,
        }
    try:
        yield base_url, Session, registry, tokens
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        engine.dispose()


def test_health_is_public_and_checks_the_database(gateway):
    base_url, _Session, _registry, _tokens = gateway
    status, body, _headers = request(base_url, "GET", "/healthz")
    assert status == 200
    assert body["ok"] is True
    assert body["database"] == "ok"


def test_openapi_is_generated_from_the_live_registry(gateway):
    base_url, _Session, registry, _tokens = gateway
    status, body, _headers = request(base_url, "GET", "/v1/openapi.json")
    assert status == 200
    assert body["openapi"].startswith("3.1")
    assert body["x-redfall-tool-count"] == len(registry.specs())
    health_path = body["paths"]["/v1/tools/redfall_health"]["post"]
    assert health_path["x-redfall-scope"] == "read"
    graph_path = body["paths"]["/v1/tools/redfall_graph_index"]["post"]
    assert graph_path["x-redfall-scope"] == "execute"


def test_tool_listing_requires_a_bearer_token(gateway):
    base_url, _Session, _registry, tokens = gateway
    status, body, headers = request(base_url, "GET", "/v1/tools")
    assert status == 401
    assert body["error"]["code"] == "unauthorized"
    assert headers.get("www-authenticate") == "Bearer"
    status, body, _headers = request(
        base_url, "GET", "/v1/tools", token=tokens["reader"]
    )
    assert status == 200
    assert len(body["tools"]) >= 44


def test_tool_call_is_trust_labelled_and_audited(gateway):
    base_url, Session, _registry, tokens = gateway
    status, body, headers = request(
        base_url,
        "POST",
        "/v1/tools/redfall_health",
        body={},
        token=tokens["reader"],
    )
    assert status == 200
    assert body["protocol"] == "http"
    assert body["tool"] == "redfall_health"
    assert body["trust"] == "untrusted-repository-data"
    assert body["result"]["ok"] is True
    assert headers["x-redfall-trust"] == "untrusted-repository-data"
    with Session() as session:
        from redfall.interop.audit import list_calls

        calls = list_calls(session)
    assert any(
        call.tool == "redfall_health" and call.agent == "reader" and call.ok
        for call in calls
    )


def test_graph_index_runs_real_work_over_http(gateway, tmp_path):
    base_url, _Session, _registry, tokens = gateway
    target = tmp_path / "service"
    target.mkdir()
    (target / "app.py").write_text("def ping():\n    return 'pong'\n", encoding="utf-8")
    status, body, _headers = request(
        base_url,
        "POST",
        "/v1/tools/redfall_graph_index",
        body={"target": str(target), "label": "http-contract"},
        token=tokens["admin"],
        timeout=30.0,
    )
    assert status == 200, body
    snapshot = body["result"]["snapshot"]
    assert snapshot["status"] == "complete"
    assert snapshot["nodes"] >= 1


def test_scope_denial_is_403_and_is_audited(gateway, tmp_path):
    base_url, Session, _registry, tokens = gateway
    target = tmp_path / "service"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    status, body, _headers = request(
        base_url,
        "POST",
        "/v1/tools/redfall_graph_index",
        body={"target": str(target)},
        token=tokens["reader"],
    )
    assert status == 403
    assert body["error"]["code"] == "forbidden"
    with Session() as session:
        from redfall.interop.audit import list_calls

        denied = [
            call
            for call in list_calls(session)
            if call.agent == "reader" and call.tool == "redfall_graph_index"
        ]
    assert denied and denied[0].ok is False
    assert "requires scope 'execute'" in denied[0].error


def test_unknown_tool_is_404(gateway):
    base_url, _Session, _registry, tokens = gateway
    status, body, _headers = request(
        base_url,
        "POST",
        "/v1/tools/redfall_no_such_tool",
        body={},
        token=tokens["admin"],
    )
    assert status == 404
    assert body["error"]["code"] == "unknown_tool"


def test_hourly_quota_returns_429(gateway):
    base_url, _Session, _registry, tokens = gateway
    first, first_body, _headers = request(
        base_url,
        "POST",
        "/v1/tools/redfall_health",
        body={},
        token=tokens["quota"],
    )
    assert first == 200, first_body
    second, second_body, _headers = request(
        base_url,
        "POST",
        "/v1/tools/redfall_health",
        body={},
        token=tokens["quota"],
    )
    assert second == 429
    assert second_body["error"]["code"] == "quota_exceeded"


def test_audit_requires_admin_scope(gateway):
    base_url, _Session, _registry, tokens = gateway
    status, _body, _headers = request(
        base_url, "GET", "/v1/audit", token=tokens["reader"]
    )
    assert status == 403
    status, body, _headers = request(
        base_url, "GET", "/v1/audit?limit=5", token=tokens["admin"]
    )
    assert status == 200
    assert isinstance(body["calls"], list)


def test_signed_artifact_url_serves_the_stored_copy_and_rejects_tampering(gateway):
    base_url, Session, _registry, _tokens = gateway
    with Session() as session:
        row = artifacts.store_artifact(
            session,
            task_id="task-test",
            tool="redfall_health",
            payload={"ok": True, "database": "ok"},
        )
        secret = artifacts.artifact_secret(session)
        session.commit()
        artifact_id = row.id
        payload = request(base_url, "GET", artifacts.signed_url(base_url, artifact_id, secret))
        assert payload[0] == 200
        assert payload[1]["artifact"]["sha256"] == row.sha256
        assert payload[1]["trust"] == "untrusted-repository-data"

        good_sig = artifacts.sign(secret, artifact_id, 9999999999)
        bad = request(
            base_url,
            "GET",
            f"/v1/artifacts/{artifact_id}?expires=9999999999&sig={'0' * 64}",
        )
        assert bad[0] == 403
        assert good_sig


def test_revoked_token_is_rejected(gateway):
    base_url, Session, _registry, _tokens = gateway
    with Session() as session:
        row, token = create_token(session, name="revoked", scopes=["read"])
        session.commit()
        token_id = row.id
    assert request(base_url, "GET", "/v1/tools", token=token)[0] == 200
    with Session() as session:
        revoke_token(session, token_id=token_id)
        session.commit()
    status, body, _headers = request(base_url, "GET", "/v1/tools", token=token)
    assert status == 401
    assert body["error"]["code"] == "unauthorized"
