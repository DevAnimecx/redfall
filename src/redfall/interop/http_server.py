"""The HTTP/OpenAPI + A2A gateway.

One server exposes three surfaces over one address:

* ``/v1/tools/{name}`` — every RedFall tool as a JSON POST, described by the
  generated OpenAPI document at ``/v1/openapi.json``;
* ``/a2a/v1`` — A2A v1.0 JSON-RPC (``SendMessage``, ``GetTask``, ...), with
  SSE for ``SendStreamingMessage`` and ``SubscribeToTask``;
* ``/.well-known/agent-card.json`` — the public A2A Agent Card.

Authentication is a bearer token looked up by SHA-256 digest in the database.
Every authenticated call is authorized against the tool's required scope,
quota-checked, audited and executed against real state.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterator
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ..config import load_config
from ..store.db import init_engine
from ..store.models import AgentToken
from ..version import __version__
from . import artifacts, audit
from .a2a import (
    A2AError,
    A2AService,
    build_agent_card,
    stream_envelope,
)
from .auth import (
    AuthError,
    QuotaError,
    ScopeError,
    authenticate,
    authorize_tool,
    grant_satisfies,
    identity_of,
)
from .openapi import build_openapi
from .tools import ToolError, ToolRegistry

TRUST_LABEL = "untrusted-repository-data"
MAX_BODY_BYTES = 8 * 1024 * 1024


class RequestError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class Gateway:
    def __init__(
        self,
        registry: ToolRegistry,
        session_factory: Any,
        *,
        base_url: str,
        verbose: bool = False,
        max_workers: int = 2,
    ) -> None:
        self.registry = registry
        self.session_factory = session_factory
        self.base_url = base_url.rstrip("/")
        self.verbose = verbose
        self.a2a = A2AService(
            session_factory,
            registry,
            base_url=self.base_url,
            max_workers=max_workers,
        )
        self.openapi = build_openapi(registry, base_url=self.base_url)

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def close(self) -> None:
        self.a2a.close()

    def database_ok(self) -> bool:
        try:
            with self.session() as session:
                session.execute(select(1))
            return True
        except Exception:  # noqa: BLE001 - health must report an unavailable database
            return False

    def record_call(
        self,
        *,
        name: str,
        arguments: dict[str, Any],
        agent: str,
        token_id: str | None,
        ok: bool,
        error: str = "",
        duration_ms: int = 0,
    ) -> None:
        with self.session() as session:
            audit.record_call(
                session,
                protocol="http",
                agent=agent,
                token_id=token_id,
                tool=name,
                arguments=arguments,
                ok=ok,
                error=error,
                duration_ms=duration_ms,
            )

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        agent: str,
        token_id: str | None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        try:
            result = self.registry.call(name, arguments)
        except Exception as exc:
            self.record_call(
                name=name,
                arguments=arguments,
                agent=agent,
                token_id=token_id,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            raise
        self.record_call(
            name=name,
            arguments=arguments,
            agent=agent,
            token_id=token_id,
            ok=True,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return result


class InteropHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        registry: ToolRegistry,
        session_factory: Any,
        public_url: str = "",
        verbose: bool = False,
        max_workers: int = 2,
    ) -> None:
        super().__init__(address, _Handler)
        host, port = self.server_address[0], self.server_address[1]
        base_url = public_url.rstrip("/") or f"http://{host}:{port}"
        self.gateway = Gateway(
            registry,
            session_factory,
            base_url=base_url,
            verbose=verbose,
            max_workers=max_workers,
        )

    def server_close(self) -> None:
        try:
            self.gateway.close()
        finally:
            super().server_close()


class _Handler(BaseHTTPRequestHandler):
    server_version = f"RedFallInterop/{__version__}"
    protocol_version = "HTTP/1.1"

    @property
    def gateway(self) -> Gateway:
        return self.server.gateway  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        if self.gateway.verbose:
            super().log_message(fmt, *args)

    # ------------------------------------------------------------- utilities
    def _send(
        self,
        status: int,
        payload: Any,
        *,
        trust: bool = False,
        headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if trust:
            self.send_header("X-Redfall-Trust", TRUST_LABEL)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _error(
        self,
        status: int,
        code: str,
        message: str,
        *,
        tool: str = "",
        trust: bool = False,
    ) -> None:
        self._send(
            status,
            {
                "protocol": "http",
                "tool": tool,
                "trust": TRUST_LABEL,
                "error": {"code": code, "message": message},
            },
            trust=trust,
        )

    def _bearer(self) -> str:
        header = self.headers.get("Authorization", "")
        if not header.lower().startswith("bearer "):
            raise AuthError("missing bearer token")
        token = header.split(" ", 1)[1].strip()
        if not token:
            raise AuthError("missing bearer token")
        return token

    def _authenticate(self, session: Session) -> AgentToken:
        return authenticate(session, self._bearer())

    def _read_json(self) -> dict[str, Any]:
        length_header = self.headers.get("Content-Length", "0")
        try:
            length = int(length_header)
        except ValueError as exc:
            raise RequestError(400, "invalid_content_length", "invalid Content-Length") from exc
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            raise RequestError(413, "payload_too_large", "request body is too large")
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RequestError(400, "invalid_json", f"invalid JSON: {exc.msg}") from exc
        if not isinstance(value, dict):
            raise RequestError(400, "invalid_json", "request body must be a JSON object")
        return value

    def _dispatch(self, action: Any) -> None:
        try:
            action()
        except AuthError as exc:
            self._send(
                401,
                {
                    "protocol": "http",
                    "trust": TRUST_LABEL,
                    "error": {"code": exc.code, "message": str(exc)},
                },
                trust=True,
                headers={"WWW-Authenticate": "Bearer"},
            )
        except ScopeError as exc:
            self._error(403, exc.code, str(exc), trust=True)
        except QuotaError as exc:
            self._error(429, exc.code, str(exc), trust=True)
        except RequestError as exc:
            self._error(exc.status, exc.code, str(exc))
        except ToolError as exc:
            self._error(400, "tool_error", str(exc), trust=True)
        except Exception as exc:  # noqa: BLE001 - log the cause, do not leak internals
            print(
                f"redfall interop: internal error: {type(exc).__name__}: {exc}",
                file=sys.stderr,
                flush=True,
            )
            self._error(500, "internal_error", "internal server error")

    # ------------------------------------------------------------------ GET
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch(self._get)

    def _get(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/healthz":
            healthy = self.gateway.database_ok()
            self._send(
                200 if healthy else 503,
                {
                    "ok": healthy,
                    "service": "redfall-http",
                    "version": __version__,
                    "database": "ok" if healthy else "unavailable",
                },
            )
            return
        if path == "/.well-known/agent-card.json":
            card = build_agent_card(
                self.gateway.base_url,
                tool_count=len(self.gateway.registry.specs()),
            )
            self._send(200, card)
            return
        if path == "/v1/openapi.json":
            self._send(200, self.gateway.openapi)
            return
        if path == "/v1/tools":
            with self.gateway.session() as session:
                self._authenticate(session)
            self._send(200, {"tools": self.gateway.registry.specs()})
            return
        if path == "/v1/audit":
            query = parse_qs(parsed.query)
            limit_raw = (query.get("limit") or ["50"])[0]
            try:
                limit = max(1, min(200, int(limit_raw)))
            except ValueError as exc:
                raise RequestError(400, "invalid_limit", "limit must be an integer") from exc
            with self.gateway.session() as session:
                token = self._authenticate(session)
                if not grant_satisfies(
                    frozenset(str(scope) for scope in (token.scopes or [])), "admin"
                ):
                    raise ScopeError("reading the audit trail requires scope 'admin'")
                rows = audit.list_calls(session, limit=limit)
                payload = {"calls": [row.to_wire() for row in rows]}
            self._send(200, payload)
            return
        if path.startswith("/v1/artifacts/"):
            self._artifact(path)
            return
        raise RequestError(404, "not_found", f"no route for GET {path}")

    def _artifact(self, path: str) -> None:
        artifact_id = path[len("/v1/artifacts/") :].strip("/")
        if not artifact_id:
            raise RequestError(404, "not_found", "artifact id is required")
        query = parse_qs(urlsplit(self.path).query)
        expires = (query.get("expires") or [""])[0]
        sig = (query.get("sig") or [""])[0]
        with self.gateway.session() as session:
            row = artifacts.get_artifact(session, artifact_id)
            if row is None:
                raise RequestError(404, "not_found", f"artifact not found: {artifact_id}")
            secret = artifacts.artifact_secret(session)
            valid = artifacts.verify(secret, artifact_id, expires, sig)
            if not valid:
                raise RequestError(403, "invalid_signature", "artifact URL is invalid or expired")
            payload = {
                "artifact": {
                    "id": row.id,
                    "task_id": row.task_id,
                    "tool": row.tool,
                    "sha256": row.sha256,
                    "payload": row.payload,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                },
                "trust": TRUST_LABEL,
            }
        self._send(200, payload, trust=True)

    # ----------------------------------------------------------------- POST
    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch(self._post)

    def _post(self) -> None:
        path = urlsplit(self.path).path
        if path == "/a2a/v1":
            self._a2a()
            return
        if path.startswith("/v1/tools/"):
            tool = path[len("/v1/tools/") :].strip("/")
            self._tool(tool)
            return
        raise RequestError(404, "not_found", f"no route for POST {path}")

    def _tool(self, name: str) -> None:
        if not name:
            raise RequestError(404, "not_found", "tool name is required")
        arguments = self._read_json()
        with self.gateway.session() as session:
            token = self._authenticate(session)
            known = {spec["name"] for spec in self.gateway.registry.specs()}
            if name not in known:
                audit.record_call(
                    session,
                    protocol="http",
                    agent=token.name,
                    token_id=token.id,
                    tool=name,
                    arguments=arguments,
                    ok=False,
                    error="unknown tool",
                )
                session.commit()
                raise RequestError(404, "unknown_tool", f"unknown tool: {name}")
            try:
                authorize_tool(session, token, name)
            except (ScopeError, QuotaError) as exc:
                audit.record_call(
                    session,
                    protocol="http",
                    agent=token.name,
                    token_id=token.id,
                    tool=name,
                    arguments=arguments,
                    ok=False,
                    error=str(exc),
                )
                session.commit()
                raise
            agent = token.name
            token_id = token.id
        result = self.gateway.call_tool(
            name, arguments, agent=agent, token_id=token_id
        )
        self._send(
            200,
            {
                "protocol": "http",
                "tool": name,
                "trust": TRUST_LABEL,
                "result": result,
            },
            trust=True,
        )

    def _a2a(self) -> None:
        body = self._read_json()
        with self.gateway.session() as session:
            token = self._authenticate(session)
            identity = identity_of(token)
        method = body.get("method") if isinstance(body, dict) else None
        if method in {"SendStreamingMessage", "SubscribeToTask"}:
            self._a2a_stream(body, identity)
            return
        response = self.gateway.a2a.handle_rpc(body, identity)
        if response is not None:
            self._send(200, response, trust=True)

    def _a2a_stream(self, body: dict[str, Any], identity: Any) -> None:
        try:
            request_id, events = self.gateway.a2a.prepare_stream(body, identity)
        except A2AError as exc:
            self._send(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": body.get("id") if isinstance(body, dict) else None,
                    "error": {"code": exc.code, "message": str(exc)},
                },
                trust=True,
            )
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Redfall-Trust", TRUST_LABEL)
        self.end_headers()
        try:
            for event in events:
                envelope = stream_envelope(request_id, event)
                chunk = f"data: {json.dumps(envelope, separators=(',', ':'), default=str)}\n\n"
                self.wfile.write(chunk.encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        finally:
            self.close_connection = True


def serve(
    registry: ToolRegistry,
    session_factory: Any,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    public_url: str = "",
    verbose: bool = False,
) -> None:
    httpd = InteropHTTPServer(
        (host, port),
        registry=registry,
        session_factory=session_factory,
        public_url=public_url,
        verbose=verbose,
    )
    address = httpd.server_address
    print(
        f"redfall interop: listening on http://{address[0]}:{address[1]} "
        f"(openapi /v1/openapi.json, a2a /a2a/v1)",
        file=sys.stderr,
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RedFall HTTP/OpenAPI and A2A gateway")
    parser.add_argument(
        "--database-url",
        default="",
        help="SQLAlchemy database URL (defaults to DATABASE_URL or the RedFall config).",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--public-url", default="", help="Externally visible base URL.")
    parser.add_argument("--verbose", action="store_true")
    options = parser.parse_args(argv)
    database_url = (
        options.database_url
        or os.getenv("DATABASE_URL")
        or load_config().database_url
    )
    os.environ["DATABASE_URL"] = database_url
    try:
        engine = init_engine(database_url)
        session_factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
        registry = ToolRegistry(session_factory)
        serve(
            registry,
            session_factory,
            host=options.host,
            port=options.port,
            public_url=options.public_url,
            verbose=options.verbose,
        )
    except OSError as exc:
        print(f"redfall interop: cannot bind: {exc}", file=sys.stderr, flush=True)
        return 1
    except Exception as exc:  # noqa: BLE001 - startup reports the real failure
        print(
            f"redfall interop: startup failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
