"""Minimal MCP stdio server for RedFall campaign and evidence tools.

MCP uses newline-delimited JSON-RPC on stdio. The transport is intentionally
small and dependency-free: the registry behind it is the same code used by the
CLI and, later, the HTTP/A2A adapters. Tool failures are returned as MCP
``isError`` results, while malformed JSON-RPC gets a JSON-RPC error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, TextIO

from sqlalchemy.orm import sessionmaker

from ..config import load_config
from ..store.db import init_engine
from ..version import __version__
from .tools import ToolError, ToolRegistry

SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[-1]


def _error(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


class MCPServer:
    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(message, dict):
            return _error(None, -32600, "request must be a JSON object")
        request_id = message.get("id")
        method = message.get("method")
        if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return _error(request_id, -32600, "invalid JSON-RPC 2.0 request")
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return _error(request_id, -32602, "params must be an object")

        is_notification = "id" not in message
        if method == "notifications/initialized":
            return None
        if method == "initialize":
            requested = str(params.get("protocolVersion") or LATEST_PROTOCOL_VERSION)
            version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION
            return _result(
                request_id,
                {
                    "protocolVersion": version,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {"name": "redfall", "version": __version__},
                    "instructions": (
                        "RedFall is a security execution layer, not a general coding agent. "
                        "Use durable campaigns and tasks, check filesystem scope with "
                        "redfall_policy_check, index real source with redfall_graph_index, "
                        "and execute scans or reproductions only through the provided tools. "
                        "A finding is reportable only when E3/E4 evidence passes the hash "
                        "chain and redfall_report_readiness. Results marked ok=false or "
                        "blocked_reason describe missing real prerequisites; do not treat "
                        "them as findings. Campaign runner tasks execute real local code."
                    ),
                },
            )
        if method == "ping":
            return _result(request_id, {})
        if method == "tools/list":
            return _result(request_id, {"tools": self.registry.specs()})
        if method == "resources/list":
            return _result(request_id, {"resources": []})
        if method == "resources/templates/list":
            return _result(request_id, {"resourceTemplates": []})
        if method == "prompts/list":
            return _result(request_id, {"prompts": []})
        if method == "logging/setLevel":
            return _result(request_id, {})
        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(name, str) or not name:
                return _error(request_id, -32602, "tools/call requires a string name")
            if not isinstance(arguments, dict):
                return _error(request_id, -32602, "tools/call arguments must be an object")
            try:
                result = self.registry.call(name, arguments)
            except ToolError as exc:
                return _result(
                    request_id,
                    {
                        "content": [{"type": "text", "text": str(exc)}],
                        "isError": True,
                    },
                )
            return _result(
                request_id,
                {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}],
                    "isError": False,
                },
            )
        if method == "shutdown":
            return _result(request_id, {})
        if is_notification:
            return None
        return _error(request_id, -32601, f"method not found: {method}")


def run_stdio(
    registry: ToolRegistry,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> None:
    source = stdin or sys.stdin
    sink = stdout or sys.stdout
    errors = stderr or sys.stderr
    server = MCPServer(registry)
    for raw_line in source:
        line = raw_line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            response = _error(None, -32700, f"parse error: {exc.msg}")
        else:
            try:
                response = server.handle(message)
            except Exception as exc:  # noqa: BLE001 - protocol boundary reports failures
                print(f"redfall mcp: internal error: {type(exc).__name__}: {exc}", file=errors, flush=True)
                request_id = message.get("id") if isinstance(message, dict) else None
                response = _error(request_id, -32603, "internal error")
        if response is not None:
            sink.write(json.dumps(response, separators=(",", ":"), default=str) + "\n")
            sink.flush()


def build_registry(database_url: str) -> ToolRegistry:
    engine = init_engine(database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    return ToolRegistry(SessionLocal)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RedFall MCP stdio server")
    parser.add_argument(
        "--database-url",
        default=os.getenv("DATABASE_URL") or load_config().database_url,
        help="SQLAlchemy database URL. Defaults to DATABASE_URL or the RedFall config.",
    )
    options = parser.parse_args(argv)
    os.environ["DATABASE_URL"] = options.database_url
    try:
        registry = build_registry(options.database_url)
    except Exception as exc:  # noqa: BLE001 - startup must report the real failure
        print(f"redfall mcp: database unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    run_stdio(registry)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
