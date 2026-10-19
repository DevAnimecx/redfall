"""A small MCP stdio client used by adapter contracts and integration tests.

The client is deliberately protocol-level: it launches a real server process,
performs the MCP initialize handshake, lists tools, and calls them over
newline-delimited JSON-RPC. It does not import the server's registry, so a
contract pass covers the transport as well as the tools.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Sequence

from ..version import __version__


class MCPClientError(RuntimeError):
    """The server process or protocol exchange failed."""


class MCPToolError(MCPClientError):
    """The server returned an isError tool result."""

    def __init__(self, message: str, *, content: list[dict[str, Any]] | None = None) -> None:
        self.content = list(content or [])
        super().__init__(message)


class MCPStdioClient:
    def __init__(
        self,
        command: Sequence[str],
        *,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not command:
            raise ValueError("command must not be empty")
        self.command = list(command)
        self.cwd = str(cwd) if cwd else None
        self.env = dict(os.environ)
        if env:
            self.env.update(env)
        self.timeout = timeout
        self._process: subprocess.Popen[str] | None = None
        self._stdout: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._stderr: list[str] = []
        self._next_id = 1
        self._lock = threading.Lock()

    def start(self) -> "MCPStdioClient":
        if self._process is not None:
            return self
        self._process = subprocess.Popen(
            self.command,
            cwd=self.cwd,
            env=self.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        threading.Thread(
            target=self._pump_stdout,
            args=(self._process.stdout,),
            name="redfall-mcp-stdout",
            daemon=True,
        ).start()
        threading.Thread(
            target=self._pump_stderr,
            args=(self._process.stderr,),
            name="redfall-mcp-stderr",
            daemon=True,
        ).start()
        return self

    def _pump_stdout(self, stream: Any) -> None:
        if stream is None:
            self._stdout.put(("eof", None))
            return
        try:
            for line in stream:
                self._stdout.put(("line", line))
        except Exception as exc:  # noqa: BLE001 - reported through the queue
            self._stdout.put(("error", f"{type(exc).__name__}: {exc}"))
        finally:
            self._stdout.put(("eof", None))

    def _pump_stderr(self, stream: Any) -> None:
        if stream is None:
            return
        try:
            for line in stream:
                if len(self._stderr) < 200:
                    self._stderr.append(line.rstrip())
        except Exception as exc:  # noqa: BLE001 - diagnostics only
            if len(self._stderr) < 200:
                self._stderr.append(f"{type(exc).__name__}: {exc}")

    @property
    def stderr(self) -> list[str]:
        return list(self._stderr)

    def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        self.start()
        if self._process is None or self._process.stdin is None:
            raise MCPClientError("server process has no stdin")
        with self._lock:
            request_id = self._next_id
            self._next_id += 1
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        try:
            self._process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
            self._process.stdin.flush()
        except Exception as exc:  # noqa: BLE001 - process may have died
            raise MCPClientError(f"could not write to server: {exc}\n{self._stderr_tail()}") from exc
        deadline = self._deadline(timeout)
        while True:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise MCPClientError(
                    f"timed out waiting for {method} response\n{self._stderr_tail()}"
                )
            try:
                kind, value = self._stdout.get(timeout=max(0.01, remaining))
            except queue.Empty as exc:
                raise MCPClientError(
                    f"no {method} response before timeout\n{self._stderr_tail()}"
                ) from exc
            if kind == "error":
                raise MCPClientError(f"stdout reader failed: {value}\n{self._stderr_tail()}")
            if kind == "eof":
                raise MCPClientError(
                    f"server exited before {method} response\n{self._stderr_tail()}"
                )
            line = str(value).strip()
            if not line:
                continue
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                # Servers that print logs to stdout violate MCP framing. Record
                # the line and keep reading; the contract reports the timeout.
                if len(self._stderr) < 200:
                    self._stderr.append(f"non-json stdout: {line[:500]}")
                continue
            if not isinstance(response, dict) or response.get("id") != request_id:
                continue
            if "error" in response:
                error = response.get("error") or {}
                raise MCPClientError(
                    f"JSON-RPC error for {method}: {error.get('code')} {error.get('message')}"
                )
            result = response.get("result")
            if not isinstance(result, dict):
                raise MCPClientError(f"{method} returned a non-object result")
            return result

    def initialize(self) -> dict[str, Any]:
        result = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "redfall-contract", "version": __version__},
            },
        )
        notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        if self._process is not None and self._process.stdin is not None:
            self._process.stdin.write(json.dumps(notification) + "\n")
            self._process.stdin.flush()
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        result = self.request("tools/list", {})
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise MCPClientError("tools/list did not return a tools array")
        return [tool for tool in tools if isinstance(tool, dict)]

    def call_tool_raw(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        result = self.call_tool_raw(name, arguments)
        content = result.get("content")
        if not isinstance(content, list):
            content = []
        text = ""
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text += str(item.get("text") or "")
        if result.get("isError"):
            raise MCPToolError(text or f"tool {name} failed", content=content)
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def close(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        try:
            if process.stdin is not None:
                process.stdin.close()
            process.wait(timeout=5)
        except Exception:  # noqa: BLE001 - close must not mask the contract result
            try:
                process.kill()
            except Exception:  # noqa: BLE001 - process may already be gone
                self._stderr.append("process could not be killed")
        for stream in (process.stdout, process.stderr):
            try:
                if stream is not None:
                    stream.close()
            except Exception:  # noqa: BLE001 - close best effort
                self._stderr.append("stream could not be closed")

    def __enter__(self) -> "MCPStdioClient":
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def _stderr_tail(self) -> str:
        if not self._stderr:
            return "server stderr: empty"
        return "server stderr:\n" + "\n".join(self._stderr[-20:])

    @staticmethod
    def _monotonic() -> float:
        import time

        return time.monotonic()

    def _deadline(self, timeout: float | None) -> float:
        return self._monotonic() + (self.timeout if timeout is None else timeout)


def default_server_command(database_url: str | None = None) -> list[str]:
    command = [sys.executable, "-m", "redfall.interop.mcp_stdio"]
    if database_url:
        command.extend(["--database-url", database_url])
    return command


def source_environment() -> dict[str, str]:
    """Make the repository's ``src`` importable for a source-tree contract run."""
    env: dict[str, str] = {}
    source = Path(__file__).resolve().parents[2]
    if (source / "redfall").is_dir():
        existing = os.environ.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(source) + (os.pathsep + existing if existing else "")
    return env
