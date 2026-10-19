"""A2A v1.0 (JSON-RPC binding) for RedFall.

The implemented subset is deliberately explicit: `SendMessage`,
`SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask` and
`SubscribeToTask`, using the A2A v1.0.0 data model (ProtoJSON enum names,
camelCase fields, one-of part shapes). Push notifications and extended agent
cards are not implemented; the Agent Card says so rather than advertising them.

One A2A message carries one tool call: a data part shaped
``{"tool": "redfall_graph_index", "arguments": {...}}``. The task row is the
source of truth for polling and streaming, and every executed tool call writes
the same audit row as the HTTP surface.
"""

from __future__ import annotations

import base64
import json
import secrets
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from threading import Event
from typing import Any, Callable, Iterator

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..store.models import AgentToken, InteropTask, utcnow
from ..version import __version__
from . import artifacts, audit
from .auth import (
    Identity,
    QuotaError,
    TOOL_SCOPES,
    grant_satisfies,
)
from .tools import ToolError, ToolRegistry

PROTOCOL_VERSION = "1.0"

TERMINAL_STATES = frozenset(
    {
        "TASK_STATE_COMPLETED",
        "TASK_STATE_FAILED",
        "TASK_STATE_CANCELED",
        "TASK_STATE_REJECTED",
    }
)
INTERRUPTED_STATES = frozenset({"TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED"})

TASK_NOT_FOUND = -32001
TASK_NOT_CANCELABLE = -32002
PUSH_NOT_SUPPORTED = -32003
UNSUPPORTED_OPERATION = -32004
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

TRUST_LABEL = "untrusted-repository-data"

_SKILLS: list[dict[str, Any]] = [
    {
        "id": "campaign",
        "name": "Security campaign",
        "description": (
            "Create, scope, start, pause, resume, cancel and report durable "
            "security campaigns with preflight budget reservations."
        ),
        "tags": ["security", "campaign", "budget", "evidence"],
        "examples": [
            "Create a discovery campaign for this repository with a 5 USD budget",
            "Report the readiness of campaign cmp-123",
        ],
    },
    {
        "id": "code-graph",
        "name": "Code graph",
        "description": (
            "Index a repository into a persisted code graph and query nodes, "
            "routes, neighbours, paths, inventories and diffs with provenance."
        ),
        "tags": ["code", "graph", "typescript", "python", "provenance"],
        "examples": ["Index /workspace/service and find its HTTP routes"],
    },
    {
        "id": "scan",
        "name": "Scan and findings",
        "description": "Run the real scanner inside the sandbox boundary and read findings.",
        "tags": ["scan", "findings", "sast"],
        "examples": ["Scan the scoped repository and list critical findings"],
    },
    {
        "id": "reproduce",
        "name": "Finding reproduction",
        "description": "Replay a finding in the sandbox and record reproduction evidence.",
        "tags": ["reproduction", "sandbox", "evidence"],
        "examples": ["Reproduce finding fnd-123 and attach the result"],
    },
    {
        "id": "report",
        "name": "Evidence-gated reporting",
        "description": "Build JSON or SARIF reports only after the evidence chain verifies.",
        "tags": ["report", "sarif", "evidence"],
        "examples": ["Build a SARIF report for campaign cmp-123"],
    },
    {
        "id": "tools",
        "name": "Tool execution",
        "description": (
            "Call any advertised RedFall tool by name with a JSON arguments object; "
            "the tool list is available from the HTTP surface."
        ),
        "tags": ["tools", "json", "automation"],
        "examples": ["Call redfall_health with no arguments"],
    },
]


class A2AError(RuntimeError):
    """A protocol-visible A2A error."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.data = data


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(10)}"


def _status_message(context_id: str, task_id: str, text: str) -> dict[str, Any]:
    return {
        "messageId": _new_id("msg"),
        "role": "ROLE_AGENT",
        "contextId": context_id,
        "taskId": task_id,
        "parts": [{"text": text}],
    }


def build_agent_card(
    base_url: str,
    *,
    tool_count: int = 0,
    streaming: bool = True,
) -> dict[str, Any]:
    """The public Agent Card served at ``/.well-known/agent-card.json``."""

    root = base_url.rstrip("/")
    return {
        "name": "RedFall",
        "description": (
            "Security execution and verification layer. RedFall runs evidence-gated "
            "campaigns, indexes code graphs and reports only findings backed by "
            "verified execution evidence."
        ),
        "version": __version__,
        "supportedInterfaces": [
            {
                "url": f"{root}/a2a/v1",
                "protocolBinding": "JSONRPC",
                "protocolVersion": PROTOCOL_VERSION,
            }
        ],
        "capabilities": {
            "streaming": streaming,
            "pushNotifications": False,
            "extendedAgentCard": False,
        },
        "securitySchemes": {
            "bearer": {
                "httpAuthSecurityScheme": {
                    "scheme": "Bearer",
                    "description": "RedFall agent token created with `redfall interop token create`.",
                }
            }
        },
        "securityRequirements": [{"schemes": {"bearer": {"list": []}}}],
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": _SKILLS,
    }


def _parse_message(params: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Return ``(tool, arguments, message, configuration)`` from SendMessage params."""

    message = params.get("message")
    if not isinstance(message, dict):
        raise A2AError(INVALID_PARAMS, "message must be an object")
    if not isinstance(message.get("messageId"), str) or not message["messageId"]:
        raise A2AError(INVALID_PARAMS, "message.messageId is required")
    role = message.get("role")
    if role != "ROLE_USER":
        raise A2AError(INVALID_PARAMS, "message.role must be ROLE_USER")
    if message.get("taskId"):
        raise A2AError(
            UNSUPPORTED_OPERATION,
            "multi-turn task interaction is not implemented; send a new task per tool call",
        )
    parts = message.get("parts")
    if not isinstance(parts, list) or not parts:
        raise A2AError(INVALID_PARAMS, "message.parts must be a non-empty array")
    configuration = params.get("configuration") or {}
    if not isinstance(configuration, dict):
        raise A2AError(INVALID_PARAMS, "configuration must be an object")

    candidates: list[Any] = []
    for part in parts:
        if not isinstance(part, dict):
            continue
        if isinstance(part.get("data"), dict):
            candidates.append(part["data"])
        if isinstance(part.get("text"), str):
            stripped = part["text"].strip()
            if stripped:
                candidates.append(stripped)
    metadata = message.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("redfall"), dict):
        candidates.append(metadata["redfall"])

    for candidate in candidates:
        payload: Any = candidate
        if isinstance(candidate, str):
            try:
                payload = json.loads(candidate)
            except json.JSONDecodeError:
                continue
        if not isinstance(payload, dict):
            continue
        tool = payload.get("tool")
        arguments = payload.get("arguments") or {}
        if isinstance(tool, str) and tool and isinstance(arguments, dict):
            return tool, arguments, message, configuration
    raise A2AError(
        INVALID_PARAMS,
        'message must contain a data part shaped like {"tool": "<name>", "arguments": {...}}',
    )


def _encode_cursor(task: InteropTask) -> str:
    stamp = (task.updated_at or task.created_at or utcnow()).isoformat()
    raw = f"{stamp}|{task.id}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode_cursor(token: str) -> tuple[datetime, str]:
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        stamp, task_id = raw.split("|", 1)
        moment = datetime.fromisoformat(stamp)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment, task_id
    except (ValueError, UnicodeDecodeError) as exc:
        raise A2AError(INVALID_PARAMS, "pageToken is not a valid cursor") from exc


class A2AService:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        registry: ToolRegistry,
        *,
        base_url: str,
        artifact_ttl: int = 900,
        wait_timeout: float = 120.0,
        stream_timeout: float = 3600.0,
        max_workers: int = 2,
        executor: Callable[[str], None] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self.registry = registry
        self.base_url = base_url.rstrip("/")
        self.artifact_ttl = artifact_ttl
        self.wait_timeout = wait_timeout
        self.stream_timeout = stream_timeout
        self._executor = executor
        self._pool: ThreadPoolExecutor | None = None
        if executor is None:
            self._pool = ThreadPoolExecutor(
                max_workers=max(1, max_workers), thread_name_prefix="redfall-a2a"
            )

    # ------------------------------------------------------------- lifecycle
    def close(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None

    @contextmanager
    def _session(self) -> Iterator[Session]:
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _dispatch(self, task_id: str) -> None:
        if self._executor is not None:
            self._executor(task_id)
            return
        if self._pool is not None:
            self._pool.submit(self.run_task, task_id)

    # --------------------------------------------------------------- queries
    def _load(self, session: Session, task_id: str, identity: Identity) -> InteropTask:
        task = session.get(InteropTask, task_id)
        if task is None or task.agent != identity.name:
            raise A2AError(TASK_NOT_FOUND, f"task not found: {task_id}")
        return task

    def _snapshot(
        self,
        task_id: str,
        identity: Identity,
        *,
        history_length: int | None = None,
        include_artifacts: bool = True,
    ) -> dict[str, Any]:
        with self._session() as session:
            task = self._load(session, task_id, identity)
            return task.to_wire(
                history_length=history_length, include_artifacts=include_artifacts
            )

    def _state(self, task_id: str) -> str:
        with self._session() as session:
            task = session.get(InteropTask, task_id)
            return task.state if task is not None else ""

    def _wait(self, task_id: str) -> None:
        elapsed = 0.0
        step = 0.1
        while elapsed < self.wait_timeout:
            state = self._state(task_id)
            if not state or state in TERMINAL_STATES or state in INTERRUPTED_STATES:
                return
            Event().wait(step)
            elapsed += step

    # ------------------------------------------------------------- execution
    def run_task(self, task_id: str) -> None:
        """Execute one persisted task. Safe to call twice; a terminal task is left alone."""

        with self._session() as session:
            task = session.get(InteropTask, task_id)
            if task is None or task.state in TERMINAL_STATES:
                return
            if task.cancel_requested:
                task.state = "TASK_STATE_CANCELED"
                task.status_message = _status_message(
                    task.context_id, task.id, "canceled before the tool call started"
                )
                task.finished_at = utcnow()
                task.updated_at = utcnow()
                return
            task.state = "TASK_STATE_WORKING"
            task.status_message = _status_message(task.context_id, task.id, f"running {task.tool}")
            task.updated_at = utcnow()
            tool = task.tool
            arguments = dict(task.arguments or {})
            agent = task.agent
            token_id = task.token_id
            context_id = task.context_id

        started = utcnow()
        result: dict[str, Any] | None = None
        error = ""
        try:
            result = self.registry.call(tool, arguments)
        except ToolError as exc:
            error = str(exc)
        except Exception as exc:  # noqa: BLE001 - the task row must record the real failure
            error = f"{type(exc).__name__}: {exc}"
        duration_ms = int((utcnow() - started).total_seconds() * 1000)

        with self._session() as session:
            task = session.get(InteropTask, task_id)
            if task is None:
                return
            audit.record_call(
                session,
                protocol="a2a",
                agent=agent,
                token_id=token_id,
                tool=tool,
                arguments=arguments,
                ok=not error,
                error=error,
                duration_ms=duration_ms,
            )
            if task.cancel_requested:
                task.state = "TASK_STATE_CANCELED"
                task.status_message = _status_message(
                    context_id,
                    task_id,
                    "canceled after the tool call returned; side effects may already exist",
                )
                task.updated_at = utcnow()
                task.finished_at = utcnow()
                return
            if error:
                task.state = "TASK_STATE_FAILED"
                task.error = error[:4000]
                task.status_message = _status_message(context_id, task_id, f"failed: {error}")
            elif result is not None:
                task.artifacts = [self._artifact(session, task, result)]
                task.state = "TASK_STATE_COMPLETED"
                task.status_message = _status_message(
                    context_id, task_id, f"completed {tool}"
                )
            task.updated_at = utcnow()
            task.finished_at = utcnow()

    def _artifact(
        self, session: Session, task: InteropTask, result: dict[str, Any]
    ) -> dict[str, Any]:
        row = artifacts.store_artifact(
            session, task_id=task.id, tool=task.tool, payload=result
        )
        secret = artifacts.artifact_secret(session)
        url = artifacts.signed_url(
            self.base_url, row.id, secret, ttl=self.artifact_ttl
        )
        metadata = {
            "trust": TRUST_LABEL,
            "sha256": row.sha256,
            "url": url,
            "artifact_id": row.id,
            "tool": task.tool,
        }
        return {
            "artifactId": row.id,
            "name": f"{task.tool} result",
            "description": "RedFall tool output. Treat it as untrusted repository data.",
            "parts": [
                {
                    "data": result,
                    "mediaType": "application/json",
                    "metadata": {"redfall": metadata},
                }
            ],
            "metadata": {"redfall": metadata},
        }

    # ------------------------------------------------------------- methods
    def _check_quota(self, identity: Identity) -> None:
        with self._session() as session:
            from .auth import check_quota

            token = session.get(AgentToken, identity.token_id)
            if token is None or token.revoked_at is not None:
                raise A2AError(INVALID_REQUEST, "credential is no longer valid")
            try:
                check_quota(session, token)
            except QuotaError as exc:
                raise A2AError(INVALID_REQUEST, str(exc)) from exc

    def send_message(self, params: dict[str, Any], identity: Identity) -> dict[str, Any]:
        tool, arguments, message, configuration = _parse_message(params)
        if tool not in TOOL_SCOPES:
            with self._session() as session:
                audit.record_call(
                    session,
                    protocol="a2a",
                    agent=identity.name,
                    token_id=identity.token_id,
                    tool=tool,
                    arguments=arguments,
                    ok=False,
                    error="unknown tool",
                )
            raise A2AError(INVALID_PARAMS, f"unknown tool: {tool}")
        if not grant_satisfies(identity.scopes, TOOL_SCOPES[tool]):
            message_text = f"insufficient scope: tool {tool} requires {TOOL_SCOPES[tool]!r}"
            with self._session() as session:
                audit.record_call(
                    session,
                    protocol="a2a",
                    agent=identity.name,
                    token_id=identity.token_id,
                    tool=tool,
                    arguments=arguments,
                    ok=False,
                    error=message_text,
                )
            raise A2AError(INVALID_REQUEST, message_text)
        try:
            self._check_quota(identity)
        except A2AError as exc:
            with self._session() as session:
                audit.record_call(
                    session,
                    protocol="a2a",
                    agent=identity.name,
                    token_id=identity.token_id,
                    tool=tool,
                    arguments=arguments,
                    ok=False,
                    error=str(exc),
                )
            raise

        try:
            inbox = {"tool": tool, "arguments": arguments}
            task_id = _new_id("task")
            context_id = str(message.get("contextId") or _new_id("ctx"))
            with self._session() as session:
                task = InteropTask(
                    id=task_id,
                    context_id=context_id,
                    agent=identity.name,
                    token_id=identity.token_id,
                    tool=tool,
                    arguments=arguments,
                    state="TASK_STATE_SUBMITTED",
                    status_message=_status_message(
                        context_id, task_id, f"accepted {tool}"
                    ),
                    history=[message],
                )
                task.updated_at = utcnow()
                session.add(task)
                session.flush()
        except Exception as exc:  # noqa: BLE001 - the caller gets a real failure
            raise A2AError(INTERNAL_ERROR, f"could not persist task: {type(exc).__name__}: {exc}")

        self._dispatch(task_id)
        if not bool(configuration.get("returnImmediately", False)):
            self._wait(task_id)
        history_length = configuration.get("historyLength")
        if not isinstance(history_length, int) or isinstance(history_length, bool):
            history_length = None
        with self._session() as session:
            task = session.get(InteropTask, task_id)
            if task is None:
                raise A2AError(INTERNAL_ERROR, "task disappeared after creation")
            wire = task.to_wire(history_length=history_length)
        wire.setdefault("metadata", {"redfall": {"tool": tool, "argumentsHash": audit.input_hash(inbox)}})
        return {"task": wire}

    def get_task(self, params: dict[str, Any], identity: Identity) -> dict[str, Any]:
        task_id = params.get("id")
        if not isinstance(task_id, str) or not task_id:
            raise A2AError(INVALID_PARAMS, "id is required")
        history_length = params.get("historyLength")
        if not isinstance(history_length, int) or isinstance(history_length, bool):
            history_length = None
        return self._snapshot(task_id, identity, history_length=history_length)

    def list_tasks(self, params: dict[str, Any], identity: Identity) -> dict[str, Any]:
        page_size = params.get("pageSize", 50)
        if not isinstance(page_size, int) or isinstance(page_size, bool):
            page_size = 50
        page_size = max(1, min(100, page_size))
        history_length = params.get("historyLength")
        if not isinstance(history_length, int) or isinstance(history_length, bool):
            history_length = None
        include_artifacts = bool(params.get("includeArtifacts", False))
        with self._session() as session:
            filters = [InteropTask.agent == identity.name]
            context_id = params.get("contextId")
            if isinstance(context_id, str) and context_id:
                filters.append(InteropTask.context_id == context_id)
            status = params.get("status")
            if isinstance(status, str) and status:
                filters.append(InteropTask.state == status)
            total = int(
                session.scalar(select(func.count(InteropTask.id)).where(*filters)) or 0
            )
            query = select(InteropTask).where(*filters)
            token = params.get("pageToken")
            if isinstance(token, str) and token:
                moment, cursor_id = _decode_cursor(token)
                query = query.where(
                    (InteropTask.updated_at < moment)
                    | ((InteropTask.updated_at == moment) & (InteropTask.id < cursor_id))
                )
            rows = list(
                session.scalars(
                    query.order_by(InteropTask.updated_at.desc(), InteropTask.id.desc())
                    .limit(page_size)
                ).all()
            )
            tasks = [
                row.to_wire(
                    history_length=history_length, include_artifacts=include_artifacts
                )
                for row in rows
            ]
            next_token = _encode_cursor(rows[-1]) if len(rows) == page_size else ""
        return {
            "tasks": tasks,
            "nextPageToken": next_token,
            "pageSize": page_size,
            "totalSize": total,
        }

    def cancel_task(self, params: dict[str, Any], identity: Identity) -> dict[str, Any]:
        task_id = params.get("id")
        if not isinstance(task_id, str) or not task_id:
            raise A2AError(INVALID_PARAMS, "id is required")
        with self._session() as session:
            task = self._load(session, task_id, identity)
            if task.state in TERMINAL_STATES:
                raise A2AError(
                    TASK_NOT_CANCELABLE,
                    f"task {task_id} is in terminal state {task.state}",
                )
            task.cancel_requested = True
            task.updated_at = utcnow()
            if task.state == "TASK_STATE_SUBMITTED":
                task.state = "TASK_STATE_CANCELED"
                task.finished_at = utcnow()
                task.status_message = _status_message(
                    task.context_id, task.id, "canceled before execution started"
                )
            return task.to_wire()

    def subscribe(self, params: dict[str, Any], identity: Identity) -> tuple[str, Iterator[dict[str, Any]]]:
        task_id = params.get("id")
        if not isinstance(task_id, str) or not task_id:
            raise A2AError(INVALID_PARAMS, "id is required")
        with self._session() as session:
            task = self._load(session, task_id, identity)
            if task.state in TERMINAL_STATES:
                raise A2AError(
                    UNSUPPORTED_OPERATION,
                    f"task {task_id} is already in terminal state {task.state}",
                )
        return task_id, self._stream_events(task_id, identity)

    def send_stream_message(
        self, params: dict[str, Any], identity: Identity
    ) -> tuple[str, Iterator[dict[str, Any]]]:
        configuration = params.get("configuration") or {}
        if not isinstance(configuration, dict):
            raise A2AError(INVALID_PARAMS, "configuration must be an object")
        result = self.send_message(
            {**params, "configuration": {**configuration, "returnImmediately": True}},
            identity,
        )
        task_id = str(result["task"]["id"])
        return task_id, self._stream_events(task_id, identity)

    def _stream_events(self, task_id: str, identity: Identity) -> Iterator[dict[str, Any]]:
        seen_artifacts = 0
        last_state = ""
        first = True
        started = datetime.now(timezone.utc)
        while True:
            if (datetime.now(timezone.utc) - started).total_seconds() > self.stream_timeout:
                return
            with self._session() as session:
                task = self._load(session, task_id, identity)
                state = task.state
                artifacts_now = list(task.artifacts or [])
                snapshot = task.to_wire(include_artifacts=False)
                context_id = task.context_id
            if first:
                yield {"task": snapshot}
                first = False
            while seen_artifacts < len(artifacts_now):
                yield {
                    "artifactUpdate": {
                        "taskId": task_id,
                        "contextId": context_id,
                        "artifact": artifacts_now[seen_artifacts],
                        "lastChunk": True,
                    }
                }
                seen_artifacts += 1
            if state != last_state and state not in TERMINAL_STATES:
                yield {
                    "statusUpdate": {
                        "taskId": task_id,
                        "contextId": context_id,
                        "status": snapshot["status"],
                    }
                }
            last_state = state
            if state in TERMINAL_STATES:
                yield {
                    "statusUpdate": {
                        "taskId": task_id,
                        "contextId": context_id,
                        "status": snapshot["status"],
                    }
                }
                return
            Event().wait(0.1)

    # ---------------------------------------------------------- JSON-RPC glue
    def handle_rpc(
        self, message: dict[str, Any], identity: Identity
    ) -> dict[str, Any] | None:
        request_id = message.get("id") if isinstance(message, dict) else None
        if not isinstance(message, dict):
            return _rpc_error(None, INVALID_REQUEST, "request must be a JSON object")
        if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            return _rpc_error(request_id, INVALID_REQUEST, "invalid JSON-RPC 2.0 request")
        method = message["method"]
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return _rpc_error(request_id, INVALID_PARAMS, "params must be an object")
        handlers: dict[str, Callable[[dict[str, Any], Identity], Any]] = {
            "SendMessage": self.send_message,
            "GetTask": self.get_task,
            "ListTasks": self.list_tasks,
            "CancelTask": self.cancel_task,
        }
        if method in {"SendStreamingMessage", "SubscribeToTask"}:
            return _rpc_error(
                request_id,
                INVALID_REQUEST,
                f"{method} requires the SSE response path",
            )
        if method == "GetExtendedAgentCard":
            return _rpc_error(
                request_id,
                UNSUPPORTED_OPERATION,
                "extended agent cards are not configured",
            )
        if method in {
            "CreateTaskPushNotificationConfig",
            "GetTaskPushNotificationConfig",
            "ListTaskPushNotificationConfigs",
            "DeleteTaskPushNotificationConfig",
        }:
            return _rpc_error(
                request_id, PUSH_NOT_SUPPORTED, "push notifications are not supported"
            )
        handler = handlers.get(method)
        if handler is None:
            return _rpc_error(request_id, METHOD_NOT_FOUND, f"method not found: {method}")
        try:
            result = handler(params, identity)
        except A2AError as exc:
            return _rpc_error(request_id, exc.code, str(exc), exc.data)
        except Exception as exc:  # noqa: BLE001 - protocol boundary reports failures
            return _rpc_error(
                request_id, INTERNAL_ERROR, f"internal error: {type(exc).__name__}: {exc}"
            )
        if request_id is None:
            return None
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def prepare_stream(
        self, message: dict[str, Any], identity: Identity
    ) -> tuple[Any, Iterator[dict[str, Any]]]:
        """Validate a streaming request and return ``(request_id, StreamResponse iterator)``."""

        if not isinstance(message, dict):
            raise A2AError(INVALID_REQUEST, "request must be a JSON object")
        if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            raise A2AError(INVALID_REQUEST, "invalid JSON-RPC 2.0 request")
        method = message["method"]
        params = message.get("params") or {}
        if not isinstance(params, dict):
            raise A2AError(INVALID_PARAMS, "params must be an object")
        request_id = message.get("id")
        if method == "SendStreamingMessage":
            _task_id, events = self.send_stream_message(params, identity)
            return request_id, events
        if method == "SubscribeToTask":
            _task_id, events = self.subscribe(params, identity)
            return request_id, events
        raise A2AError(METHOD_NOT_FOUND, f"method is not streaming: {method}")


def _rpc_error(
    request_id: Any, code: int, message: str, data: Any = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def stream_envelope(
    request_id: Any, stream_response: dict[str, Any]
) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": stream_response}
