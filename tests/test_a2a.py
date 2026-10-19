"""A2A v1.0 service: tasks, artifacts, scopes, quota, cancellation and streaming."""

from __future__ import annotations

import threading
import uuid
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from redfall.interop import artifacts
from redfall.interop.a2a import (
    A2AError,
    A2AService,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PUSH_NOT_SUPPORTED,
    TASK_NOT_CANCELABLE,
    UNSUPPORTED_OPERATION,
    build_agent_card,
)
from redfall.interop.audit import list_calls
from redfall.interop.auth import create_token, identity_of
from redfall.interop.tools import ToolRegistry
from redfall.store.models import Base


def message(
    tool: str,
    arguments: dict | None = None,
    *,
    context_id: str = "",
    message_id: str = "",
) -> dict:
    payload = {
        "messageId": message_id or f"msg-{uuid.uuid4().hex[:10]}",
        "role": "ROLE_USER",
        "parts": [{"data": {"tool": tool, "arguments": arguments or {}}}],
    }
    if context_id:
        payload["contextId"] = context_id
    return payload


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("REDFALL_ALLOWED_ROOTS", str(tmp_path))
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'a2a.db'}",
        future=True,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    registry = ToolRegistry(Session)
    dispatched: list[str] = []
    service = A2AService(
        Session,
        registry,
        base_url="http://127.0.0.1:9",
        wait_timeout=10.0,
        executor=dispatched.append,
    )
    with Session() as session:
        admin, admin_token = create_token(
            session, name="admin", scopes=["read", "execute", "admin"]
        )
        reader, reader_token = create_token(session, name="reader", scopes=["read"])
        quota, quota_token = create_token(
            session, name="quota", scopes=["read"], quota_per_hour=1
        )
        session.commit()
        identities = {
            "admin": identity_of(admin),
            "reader": identity_of(reader),
            "quota": identity_of(quota),
        }
        tokens = {
            "admin": admin_token,
            "reader": reader_token,
            "quota": quota_token,
        }
    try:
        yield SimpleNamespace(
            service=service,
            Session=Session,
            registry=registry,
            identities=identities,
            tokens=tokens,
            dispatched=dispatched,
            engine=engine,
        )
    finally:
        service.close()
        engine.dispose()


def send(env, identity_name: str, tool: str, arguments: dict | None = None) -> str:
    result = env.service.send_message(
        {
            "message": message(tool, arguments),
            "configuration": {"returnImmediately": True},
        },
        env.identities[identity_name],
    )
    return str(result["task"]["id"])


def test_agent_card_is_a2a_v1_shaped():
    card = build_agent_card("http://127.0.0.1:9999", tool_count=44)
    assert card["name"] == "RedFall"
    assert card["version"]
    interface = card["supportedInterfaces"][0]
    assert interface == {
        "url": "http://127.0.0.1:9999/a2a/v1",
        "protocolBinding": "JSONRPC",
        "protocolVersion": "1.0",
    }
    assert card["capabilities"] == {
        "streaming": True,
        "pushNotifications": False,
        "extendedAgentCard": False,
    }
    scheme = card["securitySchemes"]["bearer"]["httpAuthSecurityScheme"]
    assert scheme["scheme"] == "Bearer"
    assert card["securityRequirements"] == [{"schemes": {"bearer": {"list": []}}}]
    assert card["defaultInputModes"] == ["application/json"]
    skill_ids = {skill["id"] for skill in card["skills"]}
    assert {"campaign", "code-graph", "scan", "reproduce", "report", "tools"} <= skill_ids


def test_task_lifecycle_executes_a_real_tool_and_stores_an_artifact(env):
    task_id = send(env, "admin", "redfall_health")
    snapshot = env.service.get_task({"id": task_id}, env.identities["admin"])
    assert snapshot["id"] == task_id
    assert snapshot["status"]["state"] == "TASK_STATE_SUBMITTED"
    assert snapshot["contextId"].startswith("ctx-")

    env.service.run_task(task_id)
    completed = env.service.get_task({"id": task_id}, env.identities["admin"])
    assert completed["status"]["state"] == "TASK_STATE_COMPLETED"
    assert completed["artifacts"], completed
    artifact = completed["artifacts"][0]
    part = artifact["parts"][0]
    assert part["data"]["ok"] is True
    assert part["metadata"]["redfall"]["trust"] == "untrusted-repository-data"
    assert artifact["metadata"]["redfall"]["sha256"]

    url = part["metadata"]["redfall"]["url"]
    parsed = urlsplit(url)
    query = parse_qs(parsed.query)
    with env.Session() as session:
        secret = artifacts.artifact_secret(session)
        assert artifacts.verify(
            secret, artifact["artifactId"], query["expires"][0], query["sig"][0]
        )
        calls = list_calls(session)
    assert any(
        call.protocol == "a2a"
        and call.tool == "redfall_health"
        and call.agent == "admin"
        and call.ok
        for call in calls
    )


def test_blocking_send_message_waits_for_completion(env):
    blocking = A2AService(
        env.Session,
        env.registry,
        base_url="http://127.0.0.1:9",
        wait_timeout=10.0,
        executor=lambda task_id: env.service.run_task(task_id),
    )
    try:
        result = blocking.send_message(
            {"message": message("redfall_health")}, env.identities["admin"]
        )
    finally:
        blocking.close()
    assert result["task"]["status"]["state"] == "TASK_STATE_COMPLETED"
    assert result["task"]["artifacts"][0]["parts"][0]["data"]["ok"] is True


def test_scope_denial_is_a_jsonrpc_error_and_is_audited(env):
    with pytest.raises(A2AError) as excinfo:
        env.service.send_message(
            {"message": message("redfall_graph_index", {"target": "/tmp"})},
            env.identities["reader"],
        )
    assert excinfo.value.code == INVALID_REQUEST
    assert "insufficient scope" in str(excinfo.value)
    with env.Session() as session:
        denied = [
            call
            for call in list_calls(session)
            if call.agent == "reader" and call.tool == "redfall_graph_index"
        ]
    assert denied and denied[0].ok is False


def test_quota_is_enforced_across_tasks(env):
    first = env.service.send_message(
        {
            "message": message("redfall_health"),
            "configuration": {"returnImmediately": True},
        },
        env.identities["quota"],
    )
    env.service.run_task(str(first["task"]["id"]))
    with pytest.raises(A2AError, match="quota exceeded"):
        env.service.send_message(
            {"message": message("redfall_health")}, env.identities["quota"]
        )


def test_cancel_before_execution_marks_the_task_canceled(env):
    task_id = send(env, "admin", "redfall_health")
    canceled = env.service.cancel_task({"id": task_id}, env.identities["admin"])
    assert canceled["status"]["state"] == "TASK_STATE_CANCELED"
    assert "before execution" in canceled["status"]["message"]["parts"][0]["text"]
    env.service.run_task(task_id)
    snapshot = env.service.get_task({"id": task_id}, env.identities["admin"])
    assert snapshot["status"]["state"] == "TASK_STATE_CANCELED"


def test_cancel_during_execution_is_cooperative_and_audited(env):
    class BlockingRegistry:
        def __init__(self, inner, started, release):
            self.inner = inner
            self.started = started
            self.release = release

        def specs(self):
            return self.inner.specs()

        def call(self, name, arguments):
            self.started.set()
            assert self.release.wait(10), "test did not release the blocking call"
            return {"ok": True, "tool": name, "arguments": arguments}

    started = threading.Event()
    release = threading.Event()
    blocking_service = A2AService(
        env.Session,
        BlockingRegistry(env.registry, started, release),
        base_url="http://127.0.0.1:9",
        executor=lambda task_id: None,
    )
    try:
        result = blocking_service.send_message(
            {
                "message": message("redfall_health"),
                "configuration": {"returnImmediately": True},
            },
            env.identities["admin"],
        )
        task_id = str(result["task"]["id"])
        worker = threading.Thread(
            target=blocking_service.run_task, args=(task_id,), daemon=True
        )
        worker.start()
        assert started.wait(10), "tool call never started"
        working = blocking_service.cancel_task(
            {"id": task_id}, env.identities["admin"]
        )
        assert working["status"]["state"] == "TASK_STATE_WORKING"
        release.set()
        worker.join(timeout=10)
        assert not worker.is_alive()
        snapshot = blocking_service.get_task(
            {"id": task_id}, env.identities["admin"]
        )
    finally:
        blocking_service.close()
    assert snapshot["status"]["state"] == "TASK_STATE_CANCELED"
    assert "after the tool call returned" in snapshot["status"]["message"]["parts"][0]["text"]
    with env.Session() as session:
        calls = [call for call in list_calls(session) if call.tool == "redfall_health"]
    assert calls and calls[0].ok is True


def test_cancel_of_a_terminal_task_is_refused(env):
    task_id = send(env, "admin", "redfall_health")
    env.service.run_task(task_id)
    with pytest.raises(A2AError) as excinfo:
        env.service.cancel_task({"id": task_id}, env.identities["admin"])
    assert excinfo.value.code == TASK_NOT_CANCELABLE


def test_list_tasks_paginates_and_filters_by_context(env):
    context = "ctx-pagination"
    for _ in range(3):
        result = env.service.send_message(
            {
                "message": message("redfall_health", context_id=context),
                "configuration": {"returnImmediately": True},
            },
            env.identities["admin"],
        )
        assert result["task"]["contextId"] == context
    first = env.service.list_tasks(
        {"contextId": context, "pageSize": 2}, env.identities["admin"]
    )
    assert len(first["tasks"]) == 2
    assert first["pageSize"] == 2
    assert first["totalSize"] == 3
    assert first["nextPageToken"]
    second = env.service.list_tasks(
        {"contextId": context, "pageSize": 2, "pageToken": first["nextPageToken"]},
        env.identities["admin"],
    )
    assert len(second["tasks"]) == 1
    assert second["nextPageToken"] == ""
    ids = {task["id"] for task in first["tasks"]} | {
        task["id"] for task in second["tasks"]
    }
    assert len(ids) == 3


def test_tasks_are_isolated_by_agent_name(env):
    task_id = send(env, "admin", "redfall_health")
    with pytest.raises(A2AError, match="task not found"):
        env.service.get_task({"id": task_id}, env.identities["reader"])


def test_unknown_tool_and_multi_turn_are_rejected(env):
    with pytest.raises(A2AError) as unknown:
        env.service.send_message(
            {"message": message("redfall_no_such_tool")}, env.identities["admin"]
        )
    assert unknown.value.code == INVALID_PARAMS
    continuation = message("redfall_health")
    continuation["taskId"] = "task-existing"
    with pytest.raises(A2AError) as multi:
        env.service.send_message(
            {"message": continuation}, env.identities["admin"]
        )
    assert multi.value.code == UNSUPPORTED_OPERATION


def test_json_rpc_errors_for_unimplemented_and_unknown_methods(env):
    unknown = env.service.handle_rpc(
        {"jsonrpc": "2.0", "id": 1, "method": "NotAMethod", "params": {}},
        env.identities["admin"],
    )
    assert unknown["error"]["code"] == METHOD_NOT_FOUND
    push = env.service.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "CreateTaskPushNotificationConfig",
            "params": {},
        },
        env.identities["admin"],
    )
    assert push["error"]["code"] == PUSH_NOT_SUPPORTED
    streaming = env.service.handle_rpc(
        {"jsonrpc": "2.0", "id": 3, "method": "SendStreamingMessage", "params": {}},
        env.identities["admin"],
    )
    assert streaming["error"]["code"] == INVALID_REQUEST
    extension = env.service.handle_rpc(
        {"jsonrpc": "2.0", "id": 4, "method": "GetExtendedAgentCard", "params": {}},
        env.identities["admin"],
    )
    assert extension["error"]["code"] == UNSUPPORTED_OPERATION


def test_stream_events_begin_with_task_and_end_with_completion(env):
    task_id = send(env, "admin", "redfall_health")
    env.service.run_task(task_id)
    events = list(env.service._stream_events(task_id, env.identities["admin"]))
    assert "task" in events[0]
    artifact_updates = [event for event in events if "artifactUpdate" in event]
    assert artifact_updates
    assert artifact_updates[0]["artifactUpdate"]["lastChunk"] is True
    final = events[-1]
    assert final["statusUpdate"]["status"]["state"] == "TASK_STATE_COMPLETED"


def test_subscribe_to_working_task_streams_to_completion(env):
    task_id = send(env, "admin", "redfall_health")
    request_id, events = env.service.prepare_stream(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "SubscribeToTask",
            "params": {"id": task_id},
        },
        env.identities["admin"],
    )
    assert request_id == 9
    env.service.run_task(task_id)
    collected = list(events)
    assert "task" in collected[0]
    assert collected[-1]["statusUpdate"]["status"]["state"] == "TASK_STATE_COMPLETED"

    with pytest.raises(A2AError) as terminal:
        env.service.subscribe({"id": task_id}, env.identities["admin"])
    assert terminal.value.code == UNSUPPORTED_OPERATION
