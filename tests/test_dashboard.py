"""0.3.0: the dashboard API, its event bus and its SSE stream."""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _registry():
    from redfall.interop.tools import ToolRegistry

    # A registry whose DB scope is never entered: only the DB-free routes are
    # exercised here. The socket contract test uses a real registry.
    return ToolRegistry(lambda: None)


def _dashboard(**kw):
    from redfall.dashboard import Dashboard

    return Dashboard(_registry(), **kw)


# --------------------------------------------------------------- routing

def test_root_reports_identity():
    status, body = _dashboard().handle("GET", "/")
    assert status == 200
    assert body["name"] == "redfall dashboard"


def test_api_version_reports_tool_count():
    status, body = _dashboard().handle("GET", "/api/version")
    assert status == 200
    assert body["tools"] >= 46


def test_unknown_route_is_404_json():
    from redfall.dashboard import ApiError

    with pytest.raises(ApiError) as caught:
        _dashboard().handle("GET", "/api/nonsense")
    assert caught.value.status == 404
    assert caught.value.kind == "not_found"


def test_method_not_allowed_on_scans_collection():
    from redfall.dashboard import ApiError

    with pytest.raises(ApiError) as caught:
        _dashboard().handle("DELETE", "/api/scans")
    assert caught.value.status == 405


def test_start_scan_requires_a_target():
    from redfall.dashboard import ApiError

    with pytest.raises(ApiError) as caught:
        _dashboard().handle("POST", "/api/scans", body={})
    assert caught.value.status == 400
    assert caught.value.kind == "bad_request"


# --------------------------------------------------------------- auth

def test_auth_is_open_when_no_token_is_configured():
    status, _ = _dashboard().handle("GET", "/api/version")
    assert status == 200


def test_auth_rejects_a_missing_token():
    from redfall.dashboard import ApiError

    d = _dashboard(token="secret")
    with pytest.raises(ApiError) as caught:
        d.handle("GET", "/api/version")
    assert caught.value.status == 401


def test_auth_rejects_a_wrong_token():
    from redfall.dashboard import ApiError

    d = _dashboard(token="secret")
    with pytest.raises(ApiError) as caught:
        d.handle("GET", "/api/version", auth_header="Bearer nope")
    assert caught.value.status == 403


def test_auth_accepts_the_right_token():
    d = _dashboard(token="secret")
    status, _ = d.handle("GET", "/api/version", auth_header="Bearer secret")
    assert status == 200


# --------------------------------------------------------------- projects

def test_projects_list_returns_configured_roots(tmp_path):
    status, body = _dashboard(projects=[str(tmp_path)]).handle("GET", "/api/projects")
    assert status == 200
    assert str(tmp_path) in body["projects"]


def test_scan_target_outside_project_roots_is_refused(tmp_path):
    from redfall.dashboard import ApiError

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    d = _dashboard(projects=[str(allowed)])
    with pytest.raises(ApiError) as caught:
        d.handle("POST", "/api/scans", body={"target": str(outside)})
    assert caught.value.status == 403
    assert caught.value.kind == "out_of_scope"


def test_scan_target_inside_project_roots_passes_the_scope_gate(tmp_path):
    from redfall.dashboard import ApiError

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    d = _dashboard(projects=[str(allowed)])
    try:
        d.handle("POST", "/api/scans", body={"target": str(allowed)})
    except ApiError as err:
        # Past the scope gate: it failed for a different reason (no database
        # behind this registry), not because the path was out of scope.
        assert err.kind != "out_of_scope"


# --------------------------------------------------------------- event bus

def test_bus_publishes_and_replays_to_a_late_subscriber():
    from redfall.dashboard import EventBus

    bus = EventBus()
    bus.publish("scan:start", {"target": "x"}, "scan-1")
    bus.publish("branch:done", {"branch": "a"}, "scan-1")
    with bus.subscribe("scan-1") as sub:
        got = []
        for event in sub.events(heartbeat_s=0.01):
            if event is None:
                break
            got.append(event.kind)
            if len(got) == 2:
                break
        assert got == ["scan:start", "branch:done"]


def test_bus_filters_by_scan_id():
    from redfall.dashboard import EventBus

    bus = EventBus()
    bus.publish("a", {}, "scan-1")
    bus.publish("b", {}, "scan-2")
    with bus.subscribe("scan-1") as sub:
        events = []
        for event in sub.events(heartbeat_s=0.01):
            if event is None:
                break
            events.append(event.kind)
        assert events == ["a"]


def test_bus_bounds_history():
    from redfall.dashboard import EventBus

    bus = EventBus(history=3)
    for i in range(10):
        bus.publish("e", {"i": i}, "scan-1")
    with bus.subscribe("scan-1") as sub:
        events = []
        for event in sub.events(heartbeat_s=0.01):
            if event is None:
                break
            events.append(event.payload["i"])
        assert events == [7, 8, 9]


def test_bus_close_ends_subscribers():
    from redfall.dashboard import EventBus, EventBusError

    bus = EventBus()
    sub = bus.subscribe()
    bus.close()
    assert sub.dropped == 0
    with pytest.raises(EventBusError):
        bus.publish("x", {})


def test_event_sse_framing_is_valid():
    from redfall.dashboard.events import Event

    event = Event(seq=4, kind="finding", scan_id="s1", payload={"a": 1}, at="t")
    frame = event.sse()
    assert frame.startswith("id: 4\nevent: finding\ndata: ")
    assert frame.endswith("\n\n")
    data = json.loads(frame.split("data: ", 1)[1].strip())
    assert data["payload"] == {"a": 1}


def test_slow_subscriber_is_counted_as_dropped_not_unbounded():
    from redfall.dashboard import EventBus

    bus = EventBus(queue_size=2)
    with bus.subscribe() as sub:
        for i in range(6):
            bus.publish("e", {"i": i})
        assert sub.dropped > 0
        assert sub._sub.queue.qsize() <= 2


# --------------------------------------------------------------- real socket

@pytest.fixture()
def live_server():
    from redfall.dashboard import serve_dashboard

    server = serve_dashboard(host="127.0.0.1", port=0, registry=_registry())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield server, f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def test_socket_serves_json(live_server):
    _server, url = live_server
    with urllib.request.urlopen(f"{url}/api/version", timeout=5) as response:
        assert response.status == 200
        body = json.loads(response.read())
    assert body["tools"] >= 46


def test_socket_returns_json_for_404(live_server):
    _server, url = live_server
    try:
        urllib.request.urlopen(f"{url}/api/nope", timeout=5)
        raise AssertionError("expected a 404")
    except urllib.error.HTTPError as err:
        assert err.code == 404
        body = json.loads(err.read())
    assert body["error"]["kind"] == "not_found"


def test_socket_streams_server_sent_events(live_server):
    """A real SSE connection receives a real published event over the socket."""
    from urllib.request import Request

    server, url = live_server
    received: list[str] = []
    ready = threading.Event()

    def read_stream() -> None:
        request = Request(f"{url}/api/scans/scan-x/events")
        with urllib.request.urlopen(request, timeout=10) as response:
            assert response.headers["Content-Type"] == "text/event-stream"
            ready.set()
            for raw in response:
                line = raw.decode("utf-8")
                received.append(line)
                if "event: finding" in line:
                    break

    thread = threading.Thread(target=read_stream, daemon=True)
    thread.start()
    assert ready.wait(timeout=5), "the SSE stream never opened"
    time.sleep(0.2)  # let the server finish subscribing
    server.dashboard.bus.publish("finding", {"id": "f1"}, "scan-x")
    thread.join(timeout=5)
    assert any("event: finding" in line for line in received), received


def test_socket_rejects_a_bad_token(live_server):
    server, url = live_server
    server.dashboard.token = "secret"
    try:
        urllib.request.urlopen(f"{url}/api/version", timeout=5)
        raise AssertionError("expected a 401")
    except urllib.error.HTTPError as err:
        assert err.code == 401


# -- live scans ------------------------------------------------------------


def test_a_live_scan_is_identifiable_before_it_starts():
    """A scan mints its stream id up front, so a browser can subscribe before
    the first event. Without that, a client races the start of the scan."""
    from redfall.dashboard import EventBus

    bus = EventBus()
    scan_id = bus.new_scan_id()
    assert scan_id.startswith("live-")
    assert scan_id != bus.new_scan_id()

    sub = bus.subscribe(scan_id)
    try:
        bus.publish("scan:start", {"target": "/repo"}, scan_id)
        first = next(sub.events(heartbeat_s=0.01))
    finally:
        sub.close()
    assert first is not None
    assert first.kind == "scan:start"
    assert first.scan_id == scan_id


def test_a_live_scan_that_never_runs_is_not_in_the_store():
    """`GET /api/scans/live-...` answers from the bus, not the database."""
    dashboard = _dashboard(projects=[])
    scan_id = dashboard.bus.new_scan_id()
    status, body = dashboard.handle("GET", f"/api/scans/{scan_id}")
    assert status == 200
    assert body["live"] is True
    assert body["status"] == "running"
    assert body["queued"] is False


def test_bus_reports_whether_anyone_is_watching():
    from redfall.dashboard import EventBus

    bus = EventBus()
    assert bus.has_subscribers() is False
    assert bus.has_subscribers("live-abc") is False

    sub = bus.subscribe("live-abc")
    try:
        assert bus.has_subscribers() is True
        assert bus.has_subscribers("live-abc") is True
        assert bus.has_subscribers("live-other") is False
    finally:
        sub.close()

    assert bus.has_subscribers() is False


def test_starting_a_scan_returns_the_stream_id(tmp_path):
    """The 202 carries a scan id, so the caller can open the right stream."""
    dashboard = _dashboard(projects=[str(tmp_path)])
    status, body = dashboard.handle("POST", "/api/scans", body={"target": str(tmp_path)})
    assert status == 202
    assert body["scan_id"].startswith("live-")
    assert body["events"] == f"/api/scans/{body['scan_id']}/events"
