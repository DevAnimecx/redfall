"""Operator webhooks: URL policy, idempotent enqueue, HMAC signatures and retries."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from redfall.campaign.service import CampaignService
from redfall.interop.webhooks import (
    WebhookError,
    deliver_pending,
    enqueue_recent_events,
    list_subscriptions,
    remove_subscription,
    signature,
    subscribe,
)
from redfall.store.models import Base, CampaignEvent, WebhookDelivery


@pytest.fixture()
def session(tmp_path):
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'webhooks.db'}", future=True
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with Session() as db:
        yield db
    engine.dispose()


@pytest.fixture()
def receiver():
    received: list[dict] = []
    state = {"status": 200, "headers": {}}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            received.append(
                {
                    "headers": {key.lower(): value for key, value in self.headers.items()},
                    "body": body,
                }
            )
            self.send_response(state["status"])
            for key, value in state["headers"].items():
                self.send_header(key, value)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, fmt: str, *args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/hook"
    try:
        yield SimpleNamespace(url=url, received=received, state=state)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def make_event(session, tmp_path) -> CampaignEvent:
    campaign = CampaignService(session).create(
        str(tmp_path), scope={"repos": [str(tmp_path)]}
    )
    session.flush()
    event = (
        session.query(CampaignEvent)
        .filter(CampaignEvent.campaign_id == campaign.id)
        .order_by(CampaignEvent.seq.desc())
        .first()
    )
    assert event is not None and event.kind == "campaign.created"
    return event


def test_loopback_targets_require_explicit_opt_in(session, receiver):
    with pytest.raises(WebhookError, match="loopback"):
        subscribe(session, url=receiver.url, events=["campaign.*"])
    row, secret = subscribe(
        session,
        url=receiver.url,
        events=["campaign.*"],
        allow_loopback=True,
    )
    assert secret
    assert row.to_wire()["has_secret"] is True
    assert row.to_wire()["events"] == ["campaign.*"]


def test_non_http_and_link_local_targets_are_rejected(session):
    with pytest.raises(WebhookError, match="absolute http"):
        subscribe(session, url="ftp://example.com/hook", events=["campaign.*"])
    with pytest.raises(WebhookError, match="link-local"):
        subscribe(
            session,
            url="http://169.254.169.254/hook",
            events=["campaign.*"],
            allow_loopback=True,
        )


def test_delivery_is_signed_and_matches_the_campaign_event(session, receiver, tmp_path):
    _row, secret = subscribe(
        session,
        url=receiver.url,
        events=["campaign.*"],
        allow_loopback=True,
    )
    event = make_event(session, tmp_path)
    enqueued = enqueue_recent_events(session)
    assert enqueued == 1
    summary = deliver_pending(session, allow_loopback=True)
    assert summary == {"delivered": 1, "failed": 0, "pending": 0}
    assert len(receiver.received) == 1
    request = receiver.received[0]
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), request["body"], hashlib.sha256
    ).hexdigest()
    assert request["headers"]["x-redfall-signature"] == expected
    assert request["headers"]["x-redfall-event"] == "campaign.created"
    payload = json.loads(request["body"])
    assert payload["id"] == event.id
    assert payload["kind"] == "campaign.created"


def test_enqueue_is_idempotent(session, receiver, tmp_path):
    subscribe(
        session,
        url=receiver.url,
        events=["campaign.*"],
        allow_loopback=True,
    )
    make_event(session, tmp_path)
    assert enqueue_recent_events(session) == 1
    assert enqueue_recent_events(session) == 0
    assert session.query(WebhookDelivery).count() == 1


def test_failed_delivery_is_retried(session, receiver, tmp_path):
    subscribe(
        session,
        url=receiver.url,
        events=["campaign.*"],
        allow_loopback=True,
    )
    make_event(session, tmp_path)
    enqueue_recent_events(session)
    receiver.state["status"] = 500
    first = deliver_pending(session, allow_loopback=True)
    assert first == {"delivered": 0, "failed": 1, "pending": 0}
    delivery = session.query(WebhookDelivery).one()
    assert delivery.status == "failed"
    assert delivery.attempts == 1
    assert delivery.last_status_code == 500
    receiver.state["status"] = 200
    second = deliver_pending(session, allow_loopback=True)
    assert second == {"delivered": 1, "failed": 0, "pending": 0}
    session.refresh(delivery)
    assert delivery.status == "delivered"
    assert delivery.attempts == 2


def test_redirects_are_not_followed(session, receiver, tmp_path):
    subscribe(
        session,
        url=receiver.url,
        events=["campaign.*"],
        allow_loopback=True,
    )
    make_event(session, tmp_path)
    enqueue_recent_events(session)
    receiver.state["status"] = 302
    receiver.state["headers"] = {"Location": receiver.url + "/elsewhere"}
    summary = deliver_pending(session, allow_loopback=True)
    assert summary["failed"] == 1
    assert len(receiver.received) == 1
    delivery = session.query(WebhookDelivery).one()
    assert delivery.last_status_code == 302
    assert "HTTP 302" in delivery.last_error


def test_event_patterns_are_filters(session, tmp_path):
    subscribe(
        session,
        url="https://example.invalid/hook",
        events=["finding.*"],
    )
    make_event(session, tmp_path)
    assert enqueue_recent_events(session) == 0


def test_a_new_subscription_does_not_replay_old_events(session, tmp_path):
    make_event(session, tmp_path)
    subscribe(
        session,
        url="https://example.invalid/hook",
        events=["campaign.*"],
    )
    assert enqueue_recent_events(session) == 0


def test_matching_subscription_enqueues_the_event(session, tmp_path):
    subscribe(
        session,
        url="https://example.invalid/hook",
        events=["campaign.created"],
    )
    make_event(session, tmp_path)
    assert enqueue_recent_events(session) == 1


def test_removal(session):
    row, _secret = subscribe(
        session, url="https://example.invalid/hook", events=["campaign.*"]
    )
    assert len(list_subscriptions(session)) == 1
    assert remove_subscription(session, row.id) is True
    assert list_subscriptions(session) == []
    assert remove_subscription(session, row.id) is False


def test_signature_is_stable():
    body = b'{"a":1}'
    assert signature("secret", body) == signature("secret", body)
    assert signature("secret", body).startswith("sha256=")
    assert signature("other", body) != signature("secret", body)
