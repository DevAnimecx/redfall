"""Webhook subscriptions and delivery for campaign events.

Subscriptions are operator-configured rows. Delivery is a separate, idempotent
step: `enqueue_recent_events` mirrors campaign events into `webhook_deliveries`
once per subscription (the unique constraint makes re-running it safe), and
`deliver_pending` sends the pending set with an HMAC-SHA256 signature over the
exact request body. Failures stay visible in the delivery row instead of being
swallowed.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
from fnmatch import fnmatchcase
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..store.models import CampaignEvent, WebhookDelivery, WebhookSubscription, utcnow

MAX_ATTEMPTS = 3
DEFAULT_TIMEOUT = 10.0


class WebhookError(RuntimeError):
    """A webhook URL was rejected or a delivery failed."""


class _NoRedirect(HTTPRedirectHandler):
    """Do not follow redirects; a redirect is a failed delivery, not a new target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


_OPENER = build_opener(_NoRedirect)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(10)}"


def validate_url(url: str, *, allow_loopback: bool = False) -> str:
    """Return the URL when it is an acceptable webhook target.

    Only ``http``/``https`` are accepted; link-local addresses are always
    rejected; loopback targets are rejected unless the operator explicitly
    allows them (useful for local CI receivers, never for agent-supplied push
    configuration in production).
    """

    parts = urlsplit(url.strip())
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise WebhookError("webhook url must be an absolute http(s) URL")
    host = parts.hostname or ""
    if not host:
        raise WebhookError("webhook url has no host")
    lowered = host.lower()
    literal: ipaddress._BaseAddress | None = None
    try:
        literal = ipaddress.ip_address(lowered)
    except ValueError:
        literal = None
    if literal is not None:
        if literal.is_link_local:
            raise WebhookError("link-local webhook targets are not allowed")
        if literal.is_loopback and not allow_loopback:
            raise WebhookError("loopback webhook targets require allow_loopback")
    elif lowered in {"localhost", "localhost.localdomain"} and not allow_loopback:
        raise WebhookError("loopback webhook targets require allow_loopback")
    return url.strip()


def subscribe(
    session: Session,
    *,
    url: str,
    events: list[str],
    secret: str = "",
    allow_loopback: bool = False,
) -> tuple[WebhookSubscription, str]:
    clean_events = sorted({str(event).strip() for event in events if str(event).strip()})
    if not clean_events:
        raise WebhookError("at least one event pattern is required")
    target = validate_url(url, allow_loopback=allow_loopback)
    plaintext = secret.strip() or secrets.token_urlsafe(24)
    row = WebhookSubscription(
        id=_new_id("wh"),
        url=target,
        events=clean_events,
        secret=plaintext,
        active=True,
    )
    session.add(row)
    session.flush()
    return row, plaintext


def list_subscriptions(session: Session) -> list[WebhookSubscription]:
    return list(
        session.scalars(
            select(WebhookSubscription).order_by(WebhookSubscription.created_at.desc())
        ).all()
    )


def remove_subscription(session: Session, subscription_id: str) -> bool:
    from sqlalchemy import delete

    row = session.get(WebhookSubscription, subscription_id)
    if row is None:
        return False
    session.execute(
        delete(WebhookDelivery).where(WebhookDelivery.subscription_id == subscription_id)
    )
    session.delete(row)
    session.flush()
    return True


def matches(events: list[str], kind: str) -> bool:
    return any(fnmatchcase(kind, pattern) for pattern in events or [])


def _as_utc(value: Any) -> Any:
    from datetime import timezone

    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def signature(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def enqueue_recent_events(session: Session, *, limit: int = 200) -> int:
    """Mirror recent campaign events into pending deliveries, once per subscription."""

    events = list(
        session.scalars(
            select(CampaignEvent).order_by(CampaignEvent.created_at.desc()).limit(max(1, limit))
        ).all()
    )
    if not events:
        return 0
    subscriptions = [sub for sub in list_subscriptions(session) if sub.active]
    created = 0
    for event in reversed(events):
        for sub in subscriptions:
            if not matches(list(sub.events or []), event.kind):
                continue
            if (
                _as_utc(sub.created_at) is not None
                and _as_utc(event.created_at) is not None
                and _as_utc(event.created_at) < _as_utc(sub.created_at)
            ):
                # A subscription starts at its creation time; replaying history
                # into a brand-new receiver is how you get an accidental flood.
                continue
            existing = session.scalar(
                select(WebhookDelivery.id).where(
                    WebhookDelivery.subscription_id == sub.id,
                    WebhookDelivery.event_id == event.id,
                )
            )
            if existing is not None:
                continue
            session.add(
                WebhookDelivery(
                    id=_new_id("whd"),
                    subscription_id=sub.id,
                    event_id=event.id,
                    campaign_id=event.campaign_id,
                    event_kind=event.kind,
                    payload=event.to_wire(),
                    status="pending",
                )
            )
            created += 1
    session.flush()
    return created


def send_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    allow_loopback: bool = False,
) -> tuple[int, str]:
    """POST one JSON object and return ``(status_code, body_excerpt)``.

    Raises ``WebhookError`` on transport failure. A 3xx is returned as-is and
    treated as a failure by the caller.
    """

    target = validate_url(url, allow_loopback=allow_loopback)
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    request_headers = {"Content-Type": "application/json", "User-Agent": "redfall-interop/0.1"}
    request_headers.update(headers or {})
    request = Request(target, data=body, headers=request_headers, method="POST")
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            excerpt = response.read(2048).decode("utf-8", errors="replace")
            return int(response.status), excerpt
    except HTTPError as exc:
        excerpt = exc.read(2048).decode("utf-8", errors="replace")
        return int(exc.code), excerpt
    except (URLError, TimeoutError, OSError) as exc:
        raise WebhookError(f"{type(exc).__name__}: {exc}") from exc


def deliver_pending(
    session: Session,
    *,
    limit: int = 20,
    timeout: float = DEFAULT_TIMEOUT,
    allow_loopback: bool = False,
) -> dict[str, int]:
    """Attempt pending and retryable failed deliveries once each."""

    rows = list(
        session.scalars(
            select(WebhookDelivery)
            .where(
                (WebhookDelivery.status == "pending")
                | (
                    (WebhookDelivery.status == "failed")
                    & (WebhookDelivery.attempts < MAX_ATTEMPTS)
                )
            )
            .order_by(WebhookDelivery.created_at.asc())
            .limit(max(1, limit))
        ).all()
    )
    delivered = 0
    failed = 0
    for row in rows:
        sub = session.get(WebhookSubscription, row.subscription_id)
        if sub is None or not sub.active:
            row.status = "failed"
            row.last_error = "subscription missing or inactive"
            row.updated_at = utcnow()
            failed += 1
            continue
        body = json.dumps(
            row.payload or {}, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-Redfall-Event": row.event_kind,
            "X-Redfall-Delivery": row.id,
            "X-Redfall-Attempt": str(row.attempts + 1),
            "X-Redfall-Signature": signature(sub.secret, body),
        }
        try:
            status, excerpt = send_json(
                sub.url,
                row.payload or {},
                headers=headers,
                timeout=timeout,
                allow_loopback=allow_loopback,
            )
        except WebhookError as exc:
            row.attempts += 1
            row.status = "failed"
            row.last_error = f"{type(exc).__name__}: {exc}"[:500]
            row.updated_at = utcnow()
            failed += 1
            continue
        row.attempts += 1
        row.last_status_code = status
        row.updated_at = utcnow()
        if 200 <= status < 300:
            row.status = "delivered"
            row.last_error = ""
            delivered += 1
        else:
            row.status = "failed"
            row.last_error = f"HTTP {status}: {excerpt[:200]}"
            failed += 1
    session.flush()
    remaining = session.scalar(
        select(WebhookDelivery.id).where(WebhookDelivery.status == "pending").limit(1)
    )
    return {"delivered": delivered, "failed": failed, "pending": 1 if remaining else 0}


def deliver_push_notification(
    *,
    url: str,
    payload: dict[str, Any],
    token: str = "",
    scheme: str = "",
    timeout: float = DEFAULT_TIMEOUT,
    allow_loopback: bool = False,
) -> tuple[bool, str]:
    """One best-effort A2A push notification. Returns ``(ok, detail)``."""

    headers = {"Content-Type": "application/a2a+json"}
    if scheme and token:
        headers["Authorization"] = f"{scheme} {token}"
    try:
        status, excerpt = send_json(
            url,
            payload,
            headers=headers,
            timeout=timeout,
            allow_loopback=allow_loopback,
        )
    except WebhookError as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if 200 <= status < 300:
        return True, f"HTTP {status}"
    return False, f"HTTP {status}: {excerpt[:200]}"
