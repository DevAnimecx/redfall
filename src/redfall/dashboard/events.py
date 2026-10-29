"""A bounded, in-process event bus for the dashboard's live stream.

A running scan emits events; every connected browser gets them. The bus is
deliberately small and honest about its limits:

* **Bounded per subscriber.** A slow client cannot make the server grow without
  limit: past the bound, the oldest undelivered event is dropped and the
  subscriber is told it fell behind (`dropped` in the stream). Losing an event
  is visible, never silent.
* **Replay for late joiners.** A subscriber that connects mid-scan gets the
  buffered history first, so the UI is not empty until the next event.
* **No cross-process claim.** This bus serves one process. A multi-worker
  deployment would need Redis pub/sub; that is not claimed here, and the
  single-process scope is stated rather than implied.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterator


class EventBusError(RuntimeError):
    """The bus cannot serve a subscriber (closed, or over its limit)."""


@dataclass
class Event:
    seq: int
    kind: str
    scan_id: str | None
    payload: dict[str, Any]
    at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "scan_id": self.scan_id,
            "payload": self.payload,
            "at": self.at,
        }

    def sse(self) -> str:
        """The wire form for `text/event-stream`."""
        import json

        lines = [f"id: {self.seq}", f"event: {self.kind}"]
        lines.append("data: " + json.dumps(self.as_dict(), default=str))
        return "\n".join(lines) + "\n\n"


@dataclass
class _Subscriber:
    scan_id: str | None
    queue: "queue.Queue[Event]" = field(default_factory=lambda: queue.Queue(maxsize=256))
    dropped: int = 0


class EventBus:
    """Publish scan events; subscribe with a bounded per-client queue."""

    def __init__(self, *, history: int = 500, queue_size: int = 256) -> None:
        self._lock = threading.Lock()
        self._subs: list[_Subscriber] = []
        self._history: list[Event] = []
        self._history_max = history
        self._queue_size = queue_size
        self._seq = 0
        self._closed = False

    def new_scan_id(self) -> str:
        """Mint an id for a scan before it starts.

        A scan that has not run yet has no database id. The caller needs one
        anyway: a browser must be able to subscribe to a scan's stream before the
        scan emits its first event, otherwise it races the start. The id is
        prefixed so it is never mistaken for a persisted campaign id.
        """
        import uuid

        return f"live-{uuid.uuid4().hex[:12]}"

    def publish(self, kind: str, payload: dict[str, Any], scan_id: str | None = None) -> Event:
        from datetime import datetime, timezone

        with self._lock:
            if self._closed:
                raise EventBusError("the event bus is closed")
            self._seq += 1
            event = Event(
                seq=self._seq,
                kind=kind,
                scan_id=scan_id,
                payload=payload,
                at=datetime.now(timezone.utc).isoformat(),
            )
            self._history.append(event)
            if len(self._history) > self._history_max:
                self._history = self._history[-self._history_max :]
            for sub in list(self._subs):
                if sub.scan_id is not None and scan_id is not None and sub.scan_id != scan_id:
                    continue
                self._deliver(sub, event)
            return event

    def _deliver(self, sub: _Subscriber, event: Event) -> None:
        try:
            sub.queue.put_nowait(event)
        except queue.Full:
            # Drop the oldest so the newest is always present, and count it.
            if not sub.queue.empty():
                sub.queue.get_nowait()
            sub.dropped += 1
            try:
                sub.queue.put_nowait(event)
            except queue.Full:
                sub.dropped += 1

    def subscribe(self, scan_id: str | None = None, *, replay: bool = True) -> "_Subscription":
        sub = _Subscriber(scan_id=scan_id, queue=queue.Queue(maxsize=self._queue_size))
        with self._lock:
            if self._closed:
                raise EventBusError("the event bus is closed")
            if replay:
                for event in self._history:
                    if scan_id is None or event.scan_id == scan_id:
                        self._deliver(sub, event)
            self._subs.append(sub)
        return _Subscription(self, sub)

    def _unsubscribe(self, sub: _Subscriber) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            closing = Event(seq=self._seq + 1, kind="closed", scan_id=None, payload={}, at="")
            for sub in self._subs:
                if sub.queue.full():
                    # The subscriber is gone or not draining; there is no one
                    # left to notify, so the close event is skipped for it.
                    continue
                sub.queue.put_nowait(closing)
            self._subs.clear()

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subs)

    def has_subscribers(self, scan_id: str | None = None) -> bool:
        """True when at least one client is watching, optionally for one scan."""
        with self._lock:
            if scan_id is None:
                return bool(self._subs)
            return any(s.scan_id == scan_id for s in self._subs)


class _Subscription:
    """A live subscription. Use as a context manager or call `close`."""

    def __init__(self, bus: EventBus, sub: _Subscriber) -> None:
        self._bus = bus
        self._sub = sub
        self._closed = False

    @property
    def dropped(self) -> int:
        return self._sub.dropped

    def events(self, *, heartbeat_s: float = 15.0) -> Iterator[Event | None]:
        """Yield events; yield None on heartbeat so the caller can keep the
        connection warm and detect a dead client."""
        while not self._closed:
            try:
                yield self._sub.queue.get(timeout=heartbeat_s)
            except queue.Empty:
                yield None

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._bus._unsubscribe(self._sub)

    def __enter__(self) -> "_Subscription":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def now_ms() -> int:
    return int(time.time() * 1000)


__all__ = ["Event", "EventBus", "EventBusError"]
