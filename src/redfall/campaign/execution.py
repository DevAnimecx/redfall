"""Typed task execution contracts shared by the runner and its handlers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from sqlalchemy.orm import Session, sessionmaker

from ..config import Config
from ..store.models import Campaign, CampaignTask


class TaskBlocked(RuntimeError):
    """A task cannot proceed until an external prerequisite changes.

    Retrying the same task on the same host would produce the same blocked
    result, so the runner records a terminal task failure and blocks the
    campaign instead of burning attempts.
    """

    def __init__(self, reason: str, *, details: list[str] | None = None) -> None:
        self.reason = reason
        self.details = list(details or [])
        super().__init__(reason)


@dataclass
class TaskContext:
    campaign: Campaign
    task: CampaignTask
    session: Session
    session_factory: sessionmaker
    config: Config
    worker: str

    @property
    def payload(self) -> dict[str, Any]:
        return dict(self.task.payload or {})

    def require_payload_str(self, key: str) -> str:
        value = self.payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"task {self.task.id} requires payload.{key}")
        return value.strip()


@dataclass
class TaskResult:
    result: dict[str, Any] = field(default_factory=dict)
    spend: dict[str, float | int] = field(default_factory=dict)

    @classmethod
    def coerce(cls, value: Any) -> "TaskResult":
        if isinstance(value, cls):
            return value
        if isinstance(value, dict):
            return cls(result=value)
        raise TypeError(f"task handler returned {type(value).__name__}, expected dict or TaskResult")


@dataclass(frozen=True)
class HandlerSpec:
    name: str
    handler: Callable[[TaskContext], Any]
    estimate: Callable[[TaskContext], dict[str, float | int]] | None = None

    def estimate_for(self, context: TaskContext) -> dict[str, float | int]:
        if self.estimate is None:
            return {}
        values = self.estimate(context)
        out: dict[str, float | int] = {}
        for key in ("usd", "tokens", "sandbox_minutes"):
            raw = values.get(key, 0)
            out[key] = type(raw)(raw) if raw is not None else 0
        return out
