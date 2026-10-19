"""Campaign lifecycle, durable tasks, leases and budget enforcement.

The service owns state changes; SQLAlchemy owns persistence. There is no
in-memory fallback: every method reads and writes the session it was given. A
caller that wants a transaction boundary uses ``session_scope`` or commits its
own session.

Leases are intentionally simple. A worker claims a task, gets a deadline, and
must renew by completing or failing before the deadline. An expired lease is
requeued (or failed after ``max_attempts``), never silently treated as success.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..store.models import Campaign, CampaignEvent, CampaignTask, EvidenceRecord
from .state import (
    ACTIVE_STATES,
    SIDE_STATES,
    TERMINAL_STATES,
    CampaignState,
    ensure_transition,
    parse_state,
)

OBJECTIVES = frozenset({"discovery", "reproduction", "fix", "regression", "chain", "compliance"})


class CampaignError(RuntimeError):
    """A campaign operation cannot be completed as requested."""


class CampaignNotFound(CampaignError):
    """The requested campaign does not exist."""


class InvalidTransition(CampaignError):
    """The requested state change is not legal from the current state."""


class CampaignBudgetExceeded(CampaignError):
    """A spend would cross a campaign budget ceiling."""


class TaskStateError(CampaignError):
    """A task is not in a state that allows the requested operation."""


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


class CampaignService:
    """All state changes for campaigns, tasks, events and spend."""

    def __init__(self, session: Session, *, clock: Callable[[], datetime] | None = None) -> None:
        self.session = session
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # ------------------------------------------------------------------ read
    def _dialect(self) -> str:
        try:
            return self.session.get_bind().dialect.name
        except Exception:
            return ""

    def _get(self, campaign_id: str, *, lock: bool = False) -> Campaign:
        statement = select(Campaign).where(Campaign.id == campaign_id)
        if lock and self._dialect() not in {"sqlite", ""}:
            statement = statement.with_for_update()
        campaign = self.session.execute(statement).scalar_one_or_none()
        if campaign is None:
            raise CampaignNotFound(f"no such campaign: {campaign_id}")
        return campaign

    def get(self, campaign_id: str) -> Campaign:
        return self._get(campaign_id)

    def list_campaigns(self, *, limit: int = 50) -> list[Campaign]:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        statement = select(Campaign).order_by(Campaign.created_at.desc()).limit(limit)
        return list(self.session.execute(statement).scalars().all())

    def state(self, campaign: Campaign) -> CampaignState:
        try:
            return parse_state(campaign.status)
        except ValueError as exc:
            raise CampaignError(str(exc)) from exc

    # ------------------------------------------------------------- lifecycle
    def create(
        self,
        repo: str,
        *,
        objective: str = "discovery",
        commit: str = "",
        scope: dict[str, Any] | None = None,
        policy: dict[str, Any] | None = None,
        budget_usd: float | None = 10.0,
        budget_tokens: int | None = 500_000,
        budget_sandbox_minutes: float | None = 60.0,
        budget_wall_clock_s: int | None = 3_600,
    ) -> Campaign:
        repo = repo.strip()
        if not repo:
            raise ValueError("repo must not be empty")
        if objective not in OBJECTIVES:
            raise ValueError(f"unknown objective {objective!r}; valid: {', '.join(sorted(OBJECTIVES))}")
        self._validate_budget("budget_usd", budget_usd)
        self._validate_budget("budget_tokens", budget_tokens)
        self._validate_budget("budget_sandbox_minutes", budget_sandbox_minutes)
        self._validate_budget("budget_wall_clock_s", budget_wall_clock_s)

        now = self._clock()
        campaign = Campaign(
            id=_new_id("cmp"),
            repo=repo,
            commit=commit,
            objective=objective,
            status=CampaignState.DRAFT.value,
            scope=dict(scope or {}),
            policy=dict(policy or {}),
            budget_usd=budget_usd,
            budget_tokens=budget_tokens,
            budget_sandbox_minutes=budget_sandbox_minutes,
            budget_wall_clock_s=budget_wall_clock_s,
            spent_usd=0.0,
            spent_tokens=0,
            spent_sandbox_minutes=0.0,
            created_at=now,
            updated_at=now,
        )
        self.session.add(campaign)
        self.session.flush()
        self._event(campaign, "campaign.created", {"objective": objective, "repo": repo})
        return campaign

    def scope(self, campaign_id: str, scope: dict[str, Any]) -> Campaign:
        if not isinstance(scope, dict):
            raise ValueError("scope must be an object")
        campaign = self._get(campaign_id, lock=True)
        current = self.state(campaign)
        if current is not CampaignState.DRAFT:
            raise InvalidTransition(f"scope can only be set in draft, not {current.value}")
        campaign.scope = dict(scope)
        self._move(campaign, CampaignState.SCOPED, reason="scope set")
        return campaign

    def start(self, campaign_id: str) -> Campaign:
        campaign = self._get(campaign_id, lock=True)
        current = self.state(campaign)
        if current is not CampaignState.SCOPED:
            raise InvalidTransition(f"start requires scoped, not {current.value}")
        self._move(campaign, CampaignState.INDEXING, reason="campaign started")
        return campaign

    def advance(self, campaign_id: str, *, reason: str = "") -> Campaign:
        campaign = self._get(campaign_id, lock=True)
        current = self.state(campaign)
        from .state import NEXT

        target = NEXT.get(current)
        if target is None:
            raise InvalidTransition(f"no automatic next state from {current.value}")
        self._move(campaign, target, reason=reason or "advance")
        return campaign

    def transition(self, campaign_id: str, target: str | CampaignState, *, reason: str = "") -> Campaign:
        campaign = self._get(campaign_id, lock=True)
        current = self.state(campaign)
        try:
            wanted = parse_state(target)
        except ValueError as exc:
            raise InvalidTransition(str(exc)) from exc
        previous = parse_state(campaign.previous_status) if campaign.previous_status else None
        try:
            ensure_transition(current, wanted, previous=previous)
        except ValueError as exc:
            raise InvalidTransition(str(exc)) from exc
        self._move(campaign, wanted, reason=reason)
        return campaign

    def pause(self, campaign_id: str, *, reason: str = "") -> Campaign:
        return self.transition(campaign_id, CampaignState.PAUSED, reason=reason or "paused")

    def resume(self, campaign_id: str, *, reason: str = "") -> Campaign:
        campaign = self._get(campaign_id, lock=True)
        current = self.state(campaign)
        if current not in SIDE_STATES:
            raise InvalidTransition(f"resume requires paused or blocked, not {current.value}")
        if not campaign.previous_status:
            raise InvalidTransition(f"{current.value} campaign has no previous state to resume")
        target = parse_state(campaign.previous_status)
        self._move(campaign, target, reason=reason or "resumed")
        return campaign

    def cancel(self, campaign_id: str, *, reason: str = "") -> Campaign:
        return self.transition(campaign_id, CampaignState.CANCELLED, reason=reason or "cancelled")

    def fail(self, campaign_id: str, *, reason: str) -> Campaign:
        if not reason.strip():
            raise ValueError("a failure reason is required")
        return self.transition(campaign_id, CampaignState.FAILED, reason=reason)

    def report(self, campaign_id: str, *, reason: str = "") -> Campaign:
        return self.transition(campaign_id, CampaignState.REPORTED, reason=reason or "reported")

    def _move(self, campaign: Campaign, target: CampaignState, *, reason: str) -> None:
        current = self.state(campaign)
        now = self._clock()
        if target in SIDE_STATES:
            if current not in SIDE_STATES:
                campaign.previous_status = current.value
        elif current in SIDE_STATES:
            campaign.previous_status = None
        campaign.status = target.value
        campaign.reason = reason
        campaign.updated_at = now
        if target is CampaignState.INDEXING and campaign.started_at is None:
            campaign.started_at = now
        if target in TERMINAL_STATES:
            campaign.completed_at = now
        self._event(
            campaign,
            "campaign.transition",
            {"from": current.value, "to": target.value, "reason": reason},
        )

    # ---------------------------------------------------------------- budget
    @staticmethod
    def _validate_budget(name: str, value: float | int | None) -> None:
        if value is not None and value < 0:
            raise ValueError(f"{name} must be non-negative or null")

    def budget_remaining(self, campaign_id: str) -> dict[str, float | int | None]:
        campaign = self._get(campaign_id)
        return {
            "usd": None if campaign.budget_usd is None else campaign.budget_usd - campaign.spent_usd,
            "tokens": None if campaign.budget_tokens is None else campaign.budget_tokens - campaign.spent_tokens,
            "sandbox_minutes": (
                None
                if campaign.budget_sandbox_minutes is None
                else campaign.budget_sandbox_minutes - campaign.spent_sandbox_minutes
            ),
        }

    def record_spend(
        self,
        campaign_id: str,
        *,
        usd: float = 0.0,
        tokens: int = 0,
        sandbox_minutes: float = 0.0,
        source: str = "",
    ) -> dict[str, float | int]:
        if usd < 0 or tokens < 0 or sandbox_minutes < 0:
            raise ValueError("spend values must be non-negative")
        campaign = self._get(campaign_id, lock=True)
        if campaign.budget_usd is not None and campaign.spent_usd + usd > campaign.budget_usd + 1e-9:
            raise CampaignBudgetExceeded(
                f"USD budget exceeded: spent {campaign.spent_usd:.6f} + {usd:.6f} > {campaign.budget_usd:.6f}"
            )
        if campaign.budget_tokens is not None and campaign.spent_tokens + tokens > campaign.budget_tokens:
            raise CampaignBudgetExceeded(
                f"token budget exceeded: spent {campaign.spent_tokens} + {tokens} > {campaign.budget_tokens}"
            )
        if (
            campaign.budget_sandbox_minutes is not None
            and campaign.spent_sandbox_minutes + sandbox_minutes > campaign.budget_sandbox_minutes + 1e-9
        ):
            raise CampaignBudgetExceeded(
                "sandbox-minute budget exceeded: "
                f"spent {campaign.spent_sandbox_minutes:.3f} + {sandbox_minutes:.3f} "
                f"> {campaign.budget_sandbox_minutes:.3f}"
            )
        campaign.spent_usd += float(usd)
        campaign.spent_tokens += int(tokens)
        campaign.spent_sandbox_minutes += float(sandbox_minutes)
        campaign.updated_at = self._clock()
        self._event(
            campaign,
            "campaign.spend",
            {"usd": float(usd), "tokens": int(tokens), "sandbox_minutes": float(sandbox_minutes), "source": source},
        )
        return campaign.spent_dict()

    # ----------------------------------------------------------------- tasks
    def enqueue_task(
        self,
        campaign_id: str,
        kind: str,
        *,
        payload: dict[str, Any] | None = None,
        priority: int = 0,
        depends_on: Sequence[str] | None = None,
        max_attempts: int = 3,
    ) -> CampaignTask:
        kind = kind.strip()
        if not kind:
            raise ValueError("task kind must not be empty")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        campaign = self._get(campaign_id, lock=True)
        current = self.state(campaign)
        if current in TERMINAL_STATES or current in SIDE_STATES:
            raise InvalidTransition(f"cannot enqueue work while campaign is {current.value}")

        dependency_ids = list(dict.fromkeys(str(item) for item in (depends_on or [])))
        for dependency_id in dependency_ids:
            dependency = self.session.get(CampaignTask, dependency_id)
            if dependency is None or dependency.campaign_id != campaign_id:
                raise TaskStateError(f"dependency {dependency_id} does not belong to campaign {campaign_id}")

        now = self._clock()
        task = CampaignTask(
            id=_new_id("task"),
            campaign_id=campaign_id,
            kind=kind,
            status="pending",
            priority=int(priority),
            depends_on=dependency_ids,
            payload=dict(payload or {}),
            result={},
            attempts=0,
            max_attempts=int(max_attempts),
            created_at=now,
            updated_at=now,
        )
        self.session.add(task)
        self.session.flush()
        self._event(campaign, "task.enqueued", {"task_id": task.id, "kind": kind, "priority": int(priority)})
        return task

    def get_task(self, task_id: str) -> CampaignTask:
        task = self.session.get(CampaignTask, task_id)
        if task is None:
            raise TaskStateError(f"no such task: {task_id}")
        return task

    def list_tasks(self, campaign_id: str, *, status: str | None = None) -> list[CampaignTask]:
        statement = select(CampaignTask).where(CampaignTask.campaign_id == campaign_id)
        if status is not None:
            statement = statement.where(CampaignTask.status == status)
        statement = statement.order_by(CampaignTask.priority.desc(), CampaignTask.created_at.asc())
        return list(self.session.execute(statement).scalars().all())

    def claim_task(self, campaign_id: str, *, worker: str, lease_seconds: int = 300) -> CampaignTask | None:
        worker = worker.strip()
        if not worker:
            raise ValueError("worker must not be empty")
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be at least 1")
        campaign = self._get(campaign_id, lock=True)
        current = self.state(campaign)
        if current not in ACTIVE_STATES:
            raise InvalidTransition(f"cannot claim work while campaign is {current.value}")

        self.requeue_expired(campaign_id)
        tasks = self.list_tasks(campaign_id, status="pending")
        now = self._clock()
        for task in tasks:
            ready, blocked_reason = self._dependencies_ready(task)
            if blocked_reason:
                self._block_task(campaign, task, blocked_reason)
                continue
            if not ready:
                continue
            task.status = "running"
            task.attempts += 1
            task.lease_owner = worker
            task.lease_expires_at = now + timedelta(seconds=lease_seconds)
            task.started_at = task.started_at or now
            task.updated_at = now
            self._event(campaign, "task.claimed", {"task_id": task.id, "worker": worker, "attempt": task.attempts})
            self.session.flush()
            return task
        return None

    def complete_task(self, task_id: str, *, worker: str, result: dict[str, Any] | None = None) -> CampaignTask:
        task = self.get_task(task_id)
        self._require_lease(task, worker)
        if task.status != "running":
            raise TaskStateError(f"task {task_id} is {task.status}, not running")
        now = self._clock()
        task.status = "completed"
        task.result = dict(result or {})
        task.completed_at = now
        task.updated_at = now
        task.lease_expires_at = None
        campaign = self._get(task.campaign_id)
        self._event(campaign, "task.completed", {"task_id": task.id, "worker": worker})
        self.session.flush()
        return task

    def fail_task(
        self,
        task_id: str,
        *,
        worker: str,
        error: str,
        retry: bool = True,
    ) -> CampaignTask:
        if not error.strip():
            raise ValueError("a task failure needs an error message")
        task = self.get_task(task_id)
        self._require_lease(task, worker)
        if task.status != "running":
            raise TaskStateError(f"task {task_id} is {task.status}, not running")
        now = self._clock()
        task.error = error.strip()
        task.updated_at = now
        task.lease_expires_at = None
        if retry and task.attempts < task.max_attempts:
            task.status = "pending"
            task.lease_owner = None
            event = "task.retry"
        else:
            task.status = "failed"
            task.completed_at = now
            event = "task.failed"
        campaign = self._get(task.campaign_id)
        self._event(campaign, event, {"task_id": task.id, "worker": worker, "error": task.error})
        self.session.flush()
        return task

    def requeue_expired(self, campaign_id: str) -> int:
        campaign = self._get(campaign_id)
        now = self._clock()
        running = self.list_tasks(campaign_id, status="running")
        count = 0
        for task in running:
            expiry = _utc(task.lease_expires_at)
            if expiry is not None and expiry > now:
                continue
            task.updated_at = now
            task.lease_expires_at = None
            if task.attempts >= task.max_attempts:
                task.status = "failed"
                task.completed_at = now
                task.error = f"lease expired after {task.attempts} attempt(s)"
                event = "task.failed"
            else:
                task.status = "pending"
                task.lease_owner = None
                task.error = "lease expired; requeued"
                event = "task.requeued"
            self._event(campaign, event, {"task_id": task.id, "attempt": task.attempts})
            count += 1
        if count:
            self.session.flush()
        return count

    def _dependencies_ready(self, task: CampaignTask) -> tuple[bool, str]:
        for dependency_id in task.depends_on or []:
            dependency = self.session.get(CampaignTask, str(dependency_id))
            if dependency is None:
                return False, f"dependency {dependency_id} is missing"
            if dependency.status == "completed":
                continue
            if dependency.status in {"failed", "cancelled", "blocked"}:
                return False, f"dependency {dependency_id} is {dependency.status}"
            return False, ""
        return True, ""

    def _block_task(self, campaign: Campaign, task: CampaignTask, reason: str) -> None:
        now = self._clock()
        task.status = "blocked"
        task.error = reason
        task.completed_at = now
        task.updated_at = now
        task.lease_expires_at = None
        self._event(campaign, "task.blocked", {"task_id": task.id, "reason": reason})
        self.session.flush()

    def _require_lease(self, task: CampaignTask, worker: str) -> None:
        worker = worker.strip()
        if not worker:
            raise ValueError("worker must not be empty")
        if task.lease_owner != worker:
            raise TaskStateError(
                f"task {task.id} is leased to {task.lease_owner!r}, not {worker!r}"
            )

    # ---------------------------------------------------------------- events
    def events(self, campaign_id: str, *, since_seq: int = 0) -> list[CampaignEvent]:
        statement = (
            select(CampaignEvent)
            .where(CampaignEvent.campaign_id == campaign_id, CampaignEvent.seq > since_seq)
            .order_by(CampaignEvent.seq.asc())
        )
        return list(self.session.execute(statement).scalars().all())

    def status(self, campaign_id: str) -> dict[str, Any]:
        campaign = self._get(campaign_id)
        task_counts: dict[str, int] = {}
        for status, count in self.session.execute(
            select(CampaignTask.status, func.count())
            .where(CampaignTask.campaign_id == campaign_id)
            .group_by(CampaignTask.status)
        ).all():
            task_counts[str(status)] = int(count)
        evidence_total = int(
            self.session.execute(
                select(func.count()).select_from(EvidenceRecord).where(EvidenceRecord.campaign_id == campaign_id)
            ).scalar_one()
        )
        reportable_total = int(
            self.session.execute(
                select(func.count())
                .select_from(EvidenceRecord)
                .where(EvidenceRecord.campaign_id == campaign_id, EvidenceRecord.grade.in_(("E3", "E4")))
            ).scalar_one()
        )
        from ..evidence.ledger import EvidenceLedger

        chain = EvidenceLedger(self.session).verify(campaign_id)
        return {
            "campaign": campaign.to_wire(),
            "tasks": {"total": sum(task_counts.values()), "by_status": task_counts},
            "evidence": {"total": evidence_total, "reportable": reportable_total},
            "events": len(self.events(campaign_id)),
            "chain": chain.to_wire(),
            "budget_remaining": self.budget_remaining(campaign_id),
        }

    def _event(self, campaign: Campaign, kind: str, payload: dict[str, Any] | None = None) -> CampaignEvent:
        # Event sequence allocation and task/evidence changes share the campaign
        # row lock. Without it, two workers completing different tasks can read
        # the same max(seq) and collide on the unique constraint.
        self._get(campaign.id, lock=True)
        max_seq = self.session.execute(
            select(func.max(CampaignEvent.seq)).where(CampaignEvent.campaign_id == campaign.id)
        ).scalar_one()
        event = CampaignEvent(
            id=_new_id("evt"),
            campaign_id=campaign.id,
            seq=int(max_seq or 0) + 1,
            kind=kind,
            payload=dict(payload or {}),
            created_at=self._clock(),
        )
        self.session.add(event)
        self.session.flush()
        return event
