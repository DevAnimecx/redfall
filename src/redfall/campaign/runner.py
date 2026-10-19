"""A resumable campaign worker with real task handlers.

The runner claims one durable task at a time, reserves budget, executes the
handler, and records completion or failure under the same lease. A heartbeat
extends a long-running lease. If the worker process dies, the lease expires and
the existing campaign service requeues the task; nothing depends on an
in-memory job table.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import sessionmaker

from ..config import Config, load_config
from ..store.models import Campaign
from .execution import HandlerSpec, TaskBlocked, TaskContext, TaskResult
from .handlers import default_handlers
from .service import (
    ACTIVE_STATES,
    CampaignBudgetExceeded,
    CampaignError,
    CampaignService,
    InvalidTransition,
    TaskStateError,
    _utc,
)


class RunnerError(RuntimeError):
    """The runner cannot continue safely."""


class _LeaseHeartbeat:
    def __init__(
        self,
        session_factory: sessionmaker,
        task_id: str,
        worker: str,
        lease_seconds: int,
    ) -> None:
        self.session_factory = session_factory
        self.task_id = task_id
        self.worker = worker
        self.lease_seconds = lease_seconds
        self.interval = max(5.0, lease_seconds / 3.0)
        self.stop = threading.Event()
        self.error = ""
        self.thread = threading.Thread(target=self._run, name="redfall-lease", daemon=True)

    def _run(self) -> None:
        while not self.stop.wait(self.interval):
            try:
                with self.session_factory() as session:
                    CampaignService(session).renew_lease(
                        self.task_id,
                        worker=self.worker,
                        lease_seconds=self.lease_seconds,
                    )
                    session.commit()
            except Exception as exc:  # noqa: BLE001 - recorded, then stops the heartbeat
                self.error = f"{type(exc).__name__}: {exc}"
                return

    def __enter__(self) -> "_LeaseHeartbeat":
        self.thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop.set()
        self.thread.join(timeout=5)


class CampaignRunner:
    def __init__(
        self,
        session_factory: sessionmaker,
        *,
        worker: str,
        handlers: dict[str, HandlerSpec] | None = None,
        config: Config | None = None,
        lease_seconds: int = 300,
        max_tasks: int = 10,
        clock: Any = None,
    ) -> None:
        if not worker.strip():
            raise ValueError("worker must not be empty")
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be at least 1")
        if max_tasks < 0:
            raise ValueError("max_tasks must not be negative")
        self.session_factory = session_factory
        self.worker = worker.strip()
        self.handlers = dict(handlers or default_handlers())
        self.config = config or load_config()
        self.lease_seconds = lease_seconds
        self.max_tasks = max_tasks
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def run(self, campaign_id: str, *, max_tasks: int | None = None) -> dict[str, Any]:
        limit = self.max_tasks if max_tasks is None else max_tasks
        if limit < 0:
            raise ValueError("max_tasks must not be negative")
        started = time.monotonic()
        summary: dict[str, Any] = {
            "campaign_id": campaign_id,
            "worker": self.worker,
            "claimed": 0,
            "completed": 0,
            "failed": 0,
            "blocked": 0,
            "retried": 0,
            "results": [],
            "stop_reason": "max_tasks",
        }
        for _ in range(limit):
            claim = self._claim(campaign_id)
            if claim is None:
                summary["stop_reason"] = "no_ready_tasks"
                break
            if claim == "inactive":
                summary["stop_reason"] = "campaign_not_active"
                break
            if claim == "wall_clock":
                summary["stop_reason"] = "wall_clock_exceeded"
                break
            if isinstance(claim, dict) and "task_id" not in claim:
                summary.update(claim)
                break
            task_id = claim["task_id"]
            kind = claim["kind"]
            summary["claimed"] += 1

            spec = self.handlers.get(kind)
            if spec is None:
                reason = f"no handler is registered for task kind {kind!r}"
                self._fail_and_block(task_id, reason)
                summary["failed"] += 1
                summary["blocked"] += 1
                summary["stop_reason"] = "unknown_task_kind"
                summary["results"].append(
                    {"task_id": task_id, "kind": kind, "status": "blocked", "error": reason}
                )
                break

            reservation = self._reserve(task_id)
            if reservation == "budget":
                summary["failed"] += 1
                summary["blocked"] += 1
                summary["stop_reason"] = "budget_exhausted"
                summary["results"].append(
                    {
                        "task_id": task_id,
                        "kind": kind,
                        "status": "blocked",
                        "error": "budget reservation failed",
                    }
                )
                break

            execution = self._execute_and_settle(campaign_id, task_id, spec, reservation)
            if execution["outcome"] == "blocked":
                self._release(reservation)
                self._fail_and_block(task_id, execution["error"])
                summary["failed"] += 1
                summary["blocked"] += 1
                summary["stop_reason"] = "task_blocked"
                summary["results"].append(
                    {
                        "task_id": task_id,
                        "kind": kind,
                        "status": "blocked",
                        "error": execution["error"],
                    }
                )
                break
            if execution["outcome"] == "budget":
                self._release(reservation)
                self._fail_and_block(task_id, execution["error"])
                summary["failed"] += 1
                summary["blocked"] += 1
                summary["stop_reason"] = "budget_exhausted"
                summary["results"].append(
                    {
                        "task_id": task_id,
                        "kind": kind,
                        "status": "blocked",
                        "error": execution["error"],
                    }
                )
                break
            if execution["outcome"] == "failed":
                self._release(reservation)
                outcome = self._fail(task_id, execution["error"])
                if outcome == "retry":
                    summary["retried"] += 1
                else:
                    summary["failed"] += 1
                summary["results"].append(
                    {
                        "task_id": task_id,
                        "kind": kind,
                        "status": outcome,
                        "error": execution["error"],
                    }
                )
                continue

            summary["completed"] += 1
            summary["results"].append(
                {
                    "task_id": task_id,
                    "kind": kind,
                    "status": "completed",
                    "result": execution["result"],
                }
            )

        summary["duration_ms"] = int((time.monotonic() - started) * 1000)
        with self.session_factory() as session:
            try:
                summary["campaign_status"] = CampaignService(session).get(campaign_id).status
                summary["budget_remaining"] = CampaignService(session).budget_remaining(campaign_id)
            except CampaignError as exc:
                summary["campaign_status"] = "missing"
                summary["error"] = str(exc)
        return summary

    # ------------------------------------------------------------------ claim
    def _claim(self, campaign_id: str) -> dict[str, str] | str | None:
        with self.session_factory() as session:
            service = CampaignService(session)
            campaign = service.get(campaign_id)
            state = service.state(campaign)
            if state not in ACTIVE_STATES:
                return "inactive"
            if self._wall_clock_exceeded(campaign):
                service.block(campaign_id, reason="campaign wall-clock budget exceeded")
                session.commit()
                return "wall_clock"
            task = service.claim_task(
                campaign_id,
                worker=self.worker,
                lease_seconds=self.lease_seconds,
            )
            if task is None:
                session.commit()
                return None
            claimed = {"task_id": task.id, "kind": task.kind}
            session.commit()
            return claimed

    def _wall_clock_exceeded(self, campaign: Campaign) -> bool:
        if campaign.budget_wall_clock_s is None or campaign.started_at is None:
            return False
        started = _utc(campaign.started_at)
        if started is None:
            return False
        elapsed = (self._clock() - started).total_seconds()
        return elapsed > campaign.budget_wall_clock_s

    # -------------------------------------------------------------- reserve
    def _reserve(self, task_id: str) -> Any:
        reason = "budget reservation failed"
        with self.session_factory() as session:
            service = CampaignService(session)
            task = service.get_task(task_id)
            campaign = service.get(task.campaign_id)
            spec = self.handlers[task.kind]
            context = TaskContext(
                campaign=campaign,
                task=task,
                session=session,
                session_factory=self.session_factory,
                config=self.config,
                worker=self.worker,
            )
            try:
                estimate = spec.estimate_for(context)
                if not any(float(estimate.get(key, 0) or 0) > 0 for key in estimate):
                    session.commit()
                    return None
                reservation = service.reserve_spend(
                    task.campaign_id,
                    task_id=task.id,
                    usd=float(estimate.get("usd", 0) or 0),
                    tokens=int(estimate.get("tokens", 0) or 0),
                    sandbox_minutes=float(estimate.get("sandbox_minutes", 0) or 0),
                    source=f"task:{task.kind}",
                )
                session.commit()
                return reservation.id
            except TaskBlocked as exc:
                reason = str(exc)
                session.rollback()
            except CampaignBudgetExceeded as exc:
                reason = str(exc)
                session.rollback()
            except Exception as exc:  # noqa: BLE001 - a bad estimate is a task failure
                reason = f"budget preflight failed: {type(exc).__name__}: {exc}"
                session.rollback()
        self._fail_and_block(task_id, reason)
        return "budget"

    # --------------------------------------------------------------- execute
    def _execute_and_settle(
        self,
        campaign_id: str,
        task_id: str,
        spec: HandlerSpec,
        reservation_id: str | None,
    ) -> dict[str, Any]:
        with self.session_factory() as session:
            service = CampaignService(session)
            task = service.get_task(task_id)
            campaign = service.get(campaign_id)
            context = TaskContext(
                campaign=campaign,
                task=task,
                session=session,
                session_factory=self.session_factory,
                config=self.config,
                worker=self.worker,
            )
            with _LeaseHeartbeat(
                self.session_factory, task.id, self.worker, self.lease_seconds
            ) as heartbeat:
                try:
                    value = spec.handler(context)
                    outcome = TaskResult.coerce(value)
                    if heartbeat.error:
                        raise RunnerError(f"lease lost: {heartbeat.error}")
                    spend = outcome.spend
                    usd = float(spend.get("usd", 0) or 0)
                    tokens = int(spend.get("tokens", 0) or 0)
                    minutes = float(spend.get("sandbox_minutes", 0) or 0)
                    if reservation_id:
                        if any(item > 0 for item in (usd, tokens, minutes)):
                            # The estimate reserved the worst case we could
                            # justify up front. The measured value is the fact;
                            # accept it above the estimate when the campaign
                            # ceiling still holds, and let record_spend refuse
                            # only a real overspend.
                            service.settle_reservation(
                                reservation_id,
                                usd=usd,
                                tokens=tokens,
                                sandbox_minutes=minutes,
                                source=f"task:{task.kind}",
                                allow_overage=True,
                            )
                        else:
                            service.release_reservation(
                                reservation_id, reason="no measured spend"
                            )
                    elif any(item > 0 for item in (usd, tokens, minutes)):
                        service.record_spend(
                            task.campaign_id,
                            usd=usd,
                            tokens=tokens,
                            sandbox_minutes=minutes,
                            source=f"task:{task.kind}",
                        )
                    result = dict(outcome.result)
                    result.setdefault(
                        "spend",
                        {"usd": usd, "tokens": tokens, "sandbox_minutes": minutes},
                    )
                    service.complete_task(task_id, worker=self.worker, result=result)
                    session.commit()
                    return {"outcome": "ok", "result": result}
                except TaskBlocked as exc:
                    session.rollback()
                    details = f": {'; '.join(exc.details)}" if exc.details else ""
                    return {"outcome": "blocked", "error": f"{exc}{details}"}
                except CampaignBudgetExceeded as exc:
                    session.rollback()
                    return {"outcome": "budget", "error": str(exc)}
                except (TaskStateError, InvalidTransition) as exc:
                    session.rollback()
                    return {"outcome": "failed", "error": f"lease or task state: {exc}"}
                except Exception as exc:  # noqa: BLE001 - handler failure is task state
                    session.rollback()
                    return {"outcome": "failed", "error": f"{type(exc).__name__}: {exc}"}

    def _release(self, reservation_id: str | None) -> None:
        if not reservation_id:
            return
        with self.session_factory() as session:
            try:
                CampaignService(session).release_reservation(
                    reservation_id, reason="task did not complete"
                )
                session.commit()
            except CampaignError:
                session.rollback()

    def _fail(self, task_id: str, error: str) -> str:
        with self.session_factory() as session:
            service = CampaignService(session)
            task = service.get_task(task_id)
            outcome = service.fail_task(
                task_id,
                worker=self.worker,
                error=error,
                retry=True,
            )
            session.commit()
            if outcome.status == "pending":
                return "retry"
            return "failed"

    def _fail_and_block(self, task_id: str, reason: str) -> None:
        with self.session_factory() as session:
            service = CampaignService(session)
            try:
                task = service.get_task(task_id)
                service.fail_task(task_id, worker=self.worker, error=reason, retry=False)
                service.block(task.campaign_id, reason=reason)
                session.commit()
            except CampaignError:
                session.rollback()
