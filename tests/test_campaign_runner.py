"""The campaign runner executes real handlers under durable leases and budgets."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from redfall.campaign.execution import HandlerSpec, TaskResult
from redfall.campaign.runner import CampaignRunner
from redfall.campaign.service import CampaignService
from redfall.config import load_config
from redfall.store.models import (
    Base,
    CampaignReservation,
    Finding,
    GraphSnapshot,
    Scan,
)

ROOT = Path(__file__).resolve().parents[1]
VULNBANK = ROOT / "range" / "vulnbank"


@pytest.fixture()
def sessions(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'runner.db'}", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    yield Session
    engine.dispose()


def active_campaign(session, *, budget_usd=5.0, budget_sandbox_minutes=10.0):
    service = CampaignService(session)
    campaign = service.create(
        str(VULNBANK),
        budget_usd=budget_usd,
        budget_sandbox_minutes=budget_sandbox_minutes,
    )
    service.transition(campaign.id, "scoped")
    service.transition(campaign.id, "indexing")
    session.commit()
    return campaign.id


def test_runner_executes_dependency_chain_with_real_graph_tasks(sessions):
    with sessions() as session:
        campaign_id = active_campaign(session)
        service = CampaignService(session)
        first = service.enqueue_task(
            campaign_id,
            "graph.index",
            payload={"target": str(VULNBANK)},
        )
        second = service.enqueue_task(
            campaign_id,
            "graph.inventory",
            payload={"limit": 20},
            depends_on=[first.id],
        )
        session.commit()
        first_id, second_id = first.id, second.id

    runner = CampaignRunner(sessions, worker="runner-test", config=load_config(), max_tasks=5)
    summary = runner.run(campaign_id, max_tasks=5)
    assert summary["completed"] == 2
    assert summary["stop_reason"] == "no_ready_tasks"
    assert [item["status"] for item in summary["results"]] == ["completed", "completed"]

    with sessions() as session:
        tasks = {task.id: task for task in CampaignService(session).list_tasks(campaign_id)}
        assert tasks[first_id].status == "completed"
        assert tasks[second_id].status == "completed"
        snapshot = session.scalars(
            select(GraphSnapshot).where(GraphSnapshot.campaign_id == campaign_id)
        ).one()
        assert snapshot.node_count > 0
        assert tasks[second_id].result["inventory"]["routes"]


def test_runner_blocks_on_out_of_scope_target_and_releases_budget(sessions):
    with sessions() as session:
        campaign_id = active_campaign(session)
        task = CampaignService(session).enqueue_task(
            campaign_id,
            "graph.index",
            payload={"target": str(ROOT / "range" / "chainbank")},
        )
        session.commit()
        task_id = task.id

    runner = CampaignRunner(sessions, worker="runner-test", config=load_config(), max_tasks=1)
    summary = runner.run(campaign_id, max_tasks=1)
    assert summary["stop_reason"] == "task_blocked"
    assert summary["campaign_status"] == "blocked"

    with sessions() as session:
        assert CampaignService(session).get_task(task_id).status == "failed"
        held = session.scalars(
            select(CampaignReservation).where(
                CampaignReservation.campaign_id == campaign_id,
                CampaignReservation.status == "held",
            )
        ).all()
        assert held == []
        assert CampaignService(session).budget_remaining(campaign_id)["usd"] == 5.0


def test_runner_blocks_reproduction_without_a_stored_poc(sessions):
    with sessions() as session:
        campaign_id = active_campaign(session, budget_sandbox_minutes=10.0)
        scan = Scan(id="scan-repro", repo=str(VULNBANK), commit="", status="completed")
        finding = Finding(
            id="finding-no-poc",
            scan_id=scan.id,
            branch_id="branch-1",
            category="sql_injection",
            severity="high",
            title="A stored candidate",
            location_file="src/routes/users.ts",
            location_line=10,
            poc={},
            evidence="",
        )
        session.add_all([scan, finding])
        session.commit()
        task = CampaignService(session).enqueue_task(
            campaign_id,
            "finding.reproduce",
            payload={"finding_id": finding.id, "target": str(VULNBANK)},
        )
        session.commit()
        task_id = task.id

    summary = CampaignRunner(sessions, worker="runner-test", config=load_config(), max_tasks=1).run(
        campaign_id, max_tasks=1
    )
    assert summary["stop_reason"] == "task_blocked"
    assert summary["campaign_status"] == "blocked"
    with sessions() as session:
        task = CampaignService(session).get_task(task_id)
        assert task.status == "failed"
        assert "no stored PoC" in task.error
        assert session.scalars(
            select(CampaignReservation).where(CampaignReservation.status == "held")
        ).all() == []


def test_runner_retries_a_transient_handler_failure(sessions):
    attempts: list[int] = []

    def flaky(context):
        attempts.append(context.task.attempts)
        if len(attempts) == 1:
            raise RuntimeError("transient connection reset")
        return TaskResult(result={"attempts": len(attempts)})

    handlers = {"flaky": HandlerSpec("flaky", flaky, lambda context: {})}
    with sessions() as session:
        campaign_id = active_campaign(session)
        task = CampaignService(session).enqueue_task(
            campaign_id,
            "flaky",
            max_attempts=2,
        )
        session.commit()
        task_id = task.id

    summary = CampaignRunner(
        sessions,
        worker="runner-test",
        config=load_config(),
        handlers=handlers,
        max_tasks=4,
    ).run(campaign_id, max_tasks=4)
    assert summary["retried"] == 1
    assert summary["completed"] == 1
    assert summary["failed"] == 0
    assert attempts == [1, 2]

    with sessions() as session:
        task = CampaignService(session).get_task(task_id)
        assert task.status == "completed"
        assert task.attempts == 2
        assert task.result == {"attempts": 2, "spend": {"usd": 0.0, "tokens": 0, "sandbox_minutes": 0.0}}


def test_runner_settles_measured_spend_above_the_estimate(sessions):
    """The reservation is an allowance; the measured spend is the fact."""

    def measured(context):
        return TaskResult(result={"ok": True}, spend={"usd": 3.0})

    handlers = {
        "measured": HandlerSpec(
            "measured",
            measured,
            lambda context: {"usd": 1.0},
        )
    }
    with sessions() as session:
        campaign_id = active_campaign(session, budget_usd=5.0)
        task = CampaignService(session).enqueue_task(campaign_id, "measured")
        session.commit()
        task_id = task.id

    summary = CampaignRunner(
        sessions,
        worker="runner-test",
        config=load_config(),
        handlers=handlers,
        max_tasks=2,
    ).run(campaign_id, max_tasks=2)
    assert summary["completed"] == 1
    assert summary["failed"] == 0

    with sessions() as session:
        assert CampaignService(session).get_task(task_id).status == "completed"
        assert CampaignService(session).get(campaign_id).spent_usd == 3.0
        assert CampaignService(session).budget_remaining(campaign_id)["usd"] == 2.0
        assert session.scalars(
            select(CampaignReservation).where(CampaignReservation.task_id == task_id)
        ).one().status == "settled"


def test_runner_blocks_unknown_task_kinds_without_retry(sessions):
    with sessions() as session:
        campaign_id = active_campaign(session)
        task = CampaignService(session).enqueue_task(campaign_id, "not.a.real.handler")
        session.commit()
        task_id = task.id

    summary = CampaignRunner(sessions, worker="runner-test", config=load_config()).run(
        campaign_id, max_tasks=2
    )
    assert summary["stop_reason"] == "unknown_task_kind"
    assert summary["campaign_status"] == "blocked"
    with sessions() as session:
        task = CampaignService(session).get_task(task_id)
        assert task.status == "failed"
        assert task.attempts == 1
        assert "no handler is registered" in task.error


def test_runner_honours_wall_clock_budget(sessions):
    with sessions() as session:
        service = CampaignService(session)
        campaign = service.create(
            str(VULNBANK),
            budget_usd=5.0,
            budget_wall_clock_s=1,
        )
        service.transition(campaign.id, "scoped")
        service.transition(campaign.id, "indexing")
        service.enqueue_task(campaign.id, "graph.index", payload={"target": str(VULNBANK)})
        campaign.started_at = campaign.started_at.replace(year=2020)
        session.commit()
        campaign_id = campaign.id

    summary = CampaignRunner(sessions, worker="runner-test", config=load_config(), max_tasks=1).run(
        campaign_id, max_tasks=1
    )
    assert summary["stop_reason"] == "wall_clock_exceeded"
    assert summary["campaign_status"] == "blocked"
    with sessions() as session:
        assert CampaignService(session).list_tasks(campaign_id)[0].status == "pending"
