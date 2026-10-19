"""Preflight reservations are a budget gate, not a post-hoc report."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from redfall.campaign.service import (
    CampaignBudgetExceeded,
    CampaignService,
    TaskStateError,
)
from redfall.store.models import Base, CampaignReservation


@pytest.fixture()
def session(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'budget.db'}", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with Session() as session:
        yield session
    engine.dispose()


def active_campaign(session):
    service = CampaignService(session)
    campaign = service.create(
        "range/vulnbank",
        budget_usd=10.0,
        budget_tokens=1000,
        budget_sandbox_minutes=10.0,
    )
    service.transition(campaign.id, "scoped")
    service.transition(campaign.id, "indexing")
    session.commit()
    return campaign.id


def test_held_reservations_reduce_available_budget(session):
    campaign_id = active_campaign(session)
    service = CampaignService(session)
    reservation = service.reserve_spend(
        campaign_id,
        usd=4.0,
        tokens=400,
        sandbox_minutes=4.0,
        source="test",
    )
    session.commit()

    assert service.budget_remaining(campaign_id) == {
        "usd": 6.0,
        "tokens": 600,
        "sandbox_minutes": 6.0,
    }
    with pytest.raises(CampaignBudgetExceeded):
        service.reserve_spend(campaign_id, usd=7.0)
    session.rollback()

    released = service.release_reservation(reservation.id, reason="test release")
    session.commit()
    assert released.status == "released"
    assert service.budget_remaining(campaign_id)["usd"] == 10.0


def test_settlement_records_measured_spend_and_never_overdraws(session):
    campaign_id = active_campaign(session)
    service = CampaignService(session)
    reservation = service.reserve_spend(
        campaign_id,
        usd=4.0,
        tokens=400,
        sandbox_minutes=4.0,
        source="test",
    )
    session.commit()

    result = service.settle_reservation(
        reservation.id,
        usd=1.5,
        tokens=100,
        sandbox_minutes=1.0,
        source="measured",
    )
    session.commit()
    assert result["reservation"]["status"] == "settled"
    assert result["spent"] == {"usd": 1.5, "tokens": 100, "sandbox_minutes": 1.0}
    assert service.budget_remaining(campaign_id) == {
        "usd": 8.5,
        "tokens": 900,
        "sandbox_minutes": 9.0,
    }

    second = service.reserve_spend(campaign_id, usd=2.0, source="second")
    session.commit()
    with pytest.raises(CampaignBudgetExceeded):
        service.settle_reservation(second.id, usd=2.5)
    session.rollback()
    reloaded = session.get(CampaignReservation, second.id)
    assert reloaded is not None
    assert reloaded.status == "held"
    assert service.budget_remaining(campaign_id)["usd"] == 6.5


def test_task_reservation_must_belong_to_the_campaign(session):
    campaign_id = active_campaign(session)
    service = CampaignService(session)
    other = service.create("range/pythonbank", budget_usd=5.0)
    task = service.enqueue_task(other.id, "graph.index", payload={"target": "range/pythonbank"})
    session.commit()

    with pytest.raises(TaskStateError):
        service.reserve_spend(campaign_id, task_id=task.id, usd=1.0)
    session.rollback()
    assert service.reservations(campaign_id) == []
