"""Postgres integration for the Phase 1 tables.

SQLite proves the application semantics cheaply; this test proves the production
dialect and the ``SELECT ... FOR UPDATE`` path used for event/evidence ordering.
It runs only when CI supplies ``REDFALL_TEST_DATABASE_URL``. The transaction is
rolled back, so the test leaves no campaign rows behind.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from redfall.campaign.service import CampaignService
from redfall.evidence.ledger import EvidenceLedger
from redfall.store.models import Base

URL = os.getenv("REDFALL_TEST_DATABASE_URL")


@pytest.mark.skipif(not URL, reason="REDFALL_TEST_DATABASE_URL is not set")
def test_campaign_and_evidence_on_postgres():
    engine = create_engine(URL, pool_pre_ping=True, future=True)
    Base.metadata.create_all(engine)
    connection = engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection, expire_on_commit=False, future=True)
    campaign_id = ""
    try:
        with Session() as session:
            service = CampaignService(session)
            campaign = service.create(
                "acme/postgres",
                budget_usd=2.0,
                budget_tokens=1000,
                budget_sandbox_minutes=10.0,
            )
            campaign_id = campaign.id
            service.scope(campaign_id, {"repos": ["acme/postgres"]})
            service.start(campaign_id)
            task = service.enqueue_task(campaign_id, "index", payload={"path": "."})
            claimed = service.claim_task(campaign_id, worker="pg-worker", lease_seconds=60)
            assert claimed is not None and claimed.id == task.id
            service.complete_task(task.id, worker="pg-worker", result={"files": 2})
            service.record_spend(campaign_id, usd=0.25, tokens=100, sandbox_minutes=0.5)
            record = EvidenceLedger(session).append(
                campaign_id,
                grade="E3",
                kind="execution",
                claim="Postgres chain test",
                payload={"execution_id": "pg-exe", "observable": "marker"},
                reproduce_command="redfall reproduce pg-exe",
                environment_digest="sha256:pg-image",
            )
            assert record.reportable is True
            assert EvidenceLedger(session).verify(campaign_id).ok is True
            status = service.status(campaign_id)
            assert status["chain"]["ok"] is True
            assert status["tasks"]["by_status"]["completed"] == 1
            assert status["evidence"]["reportable"] == 1
    finally:
        transaction.rollback()
        connection.close()
        engine.dispose()
