"""Campaign state, task leases, budgets and the evidence hash chain.

These run against SQLite, not Postgres. The production store is still Postgres;
SQLite is used here because the semantics under test are application-level and
the suite must be runnable on a host without a database server.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from redfall.campaign.service import (
    CampaignBudgetExceeded,
    CampaignService,
    InvalidTransition,
    TaskStateError,
)
from redfall.evidence.ledger import EvidenceError, EvidenceLedger
from redfall.store.models import Base


@pytest.fixture()
def session_factory(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'campaign.db'}", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    yield Session
    engine.dispose()


def new_campaign(Session):
    with Session() as session:
        service = CampaignService(session)
        campaign = service.create(
            "acme/api",
            objective="discovery",
            scope={"repos": ["acme/api"]},
            budget_usd=1.0,
            budget_tokens=100,
            budget_sandbox_minutes=1.0,
        )
        session.commit()
        return campaign.id


def test_campaign_lifecycle_is_explicit_and_pausable(session_factory):
    Session = session_factory
    campaign_id = new_campaign(Session)

    with Session() as session:
        service = CampaignService(session)
        with pytest.raises(InvalidTransition):
            service.start(campaign_id)

        service.scope(campaign_id, {"repos": ["acme/api"], "hosts": ["app.internal"]})
        service.start(campaign_id)
        service.advance(campaign_id)
        service.advance(campaign_id)
        service.advance(campaign_id)
        assert service.get(campaign_id).status == "probe"

        service.pause(campaign_id, reason="operator break")
        assert service.get(campaign_id).status == "paused"
        service.resume(campaign_id)
        assert service.get(campaign_id).status == "probe"

        service.transition(campaign_id, "exploit")
        with pytest.raises(InvalidTransition):
            service.transition(campaign_id, "draft")
        service.transition(campaign_id, "reported")
        assert service.get(campaign_id).status == "reported"

        with pytest.raises(InvalidTransition):
            service.pause(campaign_id)


def test_budget_is_checked_before_it_is_recorded(session_factory):
    Session = session_factory
    campaign_id = new_campaign(Session)

    with Session() as session:
        service = CampaignService(session)
        service.record_spend(campaign_id, usd=0.5, tokens=50, sandbox_minutes=0.5)
        assert service.budget_remaining(campaign_id) == {"usd": 0.5, "tokens": 50, "sandbox_minutes": 0.5}
        with pytest.raises(CampaignBudgetExceeded):
            service.record_spend(campaign_id, usd=0.6)
        assert service.get(campaign_id).spent_usd == 0.5
        assert service.get(campaign_id).spent_tokens == 50


def test_tasks_are_leased_in_dependency_order(session_factory):
    Session = session_factory
    campaign_id = new_campaign(Session)

    with Session() as session:
        service = CampaignService(session)
        service.scope(campaign_id, {"repos": ["acme/api"]})
        service.start(campaign_id)
        first = service.enqueue_task(campaign_id, "index", priority=1, payload={"path": "."})
        second = service.enqueue_task(
            campaign_id, "recon", priority=10, depends_on=[first.id], payload={"routes": True}
        )
        session.commit()

        claimed = service.claim_task(campaign_id, worker="worker-a", lease_seconds=60)
        assert claimed is not None and claimed.id == first.id
        assert claimed.attempts == 1
        with pytest.raises(TaskStateError):
            service.complete_task(first.id, worker="worker-b", result={})
        service.complete_task(first.id, worker="worker-a", result={"files": 3})

        claimed_second = service.claim_task(campaign_id, worker="worker-a", lease_seconds=60)
        assert claimed_second is not None and claimed_second.id == second.id
        retried = service.fail_task(second.id, worker="worker-a", error="route parser failed", retry=True)
        assert retried.status == "pending"
        assert retried.attempts == 1

        claimed_again = service.claim_task(campaign_id, worker="worker-b", lease_seconds=60)
        assert claimed_again is not None and claimed_again.id == second.id
        failed = service.fail_task(second.id, worker="worker-b", error="route parser failed again", retry=False)
        assert failed.status == "failed"

        blocked = service.enqueue_task(campaign_id, "exploit", depends_on=[second.id])
        assert service.claim_task(campaign_id, worker="worker-c", lease_seconds=60) is None
        assert service.get_task(blocked.id).status == "blocked"


def test_expired_lease_is_requeued_not_treated_as_success(session_factory):
    Session = session_factory
    campaign_id = new_campaign(Session)

    with Session() as session:
        service = CampaignService(session)
        service.scope(campaign_id, {"repos": ["acme/api"]})
        service.start(campaign_id)
        task = service.enqueue_task(campaign_id, "index")
        claimed = service.claim_task(campaign_id, worker="worker-a", lease_seconds=60)
        assert claimed is not None
        claimed.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        session.commit()

        assert service.requeue_expired(campaign_id) == 1
        assert service.get_task(task.id).status == "pending"
        assert service.get_task(task.id).lease_owner is None


def test_evidence_chain_accepts_only_replayable_proof(session_factory):
    Session = session_factory
    campaign_id = new_campaign(Session)

    with Session() as session:
        ledger = EvidenceLedger(session)
        ledger.append(campaign_id, grade="E0", kind="human", claim="Analyst suspects SSRF")
        ledger.append(
            campaign_id,
            grade="E1",
            kind="static",
            claim="Request data reaches the outbound client",
            payload={"path": "src/routes/fetch.ts", "symbol": "fetchHandler"},
        )
        with pytest.raises(EvidenceError):
            ledger.append(
                campaign_id,
                grade="E3",
                kind="execution",
                claim="SSRF reaches the metadata canary",
                payload={"execution_id": "exe-1", "observable": "canary hit"},
            )
        ledger.append(
            campaign_id,
            grade="E3",
            kind="execution",
            claim="SSRF reaches the metadata canary",
            payload={"execution_id": "exe-1", "observable": "canary hit"},
            reproduce_command="redfall reproduce exe-1",
            environment_digest="sha256:image",
        )
        ledger.append(
            campaign_id,
            grade="E4",
            kind="execution",
            claim="SSRF reaches the metadata canary and returns data",
            payload={"execution_id": "exe-2", "observable": "canary body", "impact": "read the canary secret"},
            reproduce_command="redfall reproduce exe-2",
            environment_digest="sha256:image",
        )
        session.commit()

        chain = ledger.verify(campaign_id)
        assert chain.ok and chain.checked == 4
        reportable = ledger.reportable(campaign_id)
        assert [record.grade for record in reportable] == ["E3", "E4"]
        assert ledger.require_reportable(campaign_id) == reportable

        records = ledger.list(campaign_id)
        assert records[0].previous_hash == "0" * 64
        assert records[1].previous_hash == records[0].content_hash


def test_evidence_tampering_breaks_the_chain(session_factory):
    Session = session_factory
    campaign_id = new_campaign(Session)

    with Session() as session:
        ledger = EvidenceLedger(session)
        ledger.append(campaign_id, grade="E1", kind="static", claim="Path exists", payload={"path": "a.ts"})
        record = ledger.append(campaign_id, grade="E2", kind="dynamic", claim="Observed", payload={"observation": "200"})
        session.commit()

        record.payload = {"observation": "500"}
        session.commit()
        chain = ledger.verify(campaign_id)
        assert not chain.ok
        assert chain.first_bad_id == record.id
        assert "content hash" in chain.reason


def test_report_readiness_requires_an_intact_chain_and_e3(session_factory):
    Session = session_factory
    campaign_id = new_campaign(Session)

    with Session() as session:
        ledger = EvidenceLedger(session)
        with pytest.raises(EvidenceError):
            ledger.require_reportable(campaign_id)
        ledger.append(campaign_id, grade="E1", kind="static", claim="Candidate", payload={"path": "a.ts"})
        session.commit()
        with pytest.raises(EvidenceError):
            ledger.require_reportable(campaign_id)


def test_evidence_rejects_non_objects_and_unknown_campaigns(session_factory):
    Session = session_factory
    campaign_id = new_campaign(Session)

    with Session() as session:
        ledger = EvidenceLedger(session)
        with pytest.raises(EvidenceError):
            ledger.append(campaign_id, grade="E1", kind="static", claim="Bad payload", payload=["a.ts"])
        with pytest.raises(EvidenceError):
            ledger.append("cmp-missing", grade="E0", kind="human", claim="No campaign")
        with pytest.raises(EvidenceError):
            ledger.verify("cmp-missing")


def test_status_reports_chain_integrity_and_task_counts(session_factory):
    Session = session_factory
    campaign_id = new_campaign(Session)

    with Session() as session:
        service = CampaignService(session)
        service.enqueue_task(campaign_id, "index")
        ledger = EvidenceLedger(session)
        ledger.append(
            campaign_id,
            grade="E3",
            kind="execution",
            claim="Triggered",
            payload={"execution_id": "exe-1", "observable": "marker"},
            reproduce_command="cmd",
            environment_digest="digest",
        )
        data = service.status(campaign_id)
        assert data["campaign"]["id"] == campaign_id
        assert data["tasks"]["by_status"]["pending"] == 1
        assert data["evidence"]["reportable"] == 1
        assert data["chain"]["ok"] is True
