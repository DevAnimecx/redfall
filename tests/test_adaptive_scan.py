"""Tests for adaptive spawning inside a real scan, against a real database.

These use the actual `Branch` and `Finding` rows, not stand-ins, because the
contract being tested is a property of persisted state: rule 11 says an adaptive
branch's `spawned_at` is strictly after both its parent's start and the trigger's
discovery, and rule 12 says it records which finding triggered it and why. Neither
can be verified against an in-memory fake.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from redfall.branching.adaptive_scan import AdaptiveSpawner, SpawnRecord, new_tree, _priority_for
from redfall.branching.tree import TRIGGER_TYPES, BranchTree
from redfall.store.db import init_engine, session_scope
from redfall.store.models import Base, Branch, Finding, Scan

TARGET = Path(__file__).resolve().parents[1] / "range" / "vulnbank-adaptive" / "src"


@pytest.fixture()
def session(postgres_url):
    """A real Postgres session on a throwaway database."""
    engine = init_engine(postgres_url)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with session_scope() as s:
        yield s


@pytest.fixture()
def scan_id(session) -> str:
    sid = f"scan-{uuid.uuid4().hex[:10]}"
    session.add(Scan(id=sid, repo="range/vulnbank-adaptive", status="running"))
    session.flush()
    return sid


@pytest.fixture()
def parent_branch(session, scan_id) -> Branch:
    row = Branch(
        id=f"br-{uuid.uuid4().hex[:8]}",
        scan_id=scan_id,
        parent_id=None,
        type="module",
        name="parent",
        scope_files=["routes/plugins.ts"],
        scope_routes=[],
        depth=0,
        status="running",
        priority=0,
        is_adaptive=False,
    )
    row.started_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    session.add(row)
    session.flush()
    return row


class FakeIngest:
    """Only the ingestion root is used by the spawner, to resolve relative paths."""

    def __init__(self, root: Path) -> None:
        self.root = root


def make_finding(session, scan_id: str, branch_id: str, rel_file: str) -> Finding:
    row = Finding(
        id=f"f-{uuid.uuid4().hex[:8]}",
        scan_id=scan_id,
        branch_id=branch_id,
        category="cmd_injection",
        severity="critical",
        title="Command injection in the plugin audit route",
        location_file=rel_file,
        location_line=23,
        location_symbol="auditHandler",
        reproduced=True,
    )
    session.add(row)
    session.flush()
    return row


# ------------------------------------------------------------------ detection
@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_surfaces_are_detected_from_a_real_target_file(session, scan_id, parent_branch):
    spawner = AdaptiveSpawner(
        session=session,
        scan_id=scan_id,
        ingest=FakeIngest(TARGET),
        tree=new_tree(),
    )
    surfaces = spawner.surfaces_for(["routes/plugins.ts"])
    assert surfaces, "no surfaces detected in a file that is known to contain two"
    assert {s.trigger_type for s in surfaces} & {"dynamic_import", "plugin_system"}


# ------------------------------------------------------------------- spawning
@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_a_reproduced_finding_spawns_real_branch_rows(session, scan_id, parent_branch):
    spawner = AdaptiveSpawner(
        session=session,
        scan_id=scan_id,
        ingest=FakeIngest(TARGET),
        tree=new_tree(),
    )
    finding = make_finding(session, scan_id, parent_branch.id, "routes/plugins.ts")

    outcome = spawner.spawn_from_finding(finding, parent_branch_id=parent_branch.id)

    assert outcome.spawned, outcome.as_dict()
    rows = session.query(Branch).filter(Branch.is_adaptive.is_(True)).all()
    assert len(rows) == len(outcome.spawned)

    for row in rows:
        assert row.is_adaptive is True
        assert row.triggering_finding_id == finding.id
        assert row.trigger_reason in TRIGGER_TYPES
        assert row.parent_id == parent_branch.id
        assert row.scan_id == scan_id
        assert row.depth == 1


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_rule_11_spawned_after_the_trigger_and_the_parent(session, scan_id, parent_branch):
    spawner = AdaptiveSpawner(
        session=session,
        scan_id=scan_id,
        ingest=FakeIngest(TARGET),
        tree=new_tree(),
    )
    finding = make_finding(session, scan_id, parent_branch.id, "routes/plugins.ts")
    outcome = spawner.spawn_from_finding(finding, parent_branch_id=parent_branch.id)

    assert outcome.spawned
    for record in outcome.spawned:
        assert record.spawned_at > record.discovered_at, record.as_dict()
        assert record.spawned_at > parent_branch.started_at, record.as_dict()
        assert record.latency_s > 0


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_a_finding_from_the_future_cannot_spawn_a_branch(session, scan_id, parent_branch):
    """The tree must refuse a spawn that predates its own trigger."""
    spawner = AdaptiveSpawner(
        session=session,
        scan_id=scan_id,
        ingest=FakeIngest(TARGET),
        tree=new_tree(),
    )
    finding = make_finding(session, scan_id, parent_branch.id, "routes/plugins.ts")
    finding.discovered_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    session.flush()

    outcome = spawner.spawn_from_finding(finding, parent_branch_id=parent_branch.id)

    assert not outcome.spawned
    assert all(r["reason"] == "InvalidTrigger" for r in outcome.refused)


def test_an_unknown_parent_is_refused_rather_than_assumed(session, scan_id):
    spawner = AdaptiveSpawner(
        session=session,
        scan_id=scan_id,
        ingest=FakeIngest(TARGET),
        tree=new_tree(),
    )
    finding = make_finding(session, scan_id, "no-such-branch", "routes/plugins.ts")
    outcome = spawner.spawn_from_finding(finding, parent_branch_id="no-such-branch")
    assert outcome.refused and outcome.refused[0]["reason"] == "unknown_parent"


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_the_same_surface_twice_is_deduped_not_duplicated(session, scan_id, parent_branch):
    spawner = AdaptiveSpawner(
        session=session,
        scan_id=scan_id,
        ingest=FakeIngest(TARGET),
        tree=new_tree(),
    )
    first = make_finding(session, scan_id, parent_branch.id, "routes/plugins.ts")
    second = make_finding(session, scan_id, parent_branch.id, "routes/plugins.ts")

    one = spawner.spawn_from_finding(first, parent_branch_id=parent_branch.id)
    two = spawner.spawn_from_finding(second, parent_branch_id=parent_branch.id)

    assert one.spawned
    assert not two.spawned, "the same surface spawned twice"
    # A cycle is the dedupe working, so it is not reported as a refusal.
    assert not two.refused


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_the_depth_cap_is_enforced_and_reported(session, scan_id, parent_branch):
    spawner = AdaptiveSpawner(
        session=session,
        scan_id=scan_id,
        ingest=FakeIngest(TARGET),
        tree=BranchTree(max_depth=1, max_branches=1),
    )
    finding = make_finding(session, scan_id, parent_branch.id, "routes/plugins.ts")
    outcome = spawner.spawn_from_finding(finding, parent_branch_id=parent_branch.id)

    reasons = {r["reason"] for r in outcome.refused}
    assert reasons & {"MaxDepth", "MaxBranches"}, outcome.as_dict()


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_all_seven_trigger_types_are_reachable_from_the_real_target(session, scan_id):
    """Every detector must be able to produce a real persisted branch."""
    tree = new_tree()
    spawner = AdaptiveSpawner(
        session=session, scan_id=scan_id, ingest=FakeIngest(TARGET), tree=tree
    )
    files = [
        "routes/plugins.ts",
        "routes/conditional.ts",
        "routes/dynamic.ts",
        "app.ts",
    ]
    root = Branch(
        id=f"root-{uuid.uuid4().hex[:6]}",
        scan_id=scan_id,
        parent_id=None,
        type="module",
        name="root",
        scope_files=files,
        scope_routes=[],
        depth=0,
        status="running",
        is_adaptive=False,
    )
    root.started_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    session.add(root)
    session.flush()

    reached: set[str] = set()
    for index, rel in enumerate(files):
        finding = make_finding(session, scan_id, root.id, rel)
        outcome = spawner.spawn_from_finding(finding, parent_branch_id=root.id)
        reached |= outcome.trigger_types

    assert reached == set(TRIGGER_TYPES), set(TRIGGER_TYPES) - reached


def test_priority_ranks_code_execution_surface_highest():
    assert _priority_for("plugin_system") > _priority_for("dynamic_import")
    assert _priority_for("dynamic_import") > _priority_for("db_stored_code")
    assert _priority_for("dynamic_route_registration") > _priority_for("feature_flag")
    assert _priority_for("feature_flag") > _priority_for("env_conditional")
    assert _priority_for("not-a-trigger") == 30


def test_spawn_record_serialises_with_a_latency(session, scan_id):
    now = datetime.now(timezone.utc)
    record = SpawnRecord(
        branch_id="b",
        parent_id="p",
        name="n",
        trigger_type="plugin_system",
        trigger_reason="plugin_system",
        triggering_finding_id="f",
        discovered_at=now,
        spawned_at=now + timedelta(milliseconds=250),
        depth=1,
    )
    data = record.as_dict()
    assert data["spawn_latency_s"] == 0.25
    assert data["trigger_type"] == "plugin_system"


def test_surfaces_resolve_against_the_real_ingest_result(session, scan_id, parent_branch):
    """Detection must run against the ingested target, not the working directory.

    Regression: `IngestResult` records its root as `target`, and the spawner
    previously read `.root`, so every lookup missed and a real scan detected
    nothing at all while the fake-ingest tests stayed green.
    """
    from redfall.ingestion.ingest import ingest

    root = TARGET.parent
    result = ingest("spawner-root-test", root)
    spawner = AdaptiveSpawner(session=session, scan_id=scan_id, ingest=result, tree=new_tree())
    assert not hasattr(result, "root")

    surfaces = spawner.surfaces_for(["src/routes/plugins.ts"])
    assert surfaces, "no surfaces detected through a real IngestResult"


def test_surfaces_for_detects_a_file_once_then_reuses_it(session, scan_id, parent_branch):
    """Repeated findings in one file must not re-parse it every time."""
    import redfall.branching.adaptive_scan as module

    root = TARGET.parent
    spawner = AdaptiveSpawner(
        session=session, scan_id=scan_id, ingest=FakeIngest(root), tree=new_tree()
    )
    calls = {"n": 0}
    original = module.parse_source

    def counting_parse(path):
        calls["n"] += 1
        return original(path)

    module.parse_source = counting_parse
    try:
        first = spawner.surfaces_for(["src/routes/plugins.ts"])
        second = spawner.surfaces_for(["src/routes/plugins.ts"])
        assert first and second == first
        assert calls["n"] == 1, "the file was re-parsed for a repeated finding"
    finally:
        module.parse_source = original


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_spawn_records_carry_the_tree_node_id(session, scan_id, parent_branch):
    """A record without its node id cannot be nested under later, so it must."""
    spawner = AdaptiveSpawner(
        session=session,
        scan_id=scan_id,
        ingest=FakeIngest(TARGET),
        tree=new_tree(),
    )
    finding = make_finding(session, scan_id, parent_branch.id, "routes/plugins.ts")
    outcome = spawner.spawn_from_finding(finding, parent_branch_id=parent_branch.id)

    assert outcome.spawned
    for record in outcome.spawned:
        assert record.node_id, record.as_dict()
        node = spawner.tree.get(record.node_id)
        assert node.id == record.node_id
        assert record.as_dict().get("node_id") is None  # the wire shape stays stable
