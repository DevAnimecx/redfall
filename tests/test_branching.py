"""Tests for the recursive tree and the seven adaptive spawn triggers.

These exercise real code paths, not a model of them: the detectors run over the
actual TypeScript in `range/vulnbank-adaptive/src`, and the tree enforces the
timestamp rules against a real clock.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from redfall.branching.adaptive import (
    DETECTORS,
    TRIGGER_TYPES,
    Surface,
    detect_in_directory,
    detect_new_surfaces,
)
from redfall.branching.tree import (
    BranchSpec,
    BranchTree,
    Cycle,
    InvalidTrigger,
    MaxBranches,
    MaxDepth,
    TreeError,
    priority_from_severity,
)
from redfall.ingestion.parser_ts import parse_source

TARGET = Path(__file__).resolve().parents[1] / "range" / "vulnbank-adaptive" / "src"


# ---------------------------------------------------------------- adaptive tree
def test_root_exists_and_is_zero_depth():
    tree = BranchTree()
    assert len(tree) == 1
    assert tree.depth_of(tree.root) == 0


def test_legal_decomposition_inserts():
    tree = BranchTree()
    child = tree.insert(tree.root, BranchSpec(name="routes", type="route", scope_files=["a.ts"]))
    assert tree.depth_of(child) == 1
    assert tree.children_of(tree.root)[0].id == child


def test_illegal_decomposition_is_refused():
    tree = BranchTree()
    with pytest.raises(TreeError, match="not a decomposition"):
        tree.insert(tree.root, BranchSpec(name="x", type="sink_context", scope_files=["a.ts"]))


def test_max_depth_is_enforced():
    tree = BranchTree(max_depth=2)
    module = tree.insert(tree.root, BranchSpec(name="m", type="module", scope_files=["m.ts"]))
    route = tree.insert(module, BranchSpec(name="r", type="route", scope_files=["r.ts"]))
    with pytest.raises(MaxDepth):
        tree.insert(route, BranchSpec(name="d", type="data_flow", scope_files=["d.ts"]))


def test_max_branches_is_enforced():
    tree = BranchTree(max_branches=2)
    tree.insert(tree.root, BranchSpec(name="a", type="module", scope_files=["a.ts"]))
    with pytest.raises(MaxBranches):
        tree.insert(tree.root, BranchSpec(name="b", type="module", scope_files=["b.ts"]))


def test_duplicate_scope_is_refused():
    tree = BranchTree()
    tree.insert(tree.root, BranchSpec(name="a", type="module", scope_files=["same.ts"]))
    with pytest.raises(Cycle):
        tree.insert(tree.root, BranchSpec(name="b", type="module", scope_files=["same.ts"]))


def test_adaptive_requires_a_trigger():
    tree = BranchTree()
    with pytest.raises(InvalidTrigger):
        tree.insert(
            tree.root,
            BranchSpec(name="x", type="route", scope_files=["x.ts"], is_adaptive=True),
        )


def test_adaptive_requires_an_enumerated_trigger_reason():
    tree = BranchTree()
    tree.mark_started(tree.root)
    with pytest.raises(InvalidTrigger, match="not one of"):
        tree.spawn_adaptive(
            parent_id=tree.root,
            spec=BranchSpec(name="x", type="route", scope_files=["x.ts"]),
            triggering_finding_id="VULN-1",
            trigger_reason="vibes",
            trigger_discovered_at=datetime.now(timezone.utc),
        )


def test_adaptive_cannot_be_spawned_before_its_trigger_was_found():
    tree = BranchTree()
    tree.mark_started(tree.root)
    future = datetime.now(timezone.utc) + timedelta(seconds=30)
    with pytest.raises(InvalidTrigger, match="precedes the triggering finding"):
        tree.spawn_adaptive(
            parent_id=tree.root,
            spec=BranchSpec(name="x", type="route", scope_files=["x.ts"]),
            triggering_finding_id="VULN-1",
            trigger_reason="dynamic_import",
            trigger_discovered_at=future,
        )


def test_adaptive_cannot_be_spawned_from_a_parent_that_never_started():
    tree = BranchTree()
    with pytest.raises(InvalidTrigger, match="has not started"):
        tree.spawn_adaptive(
            parent_id=tree.root,
            spec=BranchSpec(name="x", type="route", scope_files=["x.ts"]),
            triggering_finding_id="VULN-1",
            trigger_reason="dynamic_import",
            trigger_discovered_at=datetime.now(timezone.utc),
        )


def test_spawned_adaptive_branch_carries_its_trigger_and_ordering():
    tree = BranchTree()
    tree.mark_started(tree.root)
    discovered = datetime.now(timezone.utc)
    time.sleep(0.01)

    node = tree.spawn_adaptive(
        parent_id=tree.root,
        spec=BranchSpec(name="plugin-scan", type="route", scope_files=["plugins.ts"]),
        triggering_finding_id="VULN-039",
        trigger_reason="plugin_system",
        trigger_discovered_at=discovered,
    )

    assert node.is_adaptive
    assert node.triggering_finding_id == "VULN-039"
    assert node.trigger_reason == "plugin_system"
    # rule 11: created strictly after both the parent start and the trigger
    assert node.created_at > tree.get(tree.root).started_at
    assert node.created_at > discovered
    assert node.spawn_latency_s(discovered) > 0
    assert len(tree.adaptive_branches()) == 1


def test_adaptive_may_leave_the_taxonomy_because_it_follows_evidence():
    tree = BranchTree()
    tree.mark_started(tree.root)
    node = tree.spawn_adaptive(
        parent_id=tree.root,
        spec=BranchSpec(name="db-code", type="sink_context", scope_files=["q.ts"]),
        triggering_finding_id="VULN-037",
        trigger_reason="db_stored_code",
        trigger_discovered_at=datetime.now(timezone.utc),
    )
    assert node.spec.type == "sink_context"


def test_priority_follows_severity():
    assert priority_from_severity("critical") > priority_from_severity("high")
    assert priority_from_severity("high") > priority_from_severity("medium")
    assert priority_from_severity("unknown") == 20


# ------------------------------------------------- detectors against real source
@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_detectors_find_all_seven_trigger_types_in_the_real_target():
    surfaces = detect_in_directory(TARGET)
    found = {s.trigger_type for s in surfaces}
    missing = set(TRIGGER_TYPES) - found
    assert not missing, f"detectors missed {sorted(missing)}; found {sorted(found)}"


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_every_detected_surface_points_at_a_real_line_in_the_target():
    surfaces = detect_in_directory(TARGET)
    assert surfaces
    for surface in surfaces:
        path = Path(surface.file)
        assert path.exists(), f"{surface.file} does not exist"
        lines = path.read_text().splitlines()
        assert 1 <= surface.line <= len(lines), f"{surface.file}:{surface.line} out of range"


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_feature_flag_detector_names_the_real_gate():
    surfaces = [s for s in detect_in_directory(TARGET) if s.trigger_type == "feature_flag"]
    names = {s.name for s in surfaces}
    assert "FEATURE_BETA_EXPORT" in names
    assert "WEBHOOK_ENABLED" in names


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_env_conditional_detector_names_the_real_environment():
    surfaces = [s for s in detect_in_directory(TARGET) if s.trigger_type == "env_conditional"]
    assert any(s.name == "NODE_ENV=production" for s in surfaces)


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_dynamic_import_detector_fires_on_require_of_a_value():
    surfaces = [s for s in detect_in_directory(TARGET) if s.trigger_type == "dynamic_import"]
    assert surfaces, "require(<value>) was not detected"
    assert any("plugins.ts" in s.file for s in surfaces)


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_middleware_registration_is_not_mistaken_for_a_dynamic_route():
    """`app.use(express.json())` is middleware. It must not look like a router."""
    parsed = parse_source(TARGET / "app.ts")
    assert parsed is not None
    surfaces = detect_new_surfaces(parsed)
    names = [s.name for s in surfaces if s.trigger_type == "dynamic_route_registration"]
    assert not any("express.json" in n for n in names), names
    assert not any("urlencoded" in n for n in names), names


def test_surface_branch_name_is_slugified():
    surface = Surface(
        trigger_type="plugin_system",
        kind="directory",
        name="Plugin Dir!",
        file="x.ts",
        line=1,
        detail="",
    )
    assert surface.branch_name() == "plugin-system-plugin-dir"


def test_all_seven_detectors_are_wired_up():
    assert len(DETECTORS) == 6  # webhook_discovery is called separately with runtime routes
    assert len(TRIGGER_TYPES) == 7


# --------------------------------------------- detectors feeding the real tree
def _spawn_all(surfaces):
    """Drive detected surfaces into a real tree the way the orchestrator does."""
    tree = BranchTree(max_depth=4)
    tree.mark_started(tree.root)
    spawned, refused = [], []
    for surface in sorted(surfaces, key=lambda s: (s.trigger_type, s.file, s.line)):
        spec = BranchSpec(
            name=surface.branch_name(),
            type="route" if surface.kind in ("route", "directory") else "module",
            scope_files=list(surface.scope_files),
            scope_routes=list(surface.scope_routes),
        )
        try:
            node = tree.spawn_adaptive(
                parent_id=tree.root,
                spec=spec,
                triggering_finding_id=f"VULN-{abs(hash((surface.file, surface.line))) % 1000:03d}",
                trigger_reason=surface.trigger_type,
                trigger_discovered_at=datetime.now(timezone.utc),
            )
            spawned.append((surface, node))
        except TreeError as err:
            refused.append((surface.trigger_type, surface.name, type(err).__name__))
    return tree, spawned, refused


def test_two_triggers_in_one_file_get_two_branches():
    """A module can hold several distinct surfaces; none may be dropped.

    This is the regression that made the tree lose whole trigger types: keying
    the scope on files alone collapsed every flag in `conditional.ts` into one
    branch.
    """
    one = Surface(
        trigger_type="feature_flag", kind="flag", name="FEATURE_A",
        file="conditional.ts", line=10, detail="", scope_files=("conditional.ts",),
    )
    two = Surface(
        trigger_type="env_conditional", kind="env", name="NODE_ENV=production",
        file="conditional.ts", line=20, detail="", scope_files=("conditional.ts",),
    )
    _tree, spawned, refused = _spawn_all([one, two])
    assert len(spawned) == 2, refused
    assert not refused


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_every_detected_surface_spawns_a_branch():
    surfaces = detect_in_directory(TARGET)
    tree, spawned, refused = _spawn_all(surfaces)
    assert not refused, f"surfaces dropped from the tree: {refused}"
    assert len(spawned) == len(surfaces)
    assert len(tree) == len(surfaces) + 1  # plus the root


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_all_seven_trigger_types_reach_the_tree():
    surfaces = detect_in_directory(TARGET)
    _tree, spawned, _refused = _spawn_all(surfaces)
    reached = {surface.trigger_type for surface, _node in spawned}
    assert reached == set(TRIGGER_TYPES), set(TRIGGER_TYPES) - reached


@pytest.mark.skipif(not TARGET.exists(), reason="vulnbank-adaptive source not present")
def test_spawned_branches_obey_the_ordering_rule():
    """Rule 11: spawned_at after the parent start and after the trigger."""
    surfaces = detect_in_directory(TARGET)
    tree, spawned, _refused = _spawn_all(surfaces)
    parent_start = tree.get(tree.root).started_at
    assert parent_start is not None
    for _surface, node in spawned:
        assert node.created_at > parent_start
        assert node.depth >= 1
        assert node.is_adaptive
        assert node.trigger_reason in TRIGGER_TYPES
        assert node.triggering_finding_id
