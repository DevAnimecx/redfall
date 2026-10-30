"""The agent mesh: role tools, separation of duties, per-role binding.

The separation tests are the ones that matter. "Independent verification" that
runs the author and the judge on the same agent is not independent, and the
failure is silent — the report looks the same either way. So the cases here
check that the mesh refuses the collapse the operator asked for and warns about
the one they did not think about.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


# -- the role table ---------------------------------------------------------

def test_the_eight_roles_are_defined():
    from redfall.mesh.roles import ROLE_NAMES

    assert set(ROLE_NAMES) == {
        "recon",
        "analyst",
        "planner",
        "exploit",
        "runtime_operator",
        "critic",
        "fixer",
        "verifier",
    }


def test_an_unknown_role_is_refused_with_the_known_ones():
    from redfall.mesh.roles import MeshError, role_named

    with pytest.raises(MeshError, match="known:"):
        role_named("necromancer")


def test_only_the_exploit_role_can_assert_a_finding():
    """A verifier confirms someone else's finding; it does not originate one."""
    from redfall.mesh.roles import ROLE_DEFINITIONS

    asserters = {name for name, spec in ROLE_DEFINITIONS.items() if spec.can_assert_findings}
    assert asserters == {"exploit"}


def test_the_verifier_cannot_write_a_fix():
    """A verifier that can author the fix can make its own proof pass."""
    from redfall.mesh.roles import check_tool, tools_for

    assert "redfall_fix_propose" not in tools_for("verifier")
    with pytest.raises(Exception, match="may not call"):
        check_tool("verifier", "redfall_fix_propose")


def test_the_fixer_cannot_run_the_reproduction():
    """The fixer judges nothing: running the proof is the verifier's job."""
    from redfall.mesh.roles import tools_for

    assert "redfall_reproduce" not in tools_for("fixer")


def test_a_role_reaching_outside_its_allowlist_raises():
    from redfall.mesh.roles import MeshError, check_tool

    with pytest.raises(MeshError, match="may not call"):
        check_tool("recon", "redfall_fix_propose")


def test_a_role_calling_one_of_its_own_tools_is_allowed():
    from redfall.mesh.roles import check_tool, tools_for

    for tool in sorted(tools_for("critic")):
        check_tool("critic", tool)  # must not raise


def test_every_role_can_read_the_graph():
    """No role should be unable to look at what it is being asked about."""
    from redfall.mesh.roles import ROLE_DEFINITIONS

    for name, spec in ROLE_DEFINITIONS.items():
        assert "redfall_graph_search" in spec.allowed_tools, name


def test_the_separation_pairs_are_deduplicated_and_stable():
    from redfall.mesh.roles import separation_pairs

    pairs = separation_pairs()
    assert len(pairs) == len(set(pairs))
    assert pairs == sorted(pairs)
    assert ("critic", "exploit") in pairs


def test_author_and_judge_are_a_separation_pair():
    from redfall.mesh.roles import separation_pairs

    pairs = separation_pairs()
    assert ("critic", "exploit") in pairs, "the critic must not be the author"


def test_a_role_never_lists_an_unknown_role_as_its_pair():
    from redfall.mesh.roles import ROLE_DEFINITIONS, ROLE_NAMES

    for spec in ROLE_DEFINITIONS.values():
        for other in spec.must_differ_from:
            assert other in ROLE_NAMES, f"{spec.name} names unknown {other}"


# -- binding ----------------------------------------------------------------

def test_binding_roles_to_different_agents_is_accepted():
    from redfall.mesh.binding import plan_for

    plan = plan_for(
        {"exploit": "codex", "critic": "gemini", "verifier": "gemini"},
        default_backend="claude-code",
    )
    assert plan.backend_for("exploit") == "codex"
    assert plan.backend_for("critic") == "gemini"
    assert plan.uses_multiple_backends() is True


def test_binding_the_author_and_critic_to_one_agent_is_refused():
    """The collapse the mesh exists to catch."""
    from redfall.mesh.binding import BindingError, plan_for

    with pytest.raises(BindingError, match="critic"):
        plan_for({"exploit": "codex", "critic": "codex"}, default_backend="claude-code")


def test_the_refusal_explains_why_it_matters():
    from redfall.mesh.binding import BindingError, plan_for

    with pytest.raises(BindingError, match="makes the critic the author"):
        plan_for({"exploit": "x", "critic": "x"}, default_backend="default")


def test_allow_shared_permits_the_collapse_but_warns():
    """Most teams run one agent everywhere; refusing outright is unusable."""
    from redfall.mesh.binding import plan_for

    plan = plan_for(
        {"exploit": "codex", "critic": "codex"},
        default_backend="claude-code",
        allow_shared=True,
    )
    assert plan.shared_acknowledged is True
    assert any("critic is not independent" in w for w in plan.warnings)


def test_an_unassigned_role_falls_back_and_warns_rather_than_failing():
    from redfall.mesh.binding import plan_for

    plan = plan_for({"exploit": "codex"}, default_backend="claude-code")
    assert plan.backend_for("recon") == "claude-code"
    assert any("fall back" in w for w in plan.warnings)


def test_check_unassigned_promotes_a_default_collapse_to_an_error():
    from redfall.mesh.binding import BindingError, plan_for

    with pytest.raises(BindingError, match="fall back"):
        plan_for({}, default_backend="claude-code", check_unassigned=True)


def test_an_empty_backend_for_a_role_is_refused():
    from redfall.mesh.binding import BindingError, plan_for

    with pytest.raises(BindingError, match="empty backend"):
        plan_for({"exploit": "   "}, default_backend="claude-code")


def test_no_default_backend_is_refused():
    from redfall.mesh.binding import BindingError, plan_for

    with pytest.raises(BindingError, match="default backend is required"):
        plan_for({"exploit": "codex"}, default_backend="  ")


def test_an_unknown_role_in_an_assignment_is_refused():
    from redfall.mesh.roles import MeshError
    from redfall.mesh.binding import plan_for

    with pytest.raises(MeshError, match="unknown role"):
        plan_for({"ghost": "codex"}, default_backend="claude-code")


def test_a_model_can_be_set_per_role():
    from redfall.mesh.binding import plan_for

    plan = plan_for(
        {"exploit": "codex", "critic": "gemini"},
        default_backend="claude-code",
        models={"exploit": "gpt-5", "critic": "gemini-2"},
    )
    assert plan.model_for("exploit") == "gpt-5"
    assert plan.model_for("critic") == "gemini-2"
    assert plan.model_for("recon") == ""


# -- config parsing ---------------------------------------------------------

def test_a_flat_config_builds_a_plan():
    from redfall.mesh.binding import bind_from_config

    plan = bind_from_config(
        {
            "default": "claude-code",
            "roles": {"exploit": "codex", "critic": "gemini"},
        }
    )
    assert plan.backend_for("exploit") == "codex"
    assert plan.backend_for("critic") == "gemini"


def test_a_config_without_a_default_is_refused():
    from redfall.mesh.binding import BindingError, bind_from_config

    with pytest.raises(BindingError, match="must name a default"):
        bind_from_config({"roles": {"exploit": "codex"}})


def test_a_config_whose_roles_are_not_a_mapping_is_refused():
    from redfall.mesh.binding import BindingError, bind_from_config

    with pytest.raises(BindingError, match="mesh.roles must be a mapping"):
        bind_from_config({"default": "claude-code", "roles": ["exploit"]})


def test_a_config_that_collapses_author_and_critic_is_refused():
    from redfall.mesh.binding import BindingError, bind_from_config

    with pytest.raises(BindingError, match="critic"):
        bind_from_config(
            {"default": "x", "roles": {"exploit": "codex", "critic": "codex"}}
        )


def test_a_config_may_acknowledge_a_collapse():
    from redfall.mesh.binding import bind_from_config

    plan = bind_from_config(
        {
            "default": "claude-code",
            "allow_shared": True,
            "roles": {"exploit": "codex", "critic": "codex"},
        }
    )
    assert plan.shared_acknowledged is True


# -- reporting --------------------------------------------------------------

def test_validate_plan_reports_a_collapse_without_raising():
    from redfall.mesh.binding import plan_for, validate_plan

    plan = plan_for(
        {"exploit": "codex", "critic": "codex"}, default_backend="claude-code", allow_shared=True
    )
    findings = validate_plan(plan)
    assert any("exploit" in f and "critic" in f for f in findings)


def test_a_sound_plan_has_no_findings():
    from redfall.mesh.binding import plan_for, validate_plan

    plan = plan_for(
        {
            "exploit": "codex",
            "critic": "gemini",
            "verifier": "gemini",
            "fixer": "claude-code",
        },
        default_backend="claude-code",
    )
    assert validate_plan(plan) == []


def test_the_summary_lists_every_role_with_its_backend():
    from redfall.mesh.binding import mesh_summary, plan_for

    summary = mesh_summary(plan_for({"exploit": "codex"}, default_backend="claude-code"))
    assert len(summary["roles"]) == 8
    assert {r["role"] for r in summary["roles"]} == {
        "recon",
        "analyst",
        "planner",
        "exploit",
        "runtime_operator",
        "critic",
        "fixer",
        "verifier",
    }
    exploit = next(r for r in summary["roles"] if r["role"] == "exploit")
    assert exploit["backend"] == "codex"
    assert exploit["bound_explicitly"] is True


def test_the_summary_names_the_backends_in_use():
    from redfall.mesh.binding import mesh_summary, plan_for

    summary = mesh_summary(
        plan_for({"exploit": "codex", "critic": "gemini"}, default_backend="claude-code")
    )
    assert sorted(summary["plan"]["backends_in_use"]) == ["claude-code", "codex", "gemini"]
