"""Sandbox tiers and the capacity planner.

The planner is arithmetic, so it can be tested exactly — and the cases that
matter are the refusals: a host with no KVM must not report a microVM tier, a
host whose memory cannot be read must not be planned on a guess, and a request
larger than the host holds must come back with the constraint that stopped it
rather than a number that cannot be honoured.

No test here boots anything. That is the point of separating capability
reporting from execution: it can be verified on a host with no KVM, no Docker
and no microVM image.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def test_the_ladder_is_ordered_weakest_to_strongest():
    from redfall.sandbox.tiers import IsolationLevel

    assert IsolationLevel.NONE.rank < IsolationLevel.KERNEL_SHARED.rank
    assert IsolationLevel.KERNEL_SHARED.rank < IsolationLevel.KERNEL_EMULATED.rank
    assert IsolationLevel.KERNEL_EMULATED.rank < IsolationLevel.KERNEL_ISOLATED.rank


def test_the_tiers_are_declared_strongest_first():
    """`detect` stops at the first ready tier, so order is the preference."""
    from redfall.sandbox.tiers import TIERS

    ranks = [tier.isolation.rank for tier in TIERS]
    assert ranks == sorted(ranks, reverse=True), "tiers must be strongest first"
    assert TIERS[0].name == "firecracker"


def test_a_microvm_tier_costs_more_than_a_container():
    from redfall.sandbox.tiers import tier_named

    vm = tier_named("firecracker")
    container = tier_named("container")
    assert vm.memory_mib_per_unit > container.memory_mib_per_unit
    assert vm.isolation.rank > container.isolation.rank


def test_an_unknown_tier_name_raises_with_the_known_ones():
    from redfall.sandbox.tiers import tier_named

    with pytest.raises(KeyError, match="known:"):
        tier_named("kata")


def test_lowest_acceptable_picks_the_cheapest_that_clears_the_floor():
    from redfall.sandbox.tiers import IsolationLevel, lowest_acceptable

    assert lowest_acceptable(IsolationLevel.KERNEL_EMULATED).name == "gvisor"
    assert lowest_acceptable(IsolationLevel.KERNEL_SHARED).name == "container"
    assert lowest_acceptable(IsolationLevel.KERNEL_ISOLATED).name == "firecracker"


# -- capacity planning ------------------------------------------------------

def _host(memory_mib: int, cpu: int = 8, kvm: bool = False):
    from redfall.sandbox.tiers import HostCapacity

    return HostCapacity(
        memory_mib=memory_mib, cpu_count=cpu, disk_free_mib=10_000, has_kvm=kvm
    )


def test_a_no_tier_host_gets_zero_and_a_reason_not_a_number():
    from redfall.sandbox.tiers import plan_capacity

    plan = plan_capacity(_host(64_000), None, requested=50)
    assert plan.allowed == 0
    assert plan.binding == "no_tier"
    assert plan.ok is False
    assert "BLOCKED.md" in plan.reason


def test_unreadable_memory_is_refused_rather_than_guessed():
    from redfall.sandbox.tiers import plan_capacity, tier_named

    plan = plan_capacity(_host(0), tier_named("gvisor"), requested=3)
    assert plan.allowed == 0
    assert plan.binding == "unknown_memory"
    assert plan.ok is False


def test_memory_is_the_binding_constraint_on_a_small_host():
    """1982 MiB and 50 microVMs: this is the arithmetic the claim needs."""
    from redfall.sandbox.tiers import plan_capacity, tier_named

    # 1982 MiB minus the 512 MiB reserve leaves 1470; at 512 per VM that is 2.
    plan = plan_capacity(_host(1982, cpu=16), tier_named("firecracker"), requested=50)
    assert plan.allowed == 2
    assert plan.binding == "memory"
    assert "usable after a 512 MiB reserve" in plan.reason


def test_a_large_host_is_still_bounded_by_the_request():
    from redfall.sandbox.tiers import plan_capacity, tier_named

    plan = plan_capacity(_host(256_000, cpu=64), tier_named("gvisor"), requested=5)
    assert plan.allowed == 5
    assert plan.binding == "request"


def test_cpu_binds_when_cores_are_scarce():
    from redfall.sandbox.tiers import plan_capacity, tier_named

    # Plenty of memory, two cores: the cores decide.
    plan = plan_capacity(_host(64_000, cpu=2), tier_named("container"), requested=10)
    assert plan.allowed == 2
    assert plan.binding == "cpu"


def test_the_reserve_keeps_the_plan_from_filling_memory_exactly():
    """Exact-fit memory is a plan that OOMs the moment anything else runs."""
    from redfall.sandbox.tiers import plan_capacity, tier_named

    # 2 * 512 MiB of VMs would fit in 1024 MiB with no reserve.
    no_reserve = plan_capacity(_host(1024), tier_named("firecracker"), requested=2, reserve_mib=0)
    with_reserve = plan_capacity(_host(1024), tier_named("firecracker"), requested=2, reserve_mib=512)
    assert no_reserve.allowed == 2
    assert with_reserve.allowed == 1


def test_a_zero_request_plans_zero_without_failing_hard():
    from redfall.sandbox.tiers import plan_capacity, tier_named

    plan = plan_capacity(_host(64_000), tier_named("gvisor"), requested=0)
    assert plan.allowed == 0
    assert plan.binding == "request"


def test_a_negative_request_is_refused():
    from redfall.sandbox.tiers import plan_capacity, tier_named

    with pytest.raises(ValueError, match="must be >= 0"):
        plan_capacity(_host(64_000), tier_named("gvisor"), requested=-1)


def test_the_plan_serialises_every_constraint_it_used():
    from redfall.sandbox.tiers import plan_capacity, tier_named

    # 4096 MiB minus the reserve over 320 MiB/unit is 11, so four cores binds.
    wire = plan_capacity(_host(4096, cpu=4), tier_named("gvisor"), requested=10).to_wire()
    assert wire["binding"] == "cpu"
    assert wire["allowed"] == 4
    assert set(wire) >= {"tier", "isolation", "allowed", "binding", "reason", "ok"}


# -- host measurement -------------------------------------------------------

def test_the_host_is_measured_not_assumed():
    from redfall.sandbox.tiers import measure_host

    host = measure_host()
    assert host.cpu_count >= 1
    # A host that reports zero memory says so, rather than silently planning.
    if host.memory_mib <= 0:
        assert any("could not read total memory" in note for note in host.notes)


def test_this_host_reports_no_kvm_and_no_firecracker_tier():
    """The honest result on a host without virtualisation, pinned deliberately.

    If this ever starts passing with a Firecracker tier, it is because the host
    changed, not because the code started guessing.
    """
    from redfall.sandbox.tiers import tier_named

    ready, reasons = tier_named("firecracker").available()
    assert ready is False
    assert any("kvm" in reason.lower() or "firecracker" in reason.lower() for reason in reasons)


def test_the_probe_reports_a_reason_for_every_tier_it_rejects():
    from redfall.sandbox.tiers import detect_tier

    tier, report = detect_tier()
    assert len(report) == 3
    for entry in report:
        assert isinstance(entry["ready"], bool)
        if not entry["ready"]:
            assert entry["reasons"], f"{entry['name']} rejected with no reason given"
    if tier is None:
        assert any(not e["ready"] for e in report)


def test_preferring_an_unavailable_tier_fails_with_the_reason():
    from redfall.sandbox.tiers import detect_tier

    tier, report = detect_tier(preferred="firecracker")
    assert tier is None
    assert report[0]["name"] == "firecracker"
    assert report[0]["reasons"]


def test_preferring_an_unknown_tier_raises():
    from redfall.sandbox.tiers import detect_tier

    with pytest.raises(ValueError, match="unknown tier"):
        detect_tier(preferred="kata")


def test_the_scale_report_agrees_with_its_parts():
    from redfall.sandbox.tiers import scale_report

    report = scale_report(requested=50)
    assert report["requested"] == 50
    assert report["plan"]["requested"] == 50
    # The plan's tier and the report's tier are the same decision, not two.
    plan_tier = report["plan"]["tier"]
    report_tier = report["tier"]["name"] if report["tier"] else None
    assert plan_tier == report_tier


# -- the memory reader ------------------------------------------------------

def test_memory_reading_is_positive_or_explicitly_zero():
    from redfall.sandbox.tiers import _total_memory_mib

    value = _total_memory_mib()
    assert value >= 0
    assert isinstance(value, int)
