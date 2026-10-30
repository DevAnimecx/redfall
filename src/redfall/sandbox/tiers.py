"""Sandbox isolation tiers: what a host can actually run, and how much of it.

The sandbox today is one class that assumes Docker plus gVisor. Scale-out needs
two things that are separable from having Firecracker installed:

1. **A tier registry.** Firecracker, gVisor-on-Docker and a plain container are
   three points on one isolation ladder. Each declares what it is and what it
   costs, so a deployment picks the strongest tier its host supports rather than
   having one hard-coded. Adding Firecracker becomes registering a tier and
   writing its `run`, not editing every call site.

2. **A capacity planner.** The scale-out target is "50 concurrent microVMs".
   Whether that fits is arithmetic — memory per VM times count against host
   memory, plus CPU and disk — and it is arithmetic that can be computed, tested
   and refused *before* a campaign is accepted. A planner that says "no, this
   host holds 3" is more useful than a scheduler that starts 50 and OOMs.

The isolation levels are ordered and named for what they defend against, not for
the product that provides them: `kernel_shared` (a container shares the host
kernel), `kernel_emulated` (gVisor intercepts syscalls), `kernel_isolated` (a
microVM has its own kernel). A deployment that claims `kernel_isolated` without
KVM is mistaken, and `detect()` reports what is real rather than what was asked
for.

Nothing here boots anything. It reports capability and plans capacity, both of
which are testable on a host with no KVM, no Docker and 2 GB of RAM — which is
exactly the host this was written on.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# Default per-unit footprints. A microVM's is higher because it boots a kernel,
# a rootfs and its own memory floor before the workload gets anything.
MIB = 1024 * 1024


class IsolationLevel(str, Enum):
    """What a tier defends against, in increasing strength."""

    NONE = "none"
    KERNEL_SHARED = "kernel_shared"
    KERNEL_EMULATED = "kernel_emulated"
    KERNEL_ISOLATED = "kernel_isolated"

    @property
    def rank(self) -> int:
        return {
            IsolationLevel.NONE: 0,
            IsolationLevel.KERNEL_SHARED: 1,
            IsolationLevel.KERNEL_EMULATED: 2,
            IsolationLevel.KERNEL_ISOLATED: 3,
        }[self]


@dataclass(frozen=True)
class RuntimeTier:
    """One isolation option: what it is, what it needs, what it costs.

    `probe` returns the reasons the tier is unavailable, empty when it is
    ready. Keeping the probe on the tier means `detect()` never needs a branch
    per runtime — a new tier arrives with its own readiness check.
    """

    name: str
    isolation: IsolationLevel
    memory_mib_per_unit: int
    cpu_millicores_per_unit: int
    startup_ms_p50: int
    startup_ms_p95: int
    network_policy: bool
    notes: str = ""

    def available(self) -> tuple[bool, list[str]]:
        reasons = _PROBES[self.name]()
        return (not reasons), reasons

    def to_wire(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "isolation": self.isolation.value,
            "memory_mib_per_unit": self.memory_mib_per_unit,
            "cpu_millicores_per_unit": self.cpu_millicores_per_unit,
            "startup_ms_p50": self.startup_ms_p50,
            "startup_ms_p95": self.startup_ms_p95,
            "network_policy": self.network_policy,
            "notes": self.notes,
        }


def _probe_firecracker() -> list[str]:
    reasons: list[str] = []
    if not Path("/dev/kvm").exists():
        reasons.append("no /dev/kvm: the kernel exposes no virtualisation to this host")
    if shutil.which("firecracker") is None:
        reasons.append("`firecracker` is not on PATH")
    if shutil.which("jailer") is None:
        # The jailer is what drops privileges before the VMM starts; a
        # microVM without it is not the isolation the tier claims.
        reasons.append("`jailer` is not on PATH (privilege drop for the VMM)")
    return reasons


def _probe_gvisor() -> list[str]:
    docker = shutil.which("docker")
    if docker is None:
        return ["the `docker` CLI is not on PATH"]
    try:
        info = subprocess.run(
            [docker, "info", "--format", "{{json .Runtimes}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as err:
        return [f"`docker info` failed: {type(err).__name__}: {err}"]
    if info.returncode != 0:
        return [f"`docker info` exited {info.returncode}"]
    if "runsc" not in (info.stdout or ""):
        return ["the `runsc` (gVisor) runtime is not registered with Docker"]
    return []


def _probe_container() -> list[str]:
    docker = shutil.which("docker")
    if docker is None:
        return ["the `docker` CLI is not on PATH"]
    try:
        info = subprocess.run(
            [docker, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as err:
        return [f"`docker info` failed: {type(err).__name__}: {err}"]
    if info.returncode != 0:
        return ["the Docker daemon is not reachable"]
    if not (info.stdout or "").strip():
        return ["the Docker daemon reported no server version"]
    return []


_PROBES = {
    "firecracker": _probe_firecracker,
    "gvisor": _probe_gvisor,
    "container": _probe_container,
}

# The ladder, strongest first. Order matters: `detect()` walks it and stops at
# the first tier that is ready, so a host with both KVM and Docker gets the
# microVM without an operator choosing.
TIERS: tuple[RuntimeTier, ...] = (
    RuntimeTier(
        name="firecracker",
        isolation=IsolationLevel.KERNEL_ISOLATED,
        memory_mib_per_unit=512,
        cpu_millicores_per_unit=1000,
        startup_ms_p50=125,
        startup_ms_p95=200,
        network_policy=True,
        notes="own kernel per workload; needs KVM and the jailer",
    ),
    RuntimeTier(
        name="gvisor",
        isolation=IsolationLevel.KERNEL_EMULATED,
        memory_mib_per_unit=320,
        cpu_millicores_per_unit=1000,
        startup_ms_p50=400,
        startup_ms_p95=900,
        network_policy=True,
        notes="user-space kernel intercepts syscalls; the current default",
    ),
    RuntimeTier(
        name="container",
        isolation=IsolationLevel.KERNEL_SHARED,
        memory_mib_per_unit=256,
        cpu_millicores_per_unit=1000,
        startup_ms_p50=350,
        startup_ms_p95=800,
        network_policy=False,
        notes="plain container; shares the host kernel, weakest tier",
    ),
)


def tier_named(name: str) -> RuntimeTier:
    for tier in TIERS:
        if tier.name == name:
            return tier
    raise KeyError(f"unknown tier {name!r}; known: {', '.join(t.name for t in TIERS)}")


def lowest_acceptable(minimum: IsolationLevel) -> RuntimeTier | None:
    """The weakest tier that still meets a floor, for a cost-aware choice."""
    candidates = [t for t in TIERS if t.isolation.rank >= minimum.rank]
    if not candidates:
        return None
    return min(candidates, key=lambda t: t.isolation.rank)


# -- host capacity ---------------------------------------------------------

@dataclass(frozen=True)
class HostCapacity:
    """What this machine has, as measured rather than assumed."""

    memory_mib: int
    cpu_count: int
    disk_free_mib: int
    has_kvm: bool
    notes: list[str] = field(default_factory=list)

    def to_wire(self) -> dict[str, Any]:
        return {
            "memory_mib": self.memory_mib,
            "cpu_count": self.cpu_count,
            "disk_free_mib": self.disk_free_mib,
            "has_kvm": self.has_kvm,
            "notes": list(self.notes),
        }


def measure_host(*, scan_root: Path | None = None) -> HostCapacity:
    """Read the host's real limits.

    Memory and disk are read from the operating system rather than configured,
    because a capacity plan built on a guessed number is how a scheduler ends up
    starting more work than the machine can hold.
    """
    notes: list[str] = []
    memory_mib = _total_memory_mib()
    if memory_mib <= 0:
        notes.append("could not read total memory; capacity planning will refuse rather than guess")
    disk_free_mib = _free_disk_mib(scan_root or Path.cwd())
    return HostCapacity(
        memory_mib=memory_mib,
        cpu_count=os.cpu_count() or 1,
        disk_free_mib=disk_free_mib,
        has_kvm=Path("/dev/kvm").exists(),
        notes=notes,
    )


def _total_memory_mib() -> int:
    """Total physical memory, cross-platform, or 0 when it cannot be read."""
    if os.name == "nt":
        try:
            # The documented way to ask Windows, without a dependency: the
            # ctypes call returns a struct whose first field is total bytes.
            import ctypes

            class _MemoryStatusEx(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = _MemoryStatusEx()
            status.dwLength = ctypes.sizeof(_MemoryStatusEx)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullTotalPhys // MIB)
        except (OSError, AttributeError):
            return 0
        return 0
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError):
        return 0
    if pages <= 0 or page_size <= 0:
        return 0
    return int((pages * page_size) // MIB)


def _free_disk_mib(path: Path) -> int:
    try:
        usage = shutil.disk_usage(str(path))
    except OSError:
        return 0
    return int(usage.free // MIB)


# -- the plan --------------------------------------------------------------

@dataclass(frozen=True)
class CapacityPlan:
    """How much concurrency a host supports, and what stopped it there.

    Exactly one binding constraint is named, because "why can I only run three"
    has one answer on a given host and a list of limits is not an answer.
    """

    tier: RuntimeTier | None
    requested: int
    allowed: int
    memory_mib: int
    cpu_count: int
    reserved_mib: int
    binding: str
    reason: str
    ok: bool

    def to_wire(self) -> dict[str, Any]:
        return {
            "tier": self.tier.name if self.tier else None,
            "isolation": self.tier.isolation.value if self.tier else None,
            "requested": self.requested,
            "allowed": self.allowed,
            "memory_mib": self.memory_mib,
            "cpu_count": self.cpu_count,
            "reserved_mib": self.reserved_mib,
            "binding": self.binding,
            "reason": self.reason,
            "ok": self.ok,
        }


# Memory the planner keeps for the orchestrator, the model client and the
# operating system itself. Without a reserve, a plan that fills memory exactly
# is a plan that swaps or OOMs the moment anything else runs.
DEFAULT_RESERVE_MIB = 512


def plan_capacity(
    host: HostCapacity,
    tier: RuntimeTier | None,
    *,
    requested: int,
    reserve_mib: int = DEFAULT_RESERVE_MIB,
) -> CapacityPlan:
    """How many concurrent units of `tier` this host can hold.

    Three constraints are computed and the tightest wins, because whichever is
    tightest is the answer an operator needs:

    * memory — total minus the reserve, divided by the per-unit footprint;
    * cpu — one unit per core, since each unit is granted a full core;
    * the request itself — a host that could run 20 but was asked for 5 gets 5.

    A tier that is None (nothing available) yields zero with the reason that no
    tier is ready, rather than a number that cannot be honoured.
    """
    if requested < 0:
        raise ValueError("requested concurrency must be >= 0")
    if tier is None:
        return CapacityPlan(
            tier=None,
            requested=requested,
            allowed=0,
            memory_mib=host.memory_mib,
            cpu_count=host.cpu_count,
            reserved_mib=reserve_mib,
            binding="no_tier",
            reason="no sandbox tier is available on this host; see BLOCKED.md",
            ok=False,
        )
    if host.memory_mib <= 0:
        return CapacityPlan(
            tier=tier,
            requested=requested,
            allowed=0,
            memory_mib=host.memory_mib,
            cpu_count=host.cpu_count,
            reserved_mib=reserve_mib,
            binding="unknown_memory",
            reason="host memory could not be read; refusing to plan on a guess",
            ok=False,
        )

    usable = max(0, host.memory_mib - reserve_mib)
    by_memory = usable // tier.memory_mib_per_unit
    by_cpu = max(1, host.cpu_count)
    allowed = min(requested, by_memory, by_cpu)


    if allowed == requested:
        binding, reason = "request", f"the host supports the {requested} requested"
    elif allowed == by_memory:
        binding = "memory"
        reason = (
            f"{usable} MiB usable after a {reserve_mib} MiB reserve, at "
            f"{tier.memory_mib_per_unit} MiB per {tier.name} unit, holds {by_memory}"
        )
    else:
        binding = "cpu"
        reason = f"{host.cpu_count} core(s) at one unit per core holds {by_cpu}"

    return CapacityPlan(
        tier=tier,
        requested=requested,
        allowed=allowed,
        memory_mib=host.memory_mib,
        cpu_count=host.cpu_count,
        reserved_mib=reserve_mib,
        binding=binding,
        reason=reason,
        ok=allowed >= min(requested, 1),
    )


def detect_tier(
    *,
    minimum: IsolationLevel = IsolationLevel.KERNEL_EMULATED,
    preferred: str = "",
) -> tuple[RuntimeTier | None, list[dict[str, Any]]]:
    """Pick a tier, and report why every other one was rejected.

    The report is returned even on success: an operator asking "why gVisor and
    not Firecracker" should get the probe output, not a single name.
    """
    report: list[dict[str, Any]] = []
    if preferred:
        try:
            tier = tier_named(preferred)
        except KeyError as err:
            raise ValueError(str(err)) from err
        ready, reasons = tier.available()
        report.append(
            {"name": tier.name, "isolation": tier.isolation.value, "ready": ready, "reasons": reasons}
        )
        if ready and tier.isolation.rank >= minimum.rank:
            return tier, report
        return None, report

    chosen: RuntimeTier | None = None
    for tier in TIERS:  # strongest first
        ready, reasons = tier.available()
        report.append(
            {"name": tier.name, "isolation": tier.isolation.value, "ready": ready, "reasons": reasons}
        )
        if ready and chosen is None and tier.isolation.rank >= minimum.rank:
            chosen = tier
    return chosen, report


def scale_report(*, requested: int, minimum: IsolationLevel = IsolationLevel.KERNEL_EMULATED) -> dict[str, Any]:
    """The full picture: what this host is, what tier it has, what fits.

    This is what `redfall doctor` and a deployment preflight both need, and
    building it in one place means the two cannot disagree.
    """
    host = measure_host()
    tier, probes = detect_tier(minimum=minimum)
    plan = plan_capacity(host, tier, requested=requested)
    return {
        "host": host.to_wire(),
        "tier": tier.to_wire() if tier else None,
        "probes": probes,
        "plan": plan.to_wire(),
        "requested": requested,
        "minimum_isolation": minimum.value,
    }
