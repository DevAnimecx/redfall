"""The branch worklist: bounded concurrency, and nothing shared across workers.

These drive the pool with a real function rather than a mock — a stand-in would
prove only that the stand-in was called. The function records what ran and on
which thread, which is what the invariants are about: branches actually overlap,
the pool never exceeds its bound, and each worker gets its own session.
"""

from __future__ import annotations

import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


class _FakeBranch:
    def __init__(self, branch_id: str, priority: int = 0) -> None:
        self.id = branch_id
        self.name = branch_id
        self.priority = priority
        self.is_adaptive = False
        self.trigger_reason = ""


class _FakeOutcome:
    def __init__(self, branch_id: str) -> None:
        self.branch_id = branch_id
        self.name = branch_id
        self.candidates = 1
        self.reproduced = 0
        self.findings: list[object] = []
        self.duration_ms = 1


def _worklist(run_branch, *, workers: int, session_factory=None):
    from redfall.branching.worklist import BranchWorklist

    return BranchWorklist(
        run_branch=run_branch,
        session_factory=session_factory or (lambda: _Session()),
        workers=workers,
    )


class _Session:
    """Stands in for a SQLAlchemy Session: an identity, and a context manager."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_worklist_runs_every_branch_and_returns_its_outcome():
    from redfall.branching.worklist import BranchWorklist

    seen: list[str] = []

    def run(branch, session):
        seen.append(branch.id)
        return _FakeOutcome(branch.id)

    pool = BranchWorklist(run_branch=run, session_factory=lambda: _Session(), workers=2)
    try:
        for name in ("a", "b", "c"):
            pool.submit(_FakeBranch(name))
        runs = []
        while pool.in_flight:
            runs.extend(pool.take_done(block=True))
    finally:
        pool.close()

    assert sorted(seen) == ["a", "b", "c"]
    assert {r.branch_id for r in runs} == {"a", "b", "c"}
    assert all(r.error is None for r in runs)


def test_worklist_never_exceeds_its_worker_bound():
    """The bound is what keeps concurrent containers within the sandbox pool."""
    from redfall.branching.worklist import BranchWorklist

    lock = threading.Lock()
    live = 0
    peak = 0

    def run(branch, session):
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        time.sleep(0.02)
        with lock:
            live -= 1
        return _FakeOutcome(branch.id)

    pool = BranchWorklist(run_branch=run, session_factory=lambda: _Session(), workers=3)
    try:
        for i in range(12):
            pool.submit(_FakeBranch(f"b{i}"))
        while pool.in_flight:
            pool.take_done(block=True)
    finally:
        pool.close()

    assert peak <= 3, f"{peak} branches ran at once with a pool of 3"
    assert peak > 1, "branches never overlapped; the pool is not parallel"


def test_each_worker_gets_its_own_session():
    """Sharing one session across threads is the bug this seam exists to avoid."""
    from redfall.branching.worklist import BranchWorklist

    sessions: list[int] = []
    lock = threading.Lock()

    def factory():
        session = _Session()
        with lock:
            sessions.append(id(session))
        return session

    # Overlapping runs must hold distinct sessions, so hold each one long
    # enough that another worker enters while it is still open.
    def run(branch, session):
        time.sleep(0.02)
        return _FakeOutcome(branch.id)

    pool = BranchWorklist(run_branch=run, session_factory=factory, workers=4)
    try:
        for i in range(4):
            pool.submit(_FakeBranch(f"s{i}"))
        while pool.in_flight:
            pool.take_done(block=True)
    finally:
        pool.close()

    assert len(sessions) == 4, f"expected one session per branch, got {len(sessions)}"
    assert len(set(sessions)) == 4, "two workers shared a session"


def test_a_branch_that_raises_is_returned_not_swallowed():
    """The caller decides what an error means; the pool must not decide for it."""
    from redfall.branching.worklist import BranchWorklist

    def run(branch, session):
        if branch.id == "bad":
            raise RuntimeError("branch exploded")
        return _FakeOutcome(branch.id)

    pool = BranchWorklist(run_branch=run, session_factory=lambda: _Session(), workers=2)
    try:
        pool.submit(_FakeBranch("good"))
        pool.submit(_FakeBranch("bad"))
        runs = []
        while pool.in_flight:
            runs.extend(pool.take_done(block=True))
    finally:
        pool.close()

    by_id = {r.branch_id: r for r in runs}
    assert by_id["good"].error is None
    assert isinstance(by_id["bad"].error, RuntimeError)


def test_a_worker_python_error_does_not_kill_the_run():
    """`BaseException` is caught so one bad branch cannot take the scan down."""
    from redfall.branching.worklist import BranchWorklist

    def run(branch, session):
        if branch.id == "boom":
            raise SystemExit(3)
        return _FakeOutcome(branch.id)

    pool = BranchWorklist(run_branch=run, session_factory=lambda: _Session(), workers=2)
    try:
        pool.submit(_FakeBranch("ok"))
        pool.submit(_FakeBranch("boom"))
        runs = []
        while pool.in_flight:
            runs.extend(pool.take_done(block=True))
    finally:
        pool.close()

    by_id = {r.branch_id: r for r in runs}
    assert by_id["ok"].error is None
    assert isinstance(by_id["boom"].error, SystemExit)


def test_take_done_without_blocking_returns_nothing_while_work_is_running():
    """The caller loops on this; a blocking call with no work must not hang."""
    from redfall.branching.worklist import BranchWorklist

    started = threading.Event()
    release = threading.Event()

    def run(branch, session):
        started.set()
        release.wait(timeout=5)
        return _FakeOutcome(branch.id)

    pool = BranchWorklist(run_branch=run, session_factory=lambda: _Session(), workers=1)
    try:
        pool.submit(_FakeBranch("slow"))
        started.wait(timeout=5)
        assert pool.take_done(block=False) == []
    finally:
        release.set()
        while pool.in_flight:
            pool.take_done(block=True)
        pool.close()


def test_has_room_tracks_the_pool_bound():
    from redfall.branching.worklist import BranchWorklist

    release = threading.Event()

    def run(branch, session):
        release.wait(timeout=5)
        return _FakeOutcome(branch.id)

    pool = BranchWorklist(run_branch=run, session_factory=lambda: _Session(), workers=2)
    try:
        assert pool.has_room() is True
        pool.submit(_FakeBranch("a"))
        pool.submit(_FakeBranch("b"))
        assert pool.has_room() is False, "the pool admitted work past its bound"
    finally:
        release.set()
        while pool.in_flight:
            pool.take_done(block=True)
        pool.close()


def test_knows_reports_queued_and_finished_branches():
    """Adaptive spawning checks this to avoid enqueueing a branch twice."""
    from redfall.branching.worklist import BranchWorklist

    pool = BranchWorklist(
        run_branch=lambda branch, session: _FakeOutcome(branch.id),
        session_factory=lambda: _Session(),
        workers=1,
    )
    try:
        assert pool.knows("x") is False
        pool.submit(_FakeBranch("x"))
        assert pool.knows("x") is True
        while pool.in_flight:
            pool.take_done(block=True)
        assert pool.knows("x") is True, "a finished branch must stay known"
    finally:
        pool.close()
