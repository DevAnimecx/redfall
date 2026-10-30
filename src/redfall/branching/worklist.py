"""Running a scan's branches, optionally several at a time.

The sequential loop this replaces did everything inline: pop a branch, run it,
fold the result into the scan outcome, then look for adaptive branches the run
spawned and append them to the worklist. That works, and it is the default, but
it leaves the machine idle while a branch waits on the sandbox or an agent.

The parallel version keeps the same shape and moves only the *execution* onto
worker threads. Everything that is shared — the event stream, the branch tree,
the adaptive spawner, the accumulators, the database session — stays on the
caller's thread, which drains finished work as it arrives. Workers are handed a
branch and their own session, and return a value; they touch nothing shared.

That split is deliberate. A worker that called `on_finding` directly would be
mutating the branch tree from a thread, and the tree's dedupe is a
check-then-insert that two workers can both pass. Returning the findings and
replaying them on one thread keeps that invariant intact.
"""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any, Callable

from .engine import BranchOutcome

# Opens a session. Workers each get their own; see the module docstring.
SessionFactory = Callable[[], Any]


@dataclass
class BranchRun:
    """One branch's result, as the caller's thread sees it.

    A worker either produced an outcome or raised. The exception is carried
    rather than re-raised on the worker, so the caller decides how it affects
    the scan — a sandbox that went away ends it, an agent error does not.
    """

    branch_id: str
    name: str
    outcome: BranchOutcome | None = None
    error: BaseException | None = None
    spawned: list[Any] = field(default_factory=list)


class BranchWorklist:
    """Owns the queue of branches and the pool that runs them.

    Usage: `add(branch)`, then repeatedly `take_done()` until it yields nothing
    and `in_flight` is zero. `add` may be called between those calls, which is
    how an adaptive branch spawned mid-scan joins the work.
    """

    def __init__(
        self,
        *,
        run_branch: Callable[[Any, Any], BranchOutcome],
        session_factory: SessionFactory,
        workers: int,
    ) -> None:
        """`run_branch(branch, session)` runs one branch and returns its outcome.

        The adapter fixes the argument order, so this module never needs to know
        the shape of the engine's keyword-only signature.
        """
        self._run_branch = run_branch
        self._session_factory = session_factory
        self._pool = ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="redfall-branch"
        )
        self._in_flight: dict[Future[BranchRun], str] = {}
        self._following: set[str] = set()

    @property
    def workers(self) -> int:
        return self._pool._max_workers  # noqa: SLF001 - reported, never set

    @property
    def in_flight(self) -> int:
        return len(self._in_flight)

    def has_room(self) -> bool:
        """True when another branch can be started without exceeding the pool."""
        return self.in_flight < self.workers

    def knows(self, branch_id: str) -> bool:
        """True if this branch is queued, running, or already finished."""
        return branch_id in self._following

    def submit(self, branch: Any) -> None:
        self._following.add(branch.id)
        future = self._pool.submit(self._execute, branch)
        self._in_flight[future] = branch.id

    def take_done(self, *, block: bool) -> list[BranchRun]:
        """Collect finished branches. Non-blocking unless `block` and work exists."""
        if not self._in_flight:
            return []
        if not block:
            finished = [f for f in self._in_flight if f.done()]
            if not finished:
                return []
        else:
            done, _pending = wait(self._in_flight, return_when=FIRST_COMPLETED)
            finished = list(done)
        runs: list[BranchRun] = []
        for future in finished:
            self._in_flight.pop(future, None)
            runs.append(future.result())
        return runs

    def close(self) -> None:
        """Wait for outstanding work, then shut the pool down.

        The caller has already folded every finished branch through
        `take_done`; anything still in flight here is work the scan chose not
        to wait for, and its outcome is discarded deliberately rather than
        silently — `take_done` is the only path that reports a result.
        """
        self._in_flight.clear()
        self._pool.shutdown(wait=True)

    # -- the worker --------------------------------------------------------
    def _execute(self, branch: Any) -> BranchRun:
        """Run one branch on its own session and return the result.

        Nothing here touches the caller's state: the session is this worker's
        own, and the findings come back on the outcome for the caller to fold
        in. The caller's `on_finding` hook is deliberately not invoked here —
        see the module docstring.
        """
        with self._session_factory() as session:
            try:
                outcome = self._run_branch(branch, session)
            except BaseException as err:  # noqa: BLE001 - the caller classifies it
                return BranchRun(branch_id=branch.id, name=branch.name, error=err)
        return BranchRun(branch_id=branch.id, name=branch.name, outcome=outcome)
