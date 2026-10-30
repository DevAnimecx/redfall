"""Scan state must survive concurrent merges, not silently drop one.

`update_scan_state` is called by every branch as it starts and by the scan as it
finishes. A read-merge-write without a transaction loses whichever patch lands
second: both branches read the same base, each writes back its own version, and
the later write discards the earlier merge.

These run against a real Redis, because that is the store whose transaction
semantics the code depends on. Without a server they skip rather than assert
against a stand-in that would pass either way.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _store(redis_url: str):
    from redfall.store.state import StateStore

    return StateStore(redis_url)


def test_update_merges_into_existing_state(redis_url):
    store = _store(redis_url)
    scan_id = "test-merge-basic"
    store.clear_scan(scan_id)
    try:
        store.set_scan_state(scan_id, {"status": "running"})
        merged = store.update_scan_state(scan_id, {"current_branch": "auth"})

        assert merged["status"] == "running"
        assert merged["current_branch"] == "auth"
        assert store.get_scan_state(scan_id) == {
            "status": "running",
            "current_branch": "auth",
        }
    finally:
        store.clear_scan(scan_id)


def test_concurrent_merges_all_land(redis_url):
    """Every branch's patch must survive, whichever order they arrive in.

    Each thread merges a distinct key. With an unguarded read-merge-write, the
    threads that read the same base overwrite each other and keys go missing —
    the count at the end is short of the number of threads.
    """
    store = _store(redis_url)
    scan_id = "test-merge-concurrent"
    store.clear_scan(scan_id)
    threads = 16
    barrier = threading.Barrier(threads)

    def merge(index: int) -> None:
        barrier.wait()
        store.update_scan_state(scan_id, {f"branch_{index}": True})

    try:
        workers = [threading.Thread(target=merge, args=(i,)) for i in range(threads)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

        final = store.get_scan_state(scan_id) or {}
        missing = [f"branch_{i}" for i in range(threads) if not final.get(f"branch_{i}")]
        assert not missing, f"merges lost under concurrency: {missing}"
    finally:
        store.clear_scan(scan_id)


def test_a_merge_never_reverts_another_key(redis_url):
    """The classic lost update: a stale base written back over a fresh value."""
    store = _store(redis_url)
    scan_id = "test-merge-stale"
    store.clear_scan(scan_id)
    try:
        store.set_scan_state(scan_id, {"findings": 0})

        # A writer that holds a base and writes much later must not clobber a
        # key another writer added in between.
        store.update_scan_state(scan_id, {"current_branch": "first"})
        store.update_scan_state(scan_id, {"findings": 3})

        final = store.get_scan_state(scan_id) or {}
        assert final["current_branch"] == "first"
        assert final["findings"] == 3
    finally:
        store.clear_scan(scan_id)


def test_merge_terminates_rather_than_spinning_forever(redis_url, monkeypatch):
    """A merge that can never win raises instead of dropping the patch.

    Eight attempts is the bound. If every attempt is invalidated the method must
    fail loudly, because the alternative — giving up quietly — is exactly the
    lost merge the transaction exists to prevent.
    """
    import redis

    store = _store(redis_url)
    scan_id = "test-merge-exhausted"
    store.clear_scan(scan_id)

    real_pipeline = store._client.pipeline

    class AlwaysConflicts:
        def __init__(self, inner):
            self._inner = inner

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def watch(self, *args, **kwargs):
            return True

        def get(self, *args, **kwargs):
            return None

        def multi(self, *args, **kwargs):
            return None

        def set(self, *args, **kwargs):
            return None

        def execute(self):
            raise redis.WatchError("forced conflict")

    monkeypatch.setattr(store._client, "pipeline", lambda *a, **k: AlwaysConflicts(real_pipeline(*a, **k)))

    import pytest

    with pytest.raises(RuntimeError, match="concurrently"):
        store.update_scan_state(scan_id, {"anything": True})
