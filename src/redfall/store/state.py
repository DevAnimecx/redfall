"""Redis-backed scan and branch state (§7: `scan:<id>:state`, `branch:<id>:queue`)."""

from __future__ import annotations

import json
from typing import Any

import redis

# Bound the optimistic-lock retry. Contention here is between branches of one
# scan, which is brief; a patch that cannot land in this many tries means
# something is wrong, and the alternative to raising is silently losing a merge.
_MERGE_ATTEMPTS = 8


class StateStore:
    """Small typed wrapper over the two key families Redfall uses."""

    def __init__(self, redis_url: str) -> None:
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)

    def ping(self) -> tuple[bool, str]:
        try:
            self._client.ping()
            return True, "PONG"
        except Exception as err:  # noqa: BLE001 - connectivity probe
            return False, f"{type(err).__name__}: {err}"

    # --- scan state ---------------------------------------------------------
    def set_scan_state(self, scan_id: str, state: dict[str, Any], ttl_s: int = 86400) -> None:
        self._client.set(f"scan:{scan_id}:state", json.dumps(state), ex=ttl_s)

    def get_scan_state(self, scan_id: str) -> dict[str, Any] | None:
        raw = self._client.get(f"scan:{scan_id}:state")
        return json.loads(raw) if raw else None

    def update_scan_state(self, scan_id: str, patch: dict[str, Any], ttl_s: int = 86400) -> dict[str, Any]:
        """Merge `patch` into the scan's state, without losing a concurrent merge.

        Branches run in parallel and each reports progress here, so a plain
        read-merge-write drops whichever patch lands second: both read the same
        base, each writes back its own version, and the later write silently
        discards the earlier merge. The value is optimistic-locked with WATCH
        instead, and the merge is retried if anyone else wrote in between.
        """
        key = f"scan:{scan_id}:state"
        for _ in range(_MERGE_ATTEMPTS):
            with self._client.pipeline() as pipe:
                try:
                    pipe.watch(key)
                    raw = pipe.get(key)
                    current = json.loads(raw) if raw else {}
                    current.update(patch)
                    pipe.multi()
                    pipe.set(key, json.dumps(current), ex=ttl_s)
                    pipe.execute()
                except redis.WatchError:
                    # Someone else merged first; re-read and try again rather
                    # than overwriting their patch with our stale base.
                    continue
                return current
        raise RuntimeError(
            f"scan {scan_id} state was modified concurrently on every one of "
            f"{_MERGE_ATTEMPTS} attempts; refusing to drop a merge"
        )

    # --- branch queue -------------------------------------------------------
    def push_branches(self, scan_id: str, branch_ids: list[str]) -> int:
        """Queue branch ids for a scan; highest priority first is the caller's job."""
        if not branch_ids:
            return 0
        return int(self._client.rpush(f"scan:{scan_id}:branch_queue", *branch_ids))

    def pop_branch(self, scan_id: str) -> str | None:
        return self._client.lpop(f"scan:{scan_id}:branch_queue")

    def queue_depth(self, scan_id: str) -> int:
        return int(self._client.llen(f"scan:{scan_id}:branch_queue"))

    def set_branch_queue(self, branch_id: str, items: list[str]) -> None:
        key = f"branch:{branch_id}:queue"
        self._client.delete(key)
        if items:
            self._client.rpush(key, *items)

    def clear_scan(self, scan_id: str) -> None:
        for suffix in ("state", "branch_queue"):
            self._client.delete(f"scan:{scan_id}:{suffix}")
