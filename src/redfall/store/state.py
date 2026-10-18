"""Redis-backed scan and branch state (§7: `scan:<id>:state`, `branch:<id>:queue`)."""

from __future__ import annotations

import json
from typing import Any

import redis


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
        current = self.get_scan_state(scan_id) or {}
        current.update(patch)
        self.set_scan_state(scan_id, current, ttl_s=ttl_s)
        return current

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
