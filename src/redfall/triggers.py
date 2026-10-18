"""The enumerated adaptive trigger types, in one place.

`branching/tree.py` enforces them, `branching/adaptive.py` produces them, and
the store checks persisted rows against them. A second copy of this tuple is a
contract that can drift, so there is exactly one.
"""

from __future__ import annotations

TRIGGER_TYPES: tuple[str, ...] = (
    "dynamic_import",
    "dynamic_route_registration",
    "plugin_system",
    "db_stored_code",
    "webhook_discovery",
    "feature_flag",
    "env_conditional",
)
