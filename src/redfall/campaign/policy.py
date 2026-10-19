"""Scope enforcement for every operation that touches a filesystem path.

An MCP client is not trusted merely because it can reach the server. A path is
allowed only when it resolves inside a campaign root or an operator-provided
allowlist. Symlinks are resolved before comparison, so a link inside an allowed
root cannot point at `/etc` and pass the check.

``REDFALL_ALLOWED_ROOTS`` is a hard outer boundary, not an alternative to
campaign scope: an MCP client can create a campaign and set its scope, so a
campaign root that is not itself inside the operator allowlist is ignored when
the allowlist is configured.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..store.models import Campaign

SCOPE_PATH_KEYS = ("roots", "paths", "allowed_paths", "targets", "repos")


class PolicyError(RuntimeError):
    """The request is outside the campaign or operator scope."""


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    action: str
    target: str
    roots: list[str]
    reason: str

    def to_wire(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "target": self.target,
            "roots": list(self.roots),
            "reason": self.reason,
        }


def _scope_values(scope: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in SCOPE_PATH_KEYS:
        raw = scope.get(key)
        if isinstance(raw, str):
            values.append(raw)
        elif isinstance(raw, (list, tuple)):
            for item in raw:
                if isinstance(item, str):
                    values.append(item)
                elif isinstance(item, dict) and isinstance(item.get("path"), str):
                    values.append(item["path"])
        elif isinstance(raw, dict) and isinstance(raw.get("path"), str):
            values.append(raw["path"])
    return values


def campaign_roots(campaign: Campaign) -> list[Path]:
    roots: list[Path] = []
    for value in _scope_values(campaign.scope or {}):
        path = Path(value).expanduser()
        if path.exists():
            roots.append(path.resolve())
    repo = Path(campaign.repo).expanduser()
    if repo.exists():
        roots.append(repo.resolve())
    allowed = env_roots()
    if allowed:
        # The client can create campaigns and rewrite scope. When the operator
        # has configured an allowlist, a claimed root broader than that
        # allowlist must not widen access: keep only roots inside it.
        roots = [
            root
            for root in roots
            if any(_same_or_inside(root, allowed_root) for allowed_root in allowed)
        ]
    unique: dict[str, Path] = {str(path): path for path in roots}
    return list(unique.values())


def env_roots() -> list[Path]:
    raw = os.getenv("REDFALL_ALLOWED_ROOTS", "")
    roots: list[Path] = []
    for value in raw.split(os.pathsep):
        value = value.strip().strip('"')
        if not value:
            continue
        path = Path(value).expanduser()
        if path.exists():
            roots.append(path.resolve())
    unique: dict[str, Path] = {str(path): path for path in roots}
    return list(unique.values())


def _same_or_inside(path: Path, root: Path) -> bool:
    """Compare canonical paths with platform case rules.

    ``Path.is_relative_to`` is case-sensitive even on Windows, where the
    filesystem is not. ``normcase`` makes the containment check match the
    filesystem that will actually be opened.
    """
    left = os.path.normcase(str(path))
    right = os.path.normcase(str(root))
    try:
        return left == right or os.path.commonpath([left, right]) == right
    except ValueError:
        return False


def _decide(action: str, target: str | Path, roots: list[Path]) -> PolicyDecision:
    raw = Path(target).expanduser()
    try:
        resolved = raw.resolve()
    except OSError as exc:
        return PolicyDecision(
            allowed=False,
            action=action,
            target=str(raw),
            roots=[str(root) for root in roots],
            reason=f"path cannot be resolved: {exc}",
        )
    root_strings = [str(root) for root in roots]
    if not roots:
        return PolicyDecision(
            allowed=False,
            action=action,
            target=str(resolved),
            roots=root_strings,
            reason=(
                "no allowed filesystem root: set a campaign scope path or "
                "REDFALL_ALLOWED_ROOTS for unscoped operations"
            ),
        )
    for root in roots:
        if _same_or_inside(resolved, root):
            return PolicyDecision(
                allowed=True,
                action=action,
                target=str(resolved),
                roots=root_strings,
                reason=f"inside allowed root {root}",
            )
    return PolicyDecision(
        allowed=False,
        action=action,
        target=str(resolved),
        roots=root_strings,
        reason="target is outside every allowed root",
    )


def check_campaign_path(
    campaign: Campaign,
    target: str | Path,
    *,
    action: str,
    require_directory: bool = True,
) -> PolicyDecision:
    decision = _decide(action, target, campaign_roots(campaign))
    if not decision.allowed:
        return decision
    path = Path(decision.target)
    if not path.exists():
        return PolicyDecision(
            allowed=False,
            action=action,
            target=decision.target,
            roots=decision.roots,
            reason="target does not exist",
        )
    if require_directory and not path.is_dir():
        return PolicyDecision(
            allowed=False,
            action=action,
            target=decision.target,
            roots=decision.roots,
            reason="target is not a directory",
        )
    return decision


def check_os_path(
    target: str | Path,
    *,
    action: str,
    require_directory: bool = True,
) -> PolicyDecision:
    decision = _decide(action, target, env_roots())
    if not decision.allowed:
        return decision
    path = Path(decision.target)
    if not path.exists():
        return PolicyDecision(
            allowed=False,
            action=action,
            target=decision.target,
            roots=decision.roots,
            reason="target does not exist",
        )
    if require_directory and not path.is_dir():
        return PolicyDecision(
            allowed=False,
            action=action,
            target=decision.target,
            roots=decision.roots,
            reason="target is not a directory",
        )
    return decision


def require_campaign_path(
    campaign: Campaign,
    target: str | Path,
    *,
    action: str,
    require_directory: bool = True,
) -> Path:
    decision = check_campaign_path(
        campaign,
        target,
        action=action,
        require_directory=require_directory,
    )
    if not decision.allowed:
        raise PolicyError(decision.reason)
    return Path(decision.target)


def require_os_path(
    target: str | Path,
    *,
    action: str,
    require_directory: bool = True,
) -> Path:
    decision = check_os_path(target, action=action, require_directory=require_directory)
    if not decision.allowed:
        raise PolicyError(decision.reason)
    return Path(decision.target)
