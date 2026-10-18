"""Read the target's git state. Real `git` via GitPython; no synthetic history."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from git import GitCommandError, InvalidGitRepositoryError, Repo


@dataclass(frozen=True)
class GitInfo:
    is_repo: bool
    commit: str
    branch: str
    dirty: bool
    changed_files: list[str]

    @property
    def label(self) -> str:
        if not self.is_repo:
            return "no-git"
        suffix = "+dirty" if self.dirty else ""
        return f"{self.branch}@{self.commit[:8]}{suffix}"


def inspect(path: str | Path) -> GitInfo:
    """Describe the repository at `path`, tolerating a plain directory."""
    p = Path(path)
    try:
        repo = Repo(p, search_parent_directories=True)
    except (InvalidGitRepositoryError, Exception):  # noqa: BLE001 - not a repo is a normal case
        return GitInfo(is_repo=False, commit="", branch="", dirty=False, changed_files=[])

    try:
        head = repo.head.commit
        commit = head.hexsha
        branch = str(repo.head.ref)
    except (ValueError, GitCommandError):
        # A repo with no commits yet
        return GitInfo(is_repo=True, commit="", branch="(unborn)", dirty=False, changed_files=[])

    changed: list[str] = []
    dirty = repo.is_dirty(untracked_files=True)
    if dirty:
        for item in repo.index.diff(None):
            changed.append(item.a_path or item.b_path or "")
        changed.extend([u[0] for u in repo.untracked_files])
    return GitInfo(is_repo=True, commit=commit, branch=branch, dirty=dirty, changed_files=changed)
