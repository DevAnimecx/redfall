"""Applying a proposed patch to the target repository.

The patch is applied with `git apply`, so a hunk that does not land exactly is
rejected rather than fuzzed into a file that looks fixed but is not. That
failure mode was measured on this range and it produces a green test run
alongside a still-exploitable endpoint.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from git import GitCommandError, InvalidGitRepositoryError, Repo


class PatchRejected(RuntimeError):
    """The patch could not be applied cleanly."""


@dataclass(frozen=True)
class ApplyResult:
    ok: bool
    branch: str
    commit: str
    message: str
    diff: str


def _git(
    repo_dir: Path,
    *args: str,
    check: bool = True,
    stdin: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run git and return a str-shaped result.

    When `stdin` is given it is sent as the patch's exact bytes. Text mode is
    not used for that path: on Windows `subprocess` rewrites every `\\n` fed to
    a text-mode pipe as `\\r\\n`, which corrupts the patch's context lines and
    makes `git apply` reject hunks that would otherwise land.
    """
    command = ["git", "-C", str(repo_dir), *args]
    if stdin is None:
        proc: subprocess.CompletedProcess = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
        )
    else:
        raw = subprocess.run(
            command,
            input=stdin.encode("utf-8"),
            capture_output=True,
            timeout=120,
        )
        proc = subprocess.CompletedProcess(
            raw.args,
            raw.returncode,
            raw.stdout.decode("utf-8", "replace"),
            raw.stderr.decode("utf-8", "replace"),
        )
    if check and proc.returncode != 0:
        raise PatchRejected(f"git {' '.join(args)} failed: {(proc.stderr or proc.stdout).strip()}")
    return proc


def check_patch(repo_dir: Path, patch: str) -> tuple[bool, str]:
    """Validate a patch against the working tree without changing anything."""
    if not patch.strip():
        return False, "patch is empty"
    probe = _git(repo_dir, "apply", "--check", "--verbose", "-", check=False, stdin=patch)
    if probe.returncode != 0:
        return False, (probe.stderr or probe.stdout).strip()
    return True, "clean"


def apply_patch_with_stdin(repo_dir: Path, patch: str, *, branch: str, message: str) -> ApplyResult:
    """Apply and commit, feeding the patch on stdin so shell quoting is not a factor."""
    root = Path(repo_dir).resolve()
    try:
        Repo(root, search_parent_directories=False)
    except InvalidGitRepositoryError as err:
        raise PatchRejected(f"{root} is not a git repository: {err}") from err

    clean, reason = check_patch(root, patch)
    if not clean:
        raise PatchRejected(f"patch does not apply cleanly: {reason}")

    base = _git(root, "rev-parse", "HEAD").stdout.strip()
    existing = _git(root, "branch", "--list", branch).stdout.strip()
    if existing:
        _git(root, "checkout", branch)
        _git(root, "reset", "--hard", base)
    else:
        _git(root, "checkout", "-b", branch)

    proc = _git(root, "apply", "--index", "-", check=False, stdin=patch)
    if proc.returncode != 0:
        _git(root, "checkout", "--", ".")
        raise PatchRejected(f"git apply failed: {(proc.stderr or proc.stdout).strip()}")

    _git(root, "commit", "-m", message, "--no-verify")
    commit = _git(root, "rev-parse", "HEAD").stdout.strip()
    diff = _git(root, "diff", f"{base}..{commit}").stdout
    return ApplyResult(ok=True, branch=branch, commit=commit, message=message, diff=diff)


def revert(repo_dir: Path, branch: str, back_to: str) -> None:
    """Return the repository to `back_to` and drop the fix branch."""
    root = Path(repo_dir).resolve()
    _git(root, "checkout", back_to, check=False)
    _git(root, "branch", "-D", branch, check=False)


def current_branch(repo_dir: Path) -> str:
    try:
        return str(Repo(Path(repo_dir).resolve(), search_parent_directories=False).head.ref)
    except (InvalidGitRepositoryError, GitCommandError, ValueError):
        return ""
