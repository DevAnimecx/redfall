"""Patch application tests against a real scratch git repository.

The repository is created on disk and driven with the real `git` binary. This
guards a failure a mock could not have caught: `check_patch` ran
`git apply --check -` without handing it the patch on stdin, so every patch was
rejected — and the rejection was silent, because "patch does not apply cleanly"
is a plausible thing for a bad patch to say.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from redfall.fix.applier import (
    PatchRejected,
    apply_patch_with_stdin,
    check_patch,
    current_branch,
    revert,
)

REL = "src/routes/accounts.ts"

ORIGINAL = """\
router.get('/:accountNo', (req, res) => {
  const account = accounts.find((a) => a.account_no === req.params.accountNo);
  res.json({ account });
});
"""

FIXED = """\
router.get('/:accountNo', requireAuth, (req, res) => {
  const account = accounts.find((a) => a.account_no === req.params.accountNo);
  res.json({ account });
});
"""

FIXED_ALT = """\
router.get('/:accountNo', (req, res) => {
  const account = accounts.find((a) => a.account_no === req.params.accountNo);
  res.json({ account: null });
});
"""


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, f"git {' '.join(args)}: {proc.stderr or proc.stdout}"
    return proc.stdout


def write(repo: Path, rel: str, content: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode("utf-8"))


def make_patch(repo: Path, rel: str, new_content: str) -> str:
    """A real `git diff` for changing `rel`, captured and then reverted."""
    write(repo, rel, new_content)
    patch = git(repo, "diff", "--", rel)
    git(repo, "checkout", "--", rel)
    return patch


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "scratch"
    root.mkdir()
    git(root, "init", "-b", "main")
    git(root, "config", "user.email", "range@test.local")
    git(root, "config", "user.name", "Range Test")
    git(root, "config", "core.autocrlf", "false")
    write(root, REL, ORIGINAL)
    git(root, "add", "-A")
    git(root, "commit", "-m", "seed", "--no-verify")
    return root


# ------------------------------------------------------------- check_patch
def test_check_patch_accepts_a_patch_that_lands(repo):
    ok, reason = check_patch(repo, make_patch(repo, REL, FIXED))
    assert ok, reason
    assert reason == "clean"


def test_check_patch_rejects_an_empty_patch(repo):
    assert check_patch(repo, "   \n") == (False, "patch is empty")


def test_check_patch_rejects_a_patch_whose_context_does_not_match(repo):
    patch = make_patch(repo, REL, FIXED).replace("accounts.find", "counts.find")
    ok, reason = check_patch(repo, patch)
    assert ok is False
    assert reason.strip()


def test_check_patch_changes_nothing(repo):
    head = git(repo, "rev-parse", "HEAD").strip()
    patch = make_patch(repo, REL, FIXED)
    assert check_patch(repo, patch)[0] is True
    assert git(repo, "rev-parse", "HEAD").strip() == head
    assert (repo / REL).read_bytes() == ORIGINAL.encode("utf-8")
    assert git(repo, "status", "--porcelain").strip() == ""


# ---------------------------------------------------------------- apply
def test_apply_commits_the_patch_on_a_branch(repo):
    result = apply_patch_with_stdin(
        repo, make_patch(repo, REL, FIXED), branch="redfall/test", message="fix accounts"
    )
    assert result.ok is True
    assert result.branch == "redfall/test"
    assert current_branch(repo) == "redfall/test"
    assert (repo / REL).read_bytes() == FIXED.encode("utf-8")
    assert "requireAuth" in result.diff
    assert git(repo, "rev-parse", "HEAD").strip() == result.commit
    git(repo, "merge-base", "--is-ancestor", "main", result.commit)
    assert git(repo, "status", "--porcelain").strip() == ""


def test_apply_rejects_a_bad_patch_and_leaves_the_tree_clean(repo):
    patch = make_patch(repo, REL, FIXED).replace("accounts.find", "counts.find")
    head = git(repo, "rev-parse", "HEAD").strip()
    with pytest.raises(PatchRejected):
        apply_patch_with_stdin(repo, patch, branch="redfall/test", message="fix accounts")
    assert git(repo, "rev-parse", "HEAD").strip() == head
    assert (repo / REL).read_bytes() == ORIGINAL.encode("utf-8")
    assert git(repo, "status", "--porcelain").strip() == ""
    assert git(repo, "branch", "--list", "redfall/test").strip() == ""


def test_apply_refuses_a_directory_that_is_not_a_repository(repo, tmp_path):
    with pytest.raises(PatchRejected):
        apply_patch_with_stdin(
            tmp_path, make_patch(repo, REL, FIXED), branch="b", message="m"
        )


def test_apply_to_a_stale_branch_rebuilds_it_from_base(repo):
    """A branch left behind by an earlier run must not swallow the new patch."""
    patch_a = make_patch(repo, REL, FIXED)
    patch_b = make_patch(repo, REL, FIXED_ALT)
    base = git(repo, "rev-parse", "HEAD").strip()

    first = apply_patch_with_stdin(repo, patch_a, branch="redfall/test", message="attempt one")
    # The tree goes back to base between attempts; only the branch is stale.
    git(repo, "checkout", "main")

    second = apply_patch_with_stdin(repo, patch_b, branch="redfall/test", message="attempt two")

    assert second.commit != first.commit
    assert (repo / REL).read_bytes() == FIXED_ALT.encode("utf-8")
    assert git(repo, "rev-parse", f"{second.commit}^").strip() == base
    branches = [line for line in git(repo, "branch", "--list").splitlines() if "redfall/test" in line]
    assert len(branches) == 1
    assert git(repo, "status", "--porcelain").strip() == ""


# ---------------------------------------------------------------- revert
def test_revert_returns_to_base_and_drops_the_branch(repo):
    base = current_branch(repo)
    result = apply_patch_with_stdin(
        repo, make_patch(repo, REL, FIXED), branch="redfall/test", message="fix accounts"
    )
    revert(repo, result.branch, base)

    assert current_branch(repo) == base
    assert git(repo, "branch", "--list", "redfall/test").strip() == ""
    assert (repo / REL).read_bytes() == ORIGINAL.encode("utf-8")
