"""The workspace pool: build the target copy once, hand out a clone per PoC.

The property that matters is isolation. Each PoC must get a workspace that no
other PoC can write into, and the template must survive all of them — if a
clone is ever the template, one exploit's writes leak into every later PoC and
a finding could be "reproduced" against state a previous run left behind.

These use real directories, because the thing under test is file copying.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture()
def target(tmp_path) -> Path:
    """A stand-in target with the shapes the pool copies."""
    root = tmp_path / "app"
    (root / "src").mkdir(parents=True)
    (root / "src" / "index.js").write_text("app.get('/x', handler)\n", encoding="utf-8")
    (root / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
    (root / "public").mkdir()
    (root / "public" / "logo.svg").write_text("<svg/>\n", encoding="utf-8")
    # A file the pool must NOT copy: not runtime material.
    (root / "secret.notes").write_text("do not ship\n", encoding="utf-8")
    return root


def _pool(target: Path, tmp_path: Path):
    from redfall.validation.workspace import WorkspacePool

    return WorkspacePool(target=target, workdir=tmp_path / "workspaces")


def test_checkout_gives_the_target_and_its_runtime_files(target, tmp_path):
    pool = _pool(target, tmp_path)
    try:
        workspace = pool.checkout("run-1")
        assert (workspace / "target" / "package.json").is_file()
        assert (workspace / "target" / "src" / "index.js").is_file()
        assert (workspace / "target" / "public" / "logo.svg").is_file()
    finally:
        pool.close()


def test_checkout_leaves_non_runtime_files_behind(target, tmp_path):
    """Only runtime material is copied; a stray notes file is not an app file."""
    pool = _pool(target, tmp_path)
    try:
        workspace = pool.checkout("run-1")
        assert not (workspace / "target" / "secret.notes").exists()
    finally:
        pool.close()


def test_two_checkouts_do_not_share_a_directory(target, tmp_path):
    """The isolation the whole design rests on."""
    pool = _pool(target, tmp_path)
    try:
        first = pool.checkout("run-1")
        second = pool.checkout("run-2")

        assert first != second
        (first / "target" / "src" / "index.js").write_text("TAMPERED\n", encoding="utf-8")

        assert (second / "target" / "src" / "index.js").read_text(encoding="utf-8") != "TAMPERED\n"
        assert (pool.template / "src" / "index.js").read_text(encoding="utf-8") != "TAMPERED\n"
    finally:
        pool.close()


def test_a_clone_is_not_the_template(target, tmp_path):
    """If checkout ever returned the template, one exploit would poison the scan."""
    pool = _pool(target, tmp_path)
    try:
        workspace = pool.checkout("run-1")
        assert workspace.resolve() != pool.template.resolve()
        assert pool.template not in workspace.resolve().parents
        assert not (pool.template / "poc.json").exists()
    finally:
        pool.close()


def test_the_template_is_built_once_for_many_checkouts(target, tmp_path):
    """The cost this exists to remove: copying the target once per scan."""
    pool = _pool(target, tmp_path)
    try:
        pool.checkout("run-1")
        built = pool.template
        first_stat = built.stat().st_mtime_ns

        for i in range(2, 6):
            pool.checkout(f"run-{i}")

        assert pool.template == built
        assert pool.template.stat().st_mtime_ns == first_stat, "the template was rebuilt"
    finally:
        pool.close()


def test_reusing_a_run_id_does_not_inherit_the_old_workspace(target, tmp_path):
    """A repeated run must start clean, not see what the previous one wrote."""
    pool = _pool(target, tmp_path)
    try:
        workspace = pool.checkout("run-1")
        (workspace / "target" / "leftover.txt").write_text("from an earlier run\n", encoding="utf-8")

        again = pool.checkout("run-1")
        assert not (again / "target" / "leftover.txt").exists()
        assert (again / "target" / "src" / "index.js").is_file()
    finally:
        pool.close()


def test_discard_removes_one_workspace_and_keeps_the_template(target, tmp_path):
    pool = _pool(target, tmp_path)
    try:
        workspace = pool.checkout("run-1")
        pool.discard("run-1")
        assert not workspace.exists()
        assert pool.template.exists(), "discarding a run must not remove the template"
    finally:
        pool.close()


def test_discard_will_not_delete_the_template_even_if_asked(target, tmp_path):
    """A defensive check: the template's name must never be discardable."""
    pool = _pool(target, tmp_path)
    try:
        template = pool.template
        pool.discard("_template")
        assert template.exists()
    finally:
        pool.close()


def test_close_removes_the_template(target, tmp_path):
    pool = _pool(target, tmp_path)
    template = pool.template
    assert template.exists()
    pool.close()
    assert not template.exists()


def test_node_modules_is_linked_rather_than_copied_when_possible(target, tmp_path):
    """Copying a host-built tree into a container gives binaries that mismatch."""
    modules = target / "node_modules" / "leftpad"
    modules.mkdir(parents=True)
    (modules / "index.js").write_text("module.exports = 1\n", encoding="utf-8")

    pool = _pool(target, tmp_path)
    try:
        workspace = pool.checkout("run-1")
        link = workspace / "target" / "node_modules"
        assert link.exists()
        # Either a symlink back to the host tree, or a real copy if the platform
        # could not make one. Both are honest; a dangling link is not.
        if link.is_symlink():
            assert link.resolve().is_dir()
        else:
            assert (link / "leftpad" / "index.js").is_file()
    finally:
        pool.close()


def test_a_symlinked_node_modules_survives_being_cloned(target, tmp_path):
    """The clone must recreate the link, not follow it into a deep copy."""
    modules = target / "node_modules" / "dep"
    modules.mkdir(parents=True)
    (modules / "index.js").write_text("module.exports = 1\n", encoding="utf-8")

    pool = _pool(target, tmp_path)
    try:
        workspace = pool.checkout("run-1")
        link = workspace / "target" / "node_modules"
        if link.is_symlink():
            assert link.resolve().is_dir()
            assert (link / "dep" / "index.js").is_file()
        else:
            pytest.skip("this platform could not create a symlink; copied instead")
    finally:
        pool.close()


def test_a_target_with_no_runtime_dirs_still_yields_a_workspace(target, tmp_path):
    """A minimal target must not crash the pool; it just copies less."""
    for entry in ("src", "public"):
        import shutil

        shutil.rmtree(target / entry)

    pool = _pool(target, tmp_path)
    try:
        workspace = pool.checkout("run-1")
        assert (workspace / "target" / "package.json").is_file()
    finally:
        pool.close()
