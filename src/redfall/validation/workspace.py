"""Prepared sandbox workspaces, built once per scan instead of once per PoC.

Every PoC needs the target application on disk beside the harness. Copying the
whole tree for each one is the dominant cost of a scan that runs many PoCs
against one target — the source is identical every time, and only the PoC and
whatever the exploit writes differ.

So the target is copied once into a template, and each PoC gets a clone of that
template. Cloning is still a real copy, not a shared directory: an exploit that
writes to disk must not be able to disturb the next PoC, and a workspace the
harness already ran `npm install` in is not safe to reuse wholesale.

This module deliberately knows nothing about containers. It prepares
directories; the validator runs them.
"""

from __future__ import annotations

import shutil
from pathlib import Path

# Files the target needs at runtime but which are not application source.
RUNTIME_GLOBS = (
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "jest.config.js",
    ".env.example",
)
RUNTIME_DIRS = ("src", "migrations", "public", "views", "templates")


class WorkspacePool:
    """Builds the target template once, then hands out a clone per PoC."""

    def __init__(self, *, target: Path, workdir: Path) -> None:
        self.target = Path(target).resolve()
        self.workdir = Path(workdir)
        self._template: Path | None = None

    @property
    def template(self) -> Path:
        """The prepared copy, built on first use and then reused."""
        if self._template is None:
            self._template = self._build_template()
        return self._template

    def _build_template(self) -> Path:
        template = self.workdir / "_template"
        if template.exists():
            shutil.rmtree(template)
        template.mkdir(parents=True)
        self._copy_target(template)
        return template

    def checkout(self, run_id: str) -> Path:
        """Give one PoC its own workspace, cloned from the template.

        The template is the authority, so a clone is made even when a directory
        with this id already exists — a resumed or repeated run must not inherit
        what a previous execution left behind.
        """
        workspace = self.workdir / run_id
        if workspace.exists():
            shutil.rmtree(workspace)
        workspace.mkdir(parents=True)
        self._copy_tree(self.template, workspace / "target")
        return workspace

    def discard(self, run_id: str) -> None:
        """Remove a PoC's workspace. Never touches the template."""
        workspace = self.workdir / run_id
        if workspace.exists() and workspace.resolve() != self.template.resolve():
            shutil.rmtree(workspace, ignore_errors=True)

    def close(self) -> None:
        """Drop the template. The scan is over; the clones are the caller's."""
        if self._template is not None and self._template.exists():
            shutil.rmtree(self._template, ignore_errors=True)
        self._template = None

    # -- copying -----------------------------------------------------------
    def _copy_target(self, dest: Path) -> None:
        for pattern in RUNTIME_GLOBS:
            src = self.target / pattern
            if src.exists():
                shutil.copy2(src, dest / pattern)
        for dirname in RUNTIME_DIRS:
            src = self.target / dirname
            if src.exists():
                shutil.copytree(src, dest / dirname, dirs_exist_ok=True)
        # node_modules is large, so a symlink stands in for a copy when the host
        # can make one. A link that cannot be created is not an error: the
        # harness runs `npm install` itself, and copying a host-built tree into a
        # container would be worse than reinstalling, because the binaries would
        # not match the container's platform.
        node_modules = self.target / "node_modules"
        if node_modules.exists():
            try:
                (dest / "node_modules").symlink_to(node_modules, target_is_directory=True)
            except OSError:
                shutil.copytree(node_modules, dest / "node_modules", dirs_exist_ok=True)

    @staticmethod
    def _copy_tree(src: Path, dest: Path) -> None:
        """Clone a prepared tree. Symlinks are recreated, not followed."""
        dest.mkdir(parents=True, exist_ok=True)
        for entry in src.iterdir():
            target = dest / entry.name
            if entry.is_symlink():
                target.symlink_to(entry.readlink(), target_is_directory=entry.is_dir())
            elif entry.is_dir():
                WorkspacePool._copy_tree(entry, target)
            else:
                shutil.copy2(entry, target)
