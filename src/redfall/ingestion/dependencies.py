"""Dependency ingestion from package.json.

Only the lockfile-less manifest is read; resolved versions are taken
from `node_modules/<pkg>/package.json` when the target has been installed, which
is the only honest source for what actually ran.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

INTERESTING_RUNTIME = {
    "express",
    "jsonwebtoken",
    "pg",
    "multer",
    "busboy",
    "js-yaml",
    "yaml",
    "body-parser",
    "cookie-parser",
    "cors",
    "helmet",
    "axios",
    "node-fetch",
    "bcrypt",
    "bcryptjs",
    "xml2js",
    "ejs",
    "pug",
    "handlebars",
    "redis",
    "stripe",
    "archiver",
    "adm-zip",
    "express-rate-limit",
}


@dataclass(frozen=True)
class Dependency:
    name: str
    declared: str
    resolved: str
    is_dev: bool


def _resolved_version(target: Path, name: str) -> str:
    manifest = target / "node_modules" / name / "package.json"
    if not manifest.exists():
        return ""
    try:
        data = json.loads(manifest.read_text())
    except (json.JSONDecodeError, OSError):
        return ""
    return str(data.get("version", ""))


def read_dependencies(target: str | Path) -> tuple[list[Dependency], dict[str, object]]:
    """Return (dependencies, raw package.json as a dict)."""
    root = Path(target)
    pkg_path = root / "package.json"
    if not pkg_path.exists():
        return [], {}
    try:
        data = json.loads(pkg_path.read_text())
    except (json.JSONDecodeError, OSError):
        return [], {}

    deps: list[Dependency] = []
    for name, spec in (data.get("dependencies") or {}).items():
        deps.append(
            Dependency(name=name, declared=str(spec), resolved=_resolved_version(root, name), is_dev=False)
        )
    for name, spec in (data.get("devDependencies") or {}).items():
        deps.append(
            Dependency(name=name, declared=str(spec), resolved=_resolved_version(root, name), is_dev=True)
        )
    return deps, data


def security_relevant(deps: list[Dependency]) -> list[Dependency]:
    """Runtime deps whose behaviour decides whole vulnerability categories."""
    return [d for d in deps if d.name in INTERESTING_RUNTIME and not d.is_dev]
