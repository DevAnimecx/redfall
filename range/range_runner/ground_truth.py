"""Load the vulnbank manifest as ground truth. Never edited by the scorer."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ManifestVuln:
    id: str
    category: str
    cwe: str
    severity: str
    route: str
    file: str
    line: int
    lines: list[int]
    symbol: str
    description: str
    poc_neutralizable: bool = True
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def anchor_line(self) -> int:
        """The line the matcher compares against."""
        return self.lines[0] if self.lines else self.line


def load_manifest_document(path: str | Path) -> dict[str, Any]:
    """Read manifest.yaml as a document.

    A target declares either `vulns` or `chains` or both, and the scorer needs to
    know which before it can pick a ground truth.
    """
    data = yaml.safe_load(Path(path).read_text())
    if isinstance(data, list):
        return {"vulns": data}
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a manifest document")
    return data


def load_manifest(path: str | Path) -> list[ManifestVuln]:
    """Read manifest.yaml and return one record per seeded vulnerability."""
    data = load_manifest_document(path)
    raw = data.get("vulns") or data.get("findings")
    if raw is None:
        raise ValueError(f"{path} declares neither `vulns` nor `findings`")
    if not isinstance(raw, list):
        raise ValueError(f"{path} does not contain a list of vulnerabilities")

    vulns: list[ManifestVuln] = []
    for entry in raw:
        loc = entry.get("location") or {}
        lines = loc.get("lines") or ([loc["line"]] if "line" in loc else [])
        poc = entry.get("poc") or {}
        vulns.append(
            ManifestVuln(
                id=str(entry["id"]),
                category=str(entry["category"]),
                cwe=str(entry.get("cwe") or ""),
                severity=str(entry.get("severity") or ""),
                route=str(entry.get("route") or ""),
                file=str(loc.get("file") or ""),
                line=int(lines[0]) if lines else 0,
                lines=[int(x) for x in lines],
                symbol=str(loc.get("symbol") or ""),
                description=str(entry.get("description") or ""),
                poc_neutralizable=bool(poc.get("poc_neutralizable", True)),
                extra={k: v for k, v in entry.items() if k not in ("location", "poc")},
            )
        )
    return vulns


def severity_breakdown(vulns: list[ManifestVuln]) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in vulns:
        out[v.severity] = out.get(v.severity, 0) + 1
    return out
