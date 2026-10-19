"""Graph vocabulary and immutable draft records.

The graph is deliberately boring: typed nodes and edges, every one carrying the
analyzer that produced it and the real source span it came from where one
exists. There is no generated or inferred node without provenance.

The constants here are also the query vocabulary. Adding a kind without teaching
the builder and the query layer about it is a code change, not a configuration
change, so a graph cannot silently grow a claim the rest of the system does not
understand.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

NODE_KINDS = frozenset(
    {
        "Repository",
        "Commit",
        "File",
        "Module",
        "Class",
        "Function",
        "Parameter",
        "Route",
        "AuthPolicy",
        "TrustBoundary",
        "Source",
        "Sink",
        "Sanitizer",
        "DataStore",
        "Config",
        "Secret",
        "Dependency",
        "Container",
        "IaCResource",
        "Test",
        "BuildRecipe",
    }
)

EDGE_KINDS = frozenset(
    {
        "CONTAINS",
        "IMPORTS",
        "CALLS",
        "OVERRIDES",
        "FLOWS_TO",
        "SANITIZES",
        "REACHES",
        "HANDLES",
        "GUARDS",
        "READS",
        "WRITES",
        "DEPENDS_ON",
        "EXPOSES",
        "CONFIGURES",
        "TESTS",
    }
)


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def stable_id(prefix: str, *parts: object) -> str:
    joined = "|".join(str(part) for part in parts)
    return f"{prefix}-{hashlib.sha256(joined.encode('utf-8')).hexdigest()[:32]}"


@dataclass
class NodeDraft:
    kind: str
    key: str
    name: str
    file: str = ""
    line: int = 0
    end_line: int = 0
    language: str = ""
    confidence: float = 1.0
    provenance: dict[str, Any] = field(default_factory=dict)
    properties: dict[str, Any] = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.kind not in NODE_KINDS:
            raise ValueError(f"unknown graph node kind: {self.kind}")
        if not self.key.strip():
            raise ValueError("graph node key must not be empty")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("graph node confidence must be between 0 and 1")

    def content_hash(self) -> str:
        return digest(
            {
                "kind": self.kind,
                "key": self.key,
                "name": self.name,
                "file": self.file,
                "line": self.line,
                "end_line": self.end_line,
                "language": self.language,
                "confidence": self.confidence,
                "provenance": self.provenance,
                "properties": self.properties,
                "evidence_ids": self.evidence_ids,
            }
        )


@dataclass
class EdgeDraft:
    kind: str
    source: tuple[str, str]
    target: tuple[str, str]
    file: str = ""
    line: int = 0
    confidence: float = 1.0
    provenance: dict[str, Any] = field(default_factory=dict)
    properties: dict[str, Any] = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.kind not in EDGE_KINDS:
            raise ValueError(f"unknown graph edge kind: {self.kind}")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("graph edge confidence must be between 0 and 1")

    @property
    def key(self) -> str:
        return (
            f"{self.kind}:{self.source[0]}:{self.source[1]}:"
            f"{self.target[0]}:{self.target[1]}:{self.file}:{self.line}"
        )

    def content_hash(self) -> str:
        return digest(
            {
                "kind": self.kind,
                "source": list(self.source),
                "target": list(self.target),
                "file": self.file,
                "line": self.line,
                "confidence": self.confidence,
                "provenance": self.provenance,
                "properties": self.properties,
                "evidence_ids": self.evidence_ids,
            }
        )
