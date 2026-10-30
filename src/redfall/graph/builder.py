"""Build a provenance-aware graph from one real ingestion result.

The builder consumes only structures that the ingestion pass proved: parsed
files, extracted symbols, resolved imports, taint paths attributable to a file
line, and call edges whose callee exists in the scanned source. It does not add
a node because a filename looked interesting, and it drops an edge whose target
node could not be resolved instead of inventing a placeholder.
"""

from __future__ import annotations

import hashlib
import posixpath
from dataclasses import dataclass, field
from pathlib import Path

from ..ingestion.ingest import IngestedFile, IngestResult
from .schema import EdgeDraft, NodeDraft

COMMIT_KEY = "commit"


@dataclass
class GraphBuild:
    snapshot_id: str
    content_digest: str
    nodes: list[NodeDraft] = field(default_factory=list)
    edges: list[EdgeDraft] = field(default_factory=list)
    route_count: int = 0
    taint_count: int = 0
    languages: list[str] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    duration_ms: int = 0

    def stats(self) -> dict[str, int]:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "routes": self.route_count,
            "taints": self.taint_count,
        }

    def analyzers(self) -> list[str]:
        """Every analyzer that actually contributed a node or edge."""
        found: set[str] = set()
        for draft in [*self.nodes, *self.edges]:
            provenance = draft.provenance or {}
            values = provenance.get("analyzers")
            if isinstance(values, (list, tuple)):
                found.update(str(item) for item in values if item)
            analyzer = str(provenance.get("analyzer") or "").strip()
            if analyzer:
                found.add(analyzer)
        return sorted(found)


def _language(path: str) -> str:
    from ..ingestion.languages import language_name_for

    return language_name_for(path)


def _join_url(prefix: str, path: str) -> str:
    if not prefix:
        return path or "/"
    if not path or path == "/":
        return prefix
    return f"{prefix.rstrip('/')}/{path.lstrip('/')}"


def _file_digest(files: list[IngestedFile]) -> str:
    outer = hashlib.sha256()
    for item in sorted(files, key=lambda f: f.path):
        file_hash = hashlib.sha256(item.content.encode("utf-8", errors="replace")).hexdigest()
        outer.update(f"{item.path}\0{file_hash}\n".encode("utf-8"))
    return outer.hexdigest()


def _function_key(path: str, name: str, line: int = 0) -> str:
    return f"{path}:{name}:{line}"


def _unique_python_candidate(base: str, files: set[str]) -> str | None:
    exact = [f"{base}.py", f"{base}/__init__.py"]
    for candidate in exact:
        if candidate in files:
            return candidate
    # Absolute imports are package-relative at runtime but repository paths
    # often start at ``src/``. Accept a suffix only when exactly one scanned
    # file matches; ambiguity is reported as unresolved, never guessed.
    suffix_files = [
        path
        for path in files
        if path.endswith(f"/{base}.py") or path.endswith(f"/{base}/__init__.py")
    ]
    unique = sorted(set(suffix_files))
    return unique[0] if len(unique) == 1 else None


def _resolve_import(
    current_rel: str,
    source: str,
    origin: str,
    files: set[str],
) -> str | None:
    """Resolve only imports whose target is one of the scanned files.

    A bare npm or pip package has no repository file, so it gets a Module node
    rather than a guessed File edge. Relative TypeScript and Python imports are
    resolved with the language's own path arithmetic.
    """
    if not source:
        return None
    if current_rel.endswith(".py"):
        level = len(source) - len(source.lstrip("."))
        rest = source.lstrip(".")
        if level:
            package = current_rel[:-3].split("/")[:-1]
            drop = level - 1
            if drop > len(package):
                return None
            parts = package[: len(package) - drop]
            if rest:
                parts.extend(rest.split("."))
            elif origin and origin != "*":
                # ``from . import util`` names the module in ``origin``.
                parts.append(origin)
        elif rest:
            parts = rest.split(".")
        else:
            return None
        base = "/".join(part for part in parts if part)
        if not base:
            return None
        candidates: list[str] = []
        if level and origin and origin != "*" and rest:
            # ``from .core import reports`` can bind the submodule file even
            # though the package __init__ also exists.
            candidates.append(f"{base}/{origin}.py")
        candidates.extend([f"{base}.py", f"{base}/__init__.py"])
        for candidate in candidates:
            if candidate in files:
                return candidate
        return _unique_python_candidate(base, files)

    if not source.startswith("."):
        return None
    base = posixpath.normpath(posixpath.join(posixpath.dirname(current_rel), source))
    for suffix in ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
        candidate = base + suffix
        if candidate in files:
            return candidate
    for suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs"):
        candidate = f"{base}/index{suffix}"
        if candidate in files:
            return candidate
    return None


class GraphBuilder:
    def __init__(self, snapshot_id: str, result: IngestResult, *, commit: str = "") -> None:
        self.snapshot_id = snapshot_id
        self.result = result
        self.commit = commit or result.git.commit
        self._nodes: dict[tuple[str, str], NodeDraft] = {}
        self._edges: dict[str, EdgeDraft] = {}
        self._file_paths = {f.path for f in result.files}
        self._function_by_file_name: dict[tuple[str, str], str] = {}
        self._source_span = f"{self.commit or result.git.label}"

    # ------------------------------------------------------------- primitives
    def _add_node(
        self,
        kind: str,
        key: str,
        name: str,
        *,
        file: str = "",
        line: int = 0,
        end_line: int = 0,
        language: str = "",
        confidence: float = 1.0,
        provenance: dict | None = None,
        properties: dict | None = None,
        evidence_ids: list[str] | None = None,
    ) -> NodeDraft:
        incoming = dict(provenance or {})
        analyzer = str(incoming.get("analyzer") or "tree-sitter")
        new_provenance = {
            "analyzer": analyzer,
            "analyzers": [analyzer],
            "builder": "redfall.graph.builder",
            "revision": self._source_span,
            **incoming,
        }
        new_provenance["analyzers"] = [analyzer]
        existing = self._nodes.get((kind, key))
        if existing is not None:
            # One node can be observed by more than one analyzer (for example a
            # call sink also appears in a taint path). Merge the observations
            # instead of silently discarding the second provenance.
            for prop_key, prop_value in (properties or {}).items():
                existing.properties.setdefault(prop_key, prop_value)
            for prov_key, prov_value in new_provenance.items():
                if prov_key in {"analyzer", "analyzers"}:
                    continue
                existing.provenance.setdefault(prov_key, prov_value)
            analyzers = list(existing.provenance.get("analyzers") or [])
            if analyzer not in analyzers:
                analyzers.append(analyzer)
            existing.provenance["analyzers"] = analyzers
            for evidence_id in evidence_ids or []:
                if evidence_id not in existing.evidence_ids:
                    existing.evidence_ids.append(evidence_id)
            return existing
        draft = NodeDraft(
            kind=kind,
            key=key,
            name=name,
            file=file,
            line=line,
            end_line=end_line,
            language=language,
            confidence=confidence,
            provenance=new_provenance,
            properties=properties or {},
            evidence_ids=evidence_ids or [],
        )
        self._nodes[(kind, key)] = draft
        return draft

    def _add_edge(
        self,
        kind: str,
        source: tuple[str, str],
        target: tuple[str, str],
        *,
        file: str = "",
        line: int = 0,
        confidence: float = 1.0,
        provenance: dict | None = None,
        properties: dict | None = None,
        evidence_ids: list[str] | None = None,
    ) -> bool:
        if source not in self._nodes or target not in self._nodes:
            return False
        draft = EdgeDraft(
            kind=kind,
            source=source,
            target=target,
            file=file,
            line=line,
            confidence=confidence,
            provenance={
                "analyzer": "tree-sitter",
                "builder": "redfall.graph.builder",
                "revision": self._source_span,
                **(provenance or {}),
            },
            properties=properties or {},
            evidence_ids=evidence_ids or [],
        )
        self._edges.setdefault(draft.key, draft)
        return True

    # ----------------------------------------------------------------- build
    def build(self) -> GraphBuild:
        root = self.result.target
        repo_key = f"repo:{root.as_posix()}"
        repository = self._add_node(
            "Repository",
            repo_key,
            root.name or root.as_posix(),
            file="",
            provenance={"analyzer": "git-inspect", "path": str(root)},
            properties={
                "path": str(root),
                "git": self.result.git.is_repo,
                "branch": self.result.git.branch,
                "dirty": self.result.git.dirty,
                "changed_files": list(self.result.git.changed_files),
                "language_registry": sorted(
                    {_language(f.path) for f in self.result.files}
                ),
            },
        )

        commit_key = f"commit:{self.commit or 'no-git'}"
        commit_node = self._add_node(
            "Commit",
            commit_key,
            self.commit[:12] if self.commit else "no-git",
            provenance={"analyzer": "git-inspect", "path": str(root)},
            properties={
                "commit": self.commit,
                "branch": self.result.git.branch,
                "label": self.result.git.label,
                "dirty": self.result.git.dirty,
            },
        )
        self._add_edge(
            "CONTAINS",
            (repository.kind, repository.key),
            (commit_node.kind, commit_node.key),
            provenance={"analyzer": "git-inspect", "path": str(root)},
        )

        # Create every file node before content edges. Ingestion order is not
        # dependency order, so an import from app.py to a later file must still
        # resolve instead of becoming a dropped edge.
        for f in self.result.files:
            language = _language(f.path)
            file_key = f"file:{f.path}"
            file_node = self._add_node(
                "File",
                file_key,
                f.path,
                file=f.path,
                line=1,
                end_line=max(1, f.line_count),
                language=language,
                provenance={"path": f.path, "bytes": f.size_bytes},
                properties={
                    "path": f.path,
                    "size_bytes": f.size_bytes,
                    "line_count": f.line_count,
                    "content_sha256": hashlib.sha256(
                        f.content.encode("utf-8", errors="replace")
                    ).hexdigest(),
                },
            )
            self._add_edge(
                "CONTAINS",
                (repository.kind, repository.key),
                (file_node.kind, file_node.key),
                file=f.path,
                provenance={"analyzer": "git-inspect", "path": f.path},
            )
            self._add_edge(
                "CONTAINS",
                (commit_node.kind, commit_node.key),
                (file_node.kind, file_node.key),
                file=f.path,
                provenance={"analyzer": "git-inspect", "path": f.path},
            )

        # Files, functions, routes, imports and concrete sink calls.
        for f in self.result.files:
            language = _language(f.path)
            file_node = self._nodes[("File", f"file:{f.path}")]

            for fn in f.symbols.functions:
                key = _function_key(f.path, fn.name, fn.line)
                self._function_by_file_name.setdefault((f.path, fn.name), key)
                function = self._add_node(
                    "Function",
                    key,
                    fn.name,
                    file=f.path,
                    line=fn.line,
                    end_line=fn.end_line,
                    language=language,
                    provenance={"symbol": "function", "path": f.path},
                    properties={"exported": fn.is_exported, "path": f.path},
                )
                self._add_edge(
                    "CONTAINS",
                    (file_node.kind, file_node.key),
                    (function.kind, function.key),
                    file=f.path,
                    line=fn.line,
                )

            for route in f.symbols.routes:
                if route.method == "USE":
                    continue
                full_path = _join_url(self.result.mount_prefixes.get(f.path, ""), route.path)
                route_key = f"route:{route.method}:{full_path}:{f.path}:{route.line}"
                route_node = self._add_node(
                    "Route",
                    route_key,
                    f"{route.method} {full_path}",
                    file=f.path,
                    line=route.line,
                    end_line=route.end_line,
                    language=language,
                    provenance={"symbol": "route", "path": f.path},
                    properties={
                        "method": route.method,
                        "path": full_path,
                        "sub_path": route.path,
                        "handler": route.handler,
                        "middleware": list(route.middleware),
                        "receiver": route.receiver,
                    },
                )
                self._add_edge(
                    "CONTAINS",
                    (file_node.kind, file_node.key),
                    (route_node.kind, route_node.key),
                    file=f.path,
                    line=route.line,
                )
                handler_key = self._function_by_file_name.get((f.path, route.handler))
                if handler_key:
                    self._add_edge(
                        "HANDLES",
                        (route_node.kind, route_node.key),
                        ("Function", handler_key),
                        file=f.path,
                        line=route.line,
                        properties={"handler": route.handler},
                    )

            # Imports. The module node is always recorded; a File target is
            # added only when the specifier resolves to a scanned file.
            for imp in f.symbols.imports:
                target_file = _resolve_import(f.path, imp.source, imp.origin, self._file_paths)
                if target_file is not None:
                    self._add_edge(
                        "IMPORTS",
                        (file_node.kind, file_node.key),
                        ("File", f"file:{target_file}"),
                        file=f.path,
                        line=imp.line,
                        properties={"source": imp.source, "name": imp.name, "origin": imp.origin},
                    )
                    continue
                module_key = f"module:{language}:{imp.source}"
                module = self._add_node(
                    "Module",
                    module_key,
                    imp.source,
                    language=language,
                    provenance={"symbol": "import", "path": f.path},
                    properties={
                        "specifier": imp.source,
                        "external": not imp.source.startswith("."),
                        "resolved": False,
                    },
                )
                self._add_edge(
                    "IMPORTS",
                    (file_node.kind, file_node.key),
                    (module.kind, module.key),
                    file=f.path,
                    line=imp.line,
                    properties={"name": imp.name, "origin": imp.origin},
                )

            # Concrete call sites are Sink nodes even before a taint path
            # reaches them. That is a fact about the code, not a finding.
            for call in f.symbols.calls:
                sink_key = f"sink:{f.path}:{call.line}:{call.kind}:{call.callee}"
                sink = self._add_node(
                    "Sink",
                    sink_key,
                    call.callee,
                    file=f.path,
                    line=call.line,
                    end_line=call.line,
                    language=language,
                    provenance={"symbol": "call", "path": f.path},
                    properties={
                        "call_kind": call.kind,
                        "callee": call.callee,
                        "argument_excerpt": call.arg_text[:400],
                        "enclosing_function": call.enclosing_function,
                    },
                )
                self._add_edge(
                    "CONTAINS",
                    (file_node.kind, file_node.key),
                    (sink.kind, sink.key),
                    file=f.path,
                    line=call.line,
                )
                if call.enclosing_function:
                    caller_key = self._function_by_file_name.get((f.path, call.enclosing_function))
                    if caller_key:
                        self._add_edge(
                            "CALLS",
                            ("Function", caller_key),
                            (sink.kind, sink.key),
                            file=f.path,
                            line=call.line,
                        )

        # Dependencies are packages, not source files.
        for dependency in self.result.dependencies:
            key = f"dependency:{dependency.name}"
            dep = self._add_node(
                "Dependency",
                key,
                dependency.name,
                provenance={"analyzer": "package-manifest", "manifest": "package.json"},
                properties={
                    "declared": dependency.declared,
                    "resolved": dependency.resolved,
                    "dev": dependency.is_dev,
                },
            )
            self._add_edge(
                "DEPENDS_ON",
                (repository.kind, repository.key),
                (dep.kind, dep.key),
                file="package.json",
                provenance={"analyzer": "package-manifest", "manifest": "package.json"},
            )

        # Resolved cross-function calls.
        for edge in self.result.call_edges:
            caller = self._function_by_file_name.get((edge.caller_file, edge.caller_function))
            callee = self._function_by_file_name.get((edge.callee_file, edge.callee_function))
            if not caller or not callee:
                continue
            self._add_edge(
                "CALLS",
                ("Function", caller),
                ("Function", callee),
                file=edge.caller_file,
                line=edge.call_line,
                properties={
                    "callee_dotted": edge.callee_dotted,
                    "tainted_params": list(edge.tainted_params),
                },
            )

        # Proven taint flows and the route surface that can reach the sink.
        for rel, taint in self.result.taint_paths:
            source_key = f"source:{rel}:{taint.source}"
            source = self._add_node(
                "Source",
                source_key,
                taint.source,
                file=rel,
                line=0,
                language=_language(rel),
                provenance={"symbol": "taint-source", "path": rel},
                properties={"label": taint.source, "line_known": False},
            )
            sink_key = f"sink:{rel}:{taint.line}:{taint.sink_kind}:{taint.sink}"
            sink = self._add_node(
                "Sink",
                sink_key,
                taint.sink,
                file=rel,
                line=taint.line,
                end_line=taint.line,
                language=_language(rel),
                provenance={"symbol": "taint-sink", "path": rel},
                properties={
                    "call_kind": taint.sink_kind,
                    "callee": taint.sink,
                    "symbol": taint.symbol,
                    "via": list(taint.via),
                    "snippet": taint.snippet,
                },
            )
            self._add_edge(
                "FLOWS_TO",
                (source.kind, source.key),
                (sink.kind, sink.key),
                file=rel,
                line=taint.line,
                confidence=0.9,
                provenance={"analyzer": "redfall.taint", "path": rel},
                properties={
                    "source": taint.source,
                    "sink": taint.sink,
                    "sink_kind": taint.sink_kind,
                    "symbol": taint.symbol,
                    "via": list(taint.via),
                },
            )
            if taint.symbol:
                owner_key = self._function_by_file_name.get((rel, taint.symbol))
                if owner_key:
                    self._add_edge(
                        "FLOWS_TO",
                        ("Function", owner_key),
                        (sink.kind, sink.key),
                        file=rel,
                        line=taint.line,
                        confidence=0.9,
                        provenance={"analyzer": "redfall.taint", "path": rel},
                        properties={"via": list(taint.via)},
                    )
            for route in self.result.routes_for_line(rel, taint.line):
                route_key = (
                    f"route:{route['method']}:{route['path']}:"
                    f"{route['file']}:{route['line']}"
                )
                if ("Route", route_key) not in self._nodes:
                    continue
                self._add_edge(
                    "REACHES",
                    ("Route", route_key),
                    (sink.kind, sink.key),
                    file=route["file"],
                    line=route["line"],
                    confidence=0.9,
                    provenance={"analyzer": "redfall.route-attribution", "path": rel},
                    properties={
                        "route": f"{route['method']} {route['path']}",
                        "handler": route["handler"],
                        "sink_line": taint.line,
                    },
                )

        languages = sorted({_language(f.path) for f in self.result.files})
        return GraphBuild(
            snapshot_id=self.snapshot_id,
            content_digest=_file_digest(self.result.files),
            nodes=sorted(self._nodes.values(), key=lambda item: (item.kind, item.key)),
            edges=sorted(self._edges.values(), key=lambda item: item.key),
            route_count=sum(1 for item in self._nodes.values() if item.kind == "Route"),
            taint_count=len(self.result.taint_paths),
            languages=languages,
            parse_errors=list(self.result.parse_errors),
            duration_ms=self.result.duration_ms,
        )
