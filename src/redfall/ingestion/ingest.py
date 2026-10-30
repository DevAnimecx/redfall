"""Ingestion orchestrator: walk the target, parse it, persist the graph."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.orm import Session

from .cache import CachedParse, ParseCache, content_key
from .dependencies import Dependency, read_dependencies, security_relevant
from .git_repo import GitInfo, inspect as inspect_git
from .inter import CallEdge, InterFile, analyse_inter
from .inter_ts import analyse_inter_ts
from .languages import support_for
from .symbols import FileSymbols
from .taint import Taint

SKIP_DIRS = {
    "node_modules",
    "dist",
    "build",
    ".git",
    "coverage",
    ".next",
    "out",
    "golden_baseline",
    "patches",
    "venv",
    ".venv",
    "env",
    ".tox",
    "site-packages",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".hypothesis",
    ".nox",
}
SKIP_DIR_PARTS = {"tests", "__tests__", "test", "spec", "scripts", "fixtures"}
# A target's own test scaffolding is evidence for the fix stage, not attack surface.
SKIP_FILES = {"conftest.py"}
MAX_FILE_BYTES = 400_000


@dataclass
class IngestedFile:
    id: str
    path: str
    line_count: int
    size_bytes: int
    symbols: FileSymbols
    taints: list[Taint]
    content: str


@dataclass
class IngestResult:
    scan_id: str
    target: Path
    git: GitInfo
    files: list[IngestedFile] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    package_json: dict = field(default_factory=dict)
    duration_ms: int = 0
    parse_errors: list[str] = field(default_factory=list)
    # repo-relative router file -> URL prefix it is mounted at
    mount_prefixes: dict[str, str] = field(default_factory=dict)
    # every cross-function call the Python pass could resolve without guessing
    call_edges: list[CallEdge] = field(default_factory=list)

    @property
    def routes(self) -> list[tuple[str, object]]:
        out: list[tuple[str, object]] = []
        for f in self.files:
            for r in f.symbols.routes:
                out.append((f.path, r))
        return out

    @property
    def taint_paths(self) -> list[tuple[str, Taint]]:
        return [(f.path, t) for f in self.files for t in f.taints]

    def http_routes(self) -> list[dict[str, object]]:
        """Route inventory for the planner, with mounts resolved to full URLs."""
        out: list[dict[str, object]] = []
        for f in self.files:
            prefix = self.mount_prefixes.get(f.path, "")
            for r in f.symbols.routes:
                if r.method == "USE":
                    continue
                full = _join_url(prefix, r.path)
                out.append(
                    {
                        "method": r.method,
                        "path": full,
                        "sub_path": r.path,
                        "file": f.path,
                        "line": r.line,
                        "handler": r.handler,
                        "middleware": r.middleware,
                    }
                )
        return out

    def _reachable_from(self, start: tuple[str, str]) -> set[tuple[str, str]]:
        """Every (file, function) callable from `start` through resolved edges."""
        seen = {start}
        queue = [start]
        while queue:
            cur_file, cur_fn = queue.pop()
            for edge in self.call_edges:
                if edge.caller_file != cur_file or edge.caller_function != cur_fn:
                    continue
                target = (edge.callee_file, edge.callee_function)
                if target not in seen:
                    seen.add(target)
                    queue.append(target)
        return seen

    def routes_for_line(self, rel_path: str, line: int) -> list[dict[str, object]]:
        """Routes that can reach `line` — used to attach a taint path to the
        HTTP surface that can actually exercise it.

        A route's reach extends past its own call expression: a named handler's
        body counts as part of the route, and so does everything reachable from
        that handler through the resolved call graph. That is what links an
        interprocedural taint in `core/reports.py` back to the route in
        `routes/reports.py` that feeds it.
        """
        fn_here = None
        for f in self.files:
            if f.path == rel_path:
                fn_here = f.symbols.containing(line)
                break
        out: list[dict[str, object]] = []
        for f in self.files:
            prefix = self.mount_prefixes.get(f.path, "")
            fn_span = {fn.name: (fn.line, fn.end_line) for fn in f.symbols.functions}
            reach: dict[str, set[tuple[str, str]]] = {}
            for r in f.symbols.routes:
                if r.method == "USE":
                    continue
                spans = [(r.line, r.end_line)]
                named = fn_span.get(r.handler)
                if named is not None:
                    spans.append(named)
                direct = f.path == rel_path and any(start <= line <= end for start, end in spans)
                via_call = False
                if not direct and fn_here and r.handler:
                    if r.handler not in reach:
                        reach[r.handler] = self._reachable_from((f.path, r.handler))
                    via_call = (rel_path, fn_here) in reach[r.handler]
                if direct or via_call:
                    out.append(
                        {
                            "method": r.method,
                            "path": _join_url(prefix, r.path),
                            "sub_path": r.path,
                            "file": f.path,
                            "line": r.line,
                            "handler": r.handler,
                            "middleware": r.middleware,
                        }
                    )
        return out

    def security_relevant_deps(self) -> list[Dependency]:
        return security_relevant(self.dependencies)


def _join_url(prefix: str, path: str) -> str:
    """Join a mount prefix and a route path into one URL, without doubling slashes."""
    if not prefix:
        return path or "/"
    if not path or path == "/":
        return prefix
    return f"{prefix.rstrip('/')}/{path.lstrip('/')}"


def _file_id(scan_id: str, rel_path: str) -> str:
    return hashlib.sha256(f"{scan_id}:{rel_path}".encode()).hexdigest()[:16]


def _repo_relative(root: Path, path: Path) -> str:
    """A repo-relative path in the canonical form the rest of Redfall uses.

    Repository-relative paths are always POSIX (`src/routes/auth.ts`): manifests,
    prompts, dedupe keys and the wire format all speak that dialect, and a
    Windows host produces backslashes from `str()` without this.
    """
    return path.relative_to(root).as_posix()


def _resolve_module(root: Path, from_rel: str, spec: str) -> str | None:
    """Resolve a relative module specifier to a repo-relative source path."""
    if not spec.startswith("."):
        return None
    base_dir = (root / from_rel).parent
    target = (base_dir / spec).resolve()
    candidates = [target]
    if target.suffix == "":
        for ext in (".ts", ".tsx", ".js", ".jsx"):
            candidates.append(target.with_name(target.name + ext))
        for ext in (".ts", ".tsx", ".js", ".jsx"):
            candidates.append(target / f"index{ext}")
    for cand in candidates:
        try:
            rel = cand.resolve().relative_to(root)
        except ValueError:
            continue
        if cand.exists() and cand.is_file():
            return rel.as_posix()
    return None


def _iter_sources(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        parts = set(rel.parts[:-1])
        if parts & SKIP_DIRS:
            continue
        if path.name in SKIP_FILES:
            continue
        if support_for(path) is None:
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        # The target's own tests are evidence for the fix stage, not attack surface.
        if parts & SKIP_DIR_PARTS:
            continue
        out.append(path)
    return out


def ingest(
    scan_id: str,
    target: str | Path,
    session: Session | None = None,
    *,
    cache: ParseCache | None = None,
) -> IngestResult:
    """Parse every source file in `target` and (optionally) persist the graph.

    Pass a `cache` to skip symbol extraction and taint on files whose bytes have
    not changed since a previous ingest. Omit it and every file is parsed from
    scratch, which is what a one-off index wants and what keeps the cache
    strictly optional rather than something a scan depends on.
    """
    started = time.time()
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"target does not exist: {root}")

    result = IngestResult(scan_id=scan_id, target=root, git=inspect_git(root))
    result.dependencies, result.package_json = read_dependencies(root)

    # TypeScript and Python files kept for the interprocedural passes: they
    # need the parsed tree and the symbols of every file at once, not one file
    # in isolation.
    inter_files: list[InterFile] = []

    for path in _iter_sources(root):
        rel = _repo_relative(root, path)
        support = support_for(path)
        if support is None:
            continue
        source = path.read_bytes()
        key = content_key(rel, source, language=support.name)
        cached = cache.get(key) if cache is not None else None

        parsed = support.parse(path, source)
        if parsed is None:
            continue

        if cached is not None:
            # The tree itself cannot be cached — it is a tree-sitter node graph,
            # not data — so it is reparsed above. What the cache saves is the
            # symbol extraction and the taint pass over it, which is where the
            # time goes on a large file.
            symbols, taints = cached.symbols, cached.taints
        else:
            try:
                symbols = support.symbols(parsed)
            except Exception as err:  # noqa: BLE001 - one bad file must not kill the scan
                result.parse_errors.append(f"{rel}: symbols: {type(err).__name__}: {err}")
                continue
            try:
                taints = support.taint(parsed, symbols)
            except Exception as err:  # noqa: BLE001
                result.parse_errors.append(f"{rel}: taint: {type(err).__name__}: {err}")
                taints = []

        text = source.decode("utf-8", errors="replace")
        line_count = text.count("\n") + 1
        if cached is None and cache is not None:
            cache.put(
                key,
                CachedParse(
                    language=support.name,
                    symbols=symbols,
                    taints=taints,
                    line_count=line_count,
                    size_bytes=len(source),
                ),
            )
        result.files.append(
            IngestedFile(
                id=_file_id(scan_id, rel),
                path=rel,
                line_count=line_count,
                size_bytes=len(source),
                symbols=symbols,
                taints=taints,
                content=text,
            )
        )
        if support.name in ("python", "typescript"):
            inter_files.append(InterFile(rel=rel, parsed=parsed, symbols=symbols))

    if inter_files:
        try:
            py_extra, py_edges = analyse_inter(inter_files)
            ts_extra, ts_edges = analyse_inter_ts(inter_files)
        except Exception as err:  # noqa: BLE001 - the intraprocedural results stand
            result.parse_errors.append(f"interprocedural pass: {type(err).__name__}: {err}")
        else:
            result.call_edges = py_edges + ts_edges
            merged: dict[str, list[Taint]] = {}
            for source in (py_extra, ts_extra):
                for rel, taints in source.items():
                    merged.setdefault(rel, []).extend(taints)
            by_path = {f.path: f for f in result.files}
            for rel, taints in merged.items():
                target = by_path.get(rel)
                if target is None:
                    continue
                existing = {t.dedupe_key for t in target.taints}
                for taint in taints:
                    if taint.dedupe_key in existing:
                        continue
                    existing.add(taint.dedupe_key)
                    target.taints.append(taint)
                target.taints.sort(key=lambda t: t.line)

    result.duration_ms = int((time.time() - started) * 1000)
    result.mount_prefixes = _resolve_mounts(root, result.files)

    if session is not None:
        from .persist import persist

        persist(result, session)
    return result


def _resolve_mounts(root: Path, files: list[IngestedFile]) -> dict[str, str]:
    """Follow `app.use('/api/x', xRoutes)` back through the imports to the file.

    Only relative imports that resolve to a parsed source file are used, so the
    prefix is never guessed — an unresolved mount simply contributes nothing.
    """
    by_path = {f.path: f for f in files}
    prefixes: dict[str, str] = {}
    for f in files:
        import_map = {imp.name: imp.source for imp in f.symbols.imports}
        for mount in f.symbols.mounts:
            spec = import_map.get(mount.local_name)
            if spec is None:
                continue
            resolved = _resolve_module(root, f.path, spec)
            if resolved is None or resolved not in by_path:
                continue
            # The first mount wins; Express serves the earliest registration.
            prefixes.setdefault(resolved, mount.prefix)
    return prefixes


