"""The seven adaptive spawn detectors.

Each detector answers one question about a real source file or a real finding:
"does this reveal attack surface that a source-only scan could not enumerate?"
When it does, it returns a `Surface` describing that surface and the enumerated
trigger type, and the orchestrator spawns a branch for it.

Everything here is AST or text analysis of actual target source. No detector
infers a surface that is not present in the code it was given.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Node

from ..ingestion.parser_ts import ParsedFile, line_of
from ..triggers import TRIGGER_TYPES


@dataclass(frozen=True)
class Surface:
    """A piece of attack surface discovered at analysis time."""

    trigger_type: str
    kind: str
    name: str
    file: str
    line: int
    detail: str
    scope_files: tuple[str, ...] = ()
    scope_routes: tuple[str, ...] = ()

    def branch_name(self) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", f"{self.trigger_type}-{self.name}".lower()).strip("-")
        return slug[:60] or self.trigger_type


@dataclass
class Detection:
    surfaces: list[Surface] = field(default_factory=list)

    def add(self, surface: Surface) -> None:
        self.surfaces.append(surface)


def _text(parsed: ParsedFile, node: Node | None) -> str:
    if node is None:
        return ""
    return parsed.text_of(node).strip()


def _is_dynamic_arg(parsed: ParsedFile, node: Node | None) -> bool:
    """True when a require/import argument is not a plain string literal."""
    if node is None:
        return False
    if node.type == "string":
        return False
    return node.type in (
        "identifier",
        "member_expression",
        "call_expression",
        "template_string",
        "binary_expression",
        "conditional_expression",
    )


def detect_dynamic_import(parsed: ParsedFile) -> list[Surface]:
    """`require(<expr>)`, `import(<expr>)`, `__import__(<expr>)`."""
    out: list[Surface] = []
    for node in parsed.walk():
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        name = _text(parsed, fn)
        if name not in ("require", "import", "__import__"):
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        positional = [c for c in args.children if c.type not in ("(", ")", ",")]
        if not positional or not _is_dynamic_arg(parsed, positional[0]):
            continue
        out.append(
            Surface(
                trigger_type="dynamic_import",
                kind="module",
                name=_text(parsed, positional[0])[:60] or "dynamic",
                file=parsed.path,
                line=line_of(node),
                detail=f"{name}() resolves its module from a value, not a literal",
                scope_files=(parsed.path,),
            )
        )
    return out


def detect_dynamic_route_registration(parsed: ParsedFile) -> list[Surface]:
    """`app.use(<expr>)`, `router.addRoute(...)`, `app.add_api_route(...)`."""
    out: list[Surface] = []
    for node in parsed.walk():
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            continue
        prop = _text(parsed, fn.child_by_field_name("property"))
        obj = _text(parsed, fn.child_by_field_name("object"))
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        positional = [c for c in args.children if c.type not in ("(", ")", ",")]
        if not positional:
            continue

        if prop == "use":
            # `app.use(express.json())` is middleware, not a router. A real router
            # is an identifier or a member expression, never a call result.
            first = positional[0]
            is_router = first.type in ("identifier", "member_expression", "template_string")
            if is_router:
                out.append(
                    Surface(
                        trigger_type="dynamic_route_registration",
                        kind="route",
                        name=_text(parsed, first)[:60] or "dynamic-router",
                        file=parsed.path,
                        line=line_of(node),
                        detail=f"{obj}.use() mounts a router chosen at runtime",
                        scope_files=(parsed.path,),
                    )
                )
            continue

        if prop in ("addRoute", "add_api_route"):
            out.append(
                Surface(
                    trigger_type="dynamic_route_registration",
                    kind="route",
                    name=prop,
                    file=parsed.path,
                    line=line_of(node),
                    detail=f"{obj}.{prop}() registers a route from data",
                    scope_files=(parsed.path,),
                )
            )
            continue

        # `app.use(x)` is handled above; nothing else in this detector matches.
    return out


def detect_plugin_system(parsed: ParsedFile) -> list[Surface]:
    """Directory-scan loaders: `readdirSync(dir).forEach(require)`."""
    out: list[Surface] = []
    source = parsed.source.decode("utf-8", errors="replace")
    pattern = re.compile(r"readdir(?:Sync)?\s*\(")
    for match in pattern.finditer(source):
        line = source.count("\n", 0, match.start()) + 1
        window = source[match.start() : match.start() + 900]
        if "require" not in window and "import(" not in window:
            continue
        out.append(
            Surface(
                trigger_type="plugin_system",
                kind="directory",
                name="plugin-dir",
                file=parsed.path,
                line=line,
                detail="every file in a directory is loaded as code on boot",
                scope_files=(parsed.path,),
            )
        )
    return out


def detect_db_stored_code(parsed: ParsedFile) -> list[Surface]:
    """SQL text that is read out of a table and then executed."""
    out: list[Surface] = []
    source = parsed.source.decode("utf-8", errors="replace")
    # A query that selects a sql-ish column, followed by that value being run.
    reader = re.compile(
        r"SELECT\s+[^\n]*\b(sql|query|statement|body)\b[^\n]*\bFROM\b",
        re.IGNORECASE,
    )
    for match in reader.finditer(source):
        line = source.count("\n", 0, match.start()) + 1
        tail = source[match.end() : match.end() + 800]
        if ".query(" not in tail:
            continue
        out.append(
            Surface(
                trigger_type="db_stored_code",
                kind="stored_query",
                name="db-stored-sql",
                file=parsed.path,
                line=line,
                detail="SQL text is read from a table and executed later",
                scope_files=(parsed.path,),
            )
        )
    return out


# Env vars whose value selects an environment rather than enabling a feature.
_ENVIRONMENT_VARS = frozenset({"NODE_ENV", "APP_ENV", "ENVIRONMENT", "RAILS_ENV", "DJANGO_ENV"})


def _find_env_tests(source: str) -> list[tuple[str, str, int]]:
    """Every `process.env.X === 'value'` in a file, with its line."""
    out = []
    pattern = re.compile(r"process\.env\.([A-Z][A-Z0-9_]{1,})\s*===?\s*['\"]([^'\"]+)['\"]")
    for match in pattern.finditer(source):
        line = source.count("\n", 0, match.start()) + 1
        out.append((match.group(1), match.group(2), line))
    return out


def _guard_gates_a_call(source: str, match_start: int) -> tuple[bool, str]:
    """Is the env test the condition of an `if` whose body calls something?

    Returns (gates_a_call, guarded_call_name). This is the actual signal: the
    difference between an environment read and an environment-gated surface is
    that the read decides whether code runs at all.
    """
    head = source[max(0, match_start - 12) : match_start]
    if not re.search(r"\bif\s*\(\s*$", head):
        return False, ""
    # The env test sits inside the if's parentheses, so skip to the `{` that
    # opens the body and then find its matching `}`.
    brace = source.find("{", match_start)
    if brace == -1:
        return False, ""
    depth = 0
    end = -1
    for index in range(brace, min(len(source), brace + 3000)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end == -1:
        return False, ""
    body = source[brace + 1 : end]
    call = re.search(r"\b(register[A-Za-z0-9_]*|[a-z][A-Za-z0-9_]*)\s*\(", body)
    return True, call.group(1) if call else "call"


def detect_feature_flag(parsed: ParsedFile) -> list[Surface]:
    """A flag whose on-path registers code that is off by default."""
    out: list[Surface] = []
    source = parsed.source.decode("utf-8", errors="replace")
    for match in re.finditer(
        r"process\.env\.([A-Z][A-Z0-9_]{1,})\s*===?\s*['\"]([^'\"]+)['\"]", source
    ):
        name, value = match.group(1), match.group(2)
        if name in _ENVIRONMENT_VARS:
            continue  # that is an environment, not a feature flag
        gates, call = _guard_gates_a_call(source, match.start())
        if not gates:
            continue
        out.append(
            Surface(
                trigger_type="feature_flag",
                kind="flag",
                name=name,
                file=parsed.path,
                line=source.count("\n", 0, match.start()) + 1,
                detail=f"{name}={value} gates {call}(); off by default",
                scope_files=(parsed.path,),
            )
        )
    return out


def detect_env_conditional(parsed: ParsedFile) -> list[Surface]:
    """`if (process.env.NODE_ENV === 'production') registerDebug(app)`."""
    out: list[Surface] = []
    source = parsed.source.decode("utf-8", errors="replace")
    for match in re.finditer(
        r"process\.env\.([A-Z][A-Z0-9_]{1,})\s*===?\s*['\"]([^'\"]+)['\"]", source
    ):
        name, value = match.group(1), match.group(2)
        if name not in _ENVIRONMENT_VARS:
            continue
        gates, call = _guard_gates_a_call(source, match.start())
        if not gates:
            continue
        out.append(
            Surface(
                trigger_type="env_conditional",
                kind="env",
                name=f"{name}={value}",
                file=parsed.path,
                line=source.count("\n", 0, match.start()) + 1,
                detail=f"{name}={value} gates {call}()",
                scope_files=(parsed.path,),
            )
        )
    return out


def detect_webhook_discovery(parsed: ParsedFile, runtime_routes: list[dict] | None = None) -> list[Surface]:
    """A webhook registration endpoint, from source or from a live route list."""
    out: list[Surface] = []
    source = parsed.source.decode("utf-8", errors="replace")
    for match in re.finditer(r"['\"](/[^'\"]*hook[^'\"]*)['\"]", source, re.IGNORECASE):
        line = source.count("\n", 0, match.start()) + 1
        out.append(
            Surface(
                trigger_type="webhook_discovery",
                kind="route",
                name=match.group(1),
                file=parsed.path,
                line=line,
                detail="a webhook route is registered at runtime",
                scope_files=(parsed.path,),
                scope_routes=(match.group(1),),
            )
        )
    for route in runtime_routes or []:
        path = str(route.get("path") or "")
        if "hook" not in path.lower():
            continue
        out.append(
            Surface(
                trigger_type="webhook_discovery",
                kind="route",
                name=path,
                file=str(route.get("file") or parsed.path),
                line=int(route.get("line") or 0),
                detail="webhook route observed on the running application",
                scope_files=(str(route.get("file") or parsed.path),),
                scope_routes=(path,),
            )
        )
    return out


DETECTORS = (
    detect_dynamic_import,
    detect_dynamic_route_registration,
    detect_plugin_system,
    detect_db_stored_code,
    detect_feature_flag,
    detect_env_conditional,
)


def detect_new_surfaces(parsed: ParsedFile, runtime_routes: list[dict] | None = None) -> list[Surface]:
    """Run every detector over one file and return the surfaces it reveals."""
    surfaces: list[Surface] = []
    for detector in DETECTORS:
        if detector is detect_webhook_discovery:
            continue
        surfaces.extend(detector(parsed))
    surfaces.extend(detect_webhook_discovery(parsed, runtime_routes))
    return _dedupe(surfaces)


def detect_in_directory(root: str | Path) -> list[Surface]:
    """Run every detector over a source tree."""
    root_path = Path(root)
    out: list[Surface] = []
    for path in sorted(root_path.rglob("*")):
        if not path.is_file() or path.suffix not in (".ts", ".tsx", ".js", ".jsx", ".mjs"):
            continue
        if any(part in {"node_modules", "dist", "golden_baseline"} for part in path.parts):
            continue
        from ..ingestion.parser_ts import parse_source

        parsed = parse_source(path)
        if parsed is None:
            continue
        out.extend(detect_new_surfaces(parsed))
    return _dedupe(out)


def _dedupe(surfaces: list[Surface]) -> list[Surface]:
    seen: set[tuple[str, str, str, int]] = set()
    out: list[Surface] = []
    for surface in surfaces:
        key = (surface.trigger_type, surface.file, surface.name, surface.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(surface)
    return out
