"""Symbol extraction from a parsed Python file.

Mirrors the TypeScript extractor: routes, functions, sink calls, imports and
same-file router mounts, all derived from the syntax tree.

Route sources understood here:
  * Flask: `@app.route` / `@bp.get|post|put|delete|patch("/x")`, with a
    same-file `Blueprint(..., url_prefix="/p")` applied to the blueprint's
    routes. A blueprint registration that lives in another file is left
    unprefixed rather than guessed.
  * FastAPI: verb decorators on an `app`/`APIRouter` variable, with a
    same-file `APIRouter(prefix="/p")` applied. `include_router` calls are
    recorded as mounts; cross-file prefix resolution is not claimed.
  * Django: `path(...)`/`re_path(...)`/`url(...)` entries inside a
    `urlpatterns` assignment, or names imported from `django.urls`.

Sink call inventory (arguments are what the taint pass reads):
  * db:   `<receiver>.execute|executemany|executescript` for cursor-like names
  * exec: `subprocess.*`, `os.system|popen`, bare `eval`/`exec`/`compile`,
    `pickle.load/loads`, `yaml.load`, `render_template_string`
  * fs:   bare `open`, `os`/`shutil` file operations, `os.path.*`, pathlib I/O
  * http: `requests`/`httpx`/`aiohttp`/`urllib` calls
"""

from __future__ import annotations

from tree_sitter import Node

from .symbols import (
    CallSymbol,
    FileSymbols,
    FunctionSymbol,
    ImportSymbol,
    MountSymbol,
    RouteSymbol,
)
from .tree import ParsedFile, end_line_of, line_of

HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "options"}
ROUTE_DECORATORS = HTTP_VERBS | {"route"}
DEFAULT_RECEIVERS = {"app", "api", "router", "bp", "server"}
APP_CONSTRUCTORS = {"Flask", "FastAPI", "Blueprint", "APIRouter"}
DJANGO_ROUTE_CALLS = {"path", "re_path", "url"}

DB_RECEIVERS = {"cursor", "cur", "conn", "connection", "session", "db", "engine", "pool", "client"}
EXEC_BARE = {"eval", "exec", "compile", "render_template_string", "render_template"}
FS_BARE = {"open"}
EXEC_MODULES = {"os": {"system", "popen"}, "subprocess": {"run", "call", "check_call", "check_output", "Popen"}, "commands": {"getoutput"}}
FS_FUNCS = {
    "remove",
    "unlink",
    "rename",
    "replace",
    "mkdir",
    "makedirs",
    "rmdir",
    "removedirs",
    "copy",
    "copy2",
    "copytree",
    "rmtree",
    "move",
    "walk",
    "listdir",
}
PATHLIB_IO = {"read_text", "write_text", "read_bytes", "write_bytes", "iterdir", "glob", "rglob"}
HTTP_CALLS = {"get", "post", "put", "delete", "patch", "request", "urlopen"}
HTTP_MODULES = {"requests", "httpx", "aiohttp", "urllib"}


def _text(parsed: ParsedFile, node: Node | None) -> str:
    if node is None:
        return ""
    return parsed.text_of(node).strip()


def _string_value(parsed: ParsedFile, node: Node | None) -> str:
    """The literal value of a string node, without quotes or prefixes."""
    if node is None:
        return ""
    if node.type == "concatenated_string":
        return "".join(_string_value(parsed, c) for c in node.children if c.type == "string")
    if node.type != "string":
        return _text(parsed, node)
    start = next((c for c in node.children if c.type == "string_start"), None)
    end = next((c for c in reversed(node.children) if c.type == "string_end"), None)
    if start is None or end is None:
        return _text(parsed, node)
    raw = parsed.source[start.end_byte : end.start_byte]
    return raw.decode("utf-8", errors="replace")


def _string_list(parsed: ParsedFile, node: Node | None) -> list[str]:
    if node is None or node.type not in ("list", "tuple", "set"):
        return []
    return [_string_value(parsed, c) for c in node.named_children if c.type == "string"]


def dotted(parsed: ParsedFile, node: Node | None) -> str:
    """`request.args.get` for an identifier/attribute/call chain; '' otherwise."""
    if node is None:
        return ""
    if node.type == "attribute":
        obj = dotted(parsed, node.child_by_field_name("object"))
        attr = _text(parsed, node.child_by_field_name("attribute"))
        return f"{obj}.{attr}" if obj else attr
    if node.type == "call":
        return dotted(parsed, node.child_by_field_name("function"))
    return _text(parsed, node)


def import_aliases(imports: list[ImportSymbol]) -> dict[str, str]:
    """Local name -> the dotted name it really refers to.

    `import subprocess`            -> subprocess            -> subprocess
    `import a.b as c`              -> c                     -> a.b
    `from subprocess import run as run_cmd` -> run_cmd      -> subprocess.run
    """
    aliases: dict[str, str] = {}
    for imp in imports:
        if not imp.source:
            continue
        if imp.origin:
            aliases[imp.name] = f"{imp.source}.{imp.origin}"
        else:
            aliases[imp.name] = imp.source
    return aliases


def resolve_dotted(dotted_text: str, aliases: dict[str, str]) -> str:
    """Rewrite the first segment of a dotted name through the import map."""
    if not dotted_text:
        return dotted_text
    parts = dotted_text.split(".")
    head = parts[0]
    if head in aliases:
        mapped = aliases[head].split(".")
        return ".".join(mapped + parts[1:])
    return dotted_text


def classify_call(resolved: str) -> tuple[str, str] | None:
    """(sink_kind, resolved label) when the dotted callee is a sink."""
    if not resolved:
        return None
    parts = resolved.split(".")
    last = parts[-1]
    if len(parts) == 1:
        if last in EXEC_BARE:
            return "exec", resolved
        if last in FS_BARE:
            return "fs", resolved
        return None
    head = ".".join(parts[:-1])
    root = parts[0]
    if root in EXEC_MODULES and last in EXEC_MODULES[root]:
        return "exec", resolved
    if root == "pickle" and last in ("load", "loads"):
        return "exec", resolved
    if root == "yaml" and last == "load":
        return "exec", resolved
    if last in {"execute", "executemany", "executescript", "raw"} and head.split(".")[-1] in DB_RECEIVERS:
        return "db", resolved
    if last in FS_FUNCS and root in {"os", "shutil"}:
        return "fs", resolved
    if head in {"os.path", "pathlib"} or root in {"os", "shutil"} and last in {"join", "exists", "isfile", "isdir", "abspath", "basename", "dirname"}:
        return "fs", resolved
    if last in PATHLIB_IO:
        return "fs", resolved
    if last in HTTP_CALLS and root in HTTP_MODULES:
        return "fetch", resolved
    return None


def _enclosing_function(parsed: ParsedFile, node: Node, functions: list[FunctionSymbol]) -> str:
    """Name of the innermost function that lexically contains `node`."""
    line = line_of(node)
    best = ""
    best_span = -1
    for fn in functions:
        if fn.line <= line <= fn.end_line:
            span = fn.end_line - fn.line
            if best_span == -1 or span < best_span:
                best = fn.name
                best_span = span
    return best


def _class_chain(parsed: ParsedFile, node: Node) -> list[str]:
    """Enclosing class names, outermost first."""
    names: list[str] = []
    cur = node.parent
    while cur is not None:
        if cur.type == "class_definition":
            names.append(_text(parsed, cur.child_by_field_name("name")))
        cur = cur.parent
    return list(reversed(names))


def _in_urlpatterns(parsed: ParsedFile, node: Node) -> bool:
    cur = node.parent
    while cur is not None:
        if cur.type == "assignment":
            return _text(parsed, cur.child_by_field_name("left")) == "urlpatterns"
        if cur.type in ("module", "function_definition", "class_definition"):
            return False
        cur = cur.parent
    return False


def _join_prefix(prefix: str, path: str) -> str:
    if not prefix:
        return path or "/"
    if not path or path == "/":
        return prefix
    return f"{prefix.rstrip('/')}/{path.lstrip('/')}"


def _receiver_table(parsed: ParsedFile, nodes: list[Node]) -> dict[str, tuple[str, str]]:
    """Local variable -> (constructor name, url prefix) for app/router objects."""
    out: dict[str, tuple[str, str]] = {}
    for node in nodes:
        if node.type != "assignment":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None or left.type != "identifier" or right.type != "call":
            continue
        ctor = dotted(parsed, right.child_by_field_name("function")).split(".")[-1]
        if ctor not in APP_CONSTRUCTORS:
            continue
        args = right.child_by_field_name("arguments")
        prefix = ""
        for kw in (c for c in (args.named_children if args else []) if c.type == "keyword_argument"):
            if _text(parsed, kw.child_by_field_name("name")) in ("url_prefix", "prefix"):
                prefix = _string_value(parsed, kw.child_by_field_name("value"))
        out[_text(parsed, left)] = (ctor, prefix)
    return out


def _route_from_decorator(
    parsed: ParsedFile,
    dec: Node,
    fn: Node,
    receivers: dict[str, tuple[str, str]],
) -> RouteSymbol | None:
    expr = dec.named_children[0] if dec.named_children else None
    if expr is None or expr.type != "call":
        return None
    fn_node = expr.child_by_field_name("function")
    if fn_node is None or fn_node.type != "attribute":
        return None
    receiver = dotted(parsed, fn_node.child_by_field_name("object")).split(".")[-1]
    prop = _text(parsed, fn_node.child_by_field_name("attribute"))
    if prop not in ROUTE_DECORATORS:
        return None
    if receiver not in receivers and receiver not in DEFAULT_RECEIVERS:
        return None
    args = expr.child_by_field_name("arguments")
    positional = [c for c in (args.named_children if args else []) if c.type != "keyword_argument"]
    path = _string_value(parsed, positional[0]) if positional else ""
    methods: list[str] = []
    if prop == "route":
        for kw in (c for c in (args.named_children if args else []) if c.type == "keyword_argument"):
            if _text(parsed, kw.child_by_field_name("name")) == "methods":
                methods = _string_list(parsed, kw.child_by_field_name("value"))
    if prop == "route":
        method = "/".join(methods) if methods else "GET"
    else:
        method = prop.upper()
    prefix = receivers.get(receiver, ("", ""))[1]
    return RouteSymbol(
        method=method,
        path=_join_prefix(prefix, path),
        line=line_of(dec),
        end_line=end_line_of(fn),
        handler=_text(parsed, fn.child_by_field_name("name")),
        middleware=[],
        receiver=receiver,
    )


def extract_symbols(parsed: ParsedFile) -> FileSymbols:
    """Walk one parsed Python file and collect every symbol Redfall cares about."""
    result = FileSymbols(path=parsed.path)
    nodes = parsed.walk()

    # --- imports ---------------------------------------------------------
    for node in nodes:
        if node.type == "import_statement":
            for child in node.children:
                if child.type == "dotted_name":
                    full = _text(parsed, child)
                    result.imports.append(
                        ImportSymbol(name=full.split(".")[0], source=full, line=line_of(node))
                    )
                elif child.type == "aliased_import":
                    full = _text(parsed, child.child_by_field_name("name"))
                    alias = _text(parsed, child.child_by_field_name("alias"))
                    result.imports.append(
                        ImportSymbol(name=alias, source=full, line=line_of(node))
                    )
        elif node.type == "import_from_statement":
            module = _text(parsed, node.child_by_field_name("module_name"))
            for child in node.children_by_field_name("name"):
                if child.type == "dotted_name":
                    name = _text(parsed, child)
                    result.imports.append(
                        ImportSymbol(name=name, source=module, line=line_of(node), origin=name)
                    )
                elif child.type == "aliased_import":
                    name = _text(parsed, child.child_by_field_name("name"))
                    alias = _text(parsed, child.child_by_field_name("alias"))
                    result.imports.append(
                        ImportSymbol(name=alias, source=module, line=line_of(node), origin=name)
                    )

    # --- functions -------------------------------------------------------
    for node in nodes:
        if node.type != "function_definition":
            continue
        name = _text(parsed, node.child_by_field_name("name"))
        chain = _class_chain(parsed, node)
        full = ".".join(chain + [name]) if name else ""
        if full:
            result.functions.append(
                FunctionSymbol(
                    name=full,
                    line=line_of(node),
                    end_line=end_line_of(node),
                    is_exported=not name.startswith("_"),
                )
            )
    result.functions.sort(key=lambda f: (f.line, -f.end_line))

    receivers = _receiver_table(parsed, nodes)
    aliases = import_aliases(result.imports)

    # --- routes: decorators ----------------------------------------------
    for node in nodes:
        if node.type != "decorated_definition":
            continue
        fn = next((c for c in node.children if c.type == "function_definition"), None)
        if fn is None:
            continue
        for dec in (c for c in node.children if c.type == "decorator"):
            route = _route_from_decorator(parsed, dec, fn, receivers)
            if route is not None:
                result.routes.append(route)

    # --- routes: Django urlpatterns --------------------------------------
    for node in nodes:
        if node.type != "call":
            continue
        fn_node = node.child_by_field_name("function")
        if fn_node is None or fn_node.type != "identifier":
            continue
        local = _text(parsed, fn_node)
        resolved = resolve_dotted(local, aliases)
        is_django = resolved.endswith(tuple(f"django.urls.{n}" for n in DJANGO_ROUTE_CALLS))
        if local not in DJANGO_ROUTE_CALLS or not (is_django or _in_urlpatterns(parsed, node)):
            continue
        args = node.child_by_field_name("arguments")
        positional = [c for c in (args.named_children if args else []) if c.type != "keyword_argument"]
        if len(positional) < 2:
            continue
        result.routes.append(
            RouteSymbol(
                method="ANY",
                path=_string_value(parsed, positional[0]),
                line=line_of(node),
                end_line=line_of(node),
                handler=_text(parsed, positional[1]),
                middleware=[],
                receiver="django",
            )
        )

    # --- calls ------------------------------------------------------------
    for node in nodes:
        if node.type != "call":
            continue
        fn_node = node.child_by_field_name("function")
        if fn_node is None:
            continue
        resolved = resolve_dotted(dotted(parsed, fn_node), aliases)
        classified = classify_call(resolved)
        if classified is None:
            continue
        kind, label = classified
        args = node.child_by_field_name("arguments")
        positional = [c for c in (args.named_children if args else []) if c.type != "keyword_argument"]
        result.calls.append(
            CallSymbol(
                kind=kind,
                callee=label,
                line=line_of(node),
                arg_text=_text(parsed, positional[0]) if positional else "",
                enclosing_function=_enclosing_function(parsed, node, result.functions),
            )
        )

    # --- mounts (same-file, informational; prefixes are never guessed) ----
    for node in nodes:
        if node.type != "call":
            continue
        fn_node = node.child_by_field_name("function")
        resolved = resolve_dotted(dotted(parsed, fn_node), aliases)
        if resolved.endswith("include_router"):
            args = node.child_by_field_name("arguments")
            positional = [c for c in (args.named_children if args else []) if c.type != "keyword_argument"]
            prefix = ""
            for kw in (c for c in (args.named_children if args else []) if c.type == "keyword_argument"):
                if _text(parsed, kw.child_by_field_name("name")) == "prefix":
                    prefix = _string_value(parsed, kw.child_by_field_name("value"))
            target = _text(parsed, positional[0]) if positional else ""
            if prefix and target:
                result.mounts.append(
                    MountSymbol(prefix=prefix, local_name=target, line=line_of(node))
                )

    for name, (_ctor, prefix) in receivers.items():
        if prefix:
            line = next(
                (line_of(c) for c in nodes if c.type == "assignment" and _text(parsed, c.child_by_field_name("left")) == name),
                0,
            )
            result.mounts.append(MountSymbol(prefix=prefix, local_name=name, line=line))

    result.routes.sort(key=lambda r: (r.line, r.path))
    result.calls.sort(key=lambda c: c.line)
    return result
