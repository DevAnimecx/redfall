"""Symbol extraction from a parsed TypeScript/JavaScript file.

Extracts, per §6.1:
  * Express routes (`app.get`, `router.post`, ...) with method, path, handler and
    the middleware chain in front of the handler
  * function declarations and arrow-function constants
  * database calls (`pool.query`, `client.query`, `db.query`) with the SQL text
  * outbound calls (`fetch`, `axios.*`, `http.request`)
  * filesystem operations (`fs.readFile`, `path.join`, ...)
  * command execution (`exec`, `spawn`, `execSync`, `execFile`)
  * imports

Everything is derived from the syntax tree; nothing is inferred from filenames.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Node

from .tree import ParsedFile, end_line_of, line_of

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "use", "all"}

# NestJS route decorators. `All` maps to every verb; the rest map to themselves.
NEST_METHODS = {"Get", "Post", "Put", "Patch", "Delete", "Head", "Options", "All"}

DB_RECEIVERS = {"pool", "client", "db", "pg", "connection", "knex"}
FS_RECEIVERS = {"fs", "fsp", "fsPromises", "promises"}
EXEC_NAMES = {"exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"}
FETCH_RECEIVERS = {"axios", "http", "https", "got", "request", "superagent"}


@dataclass
class RouteSymbol:
    method: str
    path: str
    line: int
    end_line: int
    handler: str
    middleware: list[str] = field(default_factory=list)
    receiver: str = "app"


@dataclass
class FunctionSymbol:
    name: str
    line: int
    end_line: int
    is_exported: bool = False


@dataclass
class CallSymbol:
    kind: str  # db | exec | fs | fetch
    callee: str
    line: int
    arg_text: str = ""
    enclosing_function: str = ""


@dataclass
class ImportSymbol:
    name: str
    source: str
    line: int
    is_default: bool = False
    # For `from m import x as y`: name=y, source=m, origin=x. Empty for plain imports.
    origin: str = ""


@dataclass
class MountSymbol:
    """`app.use('/api/auth', authRoutes)` — a router mounted at a prefix."""

    prefix: str
    local_name: str
    line: int


@dataclass
class FileSymbols:
    path: str
    routes: list[RouteSymbol] = field(default_factory=list)
    functions: list[FunctionSymbol] = field(default_factory=list)
    calls: list[CallSymbol] = field(default_factory=list)
    imports: list[ImportSymbol] = field(default_factory=list)
    mounts: list[MountSymbol] = field(default_factory=list)

    def containing(self, line: int) -> str:
        """Innermost named function whose body contains `line`, else ''."""
        best = ""
        best_span = -1
        for fn in self.functions:
            if fn.line <= line <= fn.end_line:
                span = fn.end_line - fn.line
                if best_span == -1 or span < best_span:
                    best = fn.name
                    best_span = span
        return best

    def containing_route(self, line: int) -> RouteSymbol | None:
        """The route registration whose body encloses `line`, if any."""
        best: RouteSymbol | None = None
        best_span = -1
        for r in self.routes:
            if r.method == "USE":
                continue
            if r.line <= line <= r.end_line:
                span = r.end_line - r.line
                if best_span == -1 or span < best_span:
                    best = r
                    best_span = span
        return best


def _text(parsed: ParsedFile, node: Node | None) -> str:
    if node is None:
        return ""
    return parsed.text_of(node).strip()


def _member_parts(parsed: ParsedFile, node: Node) -> tuple[str, str]:
    """Split `a.b.c` into ('a.b', 'c'). Non-member nodes give ('', text)."""
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        return _text(parsed, obj), _text(parsed, prop)
    return "", _text(parsed, node)


def _string_value(parsed: ParsedFile, node: Node | None) -> str:
    """The literal value of a string/template node, without quotes."""
    if node is None:
        return ""
    raw = _text(parsed, node)
    if node.type in ("string", "template_string") and len(raw) >= 2:
        return raw[1:-1]
    return raw


def _nest_path(prefix: str, sub: str) -> str:
    """`@Controller('cats')` + `@Get(':id')` -> '/cats/:id'."""
    parts = [p.strip("/") for p in (prefix, sub) if p and p.strip("/")]
    return "/" + "/".join(parts)


def _enclosing_function(parsed: ParsedFile, node: Node, functions: list[FunctionSymbol]) -> str:
    """Name of the innermost function that lexically contains `node`."""
    best = ""
    best_span = -1
    for fn in functions:
        if fn.line <= line_of(node) <= fn.end_line:
            span = fn.end_line - fn.line
            if span >= best_span:
                # prefer the tightest (smallest) enclosing span
                if best_span == -1 or span < best_span:
                    best = fn.name
                    best_span = span
    return best


def _arrow_or_function_name(parsed: ParsedFile, node: Node) -> str:
    """For `const foo = (...) => {}` / `function foo() {}`, return 'foo'."""
    if node.type == "function_declaration":
        name = node.child_by_field_name("name")
        return _text(parsed, name)
    if node.type in ("lexical_declaration", "variable_declaration"):
        for decl in node.children:
            if decl.type == "variable_declarator":
                name = decl.child_by_field_name("name")
                value = decl.child_by_field_name("value")
                if value is not None and value.type in ("arrow_function", "function_expression", "function"):
                    return _text(parsed, name)
    return ""


def _is_exported(node: Node) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type == "export_statement":
            return True
        if parent.type in ("program", "module"):
            return False
        parent = parent.parent
    return False


# Public name for the interprocedural pass: `inter_ts.py` needs to locate the
# declaration node a FunctionSymbol came from, and must use this exact rule so
# the two passes cannot disagree about which node a symbol names.
arrow_or_function_name = _arrow_or_function_name


def extract_symbols(parsed: ParsedFile) -> FileSymbols:
    """Walk one parsed file and collect every symbol Redfall cares about."""
    result = FileSymbols(path=parsed.path)
    nodes = parsed.walk()

    # --- imports ---------------------------------------------------------
    for node in nodes:
        if node.type == "import_statement":
            source_node = node.child_by_field_name("source")
            module = _string_value(parsed, source_node)
            clause = node.children[1] if len(node.children) > 1 else None
            default_name = ""
            if clause is not None and clause.type == "import_clause":
                for child in clause.children:
                    if child.type == "identifier":
                        default_name = _text(parsed, child)
                    elif child.type == "namespace_import":
                        alias = next((c for c in child.children if c.type == "identifier"), None)
                        if alias is not None:
                            result.imports.append(
                                ImportSymbol(
                                    name=_text(parsed, alias),
                                    source=module,
                                    line=line_of(node),
                                    origin="*",
                                )
                            )
                    elif child.type == "named_imports":
                        for spec in child.children:
                            if spec.type == "import_specifier":
                                nm = spec.child_by_field_name("name")
                                alias = spec.child_by_field_name("alias")
                                result.imports.append(
                                    ImportSymbol(
                                        name=_text(parsed, alias or nm),
                                        source=module,
                                        line=line_of(node),
                                        origin=_text(parsed, nm),
                                    )
                                )
                        continue
            if default_name:
                result.imports.append(
                    ImportSymbol(name=default_name, source=module, line=line_of(node), is_default=True)
                )

    # --- CommonJS requires: `const x = require('./m')` --------------------
    # Recorded with the same shapes as the ESM forms so the interprocedural
    # pass can resolve both without special cases: a bare identifier binds a
    # namespace ("*"), a destructured pattern binds each name it introduces.
    for node in nodes:
        if node.type != "variable_declarator":
            continue
        value = node.child_by_field_name("value")
        if value is None or value.type != "call_expression":
            continue
        if _text(parsed, value.child_by_field_name("function")) != "require":
            continue
        args = value.child_by_field_name("arguments")
        arg_list = [c for c in (args.children if args else []) if c.type not in ("(", ")", ",")]
        module = _string_value(parsed, arg_list[0]) if arg_list else ""
        name_node = node.child_by_field_name("name")
        if not module or name_node is None:
            continue
        if name_node.type == "identifier":
            result.imports.append(
                ImportSymbol(name=_text(parsed, name_node), source=module, line=line_of(node), origin="*")
            )
        elif name_node.type == "object_pattern":
            for child in name_node.named_children:
                if child.type in ("shorthand_property_identifier_pattern", "shorthand_property_identifier"):
                    bound = _text(parsed, child)
                    result.imports.append(
                        ImportSymbol(name=bound, source=module, line=line_of(node), origin=bound)
                    )
                elif child.type == "pair":
                    key = _text(parsed, child.child_by_field_name("key"))
                    bound = _text(parsed, child.child_by_field_name("value"))
                    if key:
                        result.imports.append(
                            ImportSymbol(name=bound or key, source=module, line=line_of(node), origin=key)
                        )

    # --- functions -------------------------------------------------------
    for node in nodes:
        name = _arrow_or_function_name(parsed, node)
        if name:
            result.functions.append(
                FunctionSymbol(
                    name=name,
                    line=line_of(node),
                    end_line=end_line_of(node),
                    is_exported=_is_exported(node),
                )
            )
        elif node.type == "export_statement":
            inner = node.child_by_field_name("declaration")
            if inner is not None:
                inner_name = _arrow_or_function_name(parsed, inner)
                if inner_name and not any(f.name == inner_name for f in result.functions):
                    result.functions.append(
                        FunctionSymbol(
                            name=inner_name,
                            line=line_of(inner),
                            end_line=end_line_of(inner),
                            is_exported=True,
                        )
                    )

    result.functions.sort(key=lambda f: (f.line, -f.end_line))

    # --- routes and calls ------------------------------------------------
    for node in nodes:
        if node.type != "call_expression":
            continue

        fn_node = node.child_by_field_name("function")
        if fn_node is None:
            continue
        receiver, prop = _member_parts(parsed, fn_node)

        # Express / Fastify / Koa route registration. Fastify and koa-router
        # both use the HTTP-verb methods with the same (path, handler…)
        # signature, so the receiver name is the only thing to recognise.
        if prop in HTTP_METHODS and receiver in ("app", "router", "api", "server", "route", "fastify"):
            args = node.child_by_field_name("arguments")
            arg_list = [c for c in (args.children if args else []) if c.type not in ("(", ")", ",")]
            route_path = _string_value(parsed, arg_list[0]) if arg_list else ""
            middleware: list[str] = []
            handler = ""
            for arg in arg_list[1:]:
                label = _text(parsed, arg)
                if arg.type == "identifier":
                    if handler:
                        middleware.append(handler)
                    handler = label
                elif arg.type in ("arrow_function", "function_expression", "function"):
                    handler = f"<inline@{line_of(arg)}>"
                else:
                    middleware.append(label)
            result.routes.append(
                RouteSymbol(
                    method=prop.upper() if prop != "use" else "USE",
                    path=route_path,
                    line=line_of(node),
                    end_line=end_line_of(node),
                    handler=handler,
                    middleware=middleware,
                    receiver=receiver,
                )
            )
            # `app.use('/api/auth', authRoutes)` also defines a mount point
            if prop == "use" and len(arg_list) >= 2 and arg_list[0].type == "string":
                mounted = arg_list[1]
                if mounted.type == "identifier":
                    result.mounts.append(
                        MountSymbol(
                            prefix=route_path,
                            local_name=_text(parsed, mounted),
                            line=line_of(node),
                        )
                    )
            continue

    # NestJS decorator routes: `@Controller('cats')` sets the class prefix,
    # `@Get(':id')` on a method registers the route. The receiver is the
    # decorator set itself; the path recorded is the full one.
    for node in nodes:
        if node.type != "class_declaration":
            continue
        # A class decorator is a child of the class — or of the export
        # statement wrapping it (`@Controller()` above `export class`).
        owners = [node]
        if node.parent is not None and node.parent.type == "export_statement":
            owners.append(node.parent)
        prefix = ""
        for owner in owners:
            for child in owner.children:
                if child.type != "decorator":
                    continue
                call = next((c for c in child.children if c.type == "call_expression"), None)
                if call is None:
                    continue
                if _text(parsed, call.child_by_field_name("function")) != "Controller":
                    continue
                args = call.child_by_field_name("arguments")
                arg_list = [c for c in (args.children if args else []) if c.type not in ("(", ")", ",")]
                if arg_list:
                    prefix = _string_value(parsed, arg_list[0])
        class_body = next((c for c in node.children if c.type == "class_body"), None)
        if class_body is None:
            continue
        # Method decorators are siblings that immediately precede the method.
        body_children = list(class_body.children)
        for index, method in enumerate(body_children):
            if method.type != "method_definition":
                continue
            decorators: list[Node] = []
            back = index - 1
            while back >= 0 and body_children[back].type == "decorator":
                decorators.insert(0, body_children[back])
                back -= 1
            name_node = method.child_by_field_name("name") or next(
                (c for c in method.children if c.type in ("property_identifier", "identifier")), None
            )
            method_name = _text(parsed, name_node)
            for child in decorators:
                call = next((c for c in child.children if c.type == "call_expression"), None)
                sub = ""
                if call is not None:
                    prop = _text(parsed, call.child_by_field_name("function"))
                    args = call.child_by_field_name("arguments")
                    arg_list = [c for c in (args.children if args else []) if c.type not in ("(", ")", ",")]
                    if arg_list:
                        sub = _string_value(parsed, arg_list[0])
                else:
                    prop = _text(parsed, next((c for c in child.children if c.type == "identifier"), None))
                if prop not in NEST_METHODS:
                    continue
                result.routes.append(
                    RouteSymbol(
                        method=prop.upper(),
                        path=_nest_path(prefix, sub),
                        line=line_of(child),
                        end_line=end_line_of(method),
                        handler=method_name,
                        middleware=[],
                        receiver="nest",
                    )
                )

    for node in nodes:
        if node.type != "call_expression":
            continue

        fn_node = node.child_by_field_name("function")
        if fn_node is None:
            continue
        receiver, prop = _member_parts(parsed, fn_node)

        # Database calls
        if prop == "query" and receiver in DB_RECEIVERS:
            args = node.child_by_field_name("arguments")
            arg_list = [c for c in (args.children if args else []) if c.type not in ("(", ")", ",")]
            sql_text = _text(parsed, arg_list[0]) if arg_list else ""
            result.calls.append(
                CallSymbol(
                    kind="db",
                    callee=f"{receiver}.{prop}",
                    line=line_of(node),
                    arg_text=sql_text,
                    enclosing_function=_enclosing_function(parsed, node, result.functions),
                )
            )
            continue

        # Command execution
        if prop in EXEC_NAMES or (not receiver and prop in EXEC_NAMES):
            args = node.child_by_field_name("arguments")
            arg_list = [c for c in (args.children if args else []) if c.type not in ("(", ")", ",")]
            result.calls.append(
                CallSymbol(
                    kind="exec",
                    callee=f"{receiver}.{prop}" if receiver else prop,
                    line=line_of(node),
                    arg_text=_text(parsed, arg_list[0]) if arg_list else "",
                    enclosing_function=_enclosing_function(parsed, node, result.functions),
                )
            )
            continue

        # Filesystem operations
        if receiver in FS_RECEIVERS and prop:
            result.calls.append(
                CallSymbol(
                    kind="fs",
                    callee=f"{receiver}.{prop}",
                    line=line_of(node),
                    arg_text="",
                    enclosing_function=_enclosing_function(parsed, node, result.functions),
                )
            )
            continue

        # Outbound HTTP
        if prop == "fetch" or (receiver in FETCH_RECEIVERS and prop in ("get", "post", "put", "delete", "request")):
            args = node.child_by_field_name("arguments")
            arg_list = [c for c in (args.children if args else []) if c.type not in ("(", ")", ",")]
            result.calls.append(
                CallSymbol(
                    kind="fetch",
                    callee=f"{receiver}.{prop}" if receiver else prop,
                    line=line_of(node),
                    arg_text=_text(parsed, arg_list[0]) if arg_list else "",
                    enclosing_function=_enclosing_function(parsed, node, result.functions),
                )
            )
            continue

        # path.join and friends, which matter for traversal sinks
        if receiver == "path" and prop in ("join", "resolve", "normalize"):
            result.calls.append(
                CallSymbol(
                    kind="fs",
                    callee=f"path.{prop}",
                    line=line_of(node),
                    arg_text=_text(parsed, node.child_by_field_name("arguments")) if node.child_by_field_name("arguments") else "",
                    enclosing_function=_enclosing_function(parsed, node, result.functions),
                )
            )

    return result
