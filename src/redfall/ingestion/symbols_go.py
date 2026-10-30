"""Symbol extraction for Go.

Emits the same `FileSymbols` the other extractors emit, so a Go service is read
by the graph and the planner exactly like a TypeScript, Python or JVM one.

Two Go-specific facts shape this code:

* **Routes are registered by call, not by annotation.** `http.HandleFunc("/x",
  h)` and a framework's `r.GET("/x", h)` both register a handler, so the route
  is read from the call's arguments rather than from decorators.
* **Imports are paths, and the last segment is the package name.** `import
  "net/http"` binds `http`, not `net/http`. Recording the path as the name is
  how a sink fails to resolve and a real flow is missed.
"""

from __future__ import annotations

from .symbols import (
    CallSymbol,
    FileSymbols,
    FunctionSymbol,
    ImportSymbol,
    MountSymbol,
    RouteSymbol,
)
from .tree import ParsedFile, line_of

# `net/http` registers routes through these. The verb is in the name.
STDLIB_ROUTERS = {
    "HandleFunc": "ANY",
    "Handle": "ANY",
}

# Gorilla mux and chi register through methods on a router.
ROUTER_METHODS = {
    "GET": "GET",
    "POST": "POST",
    "PUT": "PUT",
    "DELETE": "DELETE",
    "PATCH": "PATCH",
    "HEAD": "HEAD",
    "OPTIONS": "OPTIONS",
    "HandleFunc": "ANY",
    "Handle": "ANY",
}

# Gin and Echo name their registrations the same way, so one table serves both.
GIN_METHODS = {
    "GET": "GET",
    "POST": "POST",
    "PUT": "PUT",
    "DELETE": "DELETE",
    "PATCH": "PATCH",
    "Any": "ANY",
}

# Sink calls: name -> kind (db | exec | fs | fetch).
SINK_CALLS: dict[str, str] = {
    # exec
    "Command": "exec",
    "CommandContext": "exec",
    "Start": "exec",
    "Run": "exec",
    # db
    "Query": "db",
    "QueryRow": "db",
    "QueryContext": "db",
    "Exec": "db",
    "ExecContext": "db",
    "QueryRowContext": "db",
    # fs
    "Open": "fs",
    "OpenFile": "fs",
    "Create": "fs",
    "ReadFile": "fs",
    "WriteFile": "fs",
    # fetch
    "Get": "fetch",
    "Post": "fetch",
    "Do": "fetch",
    "NewRequest": "fetch",
}

# Calls whose meaning depends on the receiver. `Get` on an http.Client is a
# request; on a cache it is a lookup, and calling that SSRF would be a finding
# with no exploit behind it.
RECEIVER_GATED: dict[str, tuple[str, set[str]]] = {
    "Get": ("fetch", {"http", "client", "Client", "httpClient"}),
    "Post": ("fetch", {"http", "client", "Client", "httpClient"}),
    "Do": ("fetch", {"http", "client", "Client", "httpClient"}),
    "Open": ("fs", {"os", "ioutil", "file", "f"}),
    "Create": ("fs", {"os", "ioutil", "file", "f"}),
    "Run": ("exec", {"cmd", "command", "exec", "Command"}),
    "Start": ("exec", {"cmd", "command", "exec", "Command"}),
}

# Request accessors that make a value attacker-controlled.
SOURCE_CALLS = (
    "Query",
    "FormValue",
    "PostFormValue",
    "Cookie",
    "Header.Get",
    "URL.Query",
    "GetBody",
)

SANITISER_HINTS = (
    "Escape",
    "escape",
    "Sanitize",
    "sanitise",
    "Quote",
    "quote",
    "Clean",
    "Trim",
    "Validate",
)


def _text(parsed: ParsedFile, node) -> str:
    if node is None:
        return ""
    return parsed.text_of(node)


def _unquote(text: str) -> str:
    stripped = text.strip()
    if len(stripped) >= 2 and stripped[0] in "\"`" and stripped[-1] in "\"`":
        return stripped[1:-1]
    return stripped


def _call_parts(parsed: ParsedFile, node) -> tuple[str, str]:
    """`(receiver, name)` for a call node: `http.HandleFunc` -> ("http", "HandleFunc")."""
    if node.type != "call_expression":
        return "", ""
    fn = node.child_by_field_name("function")
    if fn is None:
        return "", ""
    if fn.type == "selector_expression":
        return (
            _text(parsed, fn.child_by_field_name("operand")),
            _text(parsed, fn.child_by_field_name("field")),
        )
    if fn.type == "identifier":
        return "", _text(parsed, fn)
    return "", _text(parsed, fn)


def _string_arguments(parsed: ParsedFile, node) -> list[str]:
    """String literals among a call's arguments, in order."""
    args = node.child_by_field_name("arguments")
    if args is None:
        return []
    out: list[str] = []
    for child in args.children:
        if child.type == "interpreted_string_literal" or child.type == "raw_string_literal":
            out.append(_unquote(_text(parsed, child)))
    return out


def extract_symbols(parsed: ParsedFile) -> FileSymbols:
    """Walk one parsed Go file and collect every symbol Redfall cares about."""
    result = FileSymbols(path=parsed.path)
    nodes = parsed.walk()

    # --- imports ---------------------------------------------------------
    for node in nodes:
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            path_node = next(
                (c for c in node.children if c.type.endswith("string_literal")), None
            )
        if path_node is None:
            continue
        source = _unquote(_text(parsed, path_node))
        # The package an import binds is the last path segment, not the whole
        # path: `net/http` is used as `http.Get`.
        bound = source.rsplit("/", 1)[-1]
        alias = node.child_by_field_name("name")
        name = _text(parsed, alias) if alias is not None else bound
        result.imports.append(
            ImportSymbol(
                name=name,
                source=source,
                line=line_of(node),
                is_default=alias is not None,
                origin=bound,
            )
        )

    # --- functions and routes --------------------------------------------
    for node in nodes:
        if node.type not in ("function_declaration", "method_declaration"):
            continue
        name = _text(parsed, node.child_by_field_name("name"))
        if name:
            result.functions.append(
                FunctionSymbol(
                    name=name,
                    line=line_of(node),
                    end_line=node.end_point[0] + 1,
                    is_exported=name[:1].isupper(),
                )
            )

    for node in nodes:
        if node.type != "call_expression":
            continue
        receiver, name = _call_parts(parsed, node)
        route = _route_for(parsed, node, receiver, name)
        if route is not None:
            result.routes.append(route)
            continue
        kind = _classify(receiver, name)
        if kind is None:
            continue
        result.calls.append(
            CallSymbol(
                kind=kind,
                callee=name,
                line=line_of(node),
                arg_text=_text(parsed, node.child_by_field_name("arguments")) or "",
                enclosing_function=_enclosing_function(parsed, node),
            )
        )

    # A router grouped under a prefix: `api := r.Group("/api")`.
    for node in nodes:
        if node.type != "short_var_declaration":
            continue
        right = node.child_by_field_name("right")
        if right is None:
            continue
        for call in right.children:
            if call.type != "call_expression":
                continue
            _, name = _call_parts(parsed, call)
            if name != "Group":
                continue
            args = _string_arguments(parsed, call)
            left = node.child_by_field_name("left")
            local = _text(parsed, left) if left is not None else ""
            if args and local:
                result.mounts.append(
                    MountSymbol(prefix=args[0], local_name=local, line=line_of(node))
                )

    return result


def _route_for(parsed: ParsedFile, node, receiver: str, name: str) -> RouteSymbol | None:
    """A RouteSymbol if this call registers an HTTP route, else None."""
    verb: str | None = None
    if name in STDLIB_ROUTERS and receiver in ("http", ""):
        verb = STDLIB_ROUTERS[name]
    elif name in GIN_METHODS and receiver:
        verb = GIN_METHODS[name]
    elif name in ROUTER_METHODS and receiver:
        verb = ROUTER_METHODS[name]
    if verb is None:
        return None

    paths = _string_arguments(parsed, node)
    if not paths:
        # A registration whose path is a variable or constant is not readable
        # here, and inventing one would be worse than recording no route.
        return None
    handler = ""
    args = node.child_by_field_name("arguments")
    if args is not None:
        for child in args.children:
            if child.type == "identifier":
                handler = _text(parsed, child)
                break
    return RouteSymbol(
        method=verb,
        path=paths[0],
        line=line_of(node),
        end_line=line_of(node),
        handler=handler,
        receiver=receiver or "http",
    )


def _enclosing_function(parsed: ParsedFile, node) -> str:
    parent = node.parent
    while parent is not None:
        if parent.type in ("function_declaration", "method_declaration", "func_literal"):
            return _text(parsed, parent.child_by_field_name("name"))
        parent = parent.parent
    return ""


def _classify(receiver: str, callee: str) -> str | None:
    """The sink kind a call resolves to, or None if it is not a sink.

    A receiver-gated name is decided solely by its receiver. `exec.Command` is
    process execution because `exec` is the os/exec package; `runner.Command` is
    a method on someone's own type, and classifying it as a sink would produce a
    taint path to something that cannot be exploited.
    """
    gated = RECEIVER_GATED.get(callee)
    if gated is not None:
        kind, receivers = gated
        if any(token in receiver for token in receivers):
            return kind
        return None

    # Names that are only sinks on a specific package or receiver.
    if callee in ("Command", "CommandContext"):
        return "exec" if receiver == "exec" else None
    if callee in ("Query", "QueryRow", "Exec", "QueryContext", "ExecContext"):
        return "db" if receiver in ("db", "tx", "conn", "") else None
    if callee in ("ReadFile", "WriteFile"):
        return "fs" if receiver in ("os", "ioutil", "") else None

    entry = SINK_CALLS.get(callee)
    if entry is None:
        return None
    # Every remaining table entry is receiver-gated by nature; without a
    # recognizable receiver it is not enough to call it a sink.
    return None
