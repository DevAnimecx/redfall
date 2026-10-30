"""Intraprocedural source→sink taint analysis for Go.

Same doctrine as the other analysers: propagation per function, and a sanitiser
is recorded but never clears taint — the sandbox decides whether a path is real.
The shared `ScopeTaint` is reused rather than a second propagation model.

Sources are the request surfaces of Go's own libraries — `r.URL.Query().Get`,
`r.FormValue`, `r.Header.Get`, `r.Cookie` — plus a handler parameter whose type
is an `*http.Request`. That last one is what makes the common Gin/Echo and
net/http handler a source without naming a variable convention.
"""

from __future__ import annotations

from tree_sitter import Node

from .taint import ScopeTaint, Taint
from .tree import ParsedFile, line_of

# Accessors on a request that return attacker-controlled data.
SOURCE_CALLS = (
    "FormValue",
    "PostFormValue",
    "Get",
    "Cookie",
    "Cookies",
    "Query",
    "ParseForm",
    "Param",
    "QueryParam",
    "FormValue",
)

# Receivers that are request-shaped. `Get` on a map is not a request read.
SOURCE_RECEIVERS = ("URL", "r", "req", "request", "c", "ctx", "Header")

SANITISER_HINTS = (
    "Escape",
    "escape",
    "Sanitize",
    "sanitise",
    "Quote",
    "quote",
    "Clean",
    "Trim",
    "Valid",
    "Validate",
    "HtmlEscape",
)


def _text(parsed: ParsedFile, node: Node | None) -> str:
    if node is None:
        return ""
    return parsed.text_of(node).strip()


def _call_parts(parsed: ParsedFile, node: Node) -> tuple[str, str]:
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
    return "", _text(parsed, fn)


def _source_label(parsed: ParsedFile, node: Node) -> str | None:
    """A label if this node reads request data, else None."""
    if node.type == "call_expression":
        receiver, name = _call_parts(parsed, node)
        if name in SOURCE_CALLS and any(token in receiver for token in SOURCE_RECEIVERS):
            return f"{receiver}.{name}"
        return None
    if node.type == "identifier":
        text = _text(parsed, node)
        if text in ("req", "request"):
            return text
    return None


def _request_parameters(parsed: ParsedFile, fn: Node) -> set[str]:
    """Parameters whose declared type is an HTTP request."""
    params = fn.child_by_field_name("parameters")
    if params is None:
        return set()
    out: set[str] = set()
    for param in params.children:
        if param.type != "parameter_declaration":
            continue
        type_node = param.child_by_field_name("type")
        type_text = _text(parsed, type_node)
        if "http.Request" not in type_text and "echo.Context" not in type_text:
            continue
        name_node = param.child_by_field_name("name")
        if name_node is not None:
            out.add(_text(parsed, name_node))
    return out


def _identifiers(node: Node) -> list[Node]:
    out: list[Node] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "identifier":
            out.append(current)
            continue
        stack.extend(current.children)
    return out


def _target_names(parsed: ParsedFile, node: Node | None) -> list[str]:
    if node is None:
        return []
    if node.type == "expression_list":
        return [_text(parsed, child) for child in node.children if child.type == "identifier"]
    if node.type == "identifier":
        return [_text(parsed, node)]
    return [_text(parsed, child) for child in _identifiers(node)]


def _sanitisers_in(parsed: ParsedFile, node: Node) -> list[str]:
    fn = node
    while fn is not None and fn.type not in ("function_declaration", "method_declaration", "source_file"):
        fn = fn.parent
    if fn is None:
        return []
    out: list[str] = []
    stack = [fn]
    while stack:
        current = stack.pop()
        if current.type == "call_expression":
            _, name = _call_parts(parsed, current)
            if name and any(hint in name for hint in SANITISER_HINTS):
                out.append(name)
        stack.extend(current.children)
    return out


def _scopes(parsed: ParsedFile) -> list[tuple[str, int, int]]:
    out: list[tuple[str, int, int]] = []
    for node in parsed.walk():
        if node.type not in ("function_declaration", "method_declaration", "func_literal"):
            continue
        name = _text(parsed, node.child_by_field_name("name")) or "<anon>"
        out.append((name, line_of(node), node.end_point[0] + 1))
    return out


def _first_label(
    parsed: ParsedFile,
    node: Node | None,
    extra_source=None,
    tainted: dict[str, str] | None = None,
) -> str | None:
    """The first taint in a subtree: a request read, or an already-tainted name."""
    if node is None:
        return None
    if extra_source is not None:
        label = extra_source(node)
        if label:
            return label
    known = tainted or {}
    stack = [node]
    while stack:
        current = stack.pop()
        label = _source_label(parsed, current)
        if label:
            return label
        if current.type == "identifier":
            name = _text(parsed, current)
            if name in known:
                return known[name]
        stack.extend(current.children)
    return None


def collect_tainted(parsed: ParsedFile, *, extra_source=None) -> ScopeTaint:
    """Propagate request data through local variables, per function."""
    collected = ScopeTaint(scopes=_scopes(parsed))
    for fn in parsed.walk():
        if fn.type not in ("function_declaration", "method_declaration", "func_literal"):
            continue
        scope = _text(parsed, fn.child_by_field_name("name")) or "<anon>"
        body = fn.child_by_field_name("body")
        if body is None:
            continue
        # A parameter typed as a request is a source for the whole function.
        for name in _request_parameters(parsed, fn):
            collected.tainted.setdefault(scope, {})[name] = f"param:{name}"
            collected.lines.setdefault(scope, {})[name] = line_of(fn)

        for node in _walk(body):
            if node.type == "short_var_declaration":
                _bind(parsed, collected, scope, node, extra_source)
            elif node.type == "assignment_statement":
                _bind(parsed, collected, scope, node, extra_source)
            elif node.type == "var_declaration":
                for spec in node.children:
                    if spec.type == "var_spec":
                        _bind(parsed, collected, scope, spec, extra_source)
    return collected


def _bind(parsed: ParsedFile, collected: ScopeTaint, scope: str, node: Node, extra_source) -> None:
    """Propagate taint from a declaration's or assignment's right side to its name."""
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if right is None:
        # A var_spec names its value `value` rather than `right`.
        right = node.child_by_field_name("value")
    if left is None or right is None:
        return
    label = _first_label(parsed, right, extra_source, collected.tainted.get(scope, {}))
    if label is None:
        return
    for name in _target_names(parsed, left):
        if not name:
            continue
        collected.tainted.setdefault(scope, {})[name] = label
        collected.lines.setdefault(scope, {})[name] = line_of(node)


def _walk(node: Node) -> list[Node]:
    out: list[Node] = []
    stack = [node]
    while stack:
        current = stack.pop()
        out.append(current)
        stack.extend(reversed(current.children))
    return out


def find_sinks(
    parsed: ParsedFile,
    symbols,
    collected: ScopeTaint,
    extra_source=None,
) -> list[Taint]:
    """Report a Taint for every sink call that consumes tainted data."""
    out: list[Taint] = []
    seen: set[str] = set()
    sink_index = {(c.line, c.callee): c for c in symbols.calls}

    for node in parsed.walk():
        if node.type != "call_expression":
            continue
        line = line_of(node)
        _, name = _call_parts(parsed, node)
        call = sink_index.get((line, name))
        if call is None:
            continue

        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        scope = collected.scope_for(line)
        tainted_here = collected.tainted.get(scope, {})
        label = _first_label(parsed, args, extra_source, tainted_here)
        if label is None:
            continue

        key = f"{label}->{call.callee}@{line}"
        if key in seen:
            continue
        seen.add(key)

        via: list[str] = []
        sanitisers = _sanitisers_in(parsed, node)
        if sanitisers:
            via.append(f"sanitiser present but not modelled: {', '.join(sorted(set(sanitisers)))}()")

        out.append(
            Taint(
                source=label,
                sink=call.callee,
                sink_kind=call.kind,
                line=line,
                symbol=scope,
                via=via,
                snippet=parsed.text_of(node)[:400],
            )
        )
    return out


def analyse_taint(parsed: ParsedFile, symbols) -> list[Taint]:
    """Source→sink flows for one Go file."""
    collected = collect_tainted(parsed)
    return find_sinks(parsed, symbols, collected)
