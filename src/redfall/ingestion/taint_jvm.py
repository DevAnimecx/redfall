"""Intraprocedural source→sink taint analysis for Java and Kotlin.

Same doctrine as the TypeScript and Python analysers: propagation per enclosing
method, and a sanitiser is recorded but never clears taint — the sandbox decides
whether a path is real. The shared `ScopeTaint` is reused rather than a second
propagation model, so a JVM path and a Python path are summarised the same way.

Sources are Spring's request bindings — `@RequestParam`, `@PathVariable`,
`@RequestBody`, `@RequestHeader`, `@CookieValue` — and the servlet calls that
read the request directly (`getParameter`, `getHeader`, and friends). A
parameter annotated as a request binding is tainted for the whole method, which
is what makes `@RequestParam String id` a source at its use.
"""

from __future__ import annotations

from tree_sitter import Node

from .taint import ScopeTaint, Taint
from .tree import ParsedFile, line_of

# Annotations that bind an HTTP request value to a parameter.
SOURCE_ANNOTATIONS = (
    "RequestParam",
    "PathVariable",
    "RequestBody",
    "RequestHeader",
    "CookieValue",
    "MatrixVariable",
    "ModelAttribute",
    "RequestPart",
)

# Servlet/JAX-RS accessors that read the request directly.
SOURCE_CALLS = (
    "getParameter",
    "getParameterValues",
    "getParameterMap",
    "getHeader",
    "getHeaders",
    "getCookies",
    "getInputStream",
    "getReader",
    "getQueryString",
    "getPathInfo",
    "getRequestURI",
)

SANITISER_HINTS = (
    "escape",
    "escapeHtml",
    "sanitize",
    "sanitise",
    "encode",
    "quote",
    "replace",
    "stripTags",
    "clean",
    "validate",
    "normalize",
)


def _text(parsed: ParsedFile, node: Node | None) -> str:
    if node is None:
        return ""
    return parsed.text_of(node).strip()


def _method_invocation_parts(parsed: ParsedFile, node: Node) -> tuple[str, str]:
    """`(receiver, name)` for a call node, either part possibly empty."""
    if node.type == "method_invocation":
        return _text(parsed, node.child_by_field_name("object")), _text(
            parsed, node.child_by_field_name("name")
        )
    return "", ""


def _source_label(parsed: ParsedFile, node: Node) -> str | None:
    """A label if this node reads from the request, else None."""
    if node.type == "method_invocation":
        receiver, name = _method_invocation_parts(parsed, node)
        if name in SOURCE_CALLS:
            return f"{receiver}.{name}" if receiver else name
        return None
    if node.type == "identifier":
        text = _text(parsed, node)
        # `request` / `req` used bare are the servlet request object.
        if text in ("request", "req"):
            return text
    return None


def _contains_source(parsed: ParsedFile, node: Node) -> str | None:
    stack = [node]
    while stack:
        current = stack.pop()
        label = _source_label(parsed, current)
        if label:
            return label
        stack.extend(current.children)
    return None


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
    """The variables an assignment or declaration introduces."""
    if node is None:
        return []
    if node.type == "variable_declarator":
        return [_text(parsed, node.child_by_field_name("name"))]
    if node.type == "formal_parameter":
        return [_text(parsed, node.child_by_field_name("name"))]
    if node.type == "identifier":
        return [_text(parsed, node)]
    return [_text(parsed, child) for child in _identifiers(node)]


def _parameter_annotations(parsed: ParsedFile, param: Node) -> list[str]:
    """Annotation names on a parameter.

    A bare `@RequestParam` is a `marker_annotation` and one with arguments is an
    `annotation`; both bind the parameter to the request, so both are read.
    """
    names: list[str] = []
    for child in param.children:
        if child.type != "modifiers":
            continue
        for modifier in child.children:
            if modifier.type not in ("annotation", "marker_annotation"):
                continue
            for inner in modifier.children:
                if inner.type in ("identifier", "type_identifier"):
                    names.append(_text(parsed, inner))
    return names


def _method_sources(parsed: ParsedFile, method: Node) -> set[str]:
    """Parameters of this method that an HTTP request supplies."""
    params = method.child_by_field_name("parameters")
    if params is None:
        return set()
    out: set[str] = set()
    for param in params.children:
        if param.type != "formal_parameter":
            continue
        if any(name in SOURCE_ANNOTATIONS for name in _parameter_annotations(parsed, param)):
            out.update(n for n in _target_names(parsed, param) if n)
    return out


def _sanitisers_in(parsed: ParsedFile, node: Node) -> list[str]:
    """Every sanitiser-shaped call in the enclosing method.

    The scope is the method rather than the sink's own arguments because a
    sanitiser is normally applied where the value is built — `String c =
    escapeHtml(v); Runtime.exec(c)` — and scanning only the sink would never see
    it. This is a record, not a decision: the path is still reported, because a
    sanitiser that looks correct and is not would otherwise hide a real flow.
    """
    method = node
    while method is not None and method.type not in (
        "method_declaration",
        "function_declaration",
        "constructor_declaration",
        "program",
    ):
        method = method.parent
    if method is None:
        return []
    out: list[str] = []
    stack = [method]
    while stack:
        current = stack.pop()
        if current.type == "method_invocation":
            _, name = _method_invocation_parts(parsed, current)
            if name and any(hint in name.lower() for hint in SANITISER_HINTS):
                out.append(name)
        stack.extend(current.children)
    return out


def _scopes(parsed: ParsedFile) -> list[tuple[str, int, int]]:
    out: list[tuple[str, int, int]] = []
    for node in parsed.walk():
        if node.type not in ("method_declaration", "function_declaration", "constructor_declaration"):
            continue
        name = _text(parsed, node.child_by_field_name("name")) or "<anon>"
        out.append((name, line_of(node), node.end_point[0] + 1))
    return out


def collect_tainted(parsed: ParsedFile, *, extra_source=None) -> ScopeTaint:
    """Propagate request data through local variables, per method.

    `extra_source` is the interprocedural hook: it labels a node as tainted from
    outside this file, which is how a caller's argument reaches a callee's sink
    without a second propagation engine.
    """
    collected = ScopeTaint(scopes=_scopes(parsed))
    for method in parsed.walk():
        if method.type not in (
            "method_declaration",
            "function_declaration",
            "constructor_declaration",
        ):
            continue
        scope = _text(parsed, method.child_by_field_name("name")) or "<anon>"
        body = method.child_by_field_name("body")
        if body is None:
            continue
        # Parameters an annotation binds to the request start tainted.
        for name in _method_sources(parsed, method):
            collected.tainted.setdefault(scope, {})[name] = f"param:{name}"
            collected.lines.setdefault(scope, {})[name] = line_of(method)

        for node in _walk(body):
            # `String q = expr;` is a local_variable_declaration wrapping a
            # variable_declarator; a later `q = expr;` is an
            # assignment_expression. Both introduce a name bound to a value.
            if node.type == "local_variable_declaration":
                for declarator in node.children:
                    if declarator.type != "variable_declarator":
                        continue
                    _bind(parsed, collected, scope, declarator, line_of(node), extra_source)
            elif node.type == "assignment_expression":
                _bind(parsed, collected, scope, node, line_of(node), extra_source)
            elif node.type in ("variable_declarator", "assignment"):
                _bind(parsed, collected, scope, node, line_of(node), extra_source)
    return collected


def _bind(
    parsed: ParsedFile,
    collected: ScopeTaint,
    scope: str,
    node: Node,
    line: int,
    extra_source,
) -> None:
    """Propagate taint from a declarator's or assignment's right side to its name."""
    value = node.child_by_field_name("value")
    if value is None:
        value = node.child_by_field_name("right")
    if value is None:
        return
    target = node.child_by_field_name("left") or node.child_by_field_name("name")
    label = _first_label(parsed, value, extra_source, collected.tainted.get(scope, {}))
    if label is None:
        return
    names = _target_names(parsed, target) if target is not None else []
    if not names:
        # A declarator names its variable with a bare identifier child rather
        # than a field, so fall back to the first identifier that is not the
        # one the value already contributed.
        names = [_text(parsed, node.children[0])] if node.children else []
    for name in names:
        if not name:
            continue
        collected.tainted.setdefault(scope, {})[name] = label
        collected.lines.setdefault(scope, {})[name] = line


def _walk(node: Node) -> list[Node]:
    out: list[Node] = []
    stack = [node]
    while stack:
        current = stack.pop()
        out.append(current)
        stack.extend(reversed(current.children))
    return out


def _first_label(
    parsed: ParsedFile,
    node: Node | None,
    extra_source=None,
    tainted: dict[str, str] | None = None,
) -> str | None:
    """The first taint in a subtree: a request read, or an already-tainted name.

    The `tainted` map is what makes propagation work at all. `"SELECT " + id`
    contains no request read — `id` is a parameter that was tainted earlier, and
    recognising it here is how the taint reaches `q`.
    """
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
        if node.type != "method_invocation":
            continue
        line = line_of(node)
        _, name = _method_invocation_parts(parsed, node)
        call = sink_index.get((line, name))
        if call is None:
            continue

        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        scope = collected.scope_for(line)
        tainted_here = collected.tainted.get(scope, {})

        label: str | None = None
        for identifier in _identifiers(args):
            name_text = _text(parsed, identifier)
            if name_text in tainted_here:
                label = tainted_here[name_text]
                break
        if label is None:
            if extra_source is not None:
                label = extra_source(args)
            if label is None:
                label = _contains_source(parsed, args)
        if label is None:
            continue

        key = f"{label}->{call.callee}@{line}"
        if key in seen:
            continue
        seen.add(key)

        via: list[str] = []
        sanitisers = _sanitisers_in(parsed, node)
        if sanitisers:
            # Recorded, not applied: a sanitiser that looks correct and is not
            # would otherwise hide a real path.
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
    """Source→sink flows for one JVM file."""
    collected = collect_tainted(parsed)
    return find_sinks(parsed, symbols, collected)
