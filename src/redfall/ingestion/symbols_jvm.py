"""Symbol extraction for Java and Kotlin.

Emits the same `FileSymbols` the TypeScript and Python extractors emit, so
everything downstream — the graph, the planner, the planner's prompt — treats a
JVM repository exactly like the two languages that were already supported.

Two things are specific to this ecosystem and worth stating, because they are
the reason the code is shaped as it is:

* **Routes live on annotations, not calls.** `@GetMapping("/x")` is a decorator
  on a method, and the controller's own class-level `@RequestMapping` supplies a
  prefix. Both have to be read, and the class prefix has to reach the method's
  route — that is what `_class_prefix` exists for.
* **Spring's method annotations are a closed set.** The list below is the one
  Spring MVC defines. Guessing a route from a method named `get` would invent
  endpoints, which is the one thing this pipeline must never do.
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

# The HTTP verbs Spring MVC exposes as method-level annotations, mapped to the
# verb they answer. A method without one of these is not a route.
SPRING_METHODS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
    "RequestMapping": "ANY",
}

# Class-level annotations that give a controller its prefix.
SPRING_CONTROLLERS = {
    "RestController",
    "Controller",
    "RequestMapping",
}

# JAX-RS, the other common JVM routing style.
JAXRS_METHODS = {
    "GET": "GET",
    "POST": "POST",
    "PUT": "PUT",
    "DELETE": "DELETE",
    "PATCH": "PATCH",
}

# Calls worth classifying. `kind` is the taint vocabulary: db | exec | fs | fetch.
SINK_CALLS: dict[str, tuple[str, str]] = {
    # exec
    "exec": ("exec", "exec"),
    "execSync": ("exec", "exec"),
    "ProcessBuilder": ("exec", "exec"),
    "start": ("exec", "exec"),
    # db
    "executeQuery": ("db", "db"),
    "executeUpdate": ("db", "db"),
    "execute": ("db", "db"),
    "prepareStatement": ("db", "db"),
    "createQuery": ("db", "db"),
    "createNativeQuery": ("db", "db"),
    # fs
    "FileInputStream": ("fs", "fs"),
    "FileOutputStream": ("fs", "fs"),
    "readAllBytes": ("fs", "fs"),
    "write": ("fs", "fs"),
    "readString": ("fs", "fs"),
    # fetch
    "openConnection": ("fetch", "fetch"),
    "openStream": ("fetch", "fetch"),
}

# A sink whose safety depends entirely on the receiver. `run` on a Runtime is
# process execution; `run` on anything else is not. `query` on a Statement is a
# query; a `query` helper a project defines itself usually is not.
RECEIVER_GATED: dict[str, tuple[str, str, set[str]]] = {
    "exec": ("exec", "exec", {"Runtime", "ProcessBuilder"}),
    "executeQuery": ("db", "db", {"stmt", "statement", "conn", "connection"}),
}


def _text(parsed: ParsedFile, node) -> str:
    if node is None:
        return ""
    return parsed.text_of(node)


def _annotation_name(parsed: ParsedFile, node) -> str:
    """The bare name of an annotation: `@GetMapping(..)` -> `GetMapping`."""
    if node is None or node.type != "annotation":
        return ""
    for child in node.children:
        if child.type in ("identifier", "type_identifier"):
            return _text(parsed, child)
    return ""


def _annotation_arguments(parsed: ParsedFile, node) -> list[str]:
    """Every string literal the annotation was called with.

    Both `@GetMapping("/x")` and `@RequestMapping(path = "/x")` carry the path
    as a string; taking the literals rather than parsing the argument grammar
    means both forms are read, and a named argument is not silently dropped.
    """
    if node is None:
        return []
    out: list[str] = []
    for child in node.children:
        if child.type == "annotation_argument_list":
            out.extend(_string_literals(parsed, child))
    return out


def _string_literals(parsed: ParsedFile, node) -> list[str]:
    out: list[str] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "string_literal":
            out.append(_unquote(_text(parsed, current)))
        elif current.type in ("array_initializer", "element_value_array_initializer"):
            stack.extend(current.children)
        else:
            stack.extend(current.children)
    return out


def _unquote(text: str) -> str:
    stripped = text.strip()
    if len(stripped) >= 2 and stripped[0] in "\"'" and stripped[-1] == stripped[0]:
        return stripped[1:-1]
    return stripped


def _annotations_of(parsed: ParsedFile, node) -> list[tuple[str, list[str]]]:
    """Every annotation attached to a declaration, with its arguments."""
    out: list[tuple[str, list[str]]] = []
    for child in node.children:
        if child.type == "modifiers":
            for modifier in child.children:
                if modifier.type == "annotation":
                    out.append(
                        (
                            _annotation_name(parsed, modifier),
                            _annotation_arguments(parsed, modifier),
                        )
                    )
    return out


def _class_prefix(parsed: ParsedFile, class_node) -> str:
    """The path prefix a controller declares for every method it holds."""
    for name, args in _annotations_of(parsed, class_node):
        if name in SPRING_CONTROLLERS and args:
            return args[0]
    return ""


def _join(prefix: str, path: str) -> str:
    if not prefix:
        return path or "/"
    if not path:
        return prefix
    return prefix.rstrip("/") + "/" + path.lstrip("/")


def _method_routes(parsed: ParsedFile, method, class_prefix: str) -> list[RouteSymbol]:
    """Turn a method's annotations into routes. A method with none yields none."""
    routes: list[RouteSymbol] = []
    annotations = _annotations_of(parsed, method)
    handler = _text(parsed, method.child_by_field_name("name"))
    for name, args in annotations:
        if name in SPRING_METHODS:
            verb = SPRING_METHODS[name]
            values = args or [""]
            for value in values:
                routes.append(
                    RouteSymbol(
                        method=verb,
                        path=_join(class_prefix, value),
                        line=line_of(method),
                        end_line=line_of(method),
                        handler=handler,
                        receiver="controller",
                    )
                )
        elif name in JAXRS_METHODS and class_prefix is None:
            # JAX-RS uses a bare verb annotation; the class carries @Path.
            routes.append(
                RouteSymbol(
                    method=JAXRS_METHODS[name],
                    path="/",
                    line=line_of(method),
                    end_line=line_of(method),
                    handler=handler,
                    receiver="resource",
                )
            )
    return routes


def extract_symbols(parsed: ParsedFile) -> FileSymbols:
    """Walk one parsed JVM file and collect every symbol Redfall cares about."""
    result = FileSymbols(path=parsed.path)
    nodes = parsed.walk()

    # --- imports ---------------------------------------------------------
    for node in nodes:
        if node.type != "import_declaration":
            continue
        # A wildcard import is `scoped_identifier` *and* an `asterisk` sibling,
        # not a scoped identifier containing one. Reading the package from the
        # sibling is what makes `import java.util.*` resolve to `java.util`
        # rather than to a type named `*`.
        wildcard = any(child.type == "asterisk" for child in node.children)
        for child in node.children:
            if child.type != "scoped_identifier":
                continue
            full = _text(parsed, child)
            if wildcard:
                result.imports.append(
                    ImportSymbol(name="*", source=full, line=line_of(node))
                )
            else:
                name = full.rsplit(".", 1)[-1]
                result.imports.append(
                    ImportSymbol(name=name, source=full, line=line_of(node), origin=name)
                )

    # --- classes and their routes ----------------------------------------
    for node in nodes:
        if node.type in ("class_declaration", "interface_declaration", "object_declaration"):
            class_prefix = _class_prefix(parsed, node)
            class_name = _text(parsed, node.child_by_field_name("name"))
            body = node.child_by_field_name("body")
            if body is None:
                continue
            for member in body.children:
                if member.type not in ("method_declaration", "function_declaration"):
                    continue
                name = _text(parsed, member.child_by_field_name("name"))
                params = _text(parsed, member.child_by_field_name("parameters")) or ""
                result.functions.append(
                    FunctionSymbol(
                        name=name,
                        line=line_of(member),
                        end_line=line_of(member),
                        is_exported=params.startswith("public") or class_prefix != "",
                    )
                )
                result.routes.extend(_method_routes(parsed, member, class_prefix))

            # A controller mounted as a field, as Spring sometimes writes it.
            if class_prefix:
                result.mounts.append(
                    MountSymbol(prefix=class_prefix, local_name=class_name, line=line_of(node))
                )

    # --- top-level functions (Kotlin) ------------------------------------
    for node in nodes:
        if node.type == "function_declaration":
            parent_is_class = any(
                ancestor.type in ("class_declaration", "object_declaration")
                for ancestor in _ancestors(node)
            )
            if parent_is_class:
                continue
            name = _text(parsed, node.child_by_field_name("name"))
            result.functions.append(
                FunctionSymbol(name=name, line=line_of(node), end_line=line_of(node), is_exported=True)
            )

    # --- calls ------------------------------------------------------------
    for node in nodes:
        if node.type not in ("method_invocation", "object_creation_expression"):
            continue
        callee = ""
        receiver = ""
        if node.type == "method_invocation":
            callee = _text(parsed, node.child_by_field_name("name"))
            receiver = _text(parsed, node.child_by_field_name("object"))
        else:
            callee = _text(parsed, node.child_by_field_name("type"))
        kind = _classify(callee, receiver)
        if kind is None:
            continue
        args = _text(parsed, node.child_by_field_name("arguments")) or ""
        result.calls.append(
            CallSymbol(
                kind=kind,
                callee=callee,
                line=line_of(node),
                arg_text=args,
                enclosing_function=_enclosing_function(parsed, node),
            )
        )

    return result


def _ancestors(node):
    parent = node.parent
    while parent is not None:
        yield parent
        parent = parent.parent


def _enclosing_function(parsed: ParsedFile, node) -> str:
    """The name of the method this call sits inside, or empty at file scope."""
    for ancestor in _ancestors(node):
        if ancestor.type in ("method_declaration", "function_declaration", "constructor_declaration"):
            return _text(parsed, ancestor.child_by_field_name("name"))
    return ""


def _classify(callee: str, receiver: str) -> str | None:
    """The sink kind a call resolves to, or None if it is not a sink.

    A receiver-gated call is only a sink when the receiver looks like the type
    that makes it dangerous — `Runtime.getRuntime().exec` is process execution,
    a project's own `exec` helper is not, and treating it as one would produce a
    taint path to a sink that can never be exploited.
    """
    gated = RECEIVER_GATED.get(callee)
    if gated is not None:
        kind, _label, receivers = gated
        if any(token in receiver for token in receivers):
            return kind
        return None
    entry = SINK_CALLS.get(callee)
    if entry is None:
        return None
    return entry[0]
