"""Intraprocedural source→sink taint analysis for Python.

Same doctrine as the TypeScript analyser: per enclosing function, propagation
through assignment / for / with / augmented assignment, and sanitisers are
recorded but never clear taint — the sandbox decides whether a path is real.

Sources are the request surfaces of Flask/FastAPI/Django plus module-level
`flask.request` aliases. Sinks are whatever `classify_call` recognises in
`symbols_py`, resolved through the file's import aliases.

`collect_tainted` is also the seeding point of the interprocedural pass
(`inter.py`): pre-tainted parameters let it summarise which parameters can
reach a sink inside a function, without a second propagation engine that could
drift away from this one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Node

from .symbols_py import classify_call, dotted, import_aliases, resolve_dotted
from .taint import Taint
from .tree import ParsedFile, line_of

SOURCE_PREFIXES = (
    "request.args",
    "request.form",
    "request.json",
    "request.get_json",
    "request.values",
    "request.data",
    "request.files",
    "request.cookies",
    "request.headers",
    "request.GET",
    "request.POST",
    "request.body",
    "request.query_params",
)

SANITISER_HINTS = (
    "escape",
    "sanitize",
    "sanitise",
    "quote",
    "clean",
    "validate",
    "encode",
    "replace",
    "slugify",
    "secure_filename",
)


def _text(parsed: ParsedFile, node: Node | None) -> str:
    if node is None:
        return ""
    return parsed.text_of(node).strip()


def _dotted_expr(parsed: ParsedFile, node: Node | None) -> str:
    """Dotted text for attribute/call/subscript chains, else raw text."""
    if node is None:
        return ""
    if node.type == "attribute":
        obj = _dotted_expr(parsed, node.child_by_field_name("object"))
        attr = _text(parsed, node.child_by_field_name("attribute"))
        return f"{obj}.{attr}" if obj else attr
    if node.type == "call":
        return _dotted_expr(parsed, node.child_by_field_name("function")) + "()"
    if node.type == "subscript":
        return _dotted_expr(parsed, node.child_by_field_name("value"))
    return _text(parsed, node)


def _source_label(parsed: ParsedFile, node: Node) -> str | None:
    """If this node reads attacker-controlled input, return the source label."""
    raw = _dotted_expr(parsed, node)
    if not raw:
        return None
    is_call = raw.endswith("()")
    base = raw[:-2] if is_call else raw
    base = base.removeprefix("flask.")
    for prefix in SOURCE_PREFIXES:
        if base == prefix or base.startswith(prefix + "."):
            return f"{base}()" if is_call else prefix
    return None


def _contains_source(parsed: ParsedFile, node: Node) -> str | None:
    stack = [node]
    while stack:
        cur = stack.pop()
        label = _source_label(parsed, cur)
        if label:
            return label
        stack.extend(cur.children)
    return None


def _identifiers(node: Node) -> list[str]:
    out: list[str] = []
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type == "identifier":
            out.append(cur.text.decode("utf-8", errors="replace"))
        stack.extend(cur.children)
    return out


def _target_names(node: Node | None) -> list[str]:
    """Names bound by an assignment target; attribute/subscript targets are skipped."""
    if node is None:
        return []
    if node.type == "identifier":
        return [node.text.decode("utf-8", errors="replace")]
    if node.type in ("pattern_list", "tuple_pattern", "list_pattern", "as_pattern_target", "tuple"):
        names: list[str] = []
        for c in node.children:
            names.extend(_target_names(c))
        return names
    return []


def _sanitisers_in(parsed: ParsedFile, node: Node, aliases: dict[str, str]) -> list[str]:
    found: list[str] = []
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type == "call":
            callee = resolve_dotted(dotted(parsed, cur.child_by_field_name("function")), aliases)
            if any(hint in callee for hint in SANITISER_HINTS):
                found.append(callee)
        stack.extend(cur.children)
    return sorted(set(found))


# Public names for the interprocedural pass: both passes must share one source
# model and one identifier reader, so `inter.py` imports these instead of
# reimplementing them.
contains_source = _contains_source
identifiers_in = _identifiers


@dataclass
class ScopeTaint:
    """Scope -> variable -> label, plus the line the variable was tainted at."""

    tainted: dict[str, dict[str, str]] = field(default_factory=dict)
    lines: dict[str, dict[str, int]] = field(default_factory=dict)
    scopes: list[tuple[str, int, int]] = field(default_factory=list)

    def scope_for(self, line: int) -> str:
        best = "<module>"
        best_span = 10**9
        for name, start, end in self.scopes:
            if start <= line <= end and (end - start) < best_span:
                best = name
                best_span = end - start
        return best


def collect_tainted(
    parsed: ParsedFile, symbols, seeds: dict[str, dict[str, str]] | None = None
) -> ScopeTaint:
    """Propagate taint through assignment / for / with / augmented assignment.

    `seeds` pre-taints named variables per scope before the pass runs; the
    interprocedural pass uses it to ask "what can this parameter reach?".
    Labels travel with the value, so every attribution stays auditable.
    """
    result = ScopeTaint(
        scopes=sorted(
            ((fn.name, fn.line, fn.end_line) for fn in symbols.functions),
            key=lambda s: (s[1], -(s[2] - s[1])),
        )
    )
    for scope_name, marks in (seeds or {}).items():
        for name, label in marks.items():
            result.tainted.setdefault(scope_name, {})[name] = label

    def mark(scope: str, name: str, label: str, line: int) -> None:
        result.tainted.setdefault(scope, {})[name] = label
        result.lines.setdefault(scope, {})[name] = line

    def propagate(scope: str, source_node: Node | None, targets: list[str], line: int) -> None:
        if source_node is None or not targets:
            return
        label = _contains_source(parsed, source_node)
        if not label:
            for ident in _identifiers(source_node):
                if ident in result.tainted.get(scope, {}):
                    label = result.tainted[scope][ident]
                    break
        if label:
            for name in targets:
                mark(scope, name, label, line)

    for node in parsed.walk():
        if node.type == "assignment":
            line = line_of(node)
            propagate(
                result.scope_for(line),
                node.child_by_field_name("right"),
                _target_names(node.child_by_field_name("left")),
                line,
            )
        elif node.type == "augmented_assignment":
            line = line_of(node)
            left = node.child_by_field_name("left")
            if left is not None and left.type == "identifier":
                scope = result.scope_for(line)
                name = _text(parsed, left)
                label = result.tainted.get(scope, {}).get(name) or _contains_source(
                    parsed, node.child_by_field_name("right")
                )
                if label:
                    mark(scope, name, label, line)
        elif node.type == "for_statement":
            line = line_of(node)
            propagate(result.scope_for(line), node.child_by_field_name("right"), _target_names(node.child_by_field_name("left")), line)
        elif node.type == "with_item":
            line = line_of(node)
            child = node.named_children[0] if node.named_children else None
            if child is None:
                continue
            if child.type == "as_pattern":
                alias = child.child_by_field_name("alias")
                value = next((c for c in child.named_children if c is not alias), None)
                propagate(result.scope_for(line), value, _target_names(alias), line)

    return result


def analyse_taint(parsed: ParsedFile, symbols) -> list[Taint]:
    """Find every source→sink flow inside each enclosing function."""
    findings: list[Taint] = []
    seen: set[str] = set()
    aliases = import_aliases(symbols.imports)
    collected = collect_tainted(parsed, symbols)
    tainted = collected.tainted
    source_lines = collected.lines

    for node in parsed.walk():
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
        line = line_of(node)
        scope = collected.scope_for(line)
        args = node.child_by_field_name("arguments")
        if args is None:
            continue

        scope_taint = tainted.get(scope, {})
        hits = [ident for ident in _identifiers(args) if ident in scope_taint]
        direct = _contains_source(parsed, args)
        if not hits and not direct:
            continue

        via: list[str] = []
        if direct:
            via.append(f"{direct} used directly")
        for hit in sorted(set(hits)):
            src = scope_taint.get(hit, "?")
            ln = source_lines.get(scope, {}).get(hit)
            via.append(f"{src} -> {hit}" + (f" (line {ln})" if ln else ""))
        for san in _sanitisers_in(parsed, args, aliases):
            via.append(f"sanitiser present but not modelled: {san}()")

        source_label = direct or (scope_taint.get(sorted(set(hits))[0], "unknown") if hits else "unknown")
        snippet = parsed.text_of(node)
        if len(snippet) > 400:
            snippet = snippet[:400] + "…"

        taint = Taint(
            source=source_label,
            sink=label,
            sink_kind=kind,
            line=line,
            symbol=scope,
            via=via,
            snippet=snippet,
        )
        if taint.dedupe_key in seen:
            continue
        seen.add(taint.dedupe_key)
        findings.append(taint)

    findings.sort(key=lambda t: t.line)
    return findings
