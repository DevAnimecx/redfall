"""Intraprocedural source→sink taint analysis over the tree-sitter tree.

Design notes that matter for the numbers:

* The analysis is **per enclosing function**. A variable assigned from
  `req.body` in one handler does not taint a same-named variable in another.
* Taint propagates through assignment (`const q = req.query.username`),
  destructuring (`const { id } = req.params`) and through call results whose
  arguments are tainted (`path.join(UPLOAD_DIR, req.body.filename)`).
* A "sanitiser" is **recorded but never clears taint**. Redfall does not claim to
  know that `escapeHtml` neutralises an SQL sink; it does not, and pretending
  otherwise is how false negatives get created. Sanitisers surface in `via` and
  the sandbox stage is what decides whether the path is real.

`collect_tainted` is also the seeding point of the interprocedural pass
(`inter_ts.py`), exactly as it is for Python: pre-tainted parameters let it
summarise which parameters can reach a sink, without a second propagation
engine that could drift away from this one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Node

from .tree import ParsedFile, line_of
# (property chain prefix, label)
SOURCE_PROPS = [
    ("req.body", "req.body"),
    ("req.query", "req.query"),
    ("req.params", "req.params"),
    ("req.headers", "req.headers"),
    ("req.cookies", "req.cookies"),
    ("request.body", "request.body"),
    ("request.query", "request.query"),
    ("ctx.request.body", "ctx.request.body"),
]

SOURCE_IDENTIFIERS = {"req", "request"}
SOURCE_CALLS = {"text", "json", "buffer", "rawBody"}

DANGEROUS_SINK_CALLS = {
    "query",
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "spawn",
    "spawnSync",
    "fork",
    "readFile",
    "readFileSync",
    "writeFile",
    "writeFileSync",
    "createReadStream",
    "createWriteStream",
    "unlink",
    "unlinkSync",
    "open",
    "openSync",
    "eval",
    "Function",
    "render",
    "redirect",
}

SANITISER_HINTS = (
    "escape",
    "sanitize",
    "sanitise",
    "encode",
    "parameterize",
    "validate",
    "parseInt",
    "parseFloat",
    "Number(",
    "trim",
    "normalize",
    "replace",
)


@dataclass
class Taint:
    """One source→sink flow."""

    source: str
    sink: str
    sink_kind: str
    line: int
    symbol: str
    via: list[str] = field(default_factory=list)
    snippet: str = ""

    @property
    def dedupe_key(self) -> str:
        return f"{self.source}->{self.sink}@{self.line}"


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


def _text(parsed: ParsedFile, node: Node | None) -> str:
    if node is None:
        return ""
    return parsed.text_of(node).strip()


def _identifiers(node: Node) -> list[tuple[str, int]]:
    """Every identifier/property-expression text in a subtree, with its line."""
    out: list[tuple[str, int]] = []
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type in ("identifier", "shorthand_property_identifier"):
            out.append((cur.text.decode("utf-8", errors="replace"), cur.start_point[0] + 1))
        elif cur.type == "member_expression":
            out.append((cur.text.decode("utf-8", errors="replace"), cur.start_point[0] + 1))
        stack.extend(cur.children)
    return out


def _declared_names(node: Node) -> list[str]:
    """Names bound on the left-hand side of a declarator / assignment."""
    names: list[str] = []

    def walk(n: Node) -> None:
        if n.type in ("identifier", "shorthand_property_identifier"):
            names.append(n.text.decode("utf-8", errors="replace"))
        elif n.type == "pair":
            key = n.child_by_field_name("key")
            value = n.child_by_field_name("value")
            if key is not None and value is None:
                names.append(key.text.decode("utf-8", errors="replace"))
            for child in n.children:
                walk(child)
        else:
            for child in n.children:
                walk(child)

    walk(node)
    return names


def _member_chain(parsed: ParsedFile, node: Node) -> str | None:
    """`req.body.x` → 'req.body'; returns None when the expression is not a chain."""
    if node.type != "member_expression":
        return None
    full = _text(parsed, node)
    for prefix, label in SOURCE_PROPS:
        if full == prefix or full.startswith(prefix + ".") or full.startswith(prefix + "["):
            return label
    return None


def _is_source_node(parsed: ParsedFile, node: Node) -> str | None:
    """If this node reads attacker-controlled input, return the source label."""
    chain = _member_chain(parsed, node)
    if chain:
        return chain
    if node.type == "subscript_expression":
        obj = node.child_by_field_name("object")
        inner = _member_chain(parsed, obj) if obj is not None else None
        if inner:
            return inner
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type == "member_expression":
            obj = node.child_by_field_name("object") or fn.child_by_field_name("object")
            prop = fn.child_by_field_name("property")
            prop_name = _text(parsed, prop)
            obj_text = _text(parsed, obj)
            if prop_name in SOURCE_CALLS and obj_text in SOURCE_IDENTIFIERS:
                return f"{obj_text}.{prop_name}()"
            inner = _member_chain(parsed, obj) if obj is not None else None
            if inner and prop_name in SOURCE_CALLS:
                return f"{inner}.{prop_name}()"
    return None


def _contains_source(parsed: ParsedFile, node: Node) -> str | None:
    """First source label found anywhere inside `node`."""
    stack = [node]
    while stack:
        cur = stack.pop()
        label = _is_source_node(parsed, cur)
        if label:
            return label
        stack.extend(cur.children)
    return None


def _sanitisers_in(parsed: ParsedFile, node: Node) -> list[str]:
    found: list[str] = []
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type == "call_expression":
            fn = cur.child_by_field_name("function")
            name = _text(parsed, fn)
            if any(hint in name for hint in SANITISER_HINTS):
                found.append(name)
        stack.extend(cur.children)
    return sorted(set(found))


def _sink_label(parsed: ParsedFile, node: Node) -> tuple[str, str] | None:
    """(label, kind) when this call is a dangerous sink."""
    if node.type != "call_expression":
        return None
    fn = node.child_by_field_name("function")
    if fn is None:
        return None
    if fn.type == "member_expression":
        obj = _text(parsed, fn.child_by_field_name("object"))
        prop = _text(parsed, fn.child_by_field_name("property"))
        label = f"{obj}.{prop}"
    else:
        obj, prop, label = "", _text(parsed, fn), _text(parsed, fn)

    if prop not in DANGEROUS_SINK_CALLS:
        return None
    if prop == "query" and obj not in ("pool", "client", "db", "pg", "connection", "knex"):
        return None
    if prop in ("render", "redirect") and obj not in ("res", "response", "ctx", "reply"):
        return None
    if prop in ("eval", "Function"):
        return label, "exec"
    if prop in ("exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"):
        return label, "exec"
    if prop == "query":
        return label, "db"
    return label, "fs"


# Public names for the interprocedural pass: both passes must share one source
# model and one identifier reader, so `inter_ts.py` imports these instead of
# reimplementing them. (`identifiers_in` yields (text, line) pairs here.)
contains_source = _contains_source
identifiers_in = _identifiers
sink_label = _sink_label


def collect_tainted(
    parsed: ParsedFile, symbols, seeds: dict[str, dict[str, str]] | None = None
) -> ScopeTaint:
    """Propagate taint through declarations, assignments and for-of bindings.

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

    for node in parsed.walk():
        # direct source use as an argument is handled at the sink; here we only
        # track propagation into named variables
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node is None or value_node is None:
                continue
            label = _contains_source(parsed, value_node)
            scope = result.scope_for(line_of(node))
            if label:
                for nm in _declared_names(name_node):
                    mark(scope, nm, label, line_of(node))
            else:
                # propagate through previously tainted locals
                for ident, _ln in _identifiers(value_node):
                    known = result.tainted.get(scope, {}).get(ident)
                    if known:
                        for nm in _declared_names(name_node):
                            mark(scope, nm, known, line_of(node))
                        break
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                continue
            scope = result.scope_for(line_of(node))
            label = _contains_source(parsed, right)
            if not label:
                for ident, _ln in _identifiers(right):
                    known = result.tainted.get(scope, {}).get(ident)
                    if known:
                        label = known
                        break
            if label:
                for nm in _declared_names(left):
                    mark(scope, nm, label, line_of(node))
        elif node.type == "for_in_statement" or node.type == "for_of_statement":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                continue
            label = _contains_source(parsed, right)
            if label:
                scope = result.scope_for(line_of(node))
                for nm in _declared_names(left):
                    mark(scope, nm, label, line_of(node))

    return result


def analyse_taint(parsed: ParsedFile, symbols) -> list[Taint]:
    """Find every source→sink flow inside each enclosing function."""
    findings: list[Taint] = []
    seen: set[str] = set()
    collected = collect_tainted(parsed, symbols)

    for node in parsed.walk():
        labelled = _sink_label(parsed, node)
        if labelled is None:
            continue
        label, kind = labelled
        line = line_of(node)
        scope = collected.scope_for(line)
        args = node.child_by_field_name("arguments")
        if args is None:
            continue

        scope_taint = collected.tainted.get(scope, {})
        hits: list[str] = []
        for ident, _ln in _identifiers(args):
            if ident in scope_taint:
                hits.append(ident)
        direct = _contains_source(parsed, args)

        if not hits and not direct:
            continue

        via: list[str] = []
        if direct:
            via.append(f"{direct} used directly")
        for h in sorted(set(hits)):
            src = scope_taint.get(h, "?")
            ln = collected.lines.get(scope, {}).get(h)
            via.append(f"{src} -> {h}" + (f" (line {ln})" if ln else ""))
        for san in _sanitisers_in(parsed, args):
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
