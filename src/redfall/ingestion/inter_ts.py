"""Depth-one interprocedural taint over the TypeScript/JavaScript files of one
scan.

Mirrors `inter.py` for Python, with the resolution rules that are honest in JS:

  * a function declared in the same file,
  * a function reached through a relative import — named (`import { f } from
    './m'`), aliased (`f as g`), namespace (`import * as m`) or CommonJS
    (`const m = require('./m')`, `const { f } = require('./m')`) — resolved
    against the actual scanned file set with the standard extension and
    `index.*` candidates.

Default imports are skipped: without knowing which declaration is the default
export, mapping the local name to a function would be a guess. Bare specifiers
(npm packages) never resolve inside the scan. Where a specifier cannot be
resolved to exactly one scanned file the edge is dropped, not guessed.

How a hop is proved: identical to the Python pass — a callee's parameters are
pre-tainted with `param:<name>` labels and the labels that reach a sink *are*
the summary; a call site becomes a hop only when the caller's argument is
already tainted by a real source and the matching parameter reaches the sink.
Depth one, no cycles, no caller-context leakage into summaries.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field

from .inter import CallEdge, InterFile
from .symbols import ImportSymbol, arrow_or_function_name
from .taint import Taint, collect_tainted, contains_source, identifiers_in, sink_label
from .tree import ParsedFile, line_of

TS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_CANDIDATE_SUFFIXES = ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")


@dataclass
class _CallSite:
    callee: str
    line: int
    caller_function: str
    # (identifiers read by the argument, direct source label if any)
    positional: list[tuple[list[str], str | None]]


@dataclass
class _ParamHop:
    param: str
    sink: str
    sink_kind: str
    line: int
    snippet: str


def _resolve_spec(current_rel: str, spec: str, index: set[str]) -> str | None:
    """Specifier -> scanned file, using Node's file-before-index preference."""
    if not spec.startswith("."):
        return None
    base = posixpath.normpath(posixpath.join(posixpath.dirname(current_rel), spec))
    for suffix in _CANDIDATE_SUFFIXES:
        candidate = base + suffix
        if candidate in index:
            return candidate
    for suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs"):
        candidate = f"{base}/index{suffix}"
        if candidate in index:
            return candidate
    return None


def call_bindings(imports: list[ImportSymbol]) -> dict[str, tuple[str, str | None]]:
    """Local name -> (specifier, imported function name; None for a namespace)."""
    out: dict[str, tuple[str, str | None]] = {}
    for imp in imports:
        if not imp.source or not imp.name or imp.is_default:
            continue
        if imp.origin == "*":
            out[imp.name] = (imp.source, None)
        elif imp.origin:
            out[imp.name] = (imp.source, imp.origin)
        else:
            out[imp.name] = (imp.source, imp.name)
    return out


def _callee_text(parsed: ParsedFile, node) -> str:
    if node.type == "identifier":
        return parsed.text_of(node).strip()
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj is None or prop is None:
            return ""
        head = _callee_text(parsed, obj)
        return f"{head}.{parsed.text_of(prop).strip()}" if head else ""
    return ""


def _callee_is_plain(node) -> bool:
    """A callable expression without a nested call: `getPool().query(x)` mixes
    two calls, so its arguments cannot be attributed to the inner one."""
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type == "call_expression":
            return False
        stack.extend(cur.children)
    return True


def resolve_callee(
    current_rel: str,
    callee_text: str,
    bindings: dict[str, tuple[str, str | None]],
    index: set[str],
    by_rel: dict[str, InterFile],
) -> tuple[str, str] | None:
    """(file, function) for a callee that provably exists in the scan, else None."""
    if not callee_text:
        return None
    parts = callee_text.split(".")
    head = parts[0]
    binding = bindings.get(head)
    if binding is not None:
        spec, origin = binding
        path = _resolve_spec(current_rel, spec, index)
        if path is None:
            return None
        target = by_rel[path]
        if origin is None:
            if len(parts) != 2:
                return None
            fn_name = parts[1]
        else:
            if len(parts) != 1:
                return None
            fn_name = origin
        if fn_name in {fn.name for fn in target.symbols.functions}:
            return path, fn_name
        return None
    if len(parts) == 1:
        local = {fn.name for fn in by_rel[current_rel].symbols.functions}
        return (current_rel, head) if head in local else None
    return None


def _parameter_name(parsed: ParsedFile, node) -> str:
    if node.type == "identifier":
        text = parsed.text_of(node).strip()
        return "" if text == "this" else text
    if node.type in ("required_parameter", "optional_parameter"):
        pattern = node.child_by_field_name("pattern")
        if pattern is not None and pattern.type == "identifier":
            text = parsed.text_of(pattern).strip()
            return "" if text == "this" else text
        return ""
    return ""  # rest/object/array patterns cannot bind one positional argument


def _parameter_names(parsed: ParsedFile, fn_symbol) -> list[str]:
    """Parameter names in declaration order; '' marks a pattern that cannot be
    matched positionally."""
    for node in parsed.walk():
        if line_of(node) != fn_symbol.line or arrow_or_function_name(parsed, node) != fn_symbol.name:
            continue
        fn_node = node
        if node.type in ("lexical_declaration", "variable_declaration"):
            fn_node = None
            for decl in node.children:
                if decl.type != "variable_declarator":
                    continue
                name = decl.child_by_field_name("name")
                value = decl.child_by_field_name("value")
                if name is not None and value is not None and parsed.text_of(name).strip() == fn_symbol.name:
                    fn_node = value
                    break
            if fn_node is None:
                return []
        params = fn_node.child_by_field_name("parameters")
        if params is None:
            return []
        return [_parameter_name(parsed, child) for child in params.named_children]
    return []


def _param_hops(parsed: ParsedFile, symbols, fn, params: list[str]) -> list[_ParamHop]:
    """Which parameters can reach which sinks inside this function."""
    seeds = {fn.name: {p: f"param:{p}" for p in params if p}}
    collected = collect_tainted(parsed, symbols, seeds=seeds)
    scope_taint = collected.tainted.get(fn.name, {})
    if not any(label.startswith("param:") for label in scope_taint.values()):
        return []
    hops: list[_ParamHop] = []
    seen: set[tuple[str, str, int]] = set()
    for node in parsed.walk():
        if node.type != "call_expression":
            continue
        line = line_of(node)
        if not (fn.line <= line <= fn.end_line):
            continue
        if symbols.containing(line) != fn.name:
            continue  # sinks inside nested functions are that function's business
        labelled = sink_label(parsed, node)
        if labelled is None:
            continue
        label, kind = labelled
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        for ident, _ln in identifiers_in(args):
            source = scope_taint.get(ident, "")
            if not source.startswith("param:"):
                continue
            param = source[len("param:") :]
            key = (param, label, line)
            if key in seen:
                continue
            seen.add(key)
            snippet = parsed.text_of(node)
            if len(snippet) > 200:
                snippet = snippet[:200] + "…"
            hops.append(_ParamHop(param=param, sink=label, sink_kind=kind, line=line, snippet=snippet))
    return hops


def _call_sites(f: InterFile) -> list[_CallSite]:
    out: list[_CallSite] = []
    for node in f.parsed.walk():
        if node.type != "call_expression":
            continue
        line = line_of(node)
        caller = f.symbols.containing(line)
        if not caller:
            continue  # module-level calls are not this pass's business
        fn_node = node.child_by_field_name("function")
        if fn_node is None or not _callee_is_plain(fn_node):
            continue
        text = _callee_text(f.parsed, fn_node)
        if not text:
            continue
        args = node.child_by_field_name("arguments")
        positional: list[tuple[list[str], str | None]] = []
        for child in (args.named_children if args else []):
            if child.type == "spread_element":
                positional.append(([], None))  # a spread cannot be attributed
                continue
            idents = [ident for ident, _ln in identifiers_in(child)]
            positional.append((idents, contains_source(f.parsed, child)))
        out.append(_CallSite(callee=text, line=line, caller_function=caller, positional=positional))
    return out


def analyse_inter_ts(files: list[InterFile]) -> tuple[dict[str, list[Taint]], list[CallEdge]]:
    """Cross-function taints, keyed by the file the sink lives in, plus the
    call graph of every edge this pass could prove."""
    index = {f.rel for f in files if f.rel.endswith(TS_SUFFIXES)}
    by_rel = {f.rel: f for f in files}
    extra: dict[str, list[Taint]] = {}
    edges: list[CallEdge] = []
    params_cache: dict[tuple[str, str], list[str]] = {}
    hops_cache: dict[tuple[str, str], list[_ParamHop]] = {}

    for f in files:
        if not f.rel.endswith(TS_SUFFIXES):
            continue
        bindings = call_bindings(f.symbols.imports)
        collected = collect_tainted(f.parsed, f.symbols)
        seen: set[str] = set()
        for site in _call_sites(f):
            target = resolve_callee(f.rel, site.callee, bindings, index, by_rel)
            if target is None:
                continue
            target_rel, target_fn = target
            if target_rel == f.rel and target_fn == site.caller_function:
                continue  # direct recursion proves nothing at depth one
            target_file = by_rel[target_rel]
            key = (target_rel, target_fn)
            if key not in hops_cache:
                fn_symbol = next(fn for fn in target_file.symbols.functions if fn.name == target_fn)
                params_cache[key] = _parameter_names(target_file.parsed, fn_symbol)
                hops_cache[key] = _param_hops(target_file.parsed, target_file.symbols, fn_symbol, params_cache[key])
            params = params_cache[key]
            hops = hops_cache[key]
            scope_taint = collected.tainted.get(site.caller_function, {})

            tainted_params: list[str] = []

            def hop_into(param: str, source: str, arg_text: str) -> None:
                if not param:
                    return
                tainted_params.append(param)
                for hop in hops:
                    if hop.param != param:
                        continue
                    taint_key = f"{source}->{hop.sink}@{hop.line}:{target_fn}"
                    if taint_key in seen:
                        continue
                    seen.add(taint_key)
                    extra.setdefault(target_rel, []).append(
                        Taint(
                            source=source,
                            sink=hop.sink,
                            sink_kind=hop.sink_kind,
                            line=hop.line,
                            symbol=target_fn,
                            via=[
                                f"{source} -> {site.caller_function} ({f.rel}:{site.line})",
                                f"{site.callee} -> {target_fn} via {arg_text} ({target_rel})",
                                f"param {param} -> {hop.sink}",
                            ],
                            snippet=hop.snippet,
                        )
                    )

            for pos, (idents, direct) in enumerate(site.positional):
                param = params[pos] if pos < len(params) else ""
                if not param:
                    continue
                source = direct
                if not source:
                    for ident in idents:
                        label = scope_taint.get(ident)
                        if label:
                            source = label
                            break
                if source:
                    hop_into(param, source, f"argument {pos + 1}")

            edges.append(
                CallEdge(
                    caller_file=f.rel,
                    caller_function=site.caller_function,
                    call_line=site.line,
                    callee_dotted=site.callee,
                    callee_file=target_rel,
                    callee_function=target_fn,
                    tainted_params=sorted(set(tainted_params)),
                )
            )

    return extra, edges
