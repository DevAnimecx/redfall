"""Depth-one interprocedural taint over the Python files of one scan.

The intraprocedural pass stops at the function boundary. This pass adds the
first cross-function hop, plus a call graph of the edges it can resolve without
guessing:

  * a function defined in the same file (plain name, or `self.method` inside a
    class),
  * a function reached through an import, resolved against a module index built
    from the actual file paths of the scan.

When two files could satisfy the same import the edge is dropped, not guessed;
unresolved calls produce no edge and no taint.

How a hop is proved: each callee's parameters are pre-tainted one scope at a
time ("can this parameter reach a sink in here?"), which yields a summary per
function. A call site becomes a hop only when the caller's argument is already
tainted by a real source *in the caller* and the corresponding parameter
reaches a sink in the callee. The emitted taint lives at the callee's sink line
and its `via` chain names the caller, the call and the parameter, so the claim
is auditable end to end.

Depth one is deliberate: the caller's taint must come from a real source, and
summaries are computed without call-site context. That keeps the analysis
honest and the proofs small; deeper chains are a sandbox question, not a
pattern-match question.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .symbols import FileSymbols, ImportSymbol
from .symbols_py import classify_call, dotted, import_aliases, resolve_dotted
from .taint import Taint
from .taint_py import collect_tainted, contains_source, identifiers_in
from .tree import ParsedFile, line_of


@dataclass
class CallEdge:
    """A call from a scanned function to a function resolvable in the scan."""

    caller_file: str
    caller_function: str
    call_line: int
    callee_dotted: str  # as resolved through the caller's import bindings
    callee_file: str
    callee_function: str
    tainted_params: list[str] = field(default_factory=list)


@dataclass
class InterFile:
    """One scanned file, as the interprocedural pass needs it."""

    rel: str
    parsed: ParsedFile
    symbols: FileSymbols


@dataclass
class _CallSite:
    callee: str  # dotted text after the caller's import bindings are applied
    line: int
    caller_function: str
    # (identifiers read by the argument, direct source label if any)
    positional: list[tuple[list[str], str | None]]
    keywords: list[tuple[str, list[str], str | None]]


@dataclass
class _ParamHop:
    param: str
    sink: str
    sink_kind: str
    line: int
    snippet: str


def _module_index(paths: list[str]) -> dict[str, str]:
    """Dotted module name -> file, for every .py file in the scan."""
    index: dict[str, str] = {}
    for rel in sorted(paths):
        if not rel.endswith(".py"):
            continue
        dotted_name = rel[:-3].replace("/", ".")
        if dotted_name.endswith(".__init__"):
            dotted_name = dotted_name[: -len(".__init__")]
        index.setdefault(dotted_name, rel)
    return index


def _resolve_module(index: dict[str, str], candidate: str) -> str | None:
    """Exact match first, then a unique dotted-suffix match; else nothing."""
    if candidate in index:
        return index[candidate]
    matches = {path for key, path in index.items() if key.endswith("." + candidate)}
    if len(matches) == 1:
        return matches.pop()
    return None


def _import_target(current_rel: str, source: str, origin: str) -> str | None:
    """The full dotted target an import introduces, with Python's own relative
    arithmetic: level = leading dots, then walk up from the file's package."""
    if not source:
        return None
    level = len(source) - len(source.lstrip("."))
    rest = source.lstrip(".")
    if level == 0:
        base = rest
    else:
        package = current_rel[:-3].split("/")[:-1]
        drop = level - 1
        if drop > len(package):
            return None
        base = ".".join(package[: len(package) - drop] + ([rest] if rest else []))
    if not base:
        return None
    return f"{base}.{origin}" if origin else base


def call_bindings(current_rel: str, imports: list[ImportSymbol]) -> dict[str, str]:
    """Local name -> full dotted target for names an import binds.

    `import a.b` binds nothing here: the call text is already the absolute
    path. `import a.b as c`, `from x import y` and relative forms bind their
    local name to the target they really introduce.
    """
    out: dict[str, str] = {}
    for imp in imports:
        if not imp.source or not imp.name:
            continue
        if imp.origin:
            target = _import_target(current_rel, imp.source, imp.origin)
            if target:
                out[imp.name] = target
        elif imp.name != imp.source.split(".")[0]:
            target = _import_target(current_rel, imp.source, "")
            if target:
                out[imp.name] = target
    return out


def _resolve_call_dotted(dotted_text: str, bindings: dict[str, str]) -> str:
    """Rewrite the head of a dotted callee through the call bindings."""
    if not dotted_text:
        return dotted_text
    parts = dotted_text.split(".")
    head = parts[0]
    if head in bindings:
        return ".".join(bindings[head].split(".") + parts[1:])
    return dotted_text


def resolve_callee(
    current_rel: str,
    caller_function: str,
    callee_dotted: str,
    index: dict[str, str],
    local_functions: set[str],
    by_rel: dict[str, InterFile],
) -> tuple[str, str] | None:
    """(file, function) for a callee that provably exists in the scan, else None."""
    text = callee_dotted
    if text.startswith("self."):
        cls = caller_function.rsplit(".", 1)[0] if "." in caller_function else ""
        if not cls:
            return None
        text = f"{cls}.{text[len('self.'):]}"
    if not text:
        return None
    parts = text.split(".")
    if len(parts) == 1:
        return (current_rel, text) if text in local_functions else None
    module_candidate = ".".join(parts[:-1])
    fn_name = parts[-1]
    path = _resolve_module(index, module_candidate)
    if path is not None:
        target = by_rel.get(path)
        if target is not None and fn_name in {fn.name for fn in target.symbols.functions}:
            return path, fn_name
        return None
    # A dotted name that is not a module path is a same-file method: Class.method.
    if text in local_functions:
        return current_rel, text
    return None


def _parameter_names(parsed: ParsedFile, fn_symbol) -> list[str]:
    """Parameter names in declaration order; '' marks a variadic that cannot be
    matched positionally, and `self`/`cls` are dropped from methods."""
    for node in parsed.walk():
        if node.type != "function_definition" or line_of(node) != fn_symbol.line:
            continue
        params = node.child_by_field_name("parameters")
        names: list[str] = []
        if params is not None:
            for child in params.named_children:
                target = child
                if child.type in ("default_parameter", "typed_parameter", "typed_default_parameter"):
                    target = child.child_by_field_name("name") or next(
                        (
                            c
                            for c in child.named_children
                            if c.type in ("identifier", "list_splat_pattern", "dictionary_splat_pattern")
                        ),
                        None,
                    )
                if target is None:
                    names.append("")
                elif target.type == "identifier":
                    names.append(parsed.text_of(target).strip())
                else:
                    names.append("")  # variadics never bind one positional argument
        if "." in fn_symbol.name and names and names[0] in ("self", "cls"):
            names = names[1:]
        return names
    return []


def _param_hops(parsed: ParsedFile, symbols: FileSymbols, fn, params: list[str]) -> list[_ParamHop]:
    """Which parameters can reach which sinks inside this function.

    Computed by seeding every parameter with a distinct `param:<name>` label
    and reading which labels reach a sink argument. The label travels with the
    value, so the attribution is the same one propagation would give.
    """
    seeds = {fn.name: {p: f"param:{p}" for p in params if p}}
    collected = collect_tainted(parsed, symbols, seeds=seeds)
    scope_taint = collected.tainted.get(fn.name, {})
    if not any(label.startswith("param:") for label in scope_taint.values()):
        return []
    aliases = import_aliases(symbols.imports)
    hops: list[_ParamHop] = []
    seen: set[tuple[str, str, int]] = set()
    for node in parsed.walk():
        if node.type != "call":
            continue
        line = line_of(node)
        if not (fn.line <= line <= fn.end_line):
            continue
        if symbols.containing(line) != fn.name:
            continue  # sinks inside nested functions are that function's business
        fn_node = node.child_by_field_name("function")
        if fn_node is None:
            continue
        resolved = resolve_dotted(dotted(parsed, fn_node), aliases)
        classified = classify_call(resolved)
        if classified is None:
            continue
        kind, label = classified
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        idents: list[str] = []
        for child in args.named_children:
            if child.type == "keyword_argument":
                value = child.child_by_field_name("value")
                if value is not None:
                    idents.extend(identifiers_in(value))
            else:
                idents.extend(identifiers_in(child))
        for ident in idents:
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


def _callee_is_plain(fn_node) -> bool:
    """A callable expression without a nested call: attribute chains name a
    function, but `get_db().execute(x)` mixes two calls, so arguments cannot be
    attributed to the inner one."""
    stack = [fn_node]
    while stack:
        cur = stack.pop()
        if cur.type == "call":
            return False
        stack.extend(cur.children)
    return True


def _call_sites(f: InterFile, bindings: dict[str, str]) -> list[_CallSite]:
    out: list[_CallSite] = []
    for node in f.parsed.walk():
        if node.type != "call":
            continue
        line = line_of(node)
        caller = f.symbols.containing(line)
        if not caller:
            continue  # module-level calls are not this pass's business
        fn_node = node.child_by_field_name("function")
        if fn_node is None or not _callee_is_plain(fn_node):
            continue
        text = _resolve_call_dotted(dotted(f.parsed, fn_node), bindings)
        if not text:
            continue
        args = node.child_by_field_name("arguments")
        positional: list[tuple[list[str], str | None]] = []
        keywords: list[tuple[str, list[str], str | None]] = []
        for child in (args.named_children if args else []):
            if child.type == "keyword_argument":
                name = f.parsed.text_of(child.child_by_field_name("name")).strip()
                value = child.child_by_field_name("value")
                if not name or value is None:
                    continue
                keywords.append((name, identifiers_in(value), contains_source(f.parsed, value)))
            elif child.type != "comment":
                positional.append((identifiers_in(child), contains_source(f.parsed, child)))
        out.append(
            _CallSite(callee=text, line=line, caller_function=caller, positional=positional, keywords=keywords)
        )
    return out


def _functions_of(symbols: FileSymbols) -> set[str]:
    return {fn.name for fn in symbols.functions}


def _arg_source(idents: list[str], direct: str | None, scope_taint: dict[str, str]) -> str | None:
    if direct:
        return direct
    for ident in idents:
        label = scope_taint.get(ident)
        if label:
            return label
    return None


def analyse_inter(files: list[InterFile]) -> tuple[dict[str, list[Taint]], list[CallEdge]]:
    """Cross-function taints, keyed by the file the sink lives in, plus the
    call graph of every edge this pass could prove."""
    index = _module_index([f.rel for f in files])
    by_rel = {f.rel: f for f in files}
    extra: dict[str, list[Taint]] = {}
    edges: list[CallEdge] = []
    params_cache: dict[tuple[str, str], list[str]] = {}
    hops_cache: dict[tuple[str, str], list[_ParamHop]] = {}

    for f in files:
        if not f.rel.endswith(".py"):
            continue
        bindings = call_bindings(f.rel, f.symbols.imports)
        collected = collect_tainted(f.parsed, f.symbols)
        local = _functions_of(f.symbols)
        seen: set[str] = set()
        for site in _call_sites(f, bindings):
            target = resolve_callee(f.rel, site.caller_function, site.callee, index, local, by_rel)
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
                source = _arg_source(idents, direct, scope_taint)
                if source:
                    hop_into(param, source, f"argument {pos + 1}")
            for name, idents, direct in site.keywords:
                if name not in params:
                    continue
                source = _arg_source(idents, direct, scope_taint)
                if source:
                    hop_into(name, source, f"{name}=")

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
