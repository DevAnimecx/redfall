"""The language registry: one support bundle per language Redfall can read.

`ingest()` asks for support by path; every bundle exposes the same four
callables, so adding a language never touches the ingest loop.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import parser_py, parser_ts, symbols, symbols_py, taint, taint_py
from .symbols import FileSymbols
from .taint import Taint
from .tree import ParsedFile


@dataclass(frozen=True)
class LanguageSupport:
    name: str
    is_supported: Callable[[str | Path], bool]
    parse: Callable[[str | Path, bytes | None], ParsedFile | None]
    symbols: Callable[[ParsedFile], FileSymbols]
    taint: Callable[[ParsedFile, FileSymbols], list[Taint]]


SUPPORTED: tuple[LanguageSupport, ...] = (
    LanguageSupport(
        name="typescript",
        is_supported=parser_ts.is_supported,
        parse=parser_ts.parse_source,
        symbols=symbols.extract_symbols,
        taint=taint.analyse_taint,
    ),
    LanguageSupport(
        name="python",
        is_supported=parser_py.is_supported,
        parse=parser_py.parse_source,
        symbols=symbols_py.extract_symbols,
        taint=taint_py.analyse_taint,
    ),
)


def support_for(path: str | Path) -> LanguageSupport | None:
    for support in SUPPORTED:
        if support.is_supported(path):
            return support
    return None
