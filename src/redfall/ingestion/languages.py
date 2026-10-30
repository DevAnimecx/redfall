"""The language registry: one support bundle per language Redfall can read.

`ingest()` asks for support by path; every bundle exposes the same four
callables, so adding a language never touches the ingest loop.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import (
    parser_go,
    parser_java,
    parser_py,
    parser_ts,
    symbols,
    symbols_go,
    symbols_jvm,
    symbols_py,
    taint,
    taint_go,
    taint_jvm,
    taint_py,
)
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
    LanguageSupport(
        name="java",
        is_supported=parser_java.is_supported,
        parse=parser_java.parse_source,
        symbols=symbols_jvm.extract_symbols,
        taint=taint_jvm.analyse_taint,
    ),
    LanguageSupport(
        name="go",
        is_supported=parser_go.is_supported,
        parse=parser_go.parse_source,
        symbols=symbols_go.extract_symbols,
        taint=taint_go.analyse_taint,
    ),
)


# The language names the extractors can produce, for the maps elsewhere that
# used to infer a language from a file suffix and default everything unknown to
# "javascript". Kept here so adding a language updates one place.
LANGUAGE_NAMES = ("typescript", "python", "java", "kotlin", "go")

# Suffix to language. JavaScript is its own answer rather than the fallback: a
# `.jsx` file is not a TypeScript file, and recording some future language as
# "javascript" because nobody taught this map about it is how a Kotlin file ends
# up attributed to the wrong tree.
_EXTENSION_LANGUAGE: dict[str, str] = {
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
    ".pyw": "python",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".go": "go",
}


def language_name_for(path: str | Path) -> str:
    """The language a path is written in, or "unknown" if none is known.

    Returning "unknown" rather than a default is deliberate: a file whose
    language nobody recorded should be visibly unattributed, not quietly
    attributed to JavaScript.
    """
    return _EXTENSION_LANGUAGE.get(Path(path).suffix.lower(), "unknown")


def support_for(path: str | Path) -> LanguageSupport | None:
    for support in SUPPORTED:
        if support.is_supported(path):
            return support
    return None
