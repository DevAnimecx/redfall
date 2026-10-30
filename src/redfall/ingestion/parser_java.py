"""Tree-sitter parsing for Java and Kotlin sources.

The two languages share a parser module because they share an ecosystem: a
Spring service is routinely written in both, and a scan of a JVM repository
meets them side by side. Keeping them together means the extension mapping and
the dialect naming live in one place.

Each grammar is loaded once, lazily, so importing Redfall does not require
either unless a JVM file is actually parsed.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from tree_sitter import Language, Parser

# Re-exported: every extractor uses these.
from .tree import ParsedFile, end_line_of, line_of  # noqa: F401

JAVA_EXTENSIONS = {".java"}
KOTLIN_EXTENSIONS = {".kt", ".kts"}


@lru_cache(maxsize=None)
def _java_language() -> Language:
    import tree_sitter_java as tsj

    return Language(tsj.language())


@lru_cache(maxsize=None)
def _kotlin_language() -> Language:
    import tree_sitter_kotlin as tsk

    return Language(tsk.language())


def is_supported(path: str | Path) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix in JAVA_EXTENSIONS or suffix in KOTLIN_EXTENSIONS


def dialect_for(path: str | Path) -> str | None:
    """Which JVM grammar reads this path, or None if neither does."""
    suffix = Path(path).suffix.lower()
    if suffix in JAVA_EXTENSIONS:
        return "java"
    if suffix in KOTLIN_EXTENSIONS:
        return "kotlin"
    return None


def language_for(dialect: str) -> Language:
    if dialect == "java":
        return _java_language()
    if dialect == "kotlin":
        return _kotlin_language()
    raise ValueError(f"not a JVM dialect: {dialect!r}")


def parse_source(path: str | Path, source: bytes | None = None) -> ParsedFile | None:
    """Parse a Java or Kotlin file. Returns None for anything else."""
    path_str = str(path)
    dialect = dialect_for(path_str)
    if dialect is None:
        return None
    if source is None:
        source = Path(path_str).read_bytes()
    parser = Parser(language_for(dialect))
    tree = parser.parse(source)
    return ParsedFile(path=path_str, dialect=dialect, source=source, root=tree.root_node)
