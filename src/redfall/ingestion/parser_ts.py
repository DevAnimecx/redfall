"""Tree-sitter parsing for TypeScript/JavaScript sources.

One Language per dialect, loaded once. `.ts`/`.tsx`/`.js`/`.jsx` are all handled;
TSX is used for `.tsx`/`.jsx` because it accepts JSX syntax that the plain
TypeScript grammar rejects.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from tree_sitter import Language, Parser

# Re-exported: these grew up here and downstream extractors import them from here.
from .tree import ParsedFile, end_line_of, line_of  # noqa: F401

LANGUAGE_EXTENSIONS = {
    ".ts": "typescript",
    ".tsx": "tsx",
    ".js": "javascript",
    ".jsx": "jsx",
    ".mjs": "javascript",
    ".cjs": "javascript",
}


@lru_cache(maxsize=None)
def _language(dialect: str) -> Language:
    if dialect in ("typescript", "tsx"):
        import tree_sitter_typescript as tst

        pointer = tst.language_typescript() if dialect == "typescript" else tst.language_tsx()
        return Language(pointer)
    import tree_sitter_javascript as tsjs

    return Language(tsjs.language())


def dialect_for(path: str | Path) -> str | None:
    return LANGUAGE_EXTENSIONS.get(Path(path).suffix.lower())


def is_supported(path: str | Path) -> bool:
    return dialect_for(path) is not None


def parse_source(path: str | Path, source: bytes | None = None) -> ParsedFile | None:
    """Parse a file. Returns None for unsupported extensions."""
    path_str = str(path)
    dialect = dialect_for(path_str)
    if dialect is None:
        return None
    if source is None:
        source = Path(path_str).read_bytes()
    parser = Parser(_language(dialect))
    tree = parser.parse(source)
    return ParsedFile(path=path_str, dialect=dialect, source=source, root=tree.root_node)
