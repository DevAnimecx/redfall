"""Tree-sitter parsing for Python sources.

The Language is loaded once, lazily, so importing Redfall does not require the
Python grammar unless a Python file is actually parsed.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from tree_sitter import Language, Parser

# Re-exported: `line_of`/`end_line_of` grew up here and every extractor uses them.
from .tree import ParsedFile, end_line_of, line_of  # noqa: F401

PY_EXTENSIONS = {".py", ".pyw"}


@lru_cache(maxsize=None)
def _language() -> Language:
    import tree_sitter_python as tsp

    return Language(tsp.language())


def is_supported(path: str | Path) -> bool:
    return Path(path).suffix.lower() in PY_EXTENSIONS


def parse_source(path: str | Path, source: bytes | None = None) -> ParsedFile | None:
    """Parse a Python file. Returns None for anything that is not Python."""
    path_str = str(path)
    if not is_supported(path_str):
        return None
    if source is None:
        source = Path(path_str).read_bytes()
    parser = Parser(_language())
    tree = parser.parse(source)
    return ParsedFile(path=path_str, dialect="python", source=source, root=tree.root_node)
