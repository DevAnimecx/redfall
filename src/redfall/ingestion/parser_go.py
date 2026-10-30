"""Tree-sitter parsing for Go sources.

The grammar is loaded once, lazily, so importing Redfall does not require it
unless a Go file is actually parsed.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from tree_sitter import Language, Parser

# Re-exported: every extractor uses these.
from .tree import ParsedFile, end_line_of, line_of  # noqa: F401

GO_EXTENSIONS = {".go"}


@lru_cache(maxsize=None)
def _language() -> Language:
    import tree_sitter_go as tsg

    return Language(tsg.language())


def is_supported(path: str | Path) -> bool:
    return Path(path).suffix.lower() in GO_EXTENSIONS


def parse_source(path: str | Path, source: bytes | None = None) -> ParsedFile | None:
    """Parse a Go file. Returns None for anything that is not Go."""
    path_str = str(path)
    if not is_supported(path_str):
        return None
    if source is None:
        source = Path(path_str).read_bytes()
    parser = Parser(_language())
    tree = parser.parse(source)
    return ParsedFile(path=path_str, dialect="go", source=source, root=tree.root_node)
