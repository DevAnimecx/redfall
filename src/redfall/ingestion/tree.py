"""The tree wrapper shared by every language parser.

`ParsedFile` keeps a source file and its syntax tree together so downstream
extractors never have to hold two objects and hope they match.
"""

from __future__ import annotations

from dataclasses import dataclass

from tree_sitter import Node


@dataclass(frozen=True)
class ParsedFile:
    """A source file with its tree, kept together so queries stay in sync."""

    path: str
    dialect: str
    source: bytes
    root: Node

    def text_of(self, node: Node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def walk(self) -> list[Node]:
        """Every node in the tree, in document order."""
        out: list[Node] = []
        stack = [self.root]
        while stack:
            node = stack.pop()
            out.append(node)
            stack.extend(reversed(node.children))
        return out


def line_of(node: Node) -> int:
    """1-based start line, matching how editors and manifests number lines."""
    return node.start_point[0] + 1


def end_line_of(node: Node) -> int:
    return node.end_point[0] + 1
