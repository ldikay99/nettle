"""HTML serialization and prettify."""

from __future__ import annotations

from typing import List, Optional, Union

from .nodes import VOID_TAGS, Comment, Document, Element, Node, Text


def html(node: Node) -> str:
    """Serialize node to compact HTML string."""
    return str(node)


def prettify(node: Node, indent: str = "  ", max_depth: int = 64) -> str:
    """Pretty-print HTML with indentation."""
    if isinstance(node, Document):
        parts: List[str] = []
        if node.doctype:
            parts.append(f"<!DOCTYPE {node.doctype}>")
        for child in node._children:
            parts.append(_pretty_node(child, 0, indent, max_depth))
        return "\n".join(p for p in parts if p is not None and p != "")
    return _pretty_node(node, 0, indent, max_depth)


def _pretty_node(node: Node, depth: int, indent: str, max_depth: int) -> str:
    pad = indent * depth
    if isinstance(node, Text):
        text = node.content
        if not text.strip():
            return ""
        # collapse internal whitespace for pretty display of text nodes
        collapsed = " ".join(text.split())
        return f"{pad}{collapsed}"
    if isinstance(node, Comment):
        return f"{pad}<!--{node.content}-->"
    if not isinstance(node, Element):
        return ""

    if node.tag == "#document":
        return "\n".join(
            _pretty_node(c, depth, indent, max_depth) for c in node._children
        )

    attrs_str = _attrs(node)
    if node.tag in VOID_TAGS:
        return f"{pad}<{node.tag}{attrs_str}>"

    kids = node._children
    # inline if only a single short text child
    if len(kids) == 1 and isinstance(kids[0], Text):
        t = kids[0].content
        if "\n" not in t and len(t) < 80:
            return f"{pad}<{node.tag}{attrs_str}>{t}</{node.tag}>"

    if not kids:
        return f"{pad}<{node.tag}{attrs_str}></{node.tag}>"

    if depth >= max_depth:
        inner = "".join(str(c) for c in kids)
        return f"{pad}<{node.tag}{attrs_str}>{inner}</{node.tag}>"

    lines = [f"{pad}<{node.tag}{attrs_str}>"]
    for child in kids:
        line = _pretty_node(child, depth + 1, indent, max_depth)
        if line:
            lines.append(line)
    lines.append(f"{pad}</{node.tag}>")
    return "\n".join(lines)


def _attrs(el: Element) -> str:
    from .nodes import _escape_attr
    parts = []
    for k, v in el.attrs.items():
        if v is True or v is None:
            parts.append(f" {k}")
        else:
            parts.append(f' {k}="{_escape_attr(str(v))}"')
    return "".join(parts)
