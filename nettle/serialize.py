"""HTML serialization and prettify."""

from __future__ import annotations

from typing import List, Optional, Union

from .nodes import VOID_TAGS, Comment, Document, Element, Node, Text


def html(node: Node) -> str:
    """Serialize node to compact HTML string."""
    return str(node)


def _limits() -> dict:
    from .registry import registry as _registry
    return _registry.serialize


def prettify(
    node: Node,
    indent: Optional[str] = None,
    max_depth: Optional[int] = None,
    bs4_compat: Optional[bool] = None,
) -> str:
    """Pretty-print HTML with indentation.

    * ``bs4_compat=True`` replicates BeautifulSoup's ``prettify()``
      (formatter="minimal", one-space indent by default) byte for byte —
      indentation, attribute sorting, whitespace-only-string collapsing and
      the ``<br/>`` void style included. Use it to diff against HTML
      prettified historically with bs4. Default comes from
      ``registry.serialize["prettify_bs4_compat"]`` (factory: False).
    * default mode is nettle's own layout (no attribute reordering, source
      attribute order, ``<br>`` void style).

    max_depth (default mode only) defaults to
    registry.serialize["prettify_max_depth"]; beyond it, deep subtrees
    serialize inline instead of indenting (deep-tree safe). bs4_compat mode
    is iterative — no depth limit needed.
    """
    if bs4_compat is None:
        bs4_compat = bool(_limits().get("prettify_bs4_compat", False))
    if bs4_compat:
        if indent is None:
            indent = " "
        return _prettify_bs4(node, indent)
    if indent is None:
        indent = "  "
    lim = _limits()
    if max_depth is None:
        max_depth = int(lim.get("prettify_max_depth", 64))
    if isinstance(node, Document):
        parts: List[str] = []
        if node.doctype:
            parts.append(f"<!DOCTYPE {node.doctype}>")
        for child in node._children:
            parts.append(_pretty_node(child, 0, indent, max_depth))
        return "\n".join(p for p in parts if p is not None and p != "")
    return _pretty_node(node, 0, indent, max_depth)


# ---------------------------------------------------------------------------
# bs4-compat prettify — a faithful reimplementation of bs4's Tag.decode()
# with formatter="minimal" (bs4 4.12/4.13 behavior):
#   * one event per open/close/string piece, "\n" after every piece
#   * text strings are .strip()-ed, then indented at the current level
#   * <pre>/<textarea> enter "string literal mode": their contents are
#     emitted verbatim (no indent, no newline inside)
#   * attributes are SORTED alphabetically; class lists joined with " "
#   * void elements close as <br/>  (minimal formatter's slash)
#   * & < > escaped in text and attribute values, except inside
#     <script>/<style> (bs4's cdata_containing_tags)
#   * attribute quoting: "..." normally, '...' when the value has ",
#     &quot; when it has both
#   * whitespace-only text runs collapse to "\n" (or " ") the way bs4's
#     html.parser builder does at parse time — EXCEPT inside pre/textarea
# ---------------------------------------------------------------------------

_BS4_PRESERVE_WS_TAGS = frozenset({"pre", "textarea"})
_BS4_CDATA_TAGS = frozenset({"script", "style"})
_ASCII_SPACES = " \t\n\r\f"


def _bs4_substitute_xml(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _bs4_quote_attr(value: str) -> str:
    if '"' in value:
        if "'" in value:
            return '"' + value.replace('"', "&quot;") + '"'
        return "'" + value + "'"
    return '"' + value + '"'


def _bs4_format_tag(el: Element, opening: bool) -> str:
    attrs: List[str] = []
    if opening:  # bs4: attributes only on opening tags
        for key, val in sorted(el.attrs.items()):
            if val is None or val is True:
                attrs.append(str(key))
                continue
            if isinstance(val, (list, tuple)):
                val = " ".join(str(x) for x in val)
            elif not isinstance(val, str):
                val = str(val)
            attrs.append(f"{key}={_bs4_quote_attr(_bs4_substitute_xml(val))}")
    attr_str = (" " + " ".join(attrs)) if attrs else ""
    slash = "" if opening else "/"
    void_slash = "/" if (opening and el.tag in VOID_TAGS) else ""
    return f"<{slash}{el.tag}{attr_str}{void_slash}>"


def _bs4_string_out(node: Node) -> str:
    if isinstance(node, Comment):
        return f"<!--{node.content}-->"
    text = _bs4_normalize_text(node)  # Text (parse-time collapse quirk)
    if not (isinstance(node.parent, Element) and node.parent.tag in _BS4_CDATA_TAGS):
        text = _bs4_substitute_xml(text)
    return text


def _bs4_normalize_text(node: Text) -> str:
    """bs4's html.parser endData collapse, applied at serialization time:
    a text run that is ALL ASCII whitespace becomes "\n" (if it contains
    any newline) or " " — unless it lives inside <pre>/<textarea>."""
    preserve = isinstance(node.parent, Element) and node.parent.tag in _BS4_PRESERVE_WS_TAGS
    if preserve:
        return node.content
    t = node.content
    if t and not t.strip(_ASCII_SPACES):
        return "\n" if "\n" in t else " "
    return t


def _prettify_bs4(node: Node, indent: str) -> str:
    # Event stream over self+descendants (bs4's _event_stream, iterative).
    # The DOCUMENT node is hidden in bs4 (soup.hidden = True) — it emits no
    # markup and does not consume an indent level; its children start at 0.
    START, END, EMPTY, STRING = 0, 1, 2, 3
    events: List[tuple] = []
    stack: List[Element] = []
    root = node
    stream: List[Node] = [node]

    def _emit_closes(target: Node) -> None:
        while stack and (getattr(target, "parent", None) is not stack[-1]):
            events.append((END, stack.pop()))

    i = 0
    while i < len(stream):
        cur = stream[i]
        i += 1
        if isinstance(cur, Document):
            # hidden document node: never emitted, never on the close stack
            stream[i:i] = list(cur._children)
            continue
        _emit_closes(cur)
        if isinstance(cur, Element):
            if cur.tag in VOID_TAGS:
                events.append((EMPTY, cur))
            else:
                events.append((START, cur))
                stack.append(cur)
                stream[i:i] = list(cur._children)
        else:
            events.append((STRING, cur))
    while stack:
        events.append((END, stack.pop()))

    # bs4 keeps the Doctype as the first child string; nettle keeps it as a
    # document attribute — emit it first (bs4 emits it at its child position,
    # which is the source position: first in every sane document).
    pieces: List[str] = []
    doc = node if isinstance(node, Document) else None
    if doc is not None and doc.doctype:
        pieces.append(f"<!DOCTYPE {doc.doctype}>\n")

    # bs4 decode(): piece assembly with indent_before/indent_after rules.
    level = 0
    string_literal_tag: Optional[Element] = None
    for event, el in events:
        if event in (START, EMPTY):
            piece = _bs4_format_tag(el, True)
        elif event is END:
            piece = _bs4_format_tag(el, False)
            level -= 1
        else:
            piece = _bs4_string_out(el)

        if string_literal_tag is not None:
            indent_before = indent_after = False
        else:
            indent_before = indent_after = True

        if (
            event is START
            and string_literal_tag is None
            and el.tag in _BS4_PRESERVE_WS_TAGS
        ):
            indent_before, indent_after = True, False
            string_literal_tag = el
        elif event is END and el is string_literal_tag:
            indent_before, indent_after = False, True
            string_literal_tag = None

        if indent_before or indent_after:
            if event is STRING:
                # bs4 strips NavigableStrings with unicode str.strip()
                piece = piece.strip()
            if piece:
                space_before = (indent * level) if (indent_before and level) else ""
                space_after = "\n" if indent_after else ""
                piece = space_before + piece + space_after
        pieces.append(piece)  # bs4 appends every piece — even unindented
        if event is START:
            level += 1
    return "".join(pieces)


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
        if "\n" not in t and len(t) < int(_limits().get("prettify_inline_text_chars", 80)):
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
