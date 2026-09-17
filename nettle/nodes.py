"""Nettle DOM node types: Document, Element, Text, Comment."""

from __future__ import annotations

from typing import Any, Iterator, List, Optional, Union


VOID_TAGS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
})

# Tags that auto-close when another of the same (or certain siblings) opens
# When opening key, auto-close any open element whose tag is in the set.
# (Closing <p> before block tags is handled separately via BLOCK_CLOSES_P.)
AUTO_CLOSE_ON_OPEN = {
    "p": frozenset({"p"}),
    "li": frozenset({"li"}),
    "dt": frozenset({"dt", "dd"}),
    "dd": frozenset({"dt", "dd"}),
    "td": frozenset({"td", "th"}),
    "th": frozenset({"td", "th"}),
    "tr": frozenset({"tr"}),
    "option": frozenset({"option"}),
    "thead": frozenset({"thead", "tbody", "tfoot"}),
    "tbody": frozenset({"thead", "tbody", "tfoot"}),
    "tfoot": frozenset({"thead", "tbody", "tfoot"}),
}

# Block tags that close open <p>
BLOCK_CLOSES_P = frozenset({
    "div", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "table",
    "form", "section", "article", "header", "footer", "nav", "aside",
    "main", "blockquote", "pre", "hr", "address", "figure",
})


class Node:
    """Base DOM node."""

    __slots__ = ("parent",)

    def __init__(self) -> None:
        self.parent: Optional[Element] = None

    @property
    def children(self) -> List[Node]:
        return []

    @property
    def descendants(self) -> Iterator[Node]:
        return iter(())

    def detach(self) -> None:
        if self.parent is not None:
            try:
                self.parent._children.remove(self)
            except ValueError:
                pass
            self.parent = None


class Text(Node):
    """Text node."""

    __slots__ = ("content",)

    def __init__(self, content: str = "") -> None:
        super().__init__()
        self.content = content

    @property
    def text(self) -> str:
        return self.content

    def get_text(self, strip: bool = False, sep: str = "") -> str:
        t = self.content
        return t.strip() if strip else t

    def __str__(self) -> str:
        return _escape_text(self.content)

    def __repr__(self) -> str:
        preview = self.content[:40].replace("\n", "\\n")
        return f"Text({preview!r})"


class Comment(Node):
    """HTML comment node."""

    __slots__ = ("content",)

    def __init__(self, content: str = "") -> None:
        super().__init__()
        self.content = content

    @property
    def text(self) -> str:
        return ""

    def get_text(self, strip: bool = False, sep: str = "") -> str:
        return ""

    def __str__(self) -> str:
        return f"<!--{self.content}-->"

    def __repr__(self) -> str:
        return f"Comment({self.content[:40]!r})"


class Element(Node):
    """HTML element with tag, attrs, and children."""

    __slots__ = ("tag", "attrs", "_children", "_base_url_local")

    def __init__(self, tag: str, attrs: Optional[dict] = None) -> None:
        super().__init__()
        self.tag = tag.lower()
        self.attrs: dict = dict(attrs) if attrs else {}
        self._children: List[Node] = []
        self._base_url_local: Optional[str] = None

    # --- attributes --------------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        key = key.lower()
        if key not in self.attrs:
            raise KeyError(key)
        return self.attrs[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.attrs[key.lower()] = value

    def __delitem__(self, key: str) -> None:
        del self.attrs[key.lower()]

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key.lower() in self.attrs

    def get(self, key: str, default: Any = None) -> Any:
        return self.attrs.get(key.lower(), default)

    def has_attr(self, key: str) -> bool:
        return key.lower() in self.attrs

    # --- tree --------------------------------------------------------------

    @property
    def children(self) -> List[Node]:
        return list(self._children)

    @property
    def child_elements(self) -> List[Element]:
        return [c for c in self._children if isinstance(c, Element)]

    def append(self, node: Node) -> None:
        if node.parent is not None:
            node.detach()
        node.parent = self
        self._children.append(node)

    def extend(self, nodes: List[Node]) -> None:
        for n in nodes:
            self.append(n)

    def insert(self, index: int, node: Node) -> None:
        if node.parent is not None:
            node.detach()
        node.parent = self
        self._children.insert(index, node)

    @property
    def descendants(self) -> Iterator[Node]:
        for child in self._children:
            yield child
            if isinstance(child, Element):
                yield from child.descendants

    @property
    def next_sibling(self) -> Optional[Node]:
        if self.parent is None:
            return None
        sibs = self.parent._children
        try:
            i = sibs.index(self)
        except ValueError:
            return None
        return sibs[i + 1] if i + 1 < len(sibs) else None

    @property
    def previous_sibling(self) -> Optional[Node]:
        if self.parent is None:
            return None
        sibs = self.parent._children
        try:
            i = sibs.index(self)
        except ValueError:
            return None
        return sibs[i - 1] if i > 0 else None

    @property
    def next_element_sibling(self) -> Optional[Element]:
        if self.parent is None:
            return None
        sibs = self.parent._children
        try:
            i = sibs.index(self)
        except ValueError:
            return None
        for s in sibs[i + 1:]:
            if isinstance(s, Element):
                return s
        return None

    @property
    def previous_element_sibling(self) -> Optional[Element]:
        if self.parent is None:
            return None
        sibs = self.parent._children
        try:
            i = sibs.index(self)
        except ValueError:
            return None
        for s in reversed(sibs[:i]):
            if isinstance(s, Element):
                return s
        return None

    # --- text --------------------------------------------------------------

    @property
    def text(self) -> str:
        return self.get_text()

    def get_text(self, strip: bool = False, sep: str = "") -> str:
        """Collect descendant text.

        If strip=True, each text chunk is stripped and empty chunks dropped,
        then joined with sep (default ""). Matches BeautifulSoup-ish behavior
        for strip=True, sep=" ".
        """
        parts: List[str] = []

        def walk(node: Node) -> None:
            if isinstance(node, Text):
                parts.append(node.content)
            elif isinstance(node, Element):
                for child in node._children:
                    walk(child)
            # skip Comment

        for child in self._children:
            walk(child)

        if strip:
            parts = [p.strip() for p in parts]
            parts = [p for p in parts if p]
            return sep.join(parts)
        return sep.join(parts) if sep else "".join(parts)

    # --- find / select -----------------------------------------------------

    def find(self, tag: Optional[str] = None, **attrs: Any) -> Optional[Element]:
        """Find first descendant Element matching tag and/or attrs."""
        for el in self.find_all(tag, limit=1, **attrs):
            return el
        return None

    def find_all(
        self,
        tag: Optional[str] = None,
        limit: Optional[int] = None,
        **attrs: Any,
    ) -> List[Element]:
        """Find all descendant Elements matching tag and/or attrs."""
        tag_l = tag.lower() if tag else None
        results: List[Element] = []
        for node in self.descendants:
            if not isinstance(node, Element):
                continue
            if tag_l is not None and node.tag != tag_l:
                continue
            if attrs and not _match_attrs(node, attrs):
                continue
            results.append(node)
            if limit is not None and len(results) >= limit:
                break
        return results

    def select(self, selector: str) -> List[Element]:
        from .css import select as css_select
        return css_select(self, selector)

    def select_one(self, selector: str) -> Optional[Element]:
        results = self.select(selector)
        return results[0] if results else None

    def matches(self, selector: str) -> bool:
        from .css import matches as css_matches
        return css_matches(self, selector)


    # --- scrape helpers (DX) -----------------------------------------------

    def clean_text(self, mode: str = "plain") -> str:
        """Return cleaned descendant text (see nettle.text.clean_text)."""
        from .text import clean_text as _ct
        return _ct(self.get_text(), mode=mode)

    def values(self, *selectors: str, clean: str = "plain", all: bool = False):
        """Extract cleaned text for one or more CSS selectors."""
        from .extract import values as _values
        return _values(self, *selectors, clean=clean, all=all)

    def record(self, mapping: dict, *, clean: str = "plain") -> dict:
        """Extract a dict of fields from this element (see extract.fields)."""
        from .extract import fields
        return fields(self, mapping, clean=clean)

    def extract(self, schema: dict) -> dict:
        """Declarative schema extract relative to this element."""
        from .query import extract as _extract
        return _extract(self, schema)

    @property
    def base_url(self) -> Optional[str]:
        """Nearest base_url up the tree (document or any ancestor)."""
        node = self
        while node is not None:
            v = getattr(node, "_base_url_local", None)
            if v:
                return v
            node = node.parent
        return None

    @base_url.setter
    def base_url(self, value: Optional[str]) -> None:
        self._base_url_local = value

    def urls(self, **kwargs):
        """Discover URLs under this element."""
        from .urls import find_urls
        return find_urls(self, base_url=getattr(self, "base_url", None), **kwargs)

    def abs_url(self, href: str) -> str:
        """Resolve href against this node's base_url (if any)."""
        from .urls import absolutize
        return absolutize(href, getattr(self, "base_url", None))

    def table(self, selector: str = "table", **kwargs):
        """Parse first matching table under this element into list[dict]."""
        from .extract import table as _table
        return _table(self, selector, **kwargs)

    def prettify(self, indent: str = "  ") -> str:
        from .serialize import prettify
        return prettify(self, indent=indent)

    # --- serialize ---------------------------------------------------------

    @property
    def html(self) -> str:
        return str(self)

    def __str__(self) -> str:
        return _serialize_element(self)

    def __repr__(self) -> str:
        return f"<Element {self.tag} attrs={self.attrs!r} children={len(self._children)}>"


class Document(Element):
    """Root document node (tag='#document')."""

    def __init__(self) -> None:
        super().__init__("#document")
        self.doctype: Optional[str] = None
        self.base_url: Optional[str] = None

    @property
    def html_element(self) -> Optional[Element]:
        for c in self._children:
            if isinstance(c, Element) and c.tag == "html":
                return c
        return None

    def __str__(self) -> str:
        parts: List[str] = []
        if self.doctype:
            parts.append(f"<!DOCTYPE {self.doctype}>")
        for child in self._children:
            parts.append(str(child))
        return "".join(parts)

    def __repr__(self) -> str:
        return f"<Document children={len(self._children)}>"


# --- helpers ---------------------------------------------------------------

def _match_attrs(el: Element, attrs: dict) -> bool:
    for k, v in attrs.items():
        key = k.lower()
        # BeautifulSoup-style class_ → class
        if key == "class_":
            key = "class"
        if key not in el.attrs:
            return False
        actual = el.attrs[key]
        if v is True:
            continue
        if isinstance(v, str):
            if key == "class":
                classes = actual.split() if isinstance(actual, str) else list(actual)
                needed = v.split()
                if not all(c in classes for c in needed):
                    return False
            elif str(actual) != v:
                return False
        else:
            if actual != v:
                return False
    return True


def _escape_text(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _escape_attr(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _serialize_element(el: Element) -> str:
    if el.tag == "#document":
        return "".join(str(c) for c in el._children)

    attrs_str = ""
    for k, v in el.attrs.items():
        if v is True or v is None or v == "":
            # boolean-ish empty
            if v is True or v is None:
                attrs_str += f" {k}"
            else:
                attrs_str += f' {k}=""'
        else:
            attrs_str += f' {k}="{_escape_attr(str(v))}"'

    if el.tag in VOID_TAGS:
        return f"<{el.tag}{attrs_str}>"

    inner = "".join(str(c) for c in el._children)
    return f"<{el.tag}{attrs_str}>{inner}</{el.tag}>"
