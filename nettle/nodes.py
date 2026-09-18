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

    @property
    def next_sibling(self) -> Optional[Node]:
        """Next node (element OR text) under the same parent."""
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
        """Document-order walk of every descendant (iterative — deep-tree safe)."""
        stack = list(reversed(self._children))
        while stack:
            node = stack.pop()
            yield node
            if isinstance(node, Element):
                stack.extend(reversed(node._children))

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

    def get_text(self, *args: Any, strip: bool = False, sep: str = "") -> str:
        """Collect descendant text.

        Accepts both call styles:
          nettle:   get_text(strip=True, sep=" ")
          bs4:      get_text(" ")  /  get_text(" | ", True)
        A leading positional str is the separator; a positional bool is strip.
        """
        for a in args:
            if isinstance(a, str):
                sep = a
            elif isinstance(a, bool):
                strip = a
            else:
                raise TypeError(
                    "get_text() positional args must be str separator or bool "
                    f"strip, got {type(a).__name__}"
                )
        if not isinstance(strip, bool):
            raise TypeError(f"strip must be bool, got {type(strip).__name__}")
        parts: List[str] = []

        stack = list(reversed(self._children))
        while stack:
            node = stack.pop()
            if isinstance(node, Text):
                parts.append(node.content)
            elif isinstance(node, Element):
                stack.extend(reversed(node._children))
            # skip Comment

        if strip:
            parts = [p.strip() for p in parts]
            parts = [p for p in parts if p]
            return sep.join(parts)
        return sep.join(parts) if sep else "".join(parts)

    # --- find / select -----------------------------------------------------

    def find(self, tag: Any = None, *args: Any, **attrs: Any) -> Optional[Element]:
        """Find first descendant Element matching tag and/or attrs."""
        results = self.find_all(tag, *args, limit=1, **attrs)
        return results[0] if results else None

    def find_all(
        self,
        tag: Any = None,
        attrs: Optional[dict] = None,
        recursive: bool = True,
        string: Any = None,
        limit: Optional[int] = None,
        text: Any = None,
        **kwargs: Any,
    ) -> List[Element]:
        """Find descendant Elements — BeautifulSoup-compatible.

        *tag* may be: str, list/tuple/set of str, re.Pattern, or callable.
        Positional (tag, dict) or attrs=dict — bs4 style. recursive=False
        searches only direct children. string= (or bs4 alias text=) matches
        elements by their text content (str equality, regex search, or
        callable). Extra kwargs filter attributes (class_ → class).
        """
        import re as _re
        if attrs is None and kwargs:
            attrs = dict(kwargs)
        elif attrs is not None and kwargs:
            merged = dict(attrs)
            merged.update(kwargs)
            attrs = merged
        if string is None:
            string = text
        if limit is not None and limit <= 0:
            return []

        def tag_ok(node: Element) -> bool:
            if tag is None:
                return True
            if isinstance(tag, str):
                return node.tag == tag.lower()
            if isinstance(tag, (list, tuple, set)):
                wanted = {t.lower() if isinstance(t, str) else t for t in tag}
                return node.tag in {w for w in wanted if isinstance(w, str)} or any(
                    not isinstance(w, str) and _value_match(w, node.tag) for w in wanted
                )
            return _value_match(tag, node.tag)

        results: List[Element] = []
        pool = (
            [c for c in self._children if isinstance(c, Element)]
            if not recursive else None
        )
        if pool is None:
            pool = (n for n in self.descendants if isinstance(n, Element))
        for node in pool:
            if not tag_ok(node):
                continue
            if attrs and not _match_attrs(node, attrs):
                continue
            if string is not None:
                direct = "".join(
                    c.content for c in node._children if isinstance(c, Text)
                )
                if isinstance(string, str):
                    if direct != string:
                        continue
                elif isinstance(string, _re.Pattern):
                    if not string.search(direct):
                        continue
                elif callable(string):
                    if not string(direct):
                        continue
                else:
                    raise TypeError(f"string must be str/regex/callable, got {type(string).__name__}")
            results.append(node)
            if limit is not None and len(results) >= limit:
                break
        return results

    def find_parent(self, tag: Any = None, **attrs: Any) -> Optional["Element"]:
        """Nearest ancestor element matching tag and/or attrs."""
        p = self.parent
        while p is not None and p.tag != "#document":
            tag_ok = tag is None or (
                isinstance(tag, str) and p.tag == tag.lower()
            ) or (not isinstance(tag, str) and _value_match(tag, p.tag))
            if tag_ok and (not attrs or _match_attrs(p, attrs)):
                return p
            p = p.parent
        return None

    # --- bs4-style navigation ----------------------------------------------

    @property
    def parents(self) -> Iterator["Element"]:
        """Ancestor elements (nearest first), excluding the document root."""
        p = self.parent
        while p is not None and p.tag != "#document":
            yield p
            p = p.parent

    @property
    def contents(self) -> List[Node]:
        """Direct children list (bs4 alias of .children)."""
        return list(self._children)

    @property
    def name(self) -> str:
        """bs4 alias for .tag."""
        return self.tag

    @name.setter
    def name(self, value: str) -> None:
        self.tag = str(value).lower()

    @property
    def string(self) -> Optional[str]:
        """bs4 semantics: the only Text child, or the only child element's .string."""
        kids = self._children
        if len(kids) == 1 and isinstance(kids[0], Text):
            return kids[0].content
        if len(kids) == 1 and isinstance(kids[0], Element):
            return kids[0].string
        return None

    @property
    def strings(self) -> Iterator[str]:
        for d in self.descendants:
            if isinstance(d, Text) and d.content:
                yield d.content

    @property
    def stripped_strings(self) -> Iterator[str]:
        for t in self.strings:
            t2 = t.strip()
            if t2:
                yield t2

    def _document_stream(self) -> List[Node]:
        root: Node = self
        while root.parent is not None:
            root = root.parent
        if root is self:
            return list(self.descendants)
        return list(root.descendants)

    @property
    def next_element(self) -> Optional[Node]:
        """Next node in document order (bs4-style)."""
        stream = self._document_stream()
        try:
            i = stream.index(self)
        except ValueError:
            return None
        return stream[i + 1] if i + 1 < len(stream) else None

    @property
    def previous_element(self) -> Optional[Node]:
        stream = self._document_stream()
        try:
            i = stream.index(self)
        except ValueError:
            return None
        return stream[i - 1] if i > 0 else None

    # --- tree surgery (bs4-compatible names) --------------------------------

    def decompose(self) -> None:
        """Detach from parent and discard all children (bs4 decompose)."""
        self.detach()
        self._children.clear()

    def clear(self) -> None:
        """Remove all children, keep the element itself."""
        for c in list(self._children):
            c.parent = None
        self._children.clear()

    def unwrap(self) -> "Element":
        """Replace this element with its own children. Returns the empty shell."""
        parent = self.parent
        if parent is None:
            from .exceptions import NettleError
            raise NettleError("unwrap() requires the element to have a parent")
        idx = parent._children.index(self)
        parent._children.pop(idx)
        for c in list(self._children):
            c.parent = parent
            parent._children.insert(idx, c)
            idx += 1
        self._children.clear()
        self.parent = None
        return self

    def replace_with(self, *nodes: Node) -> "Element":
        """Replace this element with *nodes* in the parent. Returns self."""
        parent = self.parent
        if parent is None:
            from .exceptions import NettleError
            raise NettleError("replace_with() requires the element to have a parent")
        idx = parent._children.index(self)
        parent._children.pop(idx)
        for i, n in enumerate(nodes):
            if n.parent is not None:
                n.detach()
            n.parent = parent
            parent._children.insert(idx + i, n)
        self.parent = None
        return self

    def wrap(self, wrapper: "Element") -> "Element":
        """Wrap this element inside *wrapper*. Returns the wrapper."""
        if not isinstance(wrapper, Element):
            raise TypeError(f"wrap() expects an Element, got {type(wrapper).__name__}")
        parent = self.parent
        if parent is None:
            from .exceptions import NettleError
            raise NettleError("wrap() requires the element to have a parent")
        idx = parent._children.index(self)
        parent._children.pop(idx)
        wrapper.parent = parent
        parent._children.insert(idx, wrapper)
        wrapper.append(self)
        return wrapper

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
        """Return cleaned descendant text (already parser-decoded)."""
        from .text import clean_text as _ct
        return _ct(self.get_text(), mode=mode, decode=False)

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

    @property
    def head(self) -> Optional[Element]:
        html = self.html_element
        if html is not None:
            for c in html.child_elements:
                if c.tag == "head":
                    return c
        return self.select_one("head")

    @property
    def body(self) -> Optional[Element]:
        html = self.html_element
        if html is not None:
            for c in html.child_elements:
                if c.tag == "body":
                    return c
        return self.select_one("body")

    @property
    def title(self) -> Optional[str]:
        el = self.select_one("title")
        return el.get_text(strip=True) if el is not None else None

    def lists(self, selector: str = "ul, ol", *, item: str = "li", clean: str = "plain"):
        """Extract list items (README-promised shortcut for extract.lists)."""
        from .extract import lists as _lists
        return _lists(self, selector, item=item, clean=clean)

    def __str__(self) -> str:
        return _serialize_element(self)

    def __repr__(self) -> str:
        return f"<Document children={len(self._children)}>"


# --- helpers ---------------------------------------------------------------

def _value_match(matcher: Any, value: Any) -> bool:
    """str equality / regex search / list any-of / callable — bs4-style matching."""
    import re as _re
    if matcher is None:
        return True
    if isinstance(matcher, str):
        return value == matcher
    if isinstance(matcher, _re.Pattern):
        return bool(matcher.search(str(value)))
    if isinstance(matcher, (list, tuple, set)):
        return any(_value_match(m, value) for m in matcher)
    if callable(matcher):
        return bool(matcher(value))
    return value == matcher


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
        if isinstance(v, str) and key == "class":
            classes = actual.split() if isinstance(actual, str) else list(actual)
            needed = v.split()
            if not all(c in classes for c in needed):
                return False
        elif isinstance(v, (list, tuple, set)):
            if not any(str(actual) == str(m) for m in v):
                return False
        elif hasattr(v, "search"):  # re.Pattern
            if not v.search(str(actual)):
                return False
        elif callable(v):
            if not v(actual):
                return False
        elif str(actual) != str(v):
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


# children of these tags serialize UNESCAPED (raw text), like browsers do
RAW_TEXT_SERIALIZE = frozenset({
    "script", "style", "textarea", "title", "xmp",
    "iframe", "noembed", "noframes", "noscript",
})


def _serialize_attrs(el: Element) -> str:
    out = []
    for k, v in el.attrs.items():
        if v is True or v is None:
            out.append(f" {k}")
        elif v == "":
            out.append(f' {k}=""')
        else:
            out.append(f' {k}="{_escape_attr(str(v))}"')
    return "".join(out)


def _serialize_element(root: Node) -> str:
    """Iterative serialization — deep-tree safe, raw-text aware."""
    out: List[str] = []
    _OPEN, _CLOSE = 0, 1
    stack = [(root, _OPEN, False)]
    while stack:
        node, phase, raw = stack.pop()
        if isinstance(node, Text):
            out.append(node.content if raw else _escape_text(node.content))
            continue
        if isinstance(node, Comment):
            out.append(f"<!--{node.content}-->")
            continue
        if not isinstance(node, Element):
            continue
        if node.tag == "#document":
            if phase == _OPEN:
                doctype = getattr(node, "doctype", None)
                if doctype:
                    out.append(f"<!DOCTYPE {doctype}>")
                for c in reversed(node._children):
                    stack.append((c, _OPEN, False))
            continue
        if phase == _OPEN:
            attrs_str = _serialize_attrs(node)
            if node.tag in VOID_TAGS:
                out.append(f"<{node.tag}{attrs_str}>")
                continue
            out.append(f"<{node.tag}{attrs_str}>")
            stack.append((node, _CLOSE, False))
            child_raw = node.tag in RAW_TEXT_SERIALIZE
            for c in reversed(node._children):
                stack.append((c, _OPEN, child_raw))
        else:
            out.append(f"</{node.tag}>")
    return "".join(out)
