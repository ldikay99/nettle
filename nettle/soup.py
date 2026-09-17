"""High-level Nettle document facade — BeautifulSoup-like entry point."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from .nodes import Document, Element, Text, Comment, Node
from .parse import parse as _parse


class Nettle:
    """Parse HTML and expose Document methods at the top level.

    Usage::

        from nettle import Nettle, parse, fetch
        doc = Nettle(html, base_url="https://example.com")
        doc.extract({"title": "h1", "links": {"css": "a", "attr": "href", "all": True, "abs": True}})
    """

    def __init__(
        self,
        html: Union[str, bytes] = "",
        encoding: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
        on_error: str = "recover",
    ) -> None:
        self._doc: Document = _parse(html or "", encoding=encoding, on_error=on_error)
        if base_url:
            self._doc.base_url = base_url
        self.base_url = base_url or self._doc.base_url

    @property
    def document(self) -> Document:
        return self._doc

    # --- selection ---------------------------------------------------------

    def select(self, selector: str) -> List[Element]:
        return self._doc.select(selector)

    def select_one(self, selector: str) -> Optional[Element]:
        return self._doc.select_one(selector)

    def find(self, tag=None, **attrs):
        return self._doc.find(tag, **attrs)

    def find_all(self, tag=None, limit=None, **attrs):
        return self._doc.find_all(tag, limit=limit, **attrs)

    def matches(self, selector: str) -> bool:
        return self._doc.matches(selector)

    # --- text / serialize --------------------------------------------------

    @property
    def text(self) -> str:
        return self._doc.text

    def get_text(self, strip: bool = False, sep: str = "") -> str:
        return self._doc.get_text(strip=strip, sep=sep)

    def clean_text(self, mode: str = "plain") -> str:
        return self._doc.clean_text(mode=mode)

    @property
    def html(self) -> str:
        return self._doc.html

    def prettify(self, indent: str = "  ") -> str:
        return self._doc.prettify(indent=indent)

    # --- extract DX --------------------------------------------------------

    def extract(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        return self._doc.extract(schema)

    def record(self, mapping: Dict[str, Any], *, clean: str = "plain") -> Dict[str, Any]:
        return self._doc.record(mapping, clean=clean)

    def values(self, *selectors: str, clean: str = "plain", all: bool = False):
        return self._doc.values(*selectors, clean=clean, all=all)

    def table(self, selector: str = "table", **kwargs):
        return self._doc.table(selector, **kwargs)

    def urls(self, **kwargs):
        return self._doc.urls(**kwargs)

    def abs_url(self, href: str) -> str:
        return self._doc.abs_url(href)

    def meta(self, **kwargs):
        from .extract import meta
        return meta(self._doc, **kwargs)

    def links(self, **kwargs):
        from .extract import links
        return links(self._doc, base_url=self.base_url, **kwargs)

    # --- tree --------------------------------------------------------------

    @property
    def children(self):
        return self._doc.children

    @property
    def descendants(self):
        return self._doc.descendants

    @property
    def attrs(self):
        return self._doc.attrs

    @property
    def doctype(self) -> Optional[str]:
        return self._doc.doctype

    def __str__(self) -> str:
        return str(self._doc)

    def __repr__(self) -> str:
        return f"Nettle({self._doc!r})"

    def __getattr__(self, name: str):
        return getattr(self._doc, name)
