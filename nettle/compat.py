"""Optional BeautifulSoup-like aliases for familiarity."""

from __future__ import annotations

from typing import Any, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .nodes import Element


def select(el: "Element", selector: str) -> List["Element"]:
    """Alias of Element.select (CSS). Prefer over find_all for CSS."""
    return el.select(selector)


def select_one(el: "Element", selector: str) -> Optional["Element"]:
    return el.select_one(selector)


def find_all(el: "Element", *args: Any, **kwargs: Any) -> List["Element"]:
    """BS4-style find_all — tag/attrs, not CSS."""
    return el.find_all(*args, **kwargs)


def find(el: "Element", *args: Any, **kwargs: Any) -> Optional["Element"]:
    return el.find(*args, **kwargs)


def get_text(el: "Element", strip: bool = False, separator: str = "", **kwargs: Any) -> str:
    """BS4 uses separator=; Nettle uses sep=. Accept both."""
    sep = kwargs.pop("sep", separator)
    return el.get_text(strip=strip, sep=sep)
