"""High-level extractors: fields, records, table, lists, links, meta."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Union

from .nodes import Document, Element
from .table import parse_table
from .text import clean_text


def _root(doc_or_el: Union[Document, Element, Any]) -> Element:
    if hasattr(doc_or_el, "document") and not isinstance(doc_or_el, Element):
        return doc_or_el.document
    return doc_or_el


def fields(
    root: Union[Document, Element, Any],
    mapping: Dict[str, Any],
    *,
    clean: str = "plain",
) -> Dict[str, Any]:
    """Extract named fields from *root* using a selector mapping.

    Mapping values may be:
      - str CSS selector → cleaned text of first match
      - dict with keys: css/select, attr, all, clean, default, abs
    """
    from .query import apply_field_spec

    el = _root(root)
    out: Dict[str, Any] = {}
    for key, spec in mapping.items():
        out[key] = apply_field_spec(el, spec, default_clean=clean)
    return out


def records(
    root: Union[Document, Element, Any],
    item_selector: str,
    mapping: Dict[str, Any],
    *,
    clean: str = "plain",
) -> List[Dict[str, Any]]:
    """For each item matching *item_selector*, extract *mapping* fields."""
    el = _root(root)
    results = []
    for item in el.select(item_selector):
        results.append(fields(item, mapping, clean=clean))
    return results


def table(
    root: Union[Document, Element, Any],
    selector: str = "table",
    **kwargs: Any,
) -> List[Dict[str, str]]:
    """Extract first matching table as list[dict]."""
    el = _root(root)
    t = el.select_one(selector)
    if t is None:
        return []
    return parse_table(t, **kwargs)


def lists(
    root: Union[Document, Element, Any],
    selector: str = "ul, ol",
    *,
    item: str = "li",
    clean: str = "plain",
) -> List[List[str]]:
    """Extract list items from each matching ul/ol."""
    el = _root(root)
    out: List[List[str]] = []
    for lst in el.select(selector):
        items = [
            clean_text(li.get_text(strip=True, sep=" "), mode=clean)
            for li in lst.select(item)
        ]
        items = [i for i in items if i]
        if items:
            out.append(items)
    return out


def links(
    root: Union[Document, Element, Any],
    selector: str = "a[href]",
    *,
    abs: bool = False,
    base_url: Optional[str] = None,
    clean: str = "plain",
) -> List[Dict[str, str]]:
    """Extract links as [{text, href, ...}]."""
    from .urls import absolutize

    el = _root(root)
    base = base_url or getattr(el, "base_url", None) or ""
    results = []
    for a in el.select(selector):
        href = a.get("href") or ""
        text = clean_text(a.get_text(strip=True, sep=" "), mode=clean)
        if abs and href:
            href = absolutize(href, base)
        results.append({"text": text, "href": href})
    return results


def meta(
    root: Union[Document, Element, Any],
    *,
    clean: str = "plain",
) -> Dict[str, str]:
    """Extract common document metadata (title, description, og:*, canonical)."""
    el = _root(root)
    out: Dict[str, str] = {}

    title_el = el.select_one("title")
    if title_el is not None:
        out["title"] = clean_text(title_el.get_text(), mode=clean)

    for m in el.select("meta"):
        name = (m.get("name") or m.get("property") or m.get("http-equiv") or "").strip()
        content = m.get("content")
        if name and content is not None:
            key = name.lower()
            out[key] = clean_text(str(content), mode=clean)

    canon = el.select_one('link[rel="canonical"]')
    if canon is not None and canon.get("href"):
        out["canonical"] = canon.get("href")

    return out


def values(
    root: Union[Document, Element, Any],
    *selectors: str,
    clean: str = "plain",
    all: bool = False,
) -> Any:
    """Quick multi-selector text extract.

    If one selector and all=False → str
    If multiple selectors → list
    If all=True → list of texts per selector (or flat if one)
    """
    el = _root(root)
    results = []
    for sel in selectors:
        matched = el.select(sel)
        if all:
            results.append([
                clean_text(m.get_text(strip=True, sep=" "), mode=clean)
                for m in matched
            ])
        else:
            if matched:
                results.append(
                    clean_text(matched[0].get_text(strip=True, sep=" "), mode=clean)
                )
            else:
                results.append("")
    if len(selectors) == 1:
        return results[0]
    return results
