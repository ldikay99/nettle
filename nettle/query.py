"""ExtractQuery DSL: doc.extract({...}) schema mapping selectors → cleaned values."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from .exceptions import ExtractError
from .nodes import Document, Element
from .text import clean_text


def _pipeline_clean(s, mode):
    """clean_text for text that already went through the parser (no re-decode)."""
    return clean_text(s, mode=mode, decode=False) if mode else s


def extract(root: Union[Document, Element, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
    """Declarative scrape: map schema keys to cleaned nested dicts/lists.

    Schema value shapes::

        {"css": "span.text", "clean": "plain"}
        {"css": "a.tag", "all": True, "clean": "plain"}
        {"css": "a", "attr": "href", "abs": True}
        {"select": "div.quote", "each": {...}}
        {"urls": True, "same_host": True}
        "span.text"   # shorthand → css + clean plain
    """
    from collections.abc import Mapping
    if hasattr(root, "document") and not isinstance(root, Element):
        root = root.document
    if not isinstance(schema, Mapping):
        raise ExtractError(
            f"extract() schema must be a dict mapping field names to specs, "
            f"got {type(schema).__name__} — e.g. extract({{'title': 'h1'}})"
        )
    out: Dict[str, Any] = {}
    for key, spec in schema.items():
        out[key] = apply_field_spec(root, spec, default_clean="plain")
    return out


def apply_field_spec(
    root: Element,
    spec: Any,
    *,
    default_clean: str = "plain",
) -> Any:
    if spec is None:
        return None

    # shorthand string → CSS text
    if isinstance(spec, str):
        spec = {"css": spec, "clean": default_clean}

    if not isinstance(spec, dict):
        raise ExtractError(f"field spec must be str or dict, got {type(spec).__name__}")

    # urls shortcut
    if spec.get("urls") is True or spec.get("type") == "urls":
        from .urls import find_urls
        html = str(root)
        base = spec.get("base_url") or getattr(root, "base_url", None)
        return find_urls(
            root,
            same_host=spec.get("same_host"),
            ext=spec.get("ext"),
            pattern=spec.get("pattern"),
            base_url=base,
        )

    # nested each / select records
    if "each" in spec:
        sel = spec.get("select") or spec.get("css") or spec.get("items")
        if not sel:
            raise ExtractError("'each' requires 'select' / 'css'")
        items = root.select(sel)
        mapping = spec["each"]
        clean = spec.get("clean", default_clean)
        return [
            {k: apply_field_spec(item, v, default_clean=clean) for k, v in mapping.items()}
            for item in items
        ]

    # nested object (no select) — apply relative to root
    if "fields" in spec:
        clean = spec.get("clean", default_clean)
        return {
            k: apply_field_spec(root, v, default_clean=clean)
            for k, v in spec["fields"].items()
        }

    css = spec.get("css") or spec.get("select") or spec.get("selector")
    attr = spec.get("attr")
    get_all = bool(spec.get("all", False))
    clean_mode = spec.get("clean", default_clean)
    default = spec.get("default", "" if not get_all else [])
    abs_url = bool(spec.get("abs", False))
    base_url = spec.get("base_url") or getattr(root, "base_url", None) or ""

    if not css:
        # {"text": True} / {"self": True} / bare {"attr": "data-id"} all
        # operate on the current element — the most common container pattern
        if spec.get("text") is True or spec.get("self") is True or attr:
            return _value_from_el(root, attr, clean_mode, abs_url, base_url)
        raise ExtractError(f"spec missing css/select: {spec!r}")

    matched = root.select(css)
    if not matched:
        return default

    if get_all:
        return [
            _value_from_el(el, attr, clean_mode, abs_url, base_url)
            for el in matched
        ]

    return _value_from_el(matched[0], attr, clean_mode, abs_url, base_url)


def _value_from_el(
    el: Element,
    attr: Any,
    clean_mode: str,
    abs_url: bool,
    base_url: str,
) -> Any:
    # attr may be str OR ordered list/tuple of attrs to try (data-src, src, ...)
    if attr:
        attrs = list(attr) if isinstance(attr, (list, tuple)) else [attr]
        raw = None
        for a in attrs:
            raw = el.get(a)
            if raw is not None and str(raw).strip() != "":
                break
        if raw is None:
            return ""
        val = str(raw)
        if abs_url or clean_mode == "url":
            from .urls import absolutize
            val = absolutize(val, base_url)
            if clean_mode == "url":
                return val
        if clean_mode and clean_mode not in ("none", "url"):
            return _pipeline_clean(val, clean_mode)
        return val

    text = el.get_text(strip=False, sep="")
    if clean_mode and clean_mode != "none":
        return _pipeline_clean(text, clean_mode)
    return text


class ExtractQuery:
    """Fluent wrapper around extract()."""

    def __init__(self, root: Union[Document, Element, Any]) -> None:
        self.root = root

    def run(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        return extract(self.root, schema)
