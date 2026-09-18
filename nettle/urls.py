"""URL discovery from HTML/DOM -- absolute, deduped, filterable."""

from __future__ import annotations

import re
from typing import Any, Iterable, List, Optional, Sequence, Set, Union
from urllib.parse import urljoin, urlparse

from .nodes import Element
from .registry import registry as _registry

_SRCSET_RE = re.compile(r"(\S+)(?:\s+[\d.]+[wx])?", re.I)
_SRCSET_SPLIT_RE = re.compile(r",\s*")
_SRCSET_DESC_RE = re.compile(r"^(\d+(?:\.\d+)?)([wx])$", re.I)


def _parse_srcset(value: str) -> List[str]:
    """Strict srcset parsing (HTML spec candidate rules, hardened).

    Malformed input must not break URL discovery nor duplicate URLs:
      * invalid descriptors ("foo", "1.5y") are dropped, the URL is kept
      * duplicate/mixed descriptors ("1x 2x", "10w 20w") keep the URL once
      * empty candidates are skipped
    """
    out: List[str] = []
    pieces = _SRCSET_SPLIT_RE.split(value or "")
    # A comma inside a URL ("img?w=1,2 2x") produced a piece whose first
    # token is a bare number — that's a descriptor, not a candidate: glue it
    # back to the previous piece.
    glued: List[str] = []
    for piece in pieces:
        first = piece.strip().split(" ", 1)[0] if piece.strip() else ""
        if glued and first and re.fullmatch(r"[\d.]+[wx]?", first) and "," in (value or ""):
            glued[-1] += "," + piece
            continue
        glued.append(piece)
    for cand in glued:
        cand = cand.strip()
        if not cand:
            continue
        parts = cand.split()
        url = parts[0]
        if not url or url.startswith((",",)):
            continue
        # validate descriptors; on any violation we still yield the URL once
        seen: Set[str] = set()
        for d in parts[1:]:
            m = _SRCSET_DESC_RE.match(d)
            if not m or m.group(2).lower() in seen:
                break  # invalid or duplicated w/x: ignore the rest of them
            seen.add(m.group(2).lower())
        out.append(url)
    return out
_HTTP_IN_SCRIPT_RE = re.compile(
    r"""[\'"](https?://[^\'"]+)[\'"]|[\'"](/[^\'"]+)[\'"]"""
)
_META_REFRESH_RE = re.compile(r"url\s*=\s*([^\s;]+)", re.I)
_DATA_URL_ATTR_RE = re.compile(r"^data-.*(url|href|src|link|image)", re.I)

# Extension/hint tables now live in nettle.registry (user-mutable at runtime).
# These module names remain as live aliases for backwards compatibility.
ASSET_EXTS = _registry.asset_exts
MEDIA_EXTS = _registry.media_exts
DEFAULT_API_HINTS = _registry.api_hints
# kept as alias for older imports / docs
API_HINTS = DEFAULT_API_HINTS


def absolutize(href: str, base_url: Optional[str] = None) -> str:
    """Resolve href against base_url."""
    if not href:
        return ""
    href = href.strip()
    low = href.lower()
    if href.startswith("#") or low.startswith(("javascript:", "mailto:", "tel:")):
        return href
    if base_url:
        return urljoin(base_url, href)
    return href


def classify_url(
    url: str,
    *,
    hints: Optional[Sequence[str]] = None,
    use_hints: bool = True,
) -> str:
    """Classify URL as page | api | asset | media | other.

    Heuristic only. Set use_hints=False to skip predictive api/path/host rules
    (you still get media/asset/page by extension). Prefer calling endpoints
    directly with nettle.request / call_endpoint when you already have the URL.

    All heuristics live in nettle.registry and are user-extendable at runtime;
    custom classifiers registered via registry.register_classifier() run first.
    """
    if not url:
        return "other"
    for fn in list(_registry.classifiers):
        label = fn(url)
        if label:
            return label
    low = url.lower()
    if low.startswith(tuple(_registry.skip_url_prefixes)):
        return "other"
    parsed = urlparse(url)
    path = (parsed.path or "").lower()
    host = (parsed.netloc or "").lower()
    query = (parsed.query or "").lower()
    for e in _registry.media_exts:
        if path.endswith(e):
            return "media"
    for e in _registry.asset_exts:
        if path.endswith(e):
            return "asset"
    leaf = path.rsplit("/", 1)[-1]
    if not use_hints:
        if path.endswith((".html", ".htm", "/")) or "." not in leaf:
            return "page"
        return "other"
    hint_bag = tuple(_registry.api_hints) + tuple(hints or ())
    if any(h in low for h in hint_bag):
        return "api"
    host_leaf = host.split(":")[0]
    if any(host_leaf.startswith(p) or f".{p}" in f".{host_leaf}" for p in _registry.api_host_prefixes):
        if not any(path.endswith(e) for e in _registry.asset_exts | _registry.media_exts):
            return "api"
    if any(k in query for k in _registry.api_query_keys):
        return "api"
    if leaf in _registry.api_path_leaves:
        return "api"
    if path.endswith((".html", ".htm", "/")) or "." not in leaf:
        return "page"
    return "other"


def filter_urls(
    urls: Iterable[str],
    *,
    same_host: Optional[str] = None,
    ext: Optional[Union[str, Sequence[str]]] = None,
    pattern: Optional[str] = None,
    kind: Optional[Union[str, Sequence[str]]] = None,
    hints: Optional[Sequence[str]] = None,
    use_hints: bool = True,
) -> List[str]:
    """Filter URL list by host, extension, regex, and/or classify_url kind.

    *hints* / *use_hints* are forwarded to classify_url so callers can teach
    the classifier their site's own API path conventions (or disable the
    built-in heuristics entirely).
    """
    out: List[str] = []
    exts = None
    if ext:
        if isinstance(ext, str):
            exts = {ext if ext.startswith(".") else f".{ext}"}
        else:
            exts = {e if str(e).startswith(".") else f".{e}" for e in ext}
    kinds = None
    if kind:
        kinds = {kind} if isinstance(kind, str) else set(kind)
    try:
        cre = re.compile(pattern) if pattern else None
    except re.error as e:
        from .exceptions import SelectorError
        raise SelectorError(f"Invalid regex pattern {pattern!r}: {e}") from e
    host = None
    if same_host:
        host = urlparse(same_host if "://" in same_host else f"https://{same_host}").netloc.lower()
    for u in urls:
        if host:
            netloc = urlparse(u).netloc.lower()
            if netloc and netloc != host and not netloc.endswith("." + host):
                continue
        if exts:
            path = urlparse(u).path.lower()
            if not any(path.endswith(e) for e in exts):
                continue
        if cre and not cre.search(u):
            continue
        if kinds and classify_url(u, hints=hints, use_hints=use_hints) not in kinds:
            continue
        out.append(u)
    return out


def find_urls(
    html_or_doc: Any,
    *,
    same_host: Optional[Union[bool, str]] = None,
    ext: Optional[Union[str, Sequence[str]]] = None,
    pattern: Optional[str] = None,
    base_url: Optional[str] = None,
    kind: Optional[Union[str, Sequence[str]]] = None,
    hints: Optional[Sequence[str]] = None,
    use_hints: bool = True,
) -> List[str]:
    """Discover and absolutize URLs from HTML or a Nettle document/element.

    Sources: a[href], img/script/source/video/audio[src], srcset, link[href],
    data-* attrs, meta refresh, JSON-LD, inline script string literals.
    *hints* / *use_hints* are forwarded to classify_url when kind= is used.
    """
    root, html, base = _coerce(html_or_doc, base_url)
    found: List[str] = []
    seen: Set[str] = set()

    def add(u: str) -> None:
        if not u:
            return
        u = u.strip().strip("'\"")
        if not u or u.startswith("data:"):
            return
        abs_u = absolutize(u, base)
        if abs_u not in seen:
            seen.add(abs_u)
            found.append(abs_u)

    if root is not None:
        for a in root.select("a[href]"):
            add(a.get("href") or "")
        for tag in ("img", "script", "source", "video", "audio", "iframe", "embed", "track"):
            for el in root.select(f"{tag}[src]"):
                add(el.get("src") or "")
        for attr in sorted(_registry.url_source_attrs):
            for el in root.select(f"[{attr}]"):
                add(el.get(attr) or "")
        for el in root.select("[srcset]"):
            for url in _parse_srcset(el.get("srcset") or ""):
                add(url)
        for el in root.select("link[href]"):
            add(el.get("href") or "")
        for el in root.select('meta[property], meta[name]'):
            prop = (el.get("property") or el.get("name") or "").lower()
            if prop.startswith("og:") or prop in {"twitter:image", "twitter:player", "thumbnail"}:
                add(el.get("content") or "")
        for el in root.select("form[action]"):
            add(el.get("action") or "")
        for el in _all_elements(root):
            for k, v in list(el.attrs.items()):
                if not isinstance(v, str):
                    continue
                if _DATA_URL_ATTR_RE.match(k) or k in _registry.data_endpoint_attrs \
                        or k in _registry.url_source_attrs:
                    if v.startswith(("http", "/", "./")):
                        add(v)
        for m in root.select("meta[http-equiv]"):
            if (m.get("http-equiv") or "").lower() == "refresh":
                content = m.get("content") or ""
                mm = _META_REFRESH_RE.search(content)
                if mm:
                    add(mm.group(1).strip("'\""))
        for script in root.select('script[type="application/ld+json"]'):
            _urls_from_jsonish(script.get_text(), add)
        for script in root.select("script"):
            t = (script.get("type") or "").lower()
            if "ld+json" in t:
                continue
            if t and "json" in t and "javascript" not in t:
                _urls_from_jsonish(script.get_text(), add)
                continue
            text = script.get_text()
            for m in _HTTP_IN_SCRIPT_RE.finditer(text):
                add(m.group(1) or m.group(2) or "")

    host_filter = None
    if same_host is True and base:
        host_filter = base
    elif isinstance(same_host, str):
        host_filter = same_host

    return filter_urls(found, same_host=host_filter, ext=ext, pattern=pattern,
                       kind=kind, hints=hints, use_hints=use_hints)


def _all_elements(root: Element) -> List[Element]:
    out: List[Element] = []
    if root.tag != "#document":
        out.append(root)
    for n in root.descendants:
        if isinstance(n, Element):
            out.append(n)
    return out


def _urls_from_jsonish(text: str, add) -> None:
    if not text:
        return
    for m in re.finditer(r'https?://[^\\\'"\s<>]+', text):
        add(m.group(0).rstrip(".,;)]}"))
    for m in re.finditer(r'"(/[^"]+)"', text):
        add(m.group(1))


def _coerce(html_or_doc: Any, base_url: Optional[str]):
    root = None
    html = ""
    base = base_url
    if isinstance(html_or_doc, str):
        from .parse import parse
        root = parse(html_or_doc)
        html = html_or_doc
    elif hasattr(html_or_doc, "document") and not isinstance(html_or_doc, Element):
        root = html_or_doc.document
        html = str(root)
        base = base or getattr(html_or_doc, "base_url", None)
    elif isinstance(html_or_doc, Element):
        root = html_or_doc
        html = str(root)
        base = base or getattr(html_or_doc, "base_url", None)
    else:
        html = str(html_or_doc)
        from .parse import parse
        root = parse(html)
    if not base and root is not None:
        base_el = root.select_one("base[href]")
        if base_el is not None:
            base = base_el.get("href")
    return root, html, base or ""

