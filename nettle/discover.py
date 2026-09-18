"""One-call endpoint discovery: give it a URL, get ranked API endpoints.

    from nettle import discover_endpoints
    res = discover_endpoints("https://shop.example/")
    for e in res["endpoints"][:5]:
        print(e["score"], e["url"], e["evidence"])

Sources consulted (all site-agnostic, no /api/ assumptions):
  1. JS HTTP-call literals   — fetch/axios/XHR/$.ajax/ofetch/ky/Request
  2. Config assignments      — baseURL/endpoint/… = "url"  (+ registry keywords)
  3. Embedded JSON blobs     — URLs inside __NEXT_DATA__-style state
  4. data-* attributes       — data-api/data-endpoint/… (+ registry attrs)
  5. URL literals classified as api (hints user-extensible via registry)
  6. Well-known descriptors  — /openapi.json, /graphql, … (probe mode)
  7. robots.txt Sitemap hints (probe mode)
Every candidate carries its *evidence* so you can judge, not guess.

For URLs built at runtime (string concat, GraphQL over POST, auth-walled)
use nettle.sniff_network() — real Chrome, real traffic, nothing hidden.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urljoin, urlparse

from .registry import registry as _registry


def _urls_in_obj(obj: Any, out: Set[str], depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(obj, str):
        s = obj.strip()
        if s.startswith(("http://", "https://", "/")) and " " not in s[:120]:
            out.add(s)
    elif isinstance(obj, dict):
        for v in obj.values():
            _urls_in_obj(v, out, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _urls_in_obj(v, out, depth + 1)


_SITEMAP_RE = re.compile(r"Sitemap:\s*(\S+)", re.I)


def discover_endpoints(
    url: str,
    *,
    probe: bool = True,
    max_probe: int = 15,
    timeout: Optional[float] = None,
    probe_timeout: float = 8.0,
    headers: Optional[dict] = None,
    api_hints: Optional[list] = None,
    extra_keywords: Optional[list] = None,
    doc: Optional[Any] = None,
    session: Optional[Any] = None,
) -> Dict[str, Any]:
    """Discover API/data endpoints reachable from *url* — one call.

    Pass probe=False for pure static analysis (one HTML fetch only).
    With probe=True (default) the top candidates are verified with a cheap
    GET and well-known descriptors (/openapi.json, /graphql, …) are tried.

    Returns {"url", "endpoints": [ {url, score, evidence[], status?,
    content_type?, ok?, data?} ], "probed": bool} sorted best-first.
    """
    from .http import Session
    from .network import sniff_api_candidates, sniff_embedded_json
    from .urls import classify_url, find_urls

    sess = session or Session(headers=headers)
    base = url

    if doc is None:
        resp = sess.get(url, timeout=timeout, retries=1)
        doc = resp.doc
        base = resp.url
    elif isinstance(doc, (str, bytes)):
        from .soup import Nettle
        doc = Nettle(doc, base_url=base)

    scores: Dict[str, int] = {}
    evidence: Dict[str, Set[str]] = {}

    def add(u: str, ev: str, pts: int) -> None:
        if not u:
            return
        u = u.strip().strip("'\" ")
        low = u.lower()
        if not u or any(low.startswith(p) for p in _registry.skip_url_prefixes):
            return
        host = urlparse(u).netloc.lower().split(":")[0] if "://" in u else ""
        if host and host in _registry.discovery_skip_hosts:
            return
        if "${" in u or "{{" in u:
            ev += "+template"
            u = re.sub(r"[$]{[^}]*}", "", u)
            u = re.sub(r"{{[^}]*}}", "", u)
        abs_u = urljoin(base, u) if base else u
        scores[abs_u] = scores.get(abs_u, 0) + pts
        evidence.setdefault(abs_u, set()).add(ev)

    # 1+2+4+5: static scan (JS calls, config assigns, data-attrs, literals)
    for cand in sniff_api_candidates(
        doc, base_url=base, extra_keywords=extra_keywords, api_hints=api_hints,
        keep_templates=True,
    ):
        add(cand, "static-scan", 4)

    # 3: URLs inside embedded JSON state blobs
    for blob in sniff_embedded_json(doc):
        found: Set[str] = set()
        _urls_in_obj(blob.get("data"), found)
        src = str(blob.get("source", "blob"))
        for u in found:
            kind = classify_url(u, hints=api_hints)
            if kind == "media" or (kind == "page" and src.startswith("ld+json")):
                continue  # author/profile URLs from JSON-LD are not endpoints
            add(u, f"embedded-json:{src}", 3)

    # link[rel] endpoints hints: preload/prefetch/modulepreload point at data
    for el in doc.select("link[rel]"):
        rel = (el.get("rel") or "").lower()
        href = el.get("href") or ""
        if any(r in rel for r in ("preload", "prefetch")) and "as=fetch" not in href:
            # only keep ones whose `as` is fetch or type json-ish
            as_attr = (el.get("as") or "").lower()
            typ = (el.get("type") or "").lower()
            if as_attr == "fetch" or "json" in typ or href.lower().endswith(".json"):
                add(href, "link-preload-fetch", 4)

    # every discovered URL the classifier (incl. user rules) calls api
    for u in find_urls(doc, base_url=base, kind="api", hints=api_hints):
        add(u, "classified-api", 2)

    # 6: well-known descriptors on this host (probe mode verifies them)
    if probe:
        origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
        for path in sorted(_registry.well_known):
            add(origin + path, "well-known", 3)

    endpoints = [
        {"url": u, "score": s, "evidence": sorted(evidence[u])}
        for u, s in scores.items()
    ]
    endpoints.sort(key=lambda e: -e["score"])

    result: Dict[str, Any] = {"url": base, "probed": False, "endpoints": endpoints}

    if not probe:
        return result

    # --- probe phase: verify top candidates + sitemap hint from robots.txt --
    from .network import probe_apis

    to_probe = [e["url"] for e in endpoints[:max_probe]]

    # robots.txt: cheap, one request, may reveal API surfaces
    robots_u = urljoin(base, "/robots.txt")
    if robots_u not in to_probe:
        to_probe.append(robots_u)
    try:
        robots = sess.get(robots_u, timeout=probe_timeout, retries=0)
        if robots.ok:
            for m in _SITEMAP_RE.finditer(robots.text or ""):
                add(m.group(1), "robots-sitemap", 1)
            # aggressive robots rules often mark admin/api areas
            for line in (robots.text or "").splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:") and len(line) > 12:
                    path = line.split(":", 1)[1].strip().rstrip("*$")
                    if path.startswith("/") and path.count("/") >= 1 and len(path) > 3:
                        if classify_url(urljoin(base, path), hints=api_hints) == "api":
                            add(urljoin(base, path), "robots-disallow-api", 2)
            endpoints = [
                {"url": u, "score": s, "evidence": sorted(evidence[u])}
                for u, s in scores.items()
            ]
            endpoints.sort(key=lambda e: -e["score"])
            extra = [e["url"] for e in endpoints if e["url"] not in to_probe]
            to_probe.extend(extra[: max(0, max_probe - len(to_probe) + 1)])
    except Exception:
        pass

    probed = probe_apis(
        [u for u in to_probe if u != robots_u or classify_url(u) == "api"],
        timeout=probe_timeout,
        headers=headers,
    )
    probed_by_url = {p["url"]: p for p in probed}

    for e in endpoints:
        p = probed_by_url.get(e["url"])
        if not p:
            continue
        e["status"] = p.get("status")
        e["content_type"] = p.get("content_type", "")
        e["ok"] = bool(p.get("ok"))
        if "data" in p and p.get("data") is not None:
            e["data_preview"] = _preview(p["data"])
        if p.get("error"):
            e["error"] = p["error"]
        # scoring: reachable JSON beats everything; 405/401/403 prove it's
        # a real endpoint even when it refuses us
        if e.get("ok") and "json" in (e.get("content_type") or "").lower():
            e["score"] += 8
            e["evidence"] = sorted(set(e["evidence"]) | {"probe:json-ok"})
        elif e.get("status") in (401, 403, 405, 406, 415):
            e["score"] += 4
            e["evidence"] = sorted(set(e["evidence"]) | {"probe:endpoint-exists"})
        elif e.get("ok"):
            e["score"] += 2
            e["evidence"] = sorted(set(e["evidence"]) | {"probe:reachable"})

    endpoints.sort(key=lambda e: -e["score"])
    result["probed"] = True
    result["endpoints"] = endpoints
    return result


def _preview(data: Any, limit: int = 200) -> str:
    import json as _json
    try:
        s = _json.dumps(data, ensure_ascii=False, default=str)
    except Exception:
        s = str(data)
    return s[:limit] + ("…" if len(s) > limit else "")
