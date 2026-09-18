"""Network / embedded-JSON sniffing beyond the DOM.

DOM extract vs network/API extract
----------------------------------
* **DOM extract** (`doc.extract`, `select`, `table`): data rendered into HTML.
* **Network/API extract** (this module): JSON/XHR payloads that never appear as
  text nodes — embedded script JSON, HTTP-call URL literals, or live CDP sniff.

`sniff_embedded_json` is framework-agnostic (any `script[type*=json]`, any
`name = {…}` assignment that parses). Next/Nuxt globals are accelerators only.

`sniff_api_candidates` prefers fetch/axios/XHR URL arguments over path guesses.
Path hints remain a weak fallback; for runtime-built URLs use `sniff_network`.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from urllib.parse import urljoin

from .nodes import Document, Element
from .registry import registry as _registry

# --- Embedded JSON (framework-agnostic) ---------------------------------
# Named globals (registry.state_globals, user-extendable via
# registry.add_state_globals) are OPTIONAL accelerators; the scanner also
# accepts any `identifier = { ... }` / `[ ... ]` assignment that parses as JSON.

_JSON_ASSIGN_TMPL = (
    r"""(?:(?:window|self|globalThis)\.)?([A-Za-z_$][\w$]{0,@IDENT@})\s*=\s*(?=[{\[])"""
)

# --- URL / HTTP-call discovery (path-agnostic) --------------------------
# Regex caps (literal length bounds) come from registry.sniff so users can
# widen them for sites with giant signed URLs. Built lazily + cached per
# (min, max) pair; rebuilds automatically when the registry changes.

_HTTP_CALL_TMPL = (
    r"""(?:
          \bfetch\s*\(
        | \baxios\s*(?:\.\s*(?:get|post|put|delete|patch|request|head|options))?\s*\(
        | \$\s*\.\s*(?:get|post|ajax|getJSON)\s*\(
        | \bofetch\s*\(
        | \bky\s*(?:\.\s*(?:get|post|put|delete|patch))?\s*\(
        | \.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"]\s*,
        | \bnew\s+Request\s*\(
      )
      [\s\S]{0,@GAP@}?
      ['"]([^'"]{@MIN@,@MAX@})['"]
    """
)

_URL_LITERAL_TMPL = (
    r"""['"](
          https?://[^'"\s]{@MIN@,@MAX@}
        | /[A-Za-z0-9._~:/?#\[\]@!$&*+,;=%\-]{1,@MAX@}
      )['"]"""
)

_JSON_ASSIGN_CACHE: dict = {}


def _json_assign_re() -> "re.Pattern":
    import re as _re
    ident = int(_registry.sniff["identifier_max_chars"])
    key = ("json_assign", ident)
    cached = _REGEX_CACHE.get(key)
    if cached is None:
        cached = _re.compile(_render(_JSON_ASSIGN_TMPL, 2, 800, ident=ident), _re.M)
        _REGEX_CACHE[key] = cached
    return cached


_REGEX_CACHE: Dict[tuple, "re.Pattern"] = {}


def _bounds() -> tuple:
    s = _registry.sniff
    return (int(s["url_literal_min"]), int(s["url_literal_max"]))


def _render(tmpl: str, lo: int, hi: int, gap: int = None, ident: int = None) -> str:
    out = tmpl.replace("@MIN@", str(lo)).replace("@MAX@", str(hi))
    if gap is not None:
        out = out.replace("@GAP@", str(gap))
    if ident is not None:
        out = out.replace("@IDENT@", str(ident))
    return out


def _url_literal_re() -> "re.Pattern":
    lo, hi = _bounds()
    key = ("url_literal", lo, hi)
    cached = _REGEX_CACHE.get(key)
    if cached is None:
        cached = re.compile(_render(_URL_LITERAL_TMPL, lo, hi), re.I | re.VERBOSE)
        _REGEX_CACHE[key] = cached
    return cached


def _http_call_re() -> "re.Pattern":
    lo, hi = _bounds()
    gap = int(_registry.sniff["http_call_gap_chars"])
    key = ("http_call", lo, hi, gap)
    cached = _REGEX_CACHE.get(key)
    if cached is None:
        cached = re.compile(
            _render(_HTTP_CALL_TMPL, lo, hi, gap=gap), re.I | re.VERBOSE
        )
        _REGEX_CACHE[key] = cached
    return cached


_URL_ASSIGN_KEYWORDS = r"""(?:
          (?:api|data|service|services|backend|gateway|base|host|endpoint|url|uri|origin|cdn)
          (?:Url|URL|Uri|URI|Endpoint|Host|Base|Path|Prefix|Root)?
        | baseURL | BASE_URL | API_URL | DATA_URL | ENDPOINT | ORIGIN
      )"""

_URL_ASSIGN_RE = re.compile(
    _URL_ASSIGN_KEYWORDS + r"""\s*[:=]\s*['"]([^'"]{2,800})['"]""",
    re.I | re.VERBOSE,
)

# skip-lists live in nettle.registry — user-extendable at runtime
def _skip_candidate_exts() -> frozenset:
    """Read at call time — registry.reset() rebuilds set objects, so import-
    time aliases would go stale after a reset()."""
    return _registry.skip_candidate_exts


def _skip_url_prefixes() -> frozenset:
    return _registry.skip_url_prefixes
_BUILTIN_DATA_ATTRS = frozenset({
    "data-url", "data-href", "data-src", "data-api", "data-endpoint",
    "data-action", "data-feed", "data-source",
})


def _root(doc_or_el: Any) -> Element:
    if hasattr(doc_or_el, "document") and not isinstance(doc_or_el, Element):
        return doc_or_el.document
    if isinstance(doc_or_el, str):
        from .parse import parse
        return parse(doc_or_el)
    return doc_or_el


def sniff_embedded_json(
    doc: Any,
    *,
    max_blobs: Optional[int] = None,
    min_blob_chars: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Find JSON embedded in the page — any site, not only Next/Nuxt.

    Sources:
      1) script type application/ld+json | application/json | text/json
      2) script#id whose body is pure JSON (any id)
      3) JS assignments `name = {…}` / `[…]` that parse as JSON (any identifier)
      4) script body that is itself a JSON object/array

    Returns list of {"source": str, "data": Any}. Caps (max_blobs=50,
    min_blob_chars=24, …) default to registry.sniff — override per call or
    globally there.
    """
    if max_blobs is None:
        max_blobs = int(_registry.sniff["max_blobs"])
    if min_blob_chars is None:
        min_blob_chars = int(_registry.sniff["min_blob_chars"])
    fp_cap = int(_registry.sniff["fingerprint_chars"])
    min_assign = int(_registry.sniff["min_assign_chars"])
    root = _root(doc)
    results: List[Dict[str, Any]] = []
    seen_fp: set = set()

    def push(source: str, data: Any) -> None:
        if len(results) >= max_blobs:
            return
        try:
            fp = (source, json.dumps(data, sort_keys=True, default=str)[:fp_cap])
        except Exception:
            fp = (source, repr(data)[:fp_cap])
        if fp in seen_fp:
            return
        seen_fp.add(fp)
        results.append({"source": source, "data": data})

    def try_json(source: str, raw: str, *, min_chars: int = 2) -> bool:
        raw = (raw or "").strip()
        if len(raw) < min_chars:
            return False
        try:
            push(source, json.loads(raw))
            return True
        except json.JSONDecodeError:
            return False

    for typ, label in (
        ("application/ld+json", "ld+json"),
        ("application/json", "application/json"),
        ("text/json", "text/json"),
    ):
        for script in root.select(f'script[type="{typ}"]'):
            sid = script.get("id")
            source = str(sid) if sid else label
            if not try_json(source, script.get_text()):
                body = (script.get_text() or "").strip()
                if body:
                    push(f"{source}:raw", body)

    for script in root.select("script[id]"):
        body = (script.get_text() or "").strip()
        if body[:1] in "{[":
            try_json(str(script.get("id") or "script"), body)

    for script in root.select("script"):
        t = (script.get("type") or "").lower()
        if t and "javascript" not in t and t not in ("", "module", "text/javascript"):
            continue
        text_body = script.get_text()
        if not text_body or len(text_body) < min_blob_chars:
            continue

        for name in tuple(_registry.state_globals):
            if name not in text_body:
                continue
            blob = _extract_balanced_json_after(text_body, name)
            if blob and len(blob) >= 2:
                try:
                    push(name, json.loads(blob))
                except json.JSONDecodeError:
                    pass

        for m in _json_assign_re().finditer(text_body):
            name = m.group(1)
            if name in _registry.state_globals:
                continue
            if name.lower() in {"if", "for", "while", "return", "function", "switch", "catch"}:
                continue
            blob = _extract_balanced_json_at(text_body, m.end())
            if not blob or len(blob) < max(min_blob_chars, min_assign):
                continue
            if blob in ("{}", "[]"):
                continue
            try:
                data = json.loads(blob)
            except json.JSONDecodeError:
                continue
            if isinstance(data, (dict, list)) and data:
                push(f"assign:{name}", data)

        stripped = text_body.strip()
        if stripped[:1] in "{[" and stripped[-1:] in "}]":
            try_json("script-json", stripped)

    return results


def _extract_balanced_json_after(text: str, name: str) -> Optional[str]:
    """Find first { or [ after *name* and return balanced JSON substring."""
    idx = text.find(name)
    if idx < 0:
        return None
    eq = text.find("=", idx)
    search_from = eq + 1 if eq > idx and eq < idx + len(name) + 8 else idx + len(name)
    return _extract_balanced_json_at(text, search_from)


def _extract_balanced_json_at(text: str, start: int) -> Optional[str]:
    """From index *start*, skip whitespace and return a balanced JSON {...} or [...]."""
    scan_cap = int(_registry.sniff["json_scan_cap"])
    i = start
    while i < len(text) and text[i] in " \t\n\r:":
        i += 1
    if i >= len(text) or text[i] not in "{[":
        return None
    stack: List[str] = []
    in_str = False
    esc = False
    quote = ""
    start_i = i
    while i < len(text):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                in_str = False
        else:
            if ch in ('"', "'"):
                in_str = True
                quote = ch
            elif ch in "{[":
                stack.append(ch)
            elif ch in "}]":
                if not stack:
                    return None
                open_ch = stack.pop()
                if (open_ch == "{" and ch != "}") or (open_ch == "[" and ch != "]"):
                    return None
                if not stack:
                    return text[start_i : i + 1]
        i += 1
        if i - start_i > scan_cap:
            break
    return None


def sniff_api_candidates(
    doc: Any,
    base_url: Optional[str] = None,
    *,
    include_script_src: bool = False,
    include_all_url_literals: bool = True,
    extra_keywords: Optional[Sequence[str]] = None,
    api_hints: Optional[Sequence[str]] = None,
    keep_templates: bool = False,
) -> List[str]:
    """Discover likely network endpoints from HTML/JS — path-agnostic.

    Priority:
      1) URLs passed to fetch / axios / jQuery / XHR.open / Request / ofetch / ky
      2) Config assignments (baseURL, endpoint, dataUrl, …)
      3) URL literals that classify_url() labels as api
      4) data-* endpoint attributes

    *extra_keywords* adds caller-supplied identifier names to the config-
    assignment scanner (e.g. ["shopApi", "MY_SERVICE_URL"]) so site-specific
    conventions are honored without touching this module.
    *api_hints* is forwarded to classify_url for the same reason.
    *keep_templates=True* keeps URLs like "/items/${id}" (placeholders
    stripped) instead of dropping them, so runtime-built routes still surface.

    Runtime-built URLs still need sniff_network() (CDP) + MIME / XHR|Fetch.
    """
    from .urls import classify_url

    kw_extra = [k for k in (*_registry.url_keywords, *(extra_keywords or ())) if k]
    if kw_extra:
        alts = "|".join(re.escape(k) for k in kw_extra)
        assign_re = re.compile(
            rf"""(?:{alts}|{_URL_ASSIGN_KEYWORDS})\s*[:=]\s*['"]([^'"]{{2,800}})['"]""",
            re.I | re.VERBOSE,
        )
    else:
        assign_re = _URL_ASSIGN_RE

    root = _root(doc)
    if base_url is None:
        base_url = getattr(root, "base_url", None) or ""
    seen = set()
    out: List[str] = []

    def _looks_static(u: str) -> bool:
        path = (u.split("?", 1)[0].split("#", 1)[0]).lower()
        return any(path.endswith(e) for e in _skip_candidate_exts())

    def add(u: str, *, force: bool = False) -> None:
        u = (u or "").strip().strip("'\"")
        if not u:
            return
        low = u.lower()
        if any(low.startswith(p) for p in _skip_url_prefixes()):
            return
        if "${" in u or "{{" in u or "<%" in u:
            if not keep_templates:
                return
            u = re.sub(r"[$]\{[^}]*\}", "", u)
            u = re.sub(r"{{[^}]*}}", "", u)
            u = re.sub(r"<%[^%]*%>", "", u)
            if not u or u.rstrip("/") .endswith(tuple(_skip_candidate_exts())):
                return
        abs_u = urljoin(base_url, u) if base_url else u
        if abs_u in seen:
            return
        if not force and _looks_static(abs_u):
            return
        seen.add(abs_u)
        out.append(abs_u)

    for script in root.select("script"):
        text_body = script.get_text()
        if not text_body:
            if include_script_src:
                src = script.get("src")
                if src:
                    add(src, force=True)
            continue

        for m in _http_call_re().finditer(text_body):
            add(m.group(1), force=True)

        for m in assign_re.finditer(text_body):
            add(m.group(1), force=True)

        if include_all_url_literals:
            for m in _url_literal_re().finditer(text_body):
                lit = m.group(1)
                abs_u = urljoin(base_url, lit) if base_url else lit
                if classify_url(abs_u, hints=api_hints) == "api" or abs_u.lower().split("?", 1)[0].endswith(".json"):
                    add(lit)

    attrs = sorted(_registry.data_endpoint_attrs)
    if attrs:
        for el in root.select(", ".join(f"[{a}]" for a in attrs)):
            for attr in attrs:
                v = el.get(attr)
                if not v:
                    continue
                # the attribute NAME is itself evidence: data-api/data-endpoint/
                # data-action/data-feed (and anything user-registered) are
                # trusted verbatim; generic carriers still need classification.
                self_describing = (
                    attr in ("data-api", "data-endpoint", "data-action", "data-feed")
                    or attr not in _BUILTIN_DATA_ATTRS
                )
                abs_u = urljoin(base_url, v) if base_url else v
                if self_describing:
                    add(v, force=True)
                elif classify_url(abs_u, hints=api_hints) == "api" or v.lower().endswith(".json"):
                    add(v)

    return out



def call_endpoint(
    url: str,
    method: str = "GET",
    *,
    timeout: Optional[float] = None,
    headers: Optional[dict] = None,
    spoof_browser: bool = True,
    retries: Optional[int] = None,
    params: Optional[dict] = None,
    data: Any = None,
    json: Any = None,  # noqa: A002
    referer: Optional[str] = None,
):
    """Hit a user-supplied endpoint with any HTTP method. No sniffing required.

        call_endpoint("https://shop.example/catalog/load", "POST", json={"q": "x"})
        call_endpoint("https://shop.example/items/42", "DELETE")
    """
    from .http import request as http_request
    from .registry import registry as _reg
    if retries is None:
        retries = int(_reg.http.get("retries", 3))
    return http_request(
        method,
        url,
        timeout=timeout,
        headers=headers,
        spoof_browser=spoof_browser,
        retries=retries,
        params=params,
        data=data,
        json=json,
        referer=referer,
    )


def probe_apis(
    candidates: Any,
    *,
    method: str = "GET",
    timeout: Optional[float] = None,
    headers: Optional[dict] = None,
    spoof_browser: bool = True,
    max_probe: Optional[int] = None,
    json: Any = None,  # noqa: A002
    data: Any = None,
    params: Optional[dict] = None,
) -> List[Dict[str, Any]]:
    """Call endpoints the caller already has (or sniffed).

    *candidates* may be:
      - list[str] URLs (all use *method* / json / data / params)
      - list[dict] specs: {url, method?, json?, data?, params?, headers?}

    No assumption that paths contain /api/.
    Each result: {url, method, ok, status, content_type, data|text, error?}
    timeout / max_probe / preview length default to registry.sniff.
    """
    from .http import request as http_request

    if timeout is None:
        timeout = float(_registry.sniff["probe_timeout"])
    if max_probe is None:
        max_probe = int(_registry.sniff["max_probe"])
    preview_cap = int(_registry.sniff["preview_chars"])

    specs: List[Dict[str, Any]] = []
    if isinstance(candidates, str):
        candidates = [candidates]
    for c in list(candidates)[:max_probe]:
        if isinstance(c, str):
            specs.append({
                "url": c,
                "method": method,
                "json": json,
                "data": data,
                "params": params,
                "headers": headers,
            })
        elif isinstance(c, dict):
            if not c.get("url"):
                raise ValueError(
                    f"probe candidate dict needs a 'url' key, got keys: {sorted(c)[:8]}"
                )
            specs.append({
                "url": c["url"],
                "method": c.get("method", method),
                "json": c["json"] if "json" in c else json,
                "data": c["data"] if "data" in c else data,
                "params": c["params"] if "params" in c else params,
                "headers": {**(headers or {}), **(c.get("headers") or {})} or None,
            })
        else:
            raise TypeError(f"candidate must be str or dict, got {type(c)!r}")

    results: List[Dict[str, Any]] = []
    for spec in specs:
        url = spec["url"]
        meth = (spec.get("method") or "GET").upper()
        entry: Dict[str, Any] = {"url": url, "method": meth, "ok": False}
        try:
            resp = http_request(
                meth,
                url,
                timeout=timeout,
                headers=spec.get("headers"),
                spoof_browser=spoof_browser,
                params=spec.get("params"),
                data=spec.get("data"),
                json=spec.get("json"),
            )
            entry["status"] = resp.status
            entry["content_type"] = (
                resp.headers.get("Content-Type") or resp.headers.get("content-type") or ""
            )
            ct = entry["content_type"].lower()
            if "json" in ct or str(url).rstrip("/").endswith(".json"):
                try:
                    entry["data"] = resp.json()
                    entry["ok"] = resp.ok
                except Exception as e:
                    entry["text"] = resp.text[:preview_cap]
                    entry["error"] = f"json decode: {e}"
                    entry["ok"] = resp.ok
            else:
                entry["text"] = resp.text[:preview_cap]
                t = resp.text.lstrip()
                if t[:1] in "{[":
                    try:
                        entry["data"] = resp.json()
                    except Exception:
                        pass
                entry["ok"] = resp.ok
        except Exception as e:
            entry["error"] = str(e)
        results.append(entry)
    return results


def har_from_cdp(port: int = 9222, *, timeout: Optional[float] = None) -> Dict[str, Any]:
    """OPTIONAL: capture network via Chrome DevTools Protocol if reachable.

    Uses stdlib HTTP to list targets on localhost:{port}/json. Full WebSocket
    CDP framing for Network.getResponseBody is best-effort; when CDP is not
    available, returns a stub describing how to use probe_apis instead.
    timeout=None → registry.cdp["http_timeout"].
    """
    import json as _json
    from urllib.error import URLError
    from urllib.request import urlopen

    if timeout is None:
        timeout = float(_registry.cdp["http_timeout"])

    try:
        with urlopen(f"http://127.0.0.1:{port}/json/version", timeout=timeout) as resp:
            version = _json.loads(resp.read().decode("utf-8", errors="replace"))
        with urlopen(f"http://127.0.0.1:{port}/json/list", timeout=timeout) as resp:
            targets = _json.loads(resp.read().decode("utf-8", errors="replace"))
    except (URLError, OSError, TimeoutError, ValueError) as e:
        return {
            "ok": False,
            "error": f"CDP not reachable on port {port}: {e}",
            "hint": "Start Chrome with --remote-debugging-port=9222, or use "
                    "sniff_api_candidates() + probe_apis() (stdlib, no browser).",
            "entries": [],
        }

    # Minimal: list page targets + websocket debugger URLs (no full WS client —
    # Python stdlib has no websocket module; document the limitation).
    pages = []
    for t in targets if isinstance(targets, list) else []:
        if t.get("type") == "page":
            pages.append({
                "title": t.get("title"),
                "url": t.get("url"),
                "webSocketDebuggerUrl": t.get("webSocketDebuggerUrl"),
            })
    return {
        "ok": True,
        "version": version,
        "pages": pages,
        "entries": [],
        "note": "Use nettle.cdp.sniff_network(url, port=...) for full Network capture.",
        "sniff_network": "nettle.cdp.sniff_network",
    }
