"""User-mutable configuration hub — teach Nettle your site's conventions.

Every heuristic in Nettle reads this registry **at call time**, never at
import time, so anything can be extended, narrowed, or overridden from
your own code before/after importing the rest of the library:

    import nettle
    from nettle import registry

    registry.add_api_hints("/tienda-service/", "/catalogo/")
    registry.add_state_globals("MY_APP_STATE", "__SHOP_DATA__")
    registry.add_url_keywords("shopApi", "MY_SERVICE_URL")
    registry.add_media_exts(".avif", ".heic")
    registry.add_well_known("/api/swagger.json", "/docs/openapi.yaml")
    registry.register_classifier(lambda url: "api" if "/loquesea" in url else None)
    registry.http["user_agent"] = "MyBot/1.0 (+https://me.example/bot)"
    registry.reset()   # back to factory defaults

Chrome/CDP tuning (ports, headless, timings, body caps) lives in
``registry.cdp``; sniffer/probe/discovery limits live in ``registry.sniff``,
``registry.discover``, ``registry.parse`` and ``registry.css``:

    registry.cdp["ports"] = [9400, 9401, 9402]      # candidate debug ports
    registry.cdp["ports"] = range(9500, 9510)        # ranges accepted too
    registry.cdp["headless"] = False                 # launch Chrome VISIBLE
    registry.cdp["body_preview_chars"] = 8000        # CDP body previews
    registry.sniff["max_blobs"] = 100                # embedded-JSON scan
    registry.add_cdp_ports(9333)                     # extend, not replace

Every default that used to be hard-coded is readable and mutable here at
call time. If Nettle doesn't know your framework's conventions, you add
them — no fork, no monkey-patching, no waiting for a release.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Iterable, List, Optional, Set


class Registry:
    """Mutable singleton holding every heuristic table Nettle consults."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._build()

    # --- defaults -----------------------------------------------------------

    def _build(self) -> None:
        # classify_url(): substring path/query hints for "api"
        self.api_hints: Set[str] = {
            "/api/", "/apis/", "/graphql", "/gql", "/rest/", "/rpc/", "/trpc/",
            "/bff/", "/gateway/", "/service/", "/services/", "/backend/",
            "/ajax/", "/xhr/", "/endpoint/", "/endpoints/",
            "/v1/", "/v2/", "/v3/", "/v4/", "/v5/",
            "/wp-json/", "/_next/data/", "/__data", "/.netlify/functions/",
            "/_api/", "/xapi/", "/odata/",
            ".json", ".geojson",
        }
        self.api_host_prefixes: Set[str] = {"api.", "apis.", "graphql.", "gql.", "rest.", "data."}
        self.api_query_keys: Set[str] = {"format=json", "output=json", "alt=json", "type=json"}
        self.api_path_leaves: Set[str] = {"query", "search", "data", "feed", "export", "load", "fetch"}

        # extension tables (classify_url, find_urls, CDP media detection, …)
        self.media_exts: Set[str] = {
            ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".heic", ".heif",
            ".mp4", ".webm", ".m4v", ".mov", ".mkv",
            ".mp3", ".wav", ".ogg", ".m4a", ".aac", ".opus", ".flac",
            ".m3u8", ".pdf",
        }
        self.asset_exts: Set[str] = {
            ".css", ".js", ".mjs", ".cjs", ".map", ".woff", ".woff2", ".ttf",
            ".eot", ".otf", ".ico", ".svg",
        }

        # sniff_embedded_json(): known state-global names (accelerators only;
        # ANY `name = {…}` assignment that parses as JSON is already accepted)
        self.state_globals: Set[str] = {
            "__NEXT_DATA__", "__NUXT__", "__INITIAL_STATE__", "__PRELOADED_STATE__",
            "__DATA__", "__APOLLO_STATE__", "__RELAY_STORE__", "__REDUX_STATE__",
            "__STORE__", "pageData", "preloadState", "initialState", "bootstrap",
            "APP_STATE", "SERVER_DATA",
        }

        # sniff_api_candidates(): identifier names for `name = "url"` config scan
        self.url_keywords: Set[str] = set()

        # URL discovery: data-* attributes treated as potential endpoint carriers
        self.data_endpoint_attrs: Set[str] = {
            "data-url", "data-href", "data-src", "data-api", "data-endpoint",
            "data-action", "data-feed", "data-source",
        }
        # lazy-loading / media attributes scanned by find_urls()
        self.url_source_attrs: Set[str] = {
            "data-src", "data-original", "data-lazy", "data-lazy-src", "data-bg",
            "data-image", "data-thumb", "data-poster", "poster",
        }

        # candidate filters
        self.skip_candidate_exts: Set[str] = self.asset_exts | {
            ".html", ".htm",
        } | {e for e in self.media_exts if e not in {".m3u8"}}
        self.skip_url_prefixes: Set[str] = {"javascript:", "mailto:", "tel:", "data:", "#", "blob:"}

        # discover_endpoints(): paths probed on the target host when probe=True
        self.well_known: Set[str] = {
            "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
            "/v3/api-docs", "/api-docs", "/graphql",
        }

        # user classifiers run BEFORE built-in heuristics; return "label" or None.
        # labels are free-form: classify_url returns them verbatim.
        self.classifiers: List[Callable[[str], Optional[str]]] = []

        # HTTP defaults consulted by Session/request when the caller passes None
        self.http: Dict[str, Any] = {
            "timeout": 30.0,
            "retries": 3,
            "retry_backoff": 0.8,
            "retry_statuses": {408, 425, 429, 500, 502, 503, 504},
            "spoof_browser": True,
            "user_agent": None,          # None → rotating browser profiles
            "rotate_fingerprint": True,
            "headers": {},               # merged on top of browser defaults
            "verify": True,              # False → skip TLS cert verification
            "proxies": {},               # {"http": "...", "https": "..."}
            "base_url": None,            # Session relative-URL base
            "auth": None,                # Session default auth (user, password)
        }

        # Chrome DevTools Protocol defaults (sniff_network / ensure_debugging_chrome /
        # find_debugging_port). "ports" is the candidate list scanned, in order;
        # extend it with add_cdp_ports() or replace it wholesale:
        #   registry.cdp["ports"] = [9400, 9401] | range(9500, 9510)
        self.cdp: Dict[str, Any] = {
            "ports": list(range(9222, 9235)),   # scanned by find_debugging_port()
            "headless": True,                    # ensure_debugging_chrome() default
            "launch_wait": 12.0,                 # max seconds waiting for /json/version
            "settle": 4.0,                       # sniff_network() quiet pump
            "scroll_steps": 8,                   # lazy-load scrolls
            "scroll_pause": 0.4,                 # seconds between scrolls
            "body_preview_chars": 4000,          # captured body preview cap
            "max_post_data_size": 65536,         # Network.enable maxPostDataSize
            "ws_connect_timeout": 10.0,          # websocket handshake timeout
            "call_timeout": 20.0,                # CDP command default timeout
            "http_timeout": 5.0,                 # /json/* HTTP endpoint timeout
            "alive_timeout": 1.5,                # debugging_alive() probe timeout
            "tab_close_timeout": 2.0,            # /json/close/{id} timeout
            "launch_poll_interval": 0.25,        # sleep between /json/version checks
            "kill_wait": 5.0,                    # grace after SIGTERM/SIGKILL
            "runtime_eval_timeout": 5.0,         # Runtime.evaluate (scroll) calls
            "ws_handshake_max": 65536,           # max bytes for handshake headers
            "ws_recv_chunk": 4096,               # socket recv buffer size
            "pump_slice_min": 0.05,              # smallest pump timeout slice
            "pump_slice_max": 1.0,               # largest pump timeout slice
            "pump_for_slice": 0.25,              # pump_for() step
            # URL substrings that mark a CDP response worth body-fetching even
            # when its MIME/ResourceType didn't scream json/xhr.
            "body_url_hints": ("/api/", "graphql", "/wp-json/", "/_next/data/"),
        }

        # Embedded-JSON / API-candidate sniffing limits (network.py)
        self.sniff: Dict[str, Any] = {
            "max_blobs": 50,              # sniff_embedded_json() result cap
            "min_blob_chars": 24,         # min script size worth scanning
            "min_assign_chars": 40,       # min `name = {…}` blob size
            "json_scan_cap": 2_000_000,   # max chars for one balanced-JSON scan
            "fingerprint_chars": 500,     # dedup fingerprint slice
            "preview_chars": 2000,        # probe_apis() text preview cap
            "probe_timeout": 15.0,        # probe_apis() per-request timeout
            "max_probe": 20,              # probe_apis() candidate cap
            "http_call_gap_chars": 120,   # regex gap between fetch( and its URL
            "identifier_max_chars": 120,  # JS identifier length cap in scans
            "url_literal_min": 2,         # URL-literal regex min length
            "url_literal_max": 800,       # URL-literal regex max length
        }

        # discover_endpoints() limits (discover.py)
        self.discover: Dict[str, Any] = {
            "max_probe": 15,              # candidates verified per call
            "probe_timeout": 8.0,         # probe request timeout
            "json_depth": 6,              # max depth walking embedded JSON
            "preview_chars": 200,         # data_preview length
        }

        # Parser limits (parse.py)
        self.parse: Dict[str, Any] = {
            "legacy_entities": True,     # decode "&copy 2024" (no semicolon) like browsers

            "charset_sniff_bytes": 8192,  # bytes inspected by detect_charset()
        }

        # CSS engine limits (css.py)
        self.serialize: Dict[str, Any] = {
            "prettify_max_depth": 64,          # recursion guard in prettify()
            "prettify_inline_text_chars": 80,  # single-line inline threshold
        }

        self.css: Dict[str, Any] = {
            "chain_cache_max": 512,       # parsed-selector cache entries
        }

        # DNS resolution (resolve_ip)
        self.dns: Dict[str, Any] = {
            "timeout": 8.0,               # getaddrinfo wall-clock timeout
        }

        # discover_endpoints(): hosts never proposed as endpoints (namespaces,
        # standards bodies, font/CDN hosts). Extend with add_discovery_skip_hosts().
        self.discovery_skip_hosts: Set[str] = {
            "schema.org", "www.schema.org", "w3.org", "www.w3.org",
            "purl.org", "ogp.me", "xmlns.com", "www.w3schools.com",
            "fonts.googleapis.com", "fonts.gstatic.com",
            "www.googletagmanager.com", "googletagmanager.com",
            "www.google-analytics.com", "ssl.google-analytics.com",
            "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
        }

    # --- generic mutators ----------------------------------------------------

    def _add(self, target: Set[str], values: Iterable[str]) -> None:
        with self._lock:
            target.update(v for v in values if v)

    def _discard(self, target: Set[str], values: Iterable[str]) -> None:
        with self._lock:
            for v in values:
                target.discard(v)

    def add_api_hints(self, *hints: str) -> None:
        """Teach classify_url() your site's API path substrings."""
        self._add(self.api_hints, hints)

    def remove_api_hints(self, *hints: str) -> None:
        self._discard(self.api_hints, hints)

    def add_api_host_prefixes(self, *prefixes: str) -> None:
        self._add(self.api_host_prefixes, prefixes)

    def add_api_query_keys(self, *keys: str) -> None:
        self._add(self.api_query_keys, keys)

    def add_api_path_leaves(self, *leaves: str) -> None:
        self._add(self.api_path_leaves, leaves)

    def add_media_exts(self, *exts: str) -> None:
        self._add(self.media_exts, (e if e.startswith(".") else f".{e}" for e in exts))

    def add_asset_exts(self, *exts: str) -> None:
        self._add(self.asset_exts, (e if e.startswith(".") else f".{e}" for e in exts))

    def add_state_globals(self, *names: str) -> None:
        """Register your framework's global state variable names."""
        self._add(self.state_globals, names)

    def add_url_keywords(self, *names: str) -> None:
        """Register identifier names for the `name = "url"` config scanner."""
        self._add(self.url_keywords, names)

    def add_data_endpoint_attrs(self, *attrs: str) -> None:
        self._add(self.data_endpoint_attrs, attrs)

    def add_url_source_attrs(self, *attrs: str) -> None:
        self._add(self.url_source_attrs, attrs)

    def add_skip_exts(self, *exts: str) -> None:
        self._add(self.skip_candidate_exts, exts)

    def add_discovery_skip_hosts(self, *hosts: str) -> None:
        """Teach discover_endpoints() which hosts are never endpoints."""
        self._add(self.discovery_skip_hosts, hosts)

    def add_well_known(self, *paths: str) -> None:
        """Register well-known descriptor paths discover_endpoints() probes."""
        self._add(self.well_known, paths)

    # --- CDP / chrome ---------------------------------------------------------

    def set_cdp_ports(self, ports: Any) -> None:
        """Replace the CDP candidate port list.

        Accepts an int, an iterable of ints, a 2-tuple ``(lo, hi)`` inclusive
        range, or a ``range()`` object:

            registry.set_cdp_ports(9222)
            registry.set_cdp_ports([9400, 9401, 9402])
            registry.set_cdp_ports((9300, 9310))    # inclusive range
            registry.set_cdp_ports(range(9500, 9510))
        """
        with self._lock:
            self.cdp["ports"] = _normalize_ports(ports, _source="registry.set_cdp_ports")

    def add_cdp_ports(self, *ports: Any) -> None:
        """Append candidate CDP ports. Each arg may be an int or (lo, hi) tuple."""
        extra: List[int] = []
        for p in ports:
            if isinstance(p, int):
                extra.append(p)
            else:
                extra.extend(_normalize_ports(p, _source="registry.add_cdp_ports"))
        with self._lock:
            current = list(self.cdp["ports"])
            for p in extra:
                if p not in current:
                    current.append(p)
            self.cdp["ports"] = current

    def remove_cdp_ports(self, *ports: int) -> None:
        """Drop candidate CDP ports (e.g. one you know another app owns)."""
        with self._lock:
            drop = {p for p in ports if isinstance(p, int)}
            self.cdp["ports"] = [p for p in self.cdp["ports"] if p not in drop]

    def register_classifier(self, fn: Callable[[str], Optional[str]]) -> None:
        """Custom URL classifier. Runs first; return a label or None.

        Example:
            registry.register_classifier(
                lambda u: "api" if "/mi-servicio/" in u else None
            )
        """
        if not callable(fn):
            raise TypeError(
                f"classifier must be callable(url) -> label|None, "
                f"got {type(fn).__name__}"
            )
        with self._lock:
            self.classifiers.append(fn)

    def unregister_classifier(self, fn: Callable[[str], Optional[str]]) -> None:
        with self._lock:
            if fn in self.classifiers:
                self.classifiers.remove(fn)

    @property
    def builtin_data_endpoint_attrs(self) -> frozenset:
        return frozenset({
            "data-url", "data-href", "data-src", "data-api", "data-endpoint",
            "data-action", "data-feed", "data-source",
        })

    def reset(self) -> None:
        """Restore factory defaults (custom classifiers included)."""
        with self._lock:
            self._build()

    # --- views ----------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """Read-only copy of current config (for debugging / persistence)."""
        with self._lock:
            return {
                "api_hints": sorted(self.api_hints),
                "api_host_prefixes": sorted(self.api_host_prefixes),
                "api_query_keys": sorted(self.api_query_keys),
                "api_path_leaves": sorted(self.api_path_leaves),
                "media_exts": sorted(self.media_exts),
                "asset_exts": sorted(self.asset_exts),
                "state_globals": sorted(self.state_globals),
                "url_keywords": sorted(self.url_keywords),
                "data_endpoint_attrs": sorted(self.data_endpoint_attrs),
                "url_source_attrs": sorted(self.url_source_attrs),
                "skip_candidate_exts": sorted(self.skip_candidate_exts),
                "skip_url_prefixes": sorted(self.skip_url_prefixes),
                "well_known": sorted(self.well_known),
                "classifiers": len(self.classifiers),
                "http": dict(self.http),
                "cdp": {
                    **self.cdp,
                    "ports": list(self.cdp["ports"]),
                },
                "sniff": dict(self.sniff),
                "discover": dict(self.discover),
                "parse": dict(self.parse),
                "css": dict(self.css),
                "dns": dict(self.dns),
                    "serialize": dict(self.serialize),
            }

    def __repr__(self) -> str:  # pragma: no cover
        s = self.snapshot()
        s.pop("http")
        return f"<Registry {s}>"


registry = Registry()


def _normalize_ports(spec: Any, *, _source: str = "nettle") -> List[int]:
    """Coerce a port spec into a validated, ordered list of ints.

    Accepted: 9222 | [9222, 9223] | (9300, 9310) inclusive range |
    range(9500, 9510) | any iterable of ints. Raises ValueError with a
    clear message for anything else, so a typo fails loudly.
    """
    if spec is None:
        return []
    items: Any = spec
    if isinstance(spec, int) and not isinstance(spec, bool):
        items = [spec]
    elif isinstance(spec, tuple) and len(spec) == 2 and all(
        isinstance(x, int) and not isinstance(x, bool) for x in spec
    ):
        lo, hi = spec
        if hi < lo:
            raise ValueError(
                f"{_source}: port range (lo, hi) must be ascending, got ({lo}, {hi})"
            )
        items = range(lo, hi + 1)
    elif isinstance(spec, range):
        items = spec
    elif isinstance(spec, (list, tuple, set, frozenset)):
        # list/set of ints, or a 2-tuple that is NOT an int range (e.g. mixed)
        items = spec
    else:
        raise ValueError(
            f"{_source}: port spec must be an int, list/range of ints, or "
            f"(lo, hi) tuple, got {type(spec).__name__}: {spec!r}"
        )
    out: List[int] = []
    for p in items:
        if isinstance(p, bool) or not isinstance(p, int):
            raise ValueError(
                f"{_source}: ports must be ints, got {type(p).__name__} {p!r}"
            )
        if not (1 <= p <= 65535):
            raise ValueError(f"{_source}: port {p} out of range 1-65535")
        if p not in out:
            out.append(p)
    return out
