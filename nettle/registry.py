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

If Nettle doesn't know your framework's conventions, you add them —
no fork, no monkey-patching, no waiting for a release.
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
            "spoof_browser": True,
            "user_agent": None,          # None → rotating browser profiles
            "rotate_fingerprint": True,
            "headers": {},               # merged on top of browser defaults
            "verify": True,              # False → skip TLS cert verification
            "proxies": {},               # {"http": "...", "https": "..."}
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

    def register_classifier(self, fn: Callable[[str], Optional[str]]) -> None:
        """Custom URL classifier. Runs first; return a label or None.

        Example:
            registry.register_classifier(
                lambda u: "api" if "/mi-servicio/" in u else None
            )
        """
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
            }

    def __repr__(self) -> str:  # pragma: no cover
        s = self.snapshot()
        s.pop("http")
        return f"<Registry {s}>"


registry = Registry()
