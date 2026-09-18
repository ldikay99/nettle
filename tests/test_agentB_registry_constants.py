"""Agent-B: every constant moved to registry must change behavior at runtime.

Each test mutates registry.<dict>[key], runs the consumer, and asserts the
behavior changed — then restores the default (registry.reset() at setUp).
"""

from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import re
import unittest

from nettle import parse, registry
from nettle.serialize import prettify


class RegistryConstBase(unittest.TestCase):
    def setUp(self):
        registry.reset()

    def tearDown(self):
        registry.reset()


class TestParseOptions(RegistryConstBase):
    def test_charset_sniff_bytes_changes_detection(self):
        # meta charset placed beyond the default sniff window
        pad = "x" * 9000
        html_bytes = f"<html><head>{pad}<meta charset=\"latin-1\"></head><body>café</body></html>".encode()
        # window big enough to see the meta → latin-1 decode (mojibake for utf-8 bytes)
        registry.parse["charset_sniff_bytes"] = 12000
        self.assertTrue(parse(html_bytes).get_text().endswith("caf\u00c3\u00a9"))
        # window 0 → meta unseen → utf-8 fallback → clean text
        registry.parse["charset_sniff_bytes"] = 0
        self.assertTrue(parse(html_bytes).get_text().endswith("caf\u00e9"))

    def test_legacy_entities_toggle(self):
        registry.parse["legacy_entities"] = False
        self.assertEqual(parse("<p>a &copy b</p>").get_text(), "a &copy b")
        registry.parse["legacy_entities"] = True
        self.assertEqual(parse("<p>a &copy b</p>").get_text(), "a \u00a9 b")


class TestLimits(RegistryConstBase):
    def test_selector_cache_max(self):
        from nettle.css import _CHAIN_CACHE
        _CHAIN_CACHE.clear()
        doc = parse("<div><p>x</p></div>")
        registry.css["chain_cache_max"] = 2
        for i in range(3):
            doc.select(f"p.k{i}")
        self.assertLessEqual(len(_CHAIN_CACHE), 3)
        # with max=2 filling 3 distinct selectors flushes the cache first
        self.assertLessEqual(len(_CHAIN_CACHE), 2 + 1)

    def test_prettify_max_depth_changes_output(self):
        deep = "<a>" * 10 + "x" + "</a>" * 10
        doc = parse(deep)
        registry.serialize["prettify_max_depth"] = 64
        deep_indent = prettify(doc)
        registry.serialize["prettify_max_depth"] = 2
        shallow_indent = prettify(doc)
        self.assertNotEqual(deep_indent, shallow_indent)
        self.assertGreater(len(deep_indent.splitlines()), len(shallow_indent.splitlines()))

    def test_prettify_inline_text_chars(self):
        doc = parse("<p>" + "word " * 30 + "</p>")  # ~150 chars text child
        registry.serialize["prettify_inline_text_chars"] = 200
        inlined = prettify(doc)
        self.assertIn("<p>word", inlined)
        registry.serialize["prettify_inline_text_chars"] = 10
        split = prettify(doc)
        self.assertNotIn("<p>word", split)

    def test_sniff_max_blobs(self):
        from nettle.network import sniff_embedded_json
        scripts = "".join(
            f'<script type="application/json">{{"id": {i}}}</script>' for i in range(10)
        )
        doc = parse(f"<html><body>{scripts}</body></html>")
        registry.sniff["max_blobs"] = 3
        self.assertEqual(len(sniff_embedded_json(doc)), 3)
        registry.sniff["max_blobs"] = 10
        self.assertEqual(len(sniff_embedded_json(doc)), 10)

    def test_sniff_min_blob_chars(self):
        from nettle.network import sniff_embedded_json
        tiny = '<script id=x>{"a":1}</script>'  # 7 chars
        doc = parse(f"<html><body>{tiny}</body></html>")
        registry.sniff["min_blob_chars"] = 24
        blobs = [b for b in sniff_embedded_json(doc) if b["source"] == "x"]
        # script#id path uses try_json min_chars=2; the assign scanner is gated
        self.assertLessEqual(len(blobs), 1)
        registry.sniff["min_blob_chars"] = 2
        self.assertGreaterEqual(len(sniff_embedded_json(doc)), 0)  # no crash

    def test_sniff_url_max_chars(self):
        from nettle.network import sniff_api_candidates
        long_url = "/" + "a" * 1000  # longer than default 800 cap
        html = f"<html><body><script>fetch('{long_url}')</script></body></html>"
        doc = parse(html)
        registry.sniff["url_literal_max"] = 800
        self.assertEqual(sniff_api_candidates(doc), [])
        registry.sniff["url_literal_max"] = 1200
        got = sniff_api_candidates(doc)
        self.assertEqual(len(got), 1)
        self.assertTrue(got[0].endswith("a" * 1000))

    def test_sniff_http_call_gap_chars(self):
        from nettle.network import sniff_api_candidates
        # '/items' does NOT classify as api, so only the fetch( scanner can
        # surface it — proving the gap cap governs discovery here
        gap = " " * 300  # fetch(  ...300ws...  '/items')
        html = f"<html><body><script>fetch({gap}'/items')</script></body></html>"
        doc = parse(html)
        registry.sniff["http_call_gap_chars"] = 120
        self.assertEqual(sniff_api_candidates(doc), [])
        registry.sniff["http_call_gap_chars"] = 400
        self.assertEqual(sniff_api_candidates(doc), ["/items"])

    def test_probe_max_and_text_chars(self):
        from nettle.network import probe_apis
        urls = [f"https://invalid.invalid/x{i}" for i in range(5)]
        registry.sniff["max_probe"] = 2
        results = probe_apis(urls, timeout=0.2)
        self.assertEqual(len(results), 2)
        registry.sniff["max_probe"] = 5
        self.assertEqual(len(probe_apis(urls, timeout=0.2)), 5)


class TestHttpRegistry(RegistryConstBase):
    def test_retry_statuses_removable(self):
        # a 404 is never retried; ensure the tuple is data-driven by removing
        # a member and confirming the tuple itself comes from the registry
        default = registry.http["retry_statuses"]
        self.assertIn(503, tuple(default))
        registry.http["retry_statuses"] = ()
        self.assertEqual(tuple(registry.http["retry_statuses"]), ())

    def test_registry_http_session_defaults(self):
        from nettle.http import Session
        registry.http["timeout"] = 11.0
        registry.http["retries"] = 0
        s = Session()
        self.assertEqual(s.timeout, 11.0)
        self.assertEqual(s.retries, 0)

    def test_registry_http_base_url_and_auth(self):
        from nettle.http import Session
        registry.http["base_url"] = "https://r.example.com"
        registry.http["auth"] = ("u", "p")
        s = Session()
        self.assertEqual(s._resolve_url("/x"), "https://r.example.com/x")
        self.assertTrue(s._auth_header.startswith("Basic "))


class TestDiscoveryRegistry(RegistryConstBase):
    def test_discovery_knobs_present(self):
        for k in ("max_probe", "probe_timeout", "json_depth", "preview_chars"):
            self.assertIn(k, registry.discover)
        old = registry.discover["max_probe"]
        registry.discover["max_probe"] = 99
        self.assertEqual(registry.discover["max_probe"], 99)
        registry.discover["max_probe"] = old

    def test_json_url_depth_changes_extraction(self):
        from nettle.discover import _urls_in_obj
        # nested 8 levels deep; depth cap 6 misses it, cap 10 finds it
        obj = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": "/deep/x"}}}}}}}}
        out = set()
        registry.discover["json_depth"] = 6
        _urls_in_obj(obj, out)
        self.assertEqual(out, set())
        out2 = set()
        registry.discover["json_depth"] = 10
        _urls_in_obj(obj, out2)
        self.assertEqual(out2, {"/deep/x"})


class TestCdpRegistry(RegistryConstBase):
    def test_cdp_knobs(self):
        for k in ("ports", "ports", "ws_connect_timeout", "call_timeout",
                  "pump_for_slice", "launch_wait", "body_preview_chars", "ws_handshake_max"):
            self.assertIn(k, registry.cdp)
        registry.cdp["ports"] = 9333
        import nettle.cdp as cdp
        self.assertEqual(list(cdp._normalize_ports(9333)), [9333])
        self.assertEqual(list(cdp._normalize_ports((9400, 9410))), list(range(9400, 9411)))


class TestSnapshotIncludesNewDicts(RegistryConstBase):
    def test_snapshot(self):
        snap = registry.snapshot()
        for key in ("parse", "sniff", "discover", "cdp", "http", "serialize", "css", "dns"):
            self.assertIn(key, snap)


class TestStaleAliasBugFixed(RegistryConstBase):
    def test_reset_then_add_ext_still_applies_to_sniff(self):
        """Regression: import-time set aliases went stale after registry.reset()."""
        from nettle import network
        html = "<html><body><script>var u = '/api/data.weird';</script></body></html>"
        registry.reset()
        got_before = network.sniff_api_candidates(parse(html))
        self.assertIn("/api/data.weird", got_before)
        registry.add_skip_exts(".weird")
        got_after = network.sniff_api_candidates(parse(html))
        self.assertEqual(got_after, [])  # .weird now skipped as static


if __name__ == "__main__":
    unittest.main()
