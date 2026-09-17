"""Tests for the runtime-extensible registry and one-call endpoint discovery."""

import sys
import unittest

sys.path.insert(0, ".")

from nettle import registry, parse
from nettle.urls import classify_url
from nettle.network import sniff_api_candidates, sniff_embedded_json
from nettle.discover import discover_endpoints


HTML = """
<html><head>
<script>
  const MY_SHOP_API = "https://shop.example/v2/catalog";
  fetch("https://shop.example/search-items");
  window.__SHOP_DATA__ = {"items": [{"api": "/item/42/feed"}]};
</script>
</head><body>
<div data-api="/mi-endpoint-custom" data-x-endpoint="https://x.example/feed2">x</div>
</body></html>
"""


class TestRegistry(unittest.TestCase):
    def tearDown(self):
        registry.reset()

    def test_add_api_hints(self):
        self.assertNotEqual(classify_url("https://x.com/loquesea/1"), "api")
        registry.add_api_hints("/loquesea/")
        self.assertEqual(classify_url("https://x.com/loquesea/1"), "api")

    def test_custom_classifier_runs_first(self):
        registry.register_classifier(lambda u: "custom" if "special" in u else None)
        self.assertEqual(classify_url("https://x.com/special/thing.png"), "custom")

    def test_classifier_unregister(self):
        fn = lambda u: "custom" if "special" in u else None  # noqa: E731
        registry.register_classifier(fn)
        registry.unregister_classifier(fn)
        self.assertNotEqual(classify_url("https://x.com/special/thing"), "custom")

    def test_media_exts_extensible(self):
        registry.add_media_exts(".weirdfmt")
        self.assertEqual(classify_url("https://x.com/a.weirdfmt"), "media")

    def test_state_globals_extensible(self):
        registry.add_state_globals("__SHOP_DATA__")
        blobs = sniff_embedded_json(HTML)
        sources = {b["source"] for b in blobs}
        self.assertIn("__SHOP_DATA__", sources)

    def test_url_keywords_extensible(self):
        registry.add_url_keywords("MY_SHOP_API")
        cands = sniff_api_candidates(parse(HTML), base_url="https://shop.example/")
        self.assertIn("https://shop.example/v2/catalog", cands)

    def test_data_endpoint_attrs_extensible(self):
        registry.add_data_endpoint_attrs("data-x-endpoint")
        cands = sniff_api_candidates(parse(HTML), base_url="https://shop.example/")
        self.assertIn("https://x.example/feed2", cands)

    def test_http_defaults(self):
        registry.http["timeout"] = 7.5
        from nettle import Session
        self.assertEqual(Session().timeout, 7.5)

    def test_reset(self):
        registry.add_api_hints("/zzz/")
        registry.register_classifier(lambda u: "zz")
        registry.reset()
        self.assertNotEqual(classify_url("https://x.com/zzz/1"), "api")

    def test_snapshot(self):
        snap = registry.snapshot()
        self.assertIn("/api/", snap["api_hints"])
        self.assertEqual(snap["classifiers"], 0)


class TestDiscoverOffline(unittest.TestCase):
    def test_static_discovery_with_evidence(self):
        res = discover_endpoints("https://shop.example/", probe=False, doc=HTML)
        urls = [e["url"] for e in res["endpoints"]]
        self.assertTrue(any("search-items" in u for u in urls))
        self.assertTrue(any(u.endswith("/mi-endpoint-custom") for u in urls))
        top = res["endpoints"][0]
        self.assertIn("evidence", top)
        self.assertGreater(top["score"], 0)
        self.assertFalse(res["probed"])

    def test_accepts_doc_object(self):
        doc = parse(HTML)
        doc.base_url = "https://shop.example/"
        res = discover_endpoints("https://shop.example/", probe=False, doc=doc)
        self.assertTrue(res["endpoints"])

    def test_template_urls_survive(self):
        html = '<script>fetch("https://x.example/items/${id}")</script>'
        res = discover_endpoints("https://x.example/", probe=False, doc=html)
        urls = [e["url"] for e in res["endpoints"]]
        self.assertTrue(any("items/" in u for u in urls))


if __name__ == "__main__":
    unittest.main(verbosity=2)
