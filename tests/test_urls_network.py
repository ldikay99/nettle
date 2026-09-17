"""Tests for urls + network sniffing."""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nettle import parse, find_urls, classify_url, filter_urls, absolutize
from nettle.network import sniff_embedded_json, sniff_api_candidates, har_from_cdp


HTML = """
<html>
<head>
  <base href="https://example.com/app/">
  <link href="/static/a.css" rel="stylesheet">
  <script type="application/ld+json">{"url":"https://example.com/item/1"}</script>
  <script id="__NEXT_DATA__" type="application/json">{"props":{"x":1}}</script>
</head>
<body>
  <a href="/page">p</a>
  <img src="/img/x.png" srcset="/img/x.png 1x, /img/x@2x.png 2x">
  <div data-url="/api/v1/cart"></div>
  <meta http-equiv="refresh" content="0;url=/redirect">
  <script>
    fetch('/api/v1/items');
    axios.get('https://example.com/api/v1/user');
    window.__NUXT__ = {"ok": true, "n": 2};
  </script>
</body>
</html>
"""


class TestUrls(unittest.TestCase):
    def test_find_urls_abs(self):
        doc = parse(HTML)
        urls = find_urls(doc, base_url="https://example.com/app/")
        self.assertTrue(any(u.endswith("/page") for u in urls))
        self.assertTrue(any("a.css" in u for u in urls))
        self.assertTrue(any("x@2x.png" in u for u in urls))
        self.assertTrue(any("/api/v1/cart" in u for u in urls))
        self.assertTrue(any(u.endswith("/redirect") for u in urls))

    def test_same_host(self):
        doc = parse(HTML)
        urls = find_urls(doc, base_url="https://example.com/", same_host=True)
        for u in urls:
            if u.startswith("http"):
                self.assertIn("example.com", u)

    def test_classify(self):
        self.assertEqual(classify_url("https://x.com/api/v1/x"), "api")
        self.assertEqual(classify_url("https://x.com/a.css"), "asset")
        self.assertEqual(classify_url("https://x.com/a.png"), "media")
        self.assertEqual(classify_url("https://x.com/about"), "page")

    def test_classify_beyond_api_slash(self):
        self.assertEqual(classify_url("https://api.shop.com/catalog/items"), "api")
        self.assertEqual(classify_url("https://x.com/wp-json/wp/v2/posts"), "api")
        self.assertEqual(classify_url("https://x.com/_next/data/build/page.json"), "api")
        self.assertEqual(classify_url("https://x.com/data/feed?format=json"), "api")
        self.assertEqual(classify_url("https://x.com/trpc/post.list"), "api")
        self.assertEqual(classify_url("https://x.com/about-us"), "page")

    def test_filter_ext(self):
        urls = ["https://a.com/x.png", "https://a.com/y.html"]
        self.assertEqual(filter_urls(urls, ext="png"), ["https://a.com/x.png"])

    def test_absolutize(self):
        self.assertEqual(
            absolutize("/x", "https://ex.com/a/"),
            "https://ex.com/x",
        )

    def test_element_urls(self):
        doc = parse('<a href="/z">z</a>')
        doc.base_url = "https://h.com/"
        urls = doc.urls()
        self.assertIn("https://h.com/z", urls)

    def test_extract_urls_flag(self):
        doc = parse(HTML)
        doc.base_url = "https://example.com/app/"
        data = doc.extract({"u": {"urls": True, "same_host": True}})
        self.assertIsInstance(data["u"], list)
        self.assertGreater(len(data["u"]), 0)


class TestNetwork(unittest.TestCase):
    def test_next_data(self):
        doc = parse(HTML)
        blobs = sniff_embedded_json(doc)
        sources = [b["source"] for b in blobs]
        self.assertIn("__NEXT_DATA__", sources)
        self.assertIn("ld+json", sources)
        self.assertTrue(any(b["source"] == "__NUXT__" for b in blobs))

    def test_api_candidates(self):
        doc = parse(HTML)
        apis = sniff_api_candidates(doc, base_url="https://example.com/")
        joined = " ".join(apis)
        self.assertIn("/api/v1/items", joined)
        self.assertIn("/api/v1/user", joined)


    def test_api_candidates_any_fetch_path(self):
        html = """
        <html><body><script>
          fetch('/data/catalog/products');
          axios.get('https://cdn.example.com/backend/items');
          const apiUrl = 'https://svc.example.com/query';
          window.baseURL = '/services/search';
        </script>
        <div data-endpoint="/rpc/getUser"></div>
        </body></html>
        """
        doc = parse(html)
        apis = sniff_api_candidates(doc, base_url="https://shop.test/")
        joined = " ".join(apis)
        self.assertIn("/data/catalog/products", joined)
        self.assertIn("/backend/items", joined)
        self.assertIn("/query", joined)
        self.assertIn("/services/search", joined)
        self.assertIn("/rpc/getUser", joined)


    def test_embedded_json_generic_assign(self):
        html = """
        <html><body><script>
          window.shopBootstrap = {"products":[{"id":1,"name":"A"}],"ok":true};
          const unused = 1;
        </script></body></html>
        """
        blobs = sniff_embedded_json(parse(html))
        sources = [b["source"] for b in blobs]
        self.assertTrue(any(s == "assign:shopBootstrap" or s == "shopBootstrap" for s in sources))
        data = next(b["data"] for b in blobs if "shopBootstrap" in b["source"])
        self.assertEqual(data["products"][0]["id"], 1)

    def test_api_candidates_xhr_open(self):
        html = """
        <html><body><script>
          var xhr = new XMLHttpRequest();
          xhr.open('GET', '/catalog/load-items');
          fetch('/inventory/list.json');
        </script></body></html>
        """
        apis = sniff_api_candidates(parse(html), base_url="https://store.test/")
        joined = " ".join(apis)
        self.assertIn("/catalog/load-items", joined)
        self.assertIn("/inventory/list.json", joined)

    def test_har_stub_no_chrome(self):
        # unlikely CDP on random high port
        result = har_from_cdp(port=59999, timeout=0.5)
        self.assertIn("ok", result)
        self.assertFalse(result["ok"])
        self.assertIn("hint", result)


if __name__ == "__main__":
    unittest.main()
