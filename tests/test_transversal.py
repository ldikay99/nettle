"""Transversal behavior: direct endpoints, any method, many HTML shapes."""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nettle import (
    parse,
    request,
    call_endpoint,
    probe_apis,
    find_urls,
    classify_url,
    sniff_api_candidates,
    sniff_embedded_json,
    __version__,
)


class _Handler(BaseHTTPRequestHandler):
    last = {}

    def log_message(self, *args):
        pass

    def _read(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, code=200, body=b'{"ok":true}', ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        _Handler.last = {"method": "GET", "path": self.path, "body": b""}
        if self.path.startswith("/catalog/load-items"):
            self._send(body=b'{"items":[1,2,3]}')
        elif self.path.startswith("/inventory/list.json"):
            self._send(body=b'{"skus":["a"]}')
        else:
            self._send(body=b'{"path":"%s"}' % self.path.encode())

    def do_POST(self):
        raw = self._read()
        _Handler.last = {"method": "POST", "path": self.path, "body": raw}
        self._send(body=b'{"received":true,"echo":%s}' % (raw or b"null"))

    def do_PUT(self):
        raw = self._read()
        _Handler.last = {"method": "PUT", "path": self.path, "body": raw}
        self._send(body=b'{"put":true}')

    def do_PATCH(self):
        raw = self._read()
        _Handler.last = {"method": "PATCH", "path": self.path, "body": raw}
        self._send(body=b'{"patch":true}')

    def do_DELETE(self):
        _Handler.last = {"method": "DELETE", "path": self.path, "body": b""}
        self._send(body=b'{"deleted":true}')


def _serve():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, port


class TestDirectHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd, cls.port = _serve()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def test_version(self):
        self.assertTrue(__version__.startswith("0.5"))

    def test_get_weird_path_no_api(self):
        r = request("GET", f"{self.base}/catalog/load-items")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.json()["items"], [1, 2, 3])

    def test_post_json(self):
        r = request("POST", f"{self.base}/catalog/load", json={"q": "shoes"})
        self.assertTrue(r.ok)
        self.assertEqual(_Handler.last["method"], "POST")
        self.assertIn(b"shoes", _Handler.last["body"])

    def test_put_patch_delete(self):
        self.assertTrue(request("PUT", f"{self.base}/items/1", json={"n": 1}).ok)
        self.assertEqual(_Handler.last["method"], "PUT")
        self.assertTrue(request("PATCH", f"{self.base}/items/1", json={"n": 2}).ok)
        self.assertEqual(_Handler.last["method"], "PATCH")
        self.assertTrue(call_endpoint(f"{self.base}/items/1", "DELETE").ok)
        self.assertEqual(_Handler.last["method"], "DELETE")

    def test_probe_mixed_specs(self):
        out = probe_apis(
            [
                f"{self.base}/inventory/list.json",
                {"url": f"{self.base}/catalog/load", "method": "POST", "json": {"x": 1}},
            ]
        )
        self.assertEqual(len(out), 2)
        self.assertTrue(out[0]["ok"])
        self.assertIn("skus", out[0]["data"])
        self.assertEqual(out[1]["method"], "POST")
        self.assertTrue(out[1]["ok"])

    def test_params(self):
        r = request("GET", f"{self.base}/catalog/load-items", params={"page": 2})
        self.assertIn("page=2", _Handler.last["path"])


class TestClassifyAndUrls(unittest.TestCase):
    def test_use_hints_false(self):
        self.assertEqual(
            classify_url("https://x.com/api/v1/x", use_hints=False),
            "page",  # no extension → page when hints off
        )
        self.assertEqual(classify_url("https://x.com/a.png", use_hints=False), "media")

    def test_find_urls_lazy_and_og(self):
        html = """
        <html><head>
          <meta property="og:image" content="https://cdn.ex/x.webp">
        </head><body>
          <img data-src="/lazy/a.jpg" src="/placeholder.gif">
          <picture><source srcset="/p/a.avif 1x, /p/b.avif 2x"><img src="/p/fallback.jpg"></picture>
          <video poster="/posters/v.jpg"></video>
        </body></html>
        """
        urls = find_urls(html, base_url="https://shop.test/")
        joined = " ".join(urls)
        self.assertIn("cdn.ex/x.webp", joined)
        self.assertIn("/lazy/a.jpg", joined)
        self.assertIn("/p/a.avif", joined)
        self.assertIn("/posters/v.jpg", joined)


class TestManyHTMLShapes(unittest.TestCase):
    def test_ecommerce_card_extract_attr_fallback(self):
        html = """
        <div class="card" data-endpoint="/rpc/getProduct">
          <img data-src="https://img/p1.jpg" src="/spinner.gif">
          <h2 class="title">Zapato</h2>
          <span class="price">$10</span>
        </div>
        <script>
          fetch('/catalog/load-items');
          xhr.open('GET', '/inventory/list.json');
          window.shopBootstrap = {"products":[{"id":9,"name":"Zapato"}],"currency":"USD"};
        </script>
        """
        doc = parse(html)
        doc.base_url = "https://store.test/"
        data = doc.extract({
            "title": {"css": "h2.title", "clean": "plain"},
            "img": {"css": "img", "attr": ["data-src", "src"], "abs": True},
            "endpoint": {"css": "[data-endpoint]", "attr": "data-endpoint"},
        })
        self.assertEqual(data["title"], "Zapato")
        self.assertTrue(data["img"].endswith("/p1.jpg"))
        self.assertEqual(data["endpoint"], "/rpc/getProduct")

        apis = sniff_api_candidates(doc, base_url="https://store.test/")
        joined = " ".join(apis)
        self.assertIn("/catalog/load-items", joined)
        self.assertIn("/inventory/list.json", joined)

        blobs = sniff_embedded_json(doc)
        self.assertTrue(any("shopBootstrap" in b["source"] for b in blobs))

    def test_article_semantic(self):
        html = """
        <article>
          <h1>Hello</h1>
          <p class="byline">Ana</p>
          <img srcset="https://cdn/a-400.jpg 400w, https://cdn/a-800.jpg 800w">
        </article>
        """
        doc = parse(html)
        data = doc.extract({
            "title": "h1",
            "author": {"css": ".byline", "clean": "plain"},
        })
        self.assertEqual(data["title"], "Hello")
        urls = find_urls(html)
        self.assertTrue(any("a-800.jpg" in u for u in urls))


if __name__ == "__main__":
    unittest.main()
