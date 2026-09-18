"""Agent A round 3 — items 6, 7, 8 (offline): strict srcset, template-literal
embedded JSON recovery, discover/probe total_timeout (slow local server)."""
import http.server
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import nettle  # noqa: E402
from nettle import discover_endpoints, sniff_embedded_json  # noqa: E402
from nettle.urls import _parse_srcset, find_urls  # noqa: E402


class TestStrictSrcset(unittest.TestCase):
    def test_duplicate_url_descriptors_dedup(self):
        urls = find_urls('<img srcset="a.jpg 1x, a.jpg 2x, a.jpg 640w">',
                         base_url="https://e.com/")
        self.assertEqual(urls, ["https://e.com/a.jpg"])

    def test_double_descriptor_single_url(self):
        urls = find_urls('<img srcset="b.jpg 1x 2x">', base_url="https://e.com/")
        self.assertEqual(urls, ["https://e.com/b.jpg"])

    def test_invalid_descriptor_keeps_url_once(self):
        urls = find_urls('<img srcset="c.jpg foo, c.jpg bar">', base_url="https://e.com/")
        self.assertEqual(urls, ["https://e.com/c.jpg"])

    def test_trailing_comma_and_empty(self):
        urls = find_urls('<img srcset="d.jpg 2x, ,e.jpg">', base_url="https://e.com/")
        self.assertEqual(urls, ["https://e.com/d.jpg", "https://e.com/e.jpg"])

    def test_malformed_never_raises(self):
        for value in (",,,,", "x.jpg,,,,", " , ", "a b c d e", "1x", "", "a.jpg,,1x"):
            _parse_srcset(value)  # must not raise

    def test_comma_inside_url_reglued(self):
        urls = find_urls('<source srcset="g.jpg?set=a,2 2x">', base_url="https://e.com/")
        self.assertEqual(urls, ["https://e.com/g.jpg?set=a,2"])

    def test_valid_widths_and_densities(self):
        urls = find_urls(
            '<img srcset="s.jpg 480w, s2.jpg 1.5x, s3.jpg 2x">', base_url="https://e.com/")
        self.assertEqual(urls, ["https://e.com/s.jpg", "https://e.com/s2.jpg",
                                "https://e.com/s3.jpg"])


class TestEmbeddedJsonRecovery(unittest.TestCase):
    def test_template_literal_wrapper(self):
        h = ('<script>window.__DATA__ = `{"user":{"name":"Ana","langs":["es"]}}`;</script>')
        blobs = {b["source"]: b["data"] for b in sniff_embedded_json(h)}
        self.assertEqual(blobs["__DATA__"]["user"]["name"], "Ana")

    def test_template_assignment_prefix(self):
        h = ('<script>var state = `{"items": [1, 2, 3], "total": 3, '
             '"pad": "0123456789012345678901234567"}`;</script>')
        blobs = {b["source"]: b["data"] for b in sniff_embedded_json(h)}
        self.assertEqual(blobs["assign:state"]["items"], [1, 2, 3])

    def test_js_single_quote_escape_recovered(self):
        h = ('<script>var payload = {"msg": "it\\\'s fine", "n": 1, '
             '"pad": "0123456789012345678901234567"};</script>')
        blobs = {b["source"]: b["data"] for b in sniff_embedded_json(h)}
        self.assertEqual(blobs["assign:payload"]["msg"], "it's fine")

    def test_trailing_comma_recovered(self):
        h = ('<script>var d = {"a": [1, 2,], "b": {"c": 3,}, '
             '"pad": "0123456789012345678901234567"};</script>')
        blobs = {b["source"]: b["data"] for b in sniff_embedded_json(h)}
        self.assertEqual(blobs["assign:d"]["a"], [1, 2])
        self.assertEqual(blobs["assign:d"]["b"], {"c": 3})

    def test_template_braces_do_not_corrupt_neighbors(self):
        h = ('<script>'
             'var ui = {"tpl": `<b>${item.name}</b>`, "p2": `${a.b} ${c.d}`};'
             'var real = {"ok": true, "pad": "0123456789012345678901234567"};'
             '</script>')
        blobs = {b["source"]: b["data"] for b in sniff_embedded_json(h)}
        self.assertNotIn("assign:ui", blobs)  # invalid JSON omitted, not corrupted
        self.assertTrue(blobs["assign:real"]["ok"])

    def test_valid_json_never_rewritten(self):
        h = ('<script>var clean = {"a": 1, "b": [2, 3], '
             '"pad": "0123456789012345678901234567"};</script>')
        blobs = {b["source"]: b["data"] for b in sniff_embedded_json(h)}
        self.assertEqual(blobs["assign:clean"], {"a": 1, "b": [2, 3],
                                                 "pad": "0123456789012345678901234567"})

    def test_interpolation_literal_value_not_invented(self):
        # "${secret}" inside a JSON string is legal JSON: it must surface as
        # the LITERAL text (recover-without-corrupting: no value is invented)
        h = ('<script>var bad = {"x": "${secret}", '
             '"pad": "0123456789012345678901234567"};</script>')
        blobs = {b["source"]: b["data"] for b in sniff_embedded_json(h)}
        self.assertEqual(blobs["assign:bad"]["x"], "${secret}")


class _SlowHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        time.sleep(1.5)  # slow: each request burns wall time
        body = b'{"slow": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _slow_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SlowHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestTotalTimeout(unittest.TestCase):
    def test_probe_apis_total_timeout(self):
        from nettle import probe_apis
        srv = _slow_server()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            t0 = time.monotonic()
            res = probe_apis([base + f"/p{i}" for i in range(8)],
                             timeout=10, total_timeout=2)
            dt = time.monotonic() - t0
            self.assertLess(dt, 5.5, dt)
            self.assertEqual(len(res), 8)  # one entry per URL always
            errors = [r for r in res if r.get("error") == "total_timeout"]
            self.assertGreaterEqual(len(errors), 1)
            oks = [r for r in res if r.get("ok")]
            self.assertGreaterEqual(len(oks), 1)  # early ones completed
        finally:
            srv.shutdown()

    def test_discover_total_timeout_bounds_everything(self):
        srv = _slow_server()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}/"
            html = ('<script>fetch("/api/a"); fetch("/api/b"); fetch("/api/c");'
                    'fetch("/api/d"); fetch("/api/e"); fetch("/api/f");</script>')
            t0 = time.monotonic()
            res = discover_endpoints(base, doc=html, probe=True,
                                     probe_timeout=10, total_timeout=3)
            dt = time.monotonic() - t0
            self.assertLess(dt, 6.5, dt)
            self.assertTrue(res.get("timed_out"))
            self.assertGreaterEqual(len(res["endpoints"]), 3)  # partial results kept
        finally:
            srv.shutdown()

    def test_discover_without_timeout_unbounded_flag_absent(self):
        srv = _slow_server()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}/"
            html = "<script>fetch('/api/x');</script>"
            res = discover_endpoints(base, doc=html, probe=True,
                                     probe_timeout=3, max_probe=1)
            self.assertNotIn("timed_out", res)
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main(verbosity=2)
