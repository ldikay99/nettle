"""Agent A round 3 — items 4, 5, 12 (offline): retry jitter, encoding
priority BOM>meta>header, and the first-class cookie API, using a local
http.server that really sends Set-Cookie headers."""
import http.server
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import warnings

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import nettle  # noqa: E402
from nettle.http import Response, Session, _decode_body  # noqa: E402


class _CookieHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code, body, headers):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/set"):
            # /set?k=v&k2=v2 -> Set-Cookie each pair (one with attrs)
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(self.path).query)
            headers = []
            for i, (k, vs) in enumerate(q.items()):
                attrs = "; Path=/; HttpOnly"
                if i == 0:
                    attrs += "; Expires=Fri, 01 Jan 2027 00:00:00 GMT"
                headers.append(("Set-Cookie", f"{k}={vs[0]}{attrs}"))
            self._send(200, b'{"ok": true}', headers + [("Content-Type", "application/json")])
        elif self.path.startswith("/echo"):
            cookie = self.headers.get("Cookie") or ""
            self._send(200, json.dumps({"cookie": cookie}).encode(),
                       [("Content-Type", "application/json")])
        elif self.path.startswith("/br"):
            import gzip as _g
            body = b"brotli from local server: " + b"x" * 200
            comp = nettle.brotli_decompress  # noqa: F841 (ensure importable)
            from nettle.brotli_dec import BrotliError
            try:
                import brotli as _br  # optional, venv only
                payload = _br.compress(body)
                enc = "br"
            except ImportError:
                payload = _g.compress(body)
                enc = "gzip"
            self._send(200, payload, [("Content-Type", "text/plain"), ("Content-Encoding", enc)])
        elif self.path.startswith("/slow429"):
            time.sleep(0.2)
            self._send(429, b"slow down", [("Content-Type", "text/plain")])
        else:
            self._send(200, b"hi", [("Content-Type", "text/plain")])


def _start_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CookieHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


class TestRetryJitter(unittest.TestCase):
    def setUp(self):
        self._saved = dict(nettle.registry.http)
        nettle.registry.http["retry_backoff"] = 0.4
        nettle.registry.http["retry_jitter"] = True

    def tearDown(self):
        nettle.registry.http.clear()
        nettle.registry.http.update(self._saved)

    def test_delay_has_jitter_and_is_bounded(self):
        s = nettle.Session()
        for attempt in (0, 1, 2):
            delays = [s._retry_delay(attempt) for _ in range(150)]
            cap = min(0.4 * (2 ** attempt), s.retry_max_delay)
            self.assertGreaterEqual(min(delays), 0.0)
            self.assertLessEqual(max(delays), cap + 1e-9)
            # jitter actually varies (not deterministic lockstep)
            self.assertGreater(len(set(round(d, 6) for d in delays)), 50)

    def test_no_jitter_is_deterministic(self):
        nettle.registry.http["retry_jitter"] = False
        s = nettle.Session()
        self.assertEqual(s._retry_delay(1), s._retry_delay(1))
        self.assertAlmostEqual(s._retry_delay(1), 0.8, places=6)

    def test_delay_clamped_to_remaining_budget(self):
        s = nettle.Session()
        self.assertEqual(s._retry_delay(5, remaining=0.01), 0.01)

    def test_cap(self):
        nettle.registry.http["retry_backoff"] = 10.0
        s = nettle.Session()
        self.assertLessEqual(s._retry_delay(10), s.retry_max_delay)

    def test_429_retries_with_backoff_then_returns_response(self):
        srv = _start_server()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            s = nettle.Session()
            t0 = time.monotonic()
            resp = s.get(base + "/slow429", retries=2,
                         total_timeout=30, timeout=5)
            dt = time.monotonic() - t0
            self.assertEqual(resp.status, 429)
            # 2 retries => at least one backoff sleep happened
            self.assertGreaterEqual(dt, 0.2)
        finally:
            srv.shutdown()


class TestEncodingPriority(unittest.TestCase):
    def _resp(self, body, header=None, explicit=None):
        return Response(
            url="http://x/", status=200,
            headers={"Content-Type": f"text/html; charset={header}"} if header else {},
            body=body, header_encoding=header, encoding=explicit,
        )

    def test_bom_beats_meta_and_header(self):
        body = "\ufeff<meta charset=\"euc-kr\">caf\u00e9".encode("utf-8")
        r = self._resp(body, header="iso-8859-1")
        self.assertEqual(r.encoding, "utf-8-sig")
        self.assertEqual(r.text, "<meta charset=\"euc-kr\">café")  # BOM stripped

    def test_meta_beats_header(self):
        r = self._resp("<meta charset='euc-kr'><body></body>".encode(), header="iso-8859-1")
        self.assertEqual(r.encoding, "euc-kr")

    def test_header_when_no_bom_or_meta(self):
        r = self._resp(b"<html><body>hi</body></html>", header="shift_jis")
        self.assertEqual(r.encoding, "shift_jis")

    def test_explicit_override_beats_everything(self):
        r = self._resp("\ufeff<meta charset=x>".encode(), header="utf-8", explicit="latin-1")
        self.assertEqual(r.encoding, "latin-1")

    def test_utf16_bom(self):
        r = self._resp("caf\u00e9".encode("utf-16"), header="utf-8")
        self.assertEqual(r.encoding, "utf-16")

    def test_result_cached(self):
        r = self._resp(b"<html></html>", header="utf-8")
        self.assertIs(r.encoding, r.encoding)

    def test_invalid_header_charset_falls_through(self):
        r = self._resp(b"<html></html>", header="not-a-charset")
        self.assertEqual(r.encoding, "utf-8")


class TestCookiesAPI(unittest.TestCase):
    def test_set_get_dict(self):
        s = nettle.Session(base_url="https://shop.example")
        self.assertEqual(s.set_cookies({"cart": "1", "lang": "es"}), 2)
        self.assertEqual(s.get_cookie_dict("https://shop.example/any/path"),
                         {"cart": "1", "lang": "es"})
        self.assertEqual(s.get_cookie_dict("shop.example"), {"cart": "1", "lang": "es"})
        # cookies ride along on requests (subdomain matches dotted domain)
        self.assertIn("cart", s.get_cookie_dict("https://www.shop.example/"))

    def test_set_cookies_requires_domain(self):
        s = nettle.Session()
        with self.assertRaises(nettle.FetchError):
            s.set_cookies({"a": "b"})

    def test_cookie_report_fields(self):
        s = nettle.Session(base_url="https://example.com")
        s.set_cookies({"s": "1", "p": "2"}, path="/app", expires=1893456000.0, secure=True)
        rep = s.cookie_report("https://example.com/app/page")
        by_name = {c["name"]: c for c in rep}
        self.assertEqual(by_name["s"]["path"], "/app")
        self.assertEqual(by_name["s"]["expires"], 1893456000.0)
        self.assertTrue(by_name["s"]["secure"])
        self.assertEqual(by_name["s"]["domain"], ".example.com")
        # path mismatch -> not reported
        self.assertEqual(s.cookie_report("https://example.com/other"), [])

    def test_save_load_netscape_roundtrip(self):
        s = nettle.Session(base_url="https://example.com")
        s.set_cookies({"a": "1", "b": "2"})
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "cookies.txt")
            n = s.save_cookies(p)
            self.assertEqual(n, 2)
            with open(p) as fh:
                content = fh.read()
            self.assertIn("# Netscape HTTP Cookie File", content)
            s2 = nettle.Session(base_url="https://example.com")
            self.assertEqual(s2.load_cookies(p), 2)
            self.assertEqual(s2.get_cookie_dict("https://example.com/"), {"a": "1", "b": "2"})
            # expires=0 for session cookies (curl-compatible, unlike stdlib's empty column)
            with open(p) as f:
                self.assertIn(".example.com\tTRUE\t/\tFALSE\t0\ta\t1", f.read())

    def test_server_set_cookie_extraction(self):
        srv = _start_server()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            s = nettle.Session()
            r = s.get(base + "/set?session=abc&theme=dark")
            self.assertTrue(r.ok)
            got = s.get_cookie_dict(base + "/echo")
            self.assertEqual(got.get("session"), "abc")
            self.assertEqual(got.get("theme"), "dark")
            rep = s.cookie_report(base + "/echo")
            names = {c["name"] for c in rep}
            self.assertIn("session", names)
            sess = next(c for c in rep if c["name"] == "session")
            self.assertTrue(sess["httponly"])  # we sent HttpOnly
            self.assertTrue(sess["expires"] and sess["expires"] > time.time())
            theme = next(c for c in rep if c["name"] == "theme")
            self.assertIsNone(theme["expires"])  # session cookie
        finally:
            srv.shutdown()

    def test_request_cookies_param(self):
        srv = _start_server()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            s = nettle.Session()
            r = s.get(base + "/echo", cookies={"injected": "yes", "tmp": "7"})
            sent = json.loads(r.body)["cookie"]
            self.assertIn("injected=yes", sent)
            self.assertIn("tmp=7", sent)
            # persists in the jar afterwards (requests-style)
            self.assertEqual(s.get_cookie_dict(base + "/").get("injected"), "yes")
        finally:
            srv.shutdown()

    def test_ingest_cdp_cookies(self):
        s = nettle.Session()
        n = s._ingest_cdp_cookies([
            {"name": "waf", "value": "ok", "domain": "paper.example",
             "path": "/", "expires": 1893456000.0, "secure": True, "httpOnly": True},
            {"name": "sess", "value": "s1", "domain": ".paper.example",
             "path": "/", "expires": -1.0, "secure": False, "httpOnly": False},
            {"name": "", "value": "x", "domain": "y.example"},  # skipped
        ])
        self.assertEqual(n, 2)
        got = s.get_cookie_dict("https://paper.example/")
        self.assertEqual(got, {"waf": "ok", "sess": "s1"})
        rep = {c["name"]: c for c in s.cookie_report("https://paper.example/")}
        self.assertTrue(rep["waf"]["secure"])
        self.assertIsNone(rep["sess"]["expires"])  # expires=-1 -> session


class TestCompressedLocalServer(unittest.TestCase):
    def test_content_encoding_handled(self):
        srv = _start_server()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            s = nettle.Session()
            r = s.get(base + "/br")
            self.assertIn(r.body[:5], (b"brotl",))  # decoded, not compressed garbage
            self.assertTrue(r.body.endswith(b"x" * 200))
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main(verbosity=2)
