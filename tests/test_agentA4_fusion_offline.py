"""QA round A4 — fusion-zone combined cases (OFFLINE).

Drives the merged 0.8.0 code paths (http.py hooks+cookies+auth+brotli+jitter,
registry schema, css escapes, nodes RCDATA serialization, parse entities,
network.py registry-dependent regexes) against a local stdlib threading HTTP
server — no internet required. Derived from the /tmp/qa-a4 fusion probe
battery (58 offline cases) plus regressions for the two real bugs found:
  * _merge_params dropped repeated query keys (?a=1&a=2 -> a=2)
  * cookies stored with a dotted domain on IP hosts never matched
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import nettle  # noqa: E402
from nettle import Session, parse, probe_apis, discover_endpoints, sniff_api_candidates  # noqa: E402
from nettle.css import SelectorError  # noqa: E402
from nettle.http import (  # noqa: E402
    Response,
    _dispatch_hooks,
    _merge_params,
    _normalize_hooks,
    _requote_uri,
)

# ---------------------------------------------------------------- fixtures

RETRY_COUNTS: dict = {}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code=200, body=b"", ctype="text/html; charset=utf-8", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/echo":
            self._send(200, json.dumps({
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "cookies": self.headers.get("Cookie", ""),
            }).encode(), "application/json")
        elif u.path == "/503":
            tok = q.get("tok", ["t"])[0]
            RETRY_COUNTS[tok] = RETRY_COUNTS.get(tok, 0) + 1
            if RETRY_COUNTS[tok] >= 2:
                self._send(200, json.dumps({"hits": RETRY_COUNTS[tok]}).encode(), "application/json")
            else:
                self._send(503, b"busy", "text/plain", {"Retry-After": "1"})
        elif u.path == "/meta-enc":
            body = ("<html><head><meta charset='euc-jp'></head>"
                    "<body>日本語テスト</body></html>").encode("euc-jp")
            self._send(200, body, "text/html")
        elif u.path == "/slow":
            time.sleep(float(q.get("t", ["3"])[0]))
            self._send(200, b'{"slow":1}', "application/json")
        else:
            self._send(200, b"<html><body>default</body></html>")

    do_POST = do_GET


_SRV = ThreadingHTTPServer(("127.0.0.1", 0), H)
_PORT = _SRV.server_address[1]
BASE = f"http://127.0.0.1:{_PORT}"
threading.Thread(target=_SRV.serve_forever, daemon=True).start()


class TestHooksCookiesAuthFusion(unittest.TestCase):
    """hooks + cookies + auth + base_url in one session (fusion zone http.py)."""

    def test_hooks_cookies_auth_together(self):
        calls = []
        s = Session(base_url=BASE, auth=("u", "pw"),
                    hooks={"response": [lambda r: (calls.append(r.status), r)[1]]})
        s.set_cookies({"manual": "yes"})
        r = s.get("/echo", cookies={"reqc": "1"})
        echo = r.json()
        self.assertTrue(echo["headers"].get("authorization", "").startswith("Basic "))
        self.assertIn("manual=yes", echo["cookies"])
        self.assertIn("reqc=1", echo["cookies"])
        self.assertEqual(calls, [200])

    def test_hook_order_session_then_request(self):
        order = []
        s = Session(hooks={"response": [lambda r: (order.append("s"), r)[1]]})
        s.get(BASE + "/echo", hooks={"response": lambda r: (order.append("r"), r)[1]})
        self.assertEqual(order, ["s", "r"])

    def test_hook_none_keeps_response_and_replacement(self):
        s = Session(hooks={"response": [lambda r: None]})
        self.assertEqual(s.get(BASE + "/echo").status, 200)
        rep = Response(url="x", status=599, headers={}, body=b"")
        s2 = Session(hooks={"response": [lambda r: rep]})
        self.assertEqual(s2.get(BASE + "/echo").status, 599)

    def test_hook_contract_errors(self):
        with self.assertRaises(ValueError):
            Session(hooks={"request": lambda r: r})
        with self.assertRaises(TypeError):
            Session(hooks={"response": "nope"})
        with self.assertRaises(TypeError):
            Session(hooks={"response": [lambda r: "bad"]}).get(BASE + "/echo")
        # _normalize/_dispatch guard everything reachable
        self.assertEqual(_normalize_hooks(None, where="t"), {})

    def test_auth_variants(self):
        with self.assertRaises(nettle.FetchError):
            Session(auth=("only-user",))
        with self.assertRaises(nettle.FetchError):
            Session(auth=("a", "b"), auth_scheme="digest")
        self.assertEqual(Session(auth=("a", "b"), auth_scheme="bearer")._auth_header, "Bearer b")


class TestParamsMergeRegression(unittest.TestCase):
    """Bug found in QA A4: repeated query keys were collapsed."""

    def test_repeated_keys_preserved(self):
        m = _merge_params("https://x.test/p?a=1&a=2&b=3", {"c": 4})
        self.assertIn("a=1", m)
        self.assertIn("a=2", m)
        self.assertIn("c=4", m)
        self.assertIn("b=3", m)

    def test_params_append_requests_style(self):
        self.assertEqual(_merge_params("https://x.test/?a=1", {"a": 2}),
                         "https://x.test/?a=1&a=2")

    def test_list_values_expand(self):
        m = _merge_params("https://x.test/", {"b": ["x", "y"], "drop": None})
        self.assertEqual(m, "https://x.test/?b=x&b=y")

    def test_no_params_untouched(self):
        self.assertEqual(_merge_params("https://x.test/p?a=1&a=2", None),
                         "https://x.test/p?a=1&a=2")


class TestRetryAndTimeoutFusion(unittest.TestCase):
    def setUp(self):
        self._saved = dict(nettle.registry.http)
        nettle.registry.http.update(retry_jitter=False, retry_backoff=0.2,
                                    retry_max_delay=1.0, retry_statuses={503})

    def tearDown(self):
        nettle.registry.http.clear()
        nettle.registry.http.update(self._saved)

    def test_deterministic_delays_with_jitter_off(self):
        sd = Session()
        self.assertEqual([round(sd._retry_delay(i), 3) for i in range(5)],
                         [0.2, 0.4, 0.8, 1.0, 1.0])

    def test_503_retries_then_succeeds(self):
        RETRY_COUNTS.clear()
        sd = Session()
        r = sd.get(BASE + "/503?tok=offline", retries=2)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.json()["hits"], 2)  # failed once, recovered on retry

    def test_total_timeout_enforced(self):
        sd = Session()
        t0 = time.time()
        with self.assertRaises(nettle.FetchError):
            sd.get(BASE + "/slow?t=4", timeout=1, retries=2, total_timeout=1.5)
        self.assertLess(time.time() - t0, 3.5)

    def test_probe_total_timeout_marks_rest(self):
        res = probe_apis([BASE + "/slow?t=4"] * 4, timeout=2, total_timeout=3.0)
        self.assertEqual(len(res), 4)
        self.assertTrue(any(r.get("error") == "total_timeout" for r in res))


class TestRegistryResetMidSession(unittest.TestCase):
    def test_reset_keeps_live_session_intact(self):
        nettle.registry.http["user_agent"] = "QA-MUTANT/0.1"
        s = Session()
        nettle.registry.reset()
        r = s.get(BASE + "/echo", retries=0)
        self.assertEqual(r.status, 200)
        self.assertIn("QA-MUTANT", r.json()["headers"].get("user-agent", ""))
        self.assertNotIn("QA-MUTANT", Session().headers.get("User-Agent", ""))


class TestCookieScopingAndPersistence(unittest.TestCase):
    def test_ip_host_cookie_matches(self):
        # Bug found in QA A4: '.127.0.0.1' domain never matched the IP host
        s = Session()
        s.set_cookies({"k": "v"}, domain="127.0.0.1")
        self.assertEqual(s.get_cookie_dict(BASE + "/echo").get("k"), "v")

    def test_cookie_path_scoping(self):
        s = Session(base_url=BASE)
        s.set_cookies({"scoped": "1"}, domain="127.0.0.1", path="/sub")
        self.assertNotIn("scoped", s.get_cookie_dict(BASE + "/echo"))
        self.assertEqual(s.get_cookie_dict(BASE + "/sub/x").get("scoped"), "1")

    def test_save_load_roundtrip_curl_format(self):
        import re
        s = Session(base_url=BASE)
        s.set_cookies({"sess1": "v1"}, domain="127.0.0.1")
        s.set_cookies({"perm": "v2"}, domain="127.0.0.1", expires=2000000000)
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            p = f.name
        try:
            n = s.save_cookies(p)
            s2 = Session(base_url=BASE)
            self.assertEqual(s2.load_cookies(p), n)
            self.assertTrue({"sess1", "perm"} <= set(s2.get_cookie_dict(BASE + "/echo")))
            # curl interop: session cookies carry expires=0, not empty
            self.assertRegex(open(p).read(), r"\b0\tsess1\tv1")
        finally:
            os.unlink(p)


class TestCssAndParseFusion(unittest.TestCase):
    DOC = parse("""<html><body>
      <div class='a:b' data-x='Val'>1</div>
      <div class='btn.primary'>2</div>
      <section><p>one</p><p>two</p><p>three</p><p>four</p></section>
      <ul><li>l1</li><li class='sel'>l2</li><li>l3</li></ul>
    </body></html>""")

    def test_escapes_and_functional_pseudos(self):
        doc = self.DOC
        self.assertEqual(len(doc.select(".a\\:b")), 1)
        self.assertEqual(len(doc.select(".btn\\.primary")), 1)
        self.assertEqual(len(doc.select("[data-x='val' i]")), 1)
        self.assertEqual([e.get_text() for e in doc.select("section p:nth-of-type(2n)")],
                         ["two", "four"])
        self.assertEqual(len(doc.select("ul li:not(.sel)")), 2)
        self.assertEqual(len(doc.select("ul:has(> li.sel + li)")), 1)

    def test_doubled_combinator_is_selector_error(self):
        for bad in ("div >> p", "p ~ > span", "a  >>  b"):
            with self.assertRaises(SelectorError):
                self.DOC.select(bad)

    def test_rcdata_vs_raw_vs_attrs(self):
        doc = parse("<html><head><title>Bolet&iacute;n &amp; x</title></head><body>"
                    "<textarea>a &amp; b &copy; 2024</textarea>"
                    "<script>if (a<b) { x = '</p>' }</script>"
                    "<a href='?a=1&copy=2&x=3'>l</a></body></html>")
        self.assertIn("Boletín", doc.title)
        self.assertEqual(doc.select_one("textarea").get_text(), "a & b © 2024")
        self.assertIn("</p>", doc.select_one("script").get_text())
        self.assertEqual(doc.select_one("a")["href"], "?a=1&copy=2&x=3")

    def test_deep_serialize_and_utf16(self):
        deep = parse("<html><body>" + "<div>" * 3000 + "x" + "</div>" * 3000 + "</body></html>")
        self.assertEqual(str(deep).count("<div>"), 3000)
        d2 = parse("<html><body>日本語テスト</body></html>".encode("utf-16-le"))
        self.assertIn("日本語テスト", d2.get_text())

    def test_encoding_priority_meta_beats_header(self):
        resp = Response(url="x", status=200,
                        headers={"Content-Type": "text/html; charset=iso-8859-1"},
                        body="<meta charset='shift_jis'>あ".encode("shift_jis"))
        self.assertEqual(resp.encoding.lower().replace("_", "-"), "shift-jis")

    def test_meta_charset_end_to_end(self):
        r = nettle.fetch_response(BASE + "/meta-enc", retries=0)
        self.assertEqual(r.encoding.lower(), "euc-jp")
        self.assertIn("日本語", r.text)


class TestNetworkRegexRegistryFusion(unittest.TestCase):
    def test_url_bounds_change_rebuilds_cached_regex(self):
        saved = dict(nettle.registry.sniff)
        try:
            js = parse("<script>fetch('/api/" + "a" * 55 + "');fetch('/short/x');</script>")
            nettle.registry.sniff["url_literal_max"] = 40
            c1 = sniff_api_candidates(js, base_url="https://t.test/")
            nettle.registry.sniff["url_literal_max"] = 800
            c2 = sniff_api_candidates(js, base_url="https://t.test/")
            self.assertFalse(any("aaaa" in u for u in c1), c1)
            self.assertTrue(any("aaaa" in u for u in c2), c2)
        finally:
            nettle.registry.sniff.clear()
            nettle.registry.sniff.update(saved)


class TestDiscoverOffline(unittest.TestCase):
    DOC = """<html><script>
      const cfg = { baseURL: "https://api.offline.test/v2" };
      fetch("/api/items?full=1");
      var state = {"url": "https://cdn.offline.test/feed.json"};
    </script><div data-api="/api/checkout"></div>
    <a href="https://w3.org/ignore">x</a></html>"""

    def test_discover_static_analysis(self):
        disc = discover_endpoints("https://offline.test/", probe=False, doc=self.DOC)
        eps = [e["url"] for e in disc["endpoints"]]
        self.assertIn("https://offline.test/api/items?full=1", eps)
        self.assertIn("https://offline.test/api/checkout", eps)
        self.assertFalse(any("w3.org" in u for u in eps))
        self.assertTrue(any("api.offline.test" in u for u in eps))


class TestRequoteIRI(unittest.TestCase):
    def test_iri_percent_encoding(self):
        u = _requote_uri("https://ja.wikipedia.org/wiki/東京都?a=1&b=白")
        self.assertTrue(u.endswith("%E6%9D%B1%E4%BA%AC%E9%83%BD?a=1&b=%E7%99%BD"))
        # pure-ascii untouched
        self.assertEqual(_requote_uri("https://x.test/a%20b"), "https://x.test/a%20b")


if __name__ == "__main__":
    unittest.main(verbosity=2)
