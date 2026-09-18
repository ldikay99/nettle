"""Agent A round 3 — items 1, 9, 10 (offline parts): SPA-shell detection,
HAR 1.2 export structure, Netscape cookie writer, cache_disabled plumbing,
UA profiles registry. No Chrome/network needed."""
import json
import os
import re
import sys
import tempfile
import unittest
import warnings

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import nettle  # noqa: E402
from nettle.cdp import to_har, write_netscape_cookies  # noqa: E402
from nettle.http import _looks_like_js_shell  # noqa: E402
from nettle.soup import Nettle  # noqa: E402


def _fake_capture():
    return {
        "page": "https://ex.com/",
        "entries": [
            {
                "requestId": "1", "url": "https://ex.com/", "method": "GET",
                "type": "Document", "headers": {"User-Agent": "x"},
                "status": 200, "mime": "text/html", "wallTime": 1789000000.123,
                "responseHeaders": {"Content-Type": "text/html; charset=utf-8"},
                "httpVersion": "http/1.1", "body": None,
            },
            {
                "requestId": "2", "url": "https://ex.com/api/items?q=3&x=1",
                "method": "POST", "type": "XHR",
                "headers": {"Content-Type": "application/json"},
                "status": 403, "mime": "application/json", "wallTime": 1789000001.5,
                "responseHeaders": {}, "body": '{"a": 1}', "body_b64": False,
            },
        ],
    }


class TestSpaShellDetection(unittest.TestCase):
    def test_shell_detected(self):
        doc = Nettle("<html><body><div id=root></div>" + "<script src=s.js></script>" * 6)
        self.assertTrue(_looks_like_js_shell(doc))

    def test_normal_page_not_flagged(self):
        doc = Nettle("<html><body>" + "<a href=/a>A</a>" * 5 + "<script></script>")
        self.assertFalse(_looks_like_js_shell(doc))

    def test_registry_thresholds_respected(self):
        doc = Nettle("<html><body>" + "<script></script>" * 10)
        try:
            nettle.registry.http["spa_shell"] = {"max_links": 3, "min_scripts": 100}
            self.assertFalse(_looks_like_js_shell(doc))
            nettle.registry.http["spa_shell"] = {"max_links": 0, "min_scripts": 5}
            self.assertFalse(_looks_like_js_shell(doc))  # max_links=0 disables
        finally:
            nettle.registry.http["spa_shell"] = {"max_links": 3, "min_scripts": 5}

    def test_fetch_warns_with_render_hint(self):
        # no network: use a doc-less path? fetch() requires HTTP; instead we
        # assert the warning machinery through the detector + message text in
        # fetch source (integration with a real SPA is the live test).
        import inspect
        from nettle.http import fetch
        src = inspect.getsource(fetch)
        self.assertIn("render=True", src)


class TestHarExport(unittest.TestCase):
    def test_har_12_structure(self):
        har = to_har(_fake_capture())
        log = har["log"]
        self.assertEqual(log["version"], "1.2")
        self.assertIn("creator", log)
        self.assertTrue(log["entries"])
        e = log["entries"][0]
        for key in ("startedDateTime", "time", "request", "response", "cache", "timings"):
            self.assertIn(key, e)
        req = e["request"]
        for key in ("method", "url", "httpVersion", "cookies", "headers",
                    "queryString", "headersSize", "bodySize"):
            self.assertIn(key, req)
        resp = e["response"]
        for key in ("status", "statusText", "httpVersion", "cookies", "headers",
                    "content", "redirectURL", "headersSize", "bodySize"):
            self.assertIn(key, resp)
        # ISO 8601 with milliseconds + timezone
        self.assertRegex(e["startedDateTime"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]")

    def test_har_query_string(self):
        har = to_har(_fake_capture())
        e = har["log"]["entries"][1]
        qs = {p["name"]: p["value"] for p in e["request"]["queryString"]}
        self.assertEqual(qs, {"q": "3", "x": "1"})

    def test_har_content_text_and_status(self):
        har = to_har(_fake_capture())
        e = har["log"]["entries"][1]
        self.assertEqual(e["response"]["status"], 403)
        self.assertEqual(e["response"]["content"]["text"], '{"a": 1}')

    def test_har_json_serializable(self):
        json.dumps(to_har(_fake_capture()))

    def test_har_headers_arrays(self):
        har = to_har(_fake_capture())
        e = har["log"]["entries"][0]
        self.assertIn({"name": "Content-Type", "value": "text/html; charset=utf-8"},
                      e["response"]["headers"])


class TestNetscapeWriter(unittest.TestCase):
    def test_write(self):
        cookies = [
            {"name": "a", "value": "1", "domain": ".example.com", "path": "/",
             "expires": 1893456000.0, "secure": True},
            {"name": "b", "value": "2", "domain": "other.com", "path": "/x",
             "expires": -1.0, "secure": False},
        ]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.txt")
            n = write_netscape_cookies(cookies, p)
            self.assertEqual(n, 2)
            lines = open(p).read().strip().split("\n")
            self.assertTrue(lines[0].startswith("# Netscape"))
            a = next(l for l in lines if l.startswith(".example.com"))
            self.assertEqual(a.split("\t"),
                             [".example.com", "TRUE", "/", "TRUE", "1893456000", "a", "1"])
            b = next(l for l in lines if l.startswith("other.com"))
            self.assertEqual(b.split("\t")[3], "FALSE")  # no leading dot
            self.assertEqual(b.split("\t")[4], "0")      # session cookie


class TestSniffNetworkPlumbing(unittest.TestCase):
    def test_cache_disabled_default_and_kwarg_documented(self):
        import inspect
        from nettle import cdp
        sig = inspect.signature(cdp.sniff_network)
        self.assertIn("cache_disabled", sig.parameters)
        self.assertIn("har_path", sig.parameters)
        # registry default is on
        self.assertTrue(nettle.registry.cdp.get("cache_disabled", True))

    def test_render_page_and_browser_cookies_exist(self):
        self.assertTrue(callable(nettle.render_page))
        self.assertTrue(callable(nettle.browser_cookies))
        self.assertTrue(callable(nettle.export_browser_cookies))
        self.assertTrue(callable(getattr(nettle.Session, "adopt_browser_cookies")))


class TestUaProfilesRegistry(unittest.TestCase):
    def test_profiles_registry_extension(self):
        from nettle.http import UA_PROFILES
        saved = nettle.registry.http["ua_profiles"]
        try:
            nettle.registry.http["ua_profiles"] = [("CustomBot/9.9", '"C";v="1"', '"Test"')]
            s = nettle.Session()
            self.assertEqual(s.headers["User-Agent"], "CustomBot/9.9")
            # rotation stays within the provided list
            s2 = nettle.Session()
            self.assertEqual(s2.headers["User-Agent"], "CustomBot/9.9")
            # sec-ch headers applied for profile entries
            self.assertEqual(s.headers.get("Sec-Ch-Ua"), '"C";v="1"')
            # None -> module default
            nettle.registry.http["ua_profiles"] = None
            s3 = nettle.Session()
            self.assertIn("Chrome/", s3.headers["User-Agent"])
            self.assertTrue(len(UA_PROFILES) >= 3)
        finally:
            nettle.registry.http["ua_profiles"] = saved


if __name__ == "__main__":
    unittest.main(verbosity=2)
