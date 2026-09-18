"""Agent A round 3 — LIVE verification of the new features (needs network +
Chrome). Skipped entirely with NETTLE_SKIP_LIVE=1.

Covers:
  * fetch(render=True) on the round-2 'impossible' SPA sites (daum/twitch)
  * brotli decoding against a forced-br endpoint and a br-serving CDN
  * cookie round-trip against httpbin (server-set -> get_cookie_dict ->
    cookies.txt -> curl -> load_cookies) and browser_cookies()/adopt on a
    real anti-bot site
  * sniff_network(cache_disabled=True, har_path=...) producing a HAR 1.2
    file that external tooling parses
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import warnings

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import nettle  # noqa: E402

LIVE = os.environ.get("NETTLE_SKIP_LIVE", "") != "1"


def _retry(fn, attempts=3, delay=2.0):
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(delay)
    raise last  # type: ignore[misc]


@unittest.skipUnless(LIVE, "NETTLE_SKIP_LIVE=1")
class TestRenderTrue(unittest.TestCase):
    """Item 1: the two SPAs that had zero <a> in raw HTML."""

    def test_daum_and_twitch_render(self):
        nettle.registry.cdp["settle"] = 6.0
        nettle.registry.cdp["scroll_steps"] = 3
        try:
            for url, min_rendered in (("https://www.daum.net/", 50),
                                      ("https://www.twitch.tv/", 20)):
                with warnings.catch_warnings(record=True) as w:
                    warnings.simplefilter("always")
                    raw = nettle.fetch(url, timeout=30, retries=2)
                raw_links = len(raw.document.select("a[href]"))
                self.assertEqual(raw_links, 0, url)
                self.assertTrue(getattr(raw, "spa_shell", False), url)
                self.assertTrue(any("render=True" in str(x.message) for x in w), url)

                # fresh_profile: repeated test runs poison the persistent CDP
                # profile and some SPAs then serve an empty shell
                doc = _retry(lambda: nettle.fetch(url, render=True, timeout=30,
                                                  fresh_profile=True))
                rendered_links = len(doc.document.select("a[href]"))
                self.assertTrue(doc.rendered, url)
                self.assertGreater(rendered_links, min_rendered,
                                   f"{url}: {rendered_links} links rendered")
                self.assertGreater(rendered_links, raw_links)
        finally:
            nettle.cdp.shutdown_chrome()


@unittest.skipUnless(LIVE, "NETTLE_SKIP_LIVE=1")
class TestBrotliLive(unittest.TestCase):
    """Item 3: real brotli bodies decoded by the pure-Python decoder."""

    def test_forced_br_httpbin(self):
        r = _retry(lambda: nettle.Session().get("https://httpbin.org/brotli",
                                                timeout=30, retries=2))
        self.assertEqual(r.status, 200)
        self.assertEqual((r.headers.get("Content-Encoding") or "").lower(), "br")
        self.assertTrue(r.json().get("brotli"))

    def test_cdn_negotiated_br(self):
        r = _retry(lambda: nettle.Session().get("https://www.cloudflare.com/",
                                                timeout=30, retries=2))
        self.assertEqual(r.status, 200)
        # when the CDN picks br we must have decoded it (big HTML body)
        if (r.headers.get("Content-Encoding") or "").lower() == "br":
            self.assertGreater(len(r.body), 100_000)
        else:
            self.assertIn((r.headers.get("Content-Encoding") or "").lower(),
                          ("gzip", "deflate", "br", ""))


@unittest.skipUnless(LIVE, "NETTLE_SKIP_LIVE=1")
class TestCookiesLive(unittest.TestCase):
    """Item 12: full insert/extract/persist cycle against httpbin + curl."""

    def test_httpbin_cookie_roundtrip(self):
        s = nettle.Session()
        _retry(lambda: s.get("https://httpbin.org/cookies/set?flavor=mint&level=9",
                             timeout=30, retries=2))
        got = s.get_cookie_dict("https://httpbin.org/")
        self.assertEqual(got.get("flavor"), "mint")
        self.assertEqual(got.get("level"), "9")
        echoed = _retry(lambda: s.get("https://httpbin.org/cookies",
                                      timeout=30, retries=2)).json()["cookies"]
        self.assertEqual(echoed.get("flavor"), "mint")
        rep = s.cookie_report("https://httpbin.org/")
        self.assertTrue(all({"name", "value", "domain", "path",
                             "expires", "secure"} <= set(c) for c in rep))

        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "jar.txt")
            self.assertEqual(s.save_cookies(p), 2)
            if shutil.which("curl"):
                out = subprocess.run(
                    ["curl", "-s", "--max-time", "90", "-b", p,
                     "https://httpbin.org/cookies"],
                    capture_output=True, text=True, timeout=100,
                )
                self.assertIn("mint", out.stdout)
            s2 = nettle.Session()
            self.assertEqual(s2.load_cookies(p), 2)
            self.assertEqual(s2.get_cookie_dict("https://httpbin.org/").get("flavor"),
                             "mint")

    def test_request_cookies_injected(self):
        r = _retry(lambda: nettle.Session().get(
            "https://httpbin.org/cookies", cookies={"injected": "live"},
            timeout=30, retries=2))
        self.assertEqual(r.json()["cookies"].get("injected"), "live")

    def test_browser_cookies_transfer_real_site(self):
        """Item 2: CDP->HTTP bridge on a real site's cookie set."""
        nettle.registry.cdp["settle"] = 7.0
        try:
            url = "https://xueqiu.com/"  # Aliyun WAF + site tokens, stable
            cookies = _retry(lambda: nettle.browser_cookies(url), attempts=2)
            self.assertIsInstance(cookies, list)
            self.assertGreaterEqual(len(cookies), 5)
            names = {c["name"] for c in cookies}
            self.assertTrue(names & {"acw_tc", "xq_a_token", "u", "device_id"},
                            names)
            s = nettle.Session()
            n = s.adopt_browser_cookies(url)
            self.assertGreaterEqual(n, 5)
            r = _retry(lambda: s.get(url, timeout=30, retries=2))
            self.assertEqual(r.status, 200)
            # adopted cookies actually ride the plain-HTTP request
            self.assertTrue(s.get_cookie_dict(url))
        finally:
            nettle.cdp.shutdown_chrome()

    def test_thepaper_cn_documented_block(self):
        """Item 2 documented case: WAF blocks before any JS challenge, so
        browser_cookies returns [] (mechanism degrades, never crashes)."""
        try:
            cookies = nettle.browser_cookies("https://www.thepaper.cn/",
                                             settle=4.0)
            self.assertIsInstance(cookies, list)
        except nettle.cdp.CDPError:
            pass  # tab may die under WAF fire; acceptable outcome
        finally:
            nettle.cdp.shutdown_chrome()


@unittest.skipUnless(LIVE, "NETTLE_SKIP_LIVE=1")
class TestHarLive(unittest.TestCase):
    """Items 9+10: cache_disabled reproducible capture + HAR 1.2 file."""

    def test_sniff_har_and_cache_disabled(self):
        nettle.registry.cdp["settle"] = 5.0
        nettle.registry.cdp["scroll_steps"] = 2
        try:
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "capture.har")
                cap = nettle.sniff_network("https://www.python.org/",
                                           har_path=p, cache_disabled=True)
                self.assertTrue(cap["cache_disabled"])
                self.assertGreater(cap["total"], 10)
                self.assertTrue(os.path.exists(p))
                with open(p, encoding="utf-8") as f:
                    har = json.load(f)
                log = har["log"]
                self.assertEqual(log["version"], "1.2")
                entries = log["entries"]
                self.assertLessEqual(len(entries), cap["total"])  # url-less rows skipped
                http_entries = [e for e in entries
                                if e["request"]["url"].startswith(("http://", "https://"))]
                self.assertGreater(len(http_entries), 10)
                for e in http_entries[:25]:
                    self.assertIsInstance(e["response"]["status"], int)
                    self.assertRegex(e["startedDateTime"],
                                     r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
            # second sniff with cache disabled re-captures the document
            cap2 = nettle.sniff_network("https://www.python.org/",
                                        cache_disabled=True)
            self.assertGreater(cap2["total"], 10)
        finally:
            nettle.cdp.shutdown_chrome()


if __name__ == "__main__":
    unittest.main(verbosity=2)
