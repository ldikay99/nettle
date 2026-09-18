"""QA round A4 — LIVE battery (auto-skipped without internet).

A distilled version of the 40-site/15-language QA battery plus the live
fusion cases (render=True SPAs, sniff_network+HAR with real timings, forced
brotli, adopt_browser_cookies roundtrip). Skips cleanly when offline or when
Chrome is missing for the CDP portions; set NETTLE_SKIP_LIVE=1 to force-skip.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest
import warnings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import nettle  # noqa: E402


def _net_ok(timeout=4.0) -> bool:
    if os.environ.get("NETTLE_SKIP_LIVE"):
        return False
    try:
        socket.create_connection(("httpbin.org", 443), timeout=timeout).close()
        return True
    except OSError:
        return False


def _chrome_ok() -> bool:
    if os.environ.get("NETTLE_SKIP_LIVE"):
        return False
    from nettle.cdp import _chrome_binaries
    return bool(_chrome_binaries())


LIVE = _net_ok()
CHROME = _chrome_ok() and LIVE


@unittest.skipUnless(LIVE, "no network / NETTLE_SKIP_LIVE set")
class TestWorldBatterySample(unittest.TestCase):
    """One representative site per region from the QA battery."""

    SITES = [
        ("https://elpais.com/", "es"),
        ("https://www.bbc.com/news", "en"),
        ("https://ja.wikipedia.org/wiki/東京都", "ja"),
        ("https://www.sina.com.cn/", "zh"),
        ("https://www.aljazeera.net/", "ar"),
        ("https://ria.ru/", "ru"),
        ("https://www.tagesschau.de/", "de"),
        ("https://www.lemonde.fr/", "fr"),
        ("https://g1.globo.com/", "pt"),
        ("https://www.hurriyet.com.tr/", "tr"),
        ("https://www.sanook.com/", "th"),
        ("https://vnexpress.net/", "vi"),
        ("https://www.ynet.co.il/", "he"),
        ("https://www.jagran.com/", "hi"),
    ]

    def test_fetch_select_find_urls_multilingual(self):
        ok = 0
        for url, lang in self.SITES:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                doc = nettle.fetch(url, timeout=25, retries=1)
            self.assertTrue(doc.response.ok, f"{lang} {url} -> {doc.response.status}")
            self.assertGreater(len(doc.select("a")), 20, f"{lang} {url} no links")
            self.assertGreater(len(nettle.find_urls(doc)), 30, f"{lang} {url} urls")
            self.assertEqual(doc.response.text[:100000].count("\ufffd"), 0,
                             f"{lang} {url} mojibake")
            ok += 1
        self.assertGreaterEqual(ok, 12)

    def test_discover_and_embedded_json(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            disc = nettle.discover_endpoints("https://vnexpress.net/",
                                             probe=True, total_timeout=40)
        self.assertGreater(len(disc["endpoints"]), 3)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            doc = nettle.fetch("https://www.sanook.com/", timeout=25, retries=1)
        blobs = nettle.sniff_embedded_json(doc)
        self.assertTrue(any("__NEXT_DATA__" == b["source"] for b in blobs))


@unittest.skipUnless(LIVE, "no network / NETTLE_SKIP_LIVE set")
class TestCompressionLive(unittest.TestCase):
    def test_forced_brotli_decodes(self):
        r = nettle.fetch_response("https://httpbin.org/brotli", retries=1)
        self.assertEqual(r.headers.get("Content-Encoding"), "br")
        self.assertTrue(r.json()["brotli"])

    def test_negotiated_brotli_cdn(self):
        r = nettle.fetch_response(
            "https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js",
            retries=1)
        self.assertEqual(r.headers.get("Content-Encoding"), "br")
        self.assertGreater(len(r.body), 80000)
        self.assertIn("jQuery", r.text)

    def test_gzip_json(self):
        r = nettle.fetch_response("https://httpbin.org/gzip", retries=1)
        self.assertTrue(r.json()["gzipped"])


@unittest.skipUnless(CHROME, "no network or no Chrome binary")
class TestRenderSpaLive(unittest.TestCase):
    def test_daum_links_before_after(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            raw = nettle.fetch("https://www.daum.net/", timeout=25, retries=1)
            before = len(raw.select("a[href]"))
            doc = nettle.fetch("https://www.daum.net/", render=True)
        after = len(doc.select("a[href]"))
        self.assertLessEqual(before, 5)
        self.assertGreater(after, 100)
        self.assertTrue(doc.rendered)
        nettle.shutdown_chrome()
        self.assertEqual(nettle.chrome_processes_alive(), 0)

    def test_fresh_profile_render_leaks_nothing(self):
        # QA A4 bug: render_page(fresh_profile=True) shut down only the
        # FINAL port when _open_tab_resilient reopened on another one,
        # leaving a whole Chrome tree with a /tmp/nettle-render-* profile.
        import subprocess
        from nettle.cdp import render_page
        out = render_page("https://example.com/", fresh_profile=True,
                          scroll=False, settle=3.0)
        self.assertGreater(len(out["html"]), 500)
        nettle.shutdown_chrome()
        time.sleep(1.0)
        ps = subprocess.run(["pgrep", "-fa", "nettle-render-|nettle-chrome-cdp-"],
                            capture_output=True, text=True)
        orphans = [l for l in ps.stdout.splitlines() if "pgrep" not in l]
        self.assertEqual(orphans, [], f"leaked chrome: {orphans[:2]}")


@unittest.skipUnless(CHROME, "no network or no Chrome binary")
class TestSniffHarLive(unittest.TestCase):
    def test_har_with_real_timings_and_no_orphans(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "cap.har")
            cap = nettle.sniff_network("https://httpbin.org/", har_path=path,
                                       settle=3.0, scroll_steps=2)
            with open(path) as fh:
                har = json.load(fh)
        entries = har["log"]["entries"]
        self.assertGreaterEqual(len(entries), 3)
        timed = [e for e in entries if e["time"] > 0]
        self.assertGreaterEqual(len(timed), len(entries) // 2,
                                "most entries should carry measured timings")
        for e in timed:
            t = e["timings"]
            self.assertGreaterEqual(t["wait"], 0)
            self.assertGreaterEqual(t["send"], 0)
        nettle.shutdown_chrome()
        self.assertEqual(nettle.chrome_processes_alive(), 0)

    def test_adopt_browser_cookies_roundtrip_live(self):
        s = nettle.Session()
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            n = s.adopt_browser_cookies("https://www.daum.net/", settle=5.0)
        self.assertGreaterEqual(n, 3)
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            path = f.name
        try:
            self.assertEqual(s.save_cookies(path), n)
            s2 = nettle.Session()
            self.assertEqual(s2.load_cookies(path), n)
            self.assertEqual(sorted(s2.get_cookie_dict("https://www.daum.net/")),
                             sorted(s.get_cookie_dict("https://www.daum.net/")))
        finally:
            os.unlink(path)
        nettle.shutdown_chrome()
        self.assertEqual(nettle.chrome_processes_alive(), 0)


@unittest.skipUnless(LIVE, "no network / NETTLE_SKIP_LIVE set")
class TestExamplesRun(unittest.TestCase):
    """examples/ must stay runnable (offline one at least)."""

    def test_offline_example_runs(self):
        import subprocess
        out = subprocess.run(
            [sys.executable, os.path.join(ROOT, "examples", "offline_toolkit_demo.py")],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr[-400:])
        self.assertIn("3000-deep serialize", out.stdout)

    @unittest.skipUnless(CHROME, "no Chrome")
    def test_har_example_runs(self):
        import subprocess
        out = subprocess.run(
            [sys.executable, os.path.join(ROOT, "examples", "har_timings_demo.py")],
            capture_output=True, text=True, timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr[-400:])
        self.assertIn("carry measured timings", out.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
