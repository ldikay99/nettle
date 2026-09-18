"""QA round A4 — inherited TODO items a-d, offline regressions.

  (a) HAR timings: real phases from CDP timestamps + response.timing
  (b) brotli large-window (RFC 9841): specific error + remedy
  (c) adopt_browser_cookies: replay-hardening warning + strict_replay flag
  (d) CHIPS-partitioned cookies: skipped on ingest, documented on export
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import warnings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import nettle  # noqa: E402
from nettle import Session  # noqa: E402
from nettle.brotli_dec import BrotliError, BrotliLargeWindowError, decompress  # noqa: E402
from nettle.cdp import _cookie_is_partitioned, to_har, write_netscape_cookies  # noqa: E402
from nettle.http import _brotli_decompress  # noqa: E402


def _lw_stream(lgwin: int = 30) -> bytes:
    """Hand-pack the RFC 9841 large-window header: bits 1 000 100 0 + 6-bit
    lgwin, all consumed LSB-first (the marker reads as byte 0x11)."""
    reading = "1000100" + "0" + format(lgwin, "06b")[::-1] + "00"  # 16 bits
    return bytes(int(reading[i:i + 8][::-1], 2) for i in range(0, 16, 8)) + b"\0" * 4


# ---------------------------------------------------------------- (a) HAR

class TestHarTimings(unittest.TestCase):
    CAPTURE = {"page": "https://x.test/", "entries": [
        {   # full ResourceTiming + all three event timestamps
            "url": "https://x.test/a?q=3%20x", "method": "GET", "headers": {},
            "status": 200, "mime": "text/html", "wallTime": 1700000000.5,
            "cdpTimestamp": 100.0, "cdpTimestampResponse": 100.250,
            "cdpTimestampFinished": 100.640,
            "timing": {"dnsStart": 5, "dnsEnd": 25, "connectStart": 25,
                       "connectEnd": 90, "sslStart": 40, "sslEnd": 85,
                       "sendStart": 95, "sendEnd": 100, "receiveHeadersEnd": 250},
            "encodedDataLength": 51234, "responseHeaders": {},
        },
        {   # no ResourceTiming (cached) — timestamps fill send/wait/receive
            "url": "https://x.test/b", "status": 304, "headers": {},
            "cdpTimestamp": 101.0, "cdpTimestampResponse": 101.100,
            "cdpTimestampFinished": 101.140, "wallTime": 1700000001.0,
        },
        {   # failed load — receive=0, everything else N/A
            "url": "https://x.test/failed", "status": None, "headers": {},
            "cdpTimestamp": 102.0, "error_phase": "loadingFailed",
            "wallTime": 1700000002.0,
        },
    ]}

    def test_phases_from_resource_timing(self):
        e = to_har(self.CAPTURE)["log"]["entries"][0]
        t = e["timings"]
        self.assertEqual(t["dns"], 20.0)        # dnsEnd - dnsStart
        self.assertEqual(t["connect"], 65.0)    # connectEnd - connectStart
        self.assertEqual(t["ssl"], 45.0)
        self.assertEqual(t["send"], 5.0)        # sendEnd - sendStart
        self.assertEqual(t["wait"], 150.0)      # receiveHeadersEnd - sendEnd
        self.assertEqual(t["receive"], 390.0)   # finished - responseReceived
        self.assertEqual(e["time"], 675.0)      # sum of positive phases
        self.assertEqual(e["response"]["content"]["size"], 51234)

    def test_phases_fallback_without_resource_timing(self):
        e = to_har(self.CAPTURE)["log"]["entries"][1]
        t = e["timings"]
        self.assertEqual(t["dns"], -1.0)        # N/A convention
        self.assertEqual(t["send"], 0.0)
        self.assertEqual(t["wait"], 100.0)      # resp.ts - req.ts
        self.assertEqual(t["receive"], 40.0)    # fin.ts - resp.ts
        self.assertEqual(e["time"], 140.0)

    def test_failed_entry_receive_zero(self):
        e = to_har(self.CAPTURE)["log"]["entries"][2]
        self.assertEqual(e["timings"]["receive"], 0.0)
        self.assertEqual(e["time"], 0)

    def test_time_is_never_negative_placeholder(self):
        for e in to_har(self.CAPTURE)["log"]["entries"]:
            self.assertGreaterEqual(e["time"], 0)

    def test_creator_version_is_current(self):
        self.assertEqual(to_har({})["log"]["creator"]["version"], nettle.__version__)

    def test_har_loads_in_haralyzer_when_installed(self):
        try:
            from haralyzer import HarParser
        except ImportError:
            self.skipTest("haralyzer not installed (optional validator)")
        har = to_har(self.CAPTURE)
        with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as f:
            json.dump(har, f)
            path = f.name
        try:
            page = HarParser(json.loads(open(path).read())).pages[0]
            self.assertEqual(len(page.entries), 3)
            self.assertGreater(page.entries[0].time, 0)
        finally:
            os.unlink(path)

    def test_query_string_urldecoded(self):
        e = to_har(self.CAPTURE)["log"]["entries"][0]
        self.assertEqual(e["request"]["queryString"],
                         [{"name": "q", "value": "3 x"}])


# ---------------------------------------------------------------- (b) brotli

class TestBrotliLargeWindow(unittest.TestCase):
    def test_specific_error_class_and_message(self):
        with self.assertRaises(BrotliLargeWindowError) as cm:
            decompress(_lw_stream(30))
        msg = str(cm.exception)
        self.assertIn("lgwin=30", msg)
        self.assertIn("RFC 9841", msg)
        self.assertIn("pip install brotli", msg)          # remedy present
        self.assertIn("accept_encoding", msg)

    def test_large_window_is_brotli_error_subclass(self):
        self.assertTrue(issubclass(BrotliLargeWindowError, BrotliError))

    def test_lgwin_out_of_range_is_plain_error(self):
        with self.assertRaises(BrotliError) as cm:
            decompress(_lw_stream(9))
        self.assertNotIsInstance(cm.exception, BrotliLargeWindowError)

    def test_http_layer_message_is_actionable(self):
        with self.assertRaises(nettle.FetchError) as cm:
            _brotli_decompress(_lw_stream(24))
        msg = str(cm.exception)
        self.assertIn("large-window", msg)
        self.assertIn("pip install brotli", msg)

    def test_normal_streams_still_decode(self):
        # minimal valid stream: WBITS=16 (bit 0), ISLAST=1, ISLASTEMPTY=1
        # — reading-order bits "011" pack LSB-first into byte 0x06
        self.assertEqual(decompress(bytes([0b110])), b"")


# ---------------------------------------------------------------- (c) replay

class TestAdoptBrowserCookiesReplaySafety(unittest.TestCase):
    """adopt_browser_cookies() warning/strict_replay logic, without Chrome:
    the CDP call is monkeypatched to a fixed cookie payload."""

    PAYLOAD = [
        {"name": "plain", "value": "1", "domain": ".t.test", "path": "/"},
        {"name": "hard", "value": "2", "domain": ".t.test", "path": "/",
         "secure": True, "httpOnly": True},
        {"name": "chips", "value": "3", "domain": ".t.test", "path": "/",
         "partitionKey": "https://top.test"},
    ]

    def _adopt(self, strict=False):
        s = Session(user_agent="NOT-CHROME/1.0")
        import nettle.cdp
        orig = nettle.cdp.browser_cookies
        nettle.cdp.browser_cookies = (
            lambda url, **kw: ({"cookies": self.PAYLOAD, "user_agent": "Chrome/999 QA",
                                "platform": "Linux"} if kw.get("fingerprint")
                              else list(self.PAYLOAD))
        )
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                n = s.adopt_browser_cookies("https://t.test/", strict_replay=strict)
        finally:
            nettle.cdp.browser_cookies = orig
        return s, n, [str(w.message) for w in caught]

    def test_warns_on_secure_httponly_replay_risk(self):
        _, n, msgs = self._adopt()
        self.assertEqual(n, 2)  # plain + hard imported, chips skipped
        self.assertTrue(any("Secure+HttpOnly" in m for m in msgs), msgs)

    def test_strict_replay_adopts_chrome_ua(self):
        s, _, msgs = self._adopt(strict=True)
        self.assertEqual(s.headers["User-Agent"], "Chrome/999 QA")
        self.assertNotIn("Sec-Ch-Ua", s.headers)  # contradicting hints dropped

    def test_chips_skipped_and_reported(self):
        s, n, msgs = self._adopt()
        self.assertNotIn("chips", s.get_cookie_dict("https://t.test/"))
        self.assertTrue(any("partitioned" in m for m in msgs), msgs)


# ---------------------------------------------------------------- (d) CHIPS

class TestChipsExport(unittest.TestCase):
    COOKIES = [
        {"name": "sid", "value": "abc", "domain": ".x.test", "path": "/",
         "expires": 1893456000.0, "secure": True},
        {"name": "chips1", "value": "c1", "domain": ".x.test", "path": "/",
         "expires": 1893456000.0, "partitionKey": "https://embedder.test"},
        {"name": "chips2", "value": "c2", "domain": ".x.test", "path": "/",
         "sameParty": True},
        {"name": "chips3", "value": "c3", "domain": ".x.test", "path": "/",
         "expires": 1893456000.0, "partitionKey": {"topLevelSite": "https://top.test"}},
    ]

    def test_partition_detection(self):
        self.assertFalse(_cookie_is_partitioned(self.COOKIES[0]))
        self.assertTrue(_cookie_is_partitioned(self.COOKIES[1]))
        self.assertTrue(_cookie_is_partitioned(self.COOKIES[2]))
        self.assertTrue(_cookie_is_partitioned(self.COOKIES[3]))
        # unpartitioned shapes must NOT be flagged
        self.assertFalse(_cookie_is_partitioned({"partitionKey": ""}))
        self.assertFalse(_cookie_is_partitioned({"sameParty": False}))
        self.assertFalse(_cookie_is_partitioned({}))

    def test_export_rows_and_comments(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            path = f.name
        try:
            n = write_netscape_cookies(self.COOKIES, path)
            txt = open(path).read()
            self.assertEqual(n, 1)                       # only the replayable row
            self.assertIn(".x.test\tTRUE", txt)          # normal row present
            self.assertNotIn("chips1\tc1", txt.replace("\t", "\t"))  # no data rows
            for name in ("chips1", "chips2", "chips3"):
                self.assertNotRegex(txt, f"^[^\n]*\t{name}\t")  # not TSV rows
                self.assertIn(f"# partitioned: {name}=", txt)   # documented
            self.assertIn("CHIPS", txt)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
