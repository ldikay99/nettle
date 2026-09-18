"""Agent-A: error-path robustness — everything that must fail, must fail
with a CLEAR error (cause + what to do), and never with a stack-trace
surprise from deep inside stdlib.
"""
import socket
import sys
import threading
import unittest

sys.path.insert(0, ".")

import nettle
from nettle import registry
from nettle.cdp import _pick_launch_port, CDPError
from nettle.exceptions import FetchError, SelectorError, JsonBodyError
from nettle.registry import _normalize_ports


def _online() -> bool:
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=2).close()
        return True
    except OSError:
        return False


class TestFetchErrors(unittest.TestCase):
    @unittest.skipUnless(_online(), "no network")
    def test_nonexistent_host(self):
        with self.assertRaises(FetchError) as cm:
            nettle.fetch("https://host-zzz-nx-99824.example/", timeout=8)
        msg = str(cm.exception)
        self.assertIn("host-zzz-nx-99824.example", msg)

    def test_url_without_scheme(self):
        for bad in ("example.com/path", "www.google.com", "/just/a/path"):
            with self.assertRaises(FetchError) as cm:
                nettle.fetch(bad)
            self.assertIn("scheme", str(cm.exception))

    def test_dns_not_resolving_clear_message(self):
        with self.assertRaises(FetchError) as cm:
            nettle.resolve_ip("definitely-not-a-real-host-8831.example")
        msg = str(cm.exception)
        self.assertTrue(
            "does not resolve" in msg or "DNS" in msg,
            f"message lacks cause: {msg}",
        )

    def test_invalid_url_retries_not_wasted(self):
        # malformed/unknown-scheme URLs must fail fast, not retry 3 times
        # (regression: 'htp://…' used to burn 5.6s of retry backoff)
        import time
        t0 = time.time()
        with self.assertRaises(FetchError):
            nettle.request("GET", "htp://bad scheme/", retries=3)
        self.assertLess(time.time() - t0, 1.0)


class TestSelectorErrors(unittest.TestCase):
    def test_valid_selector_empty_tree_returns_empty(self):
        doc = nettle.parse("<html><body><p>hi</p></body></html>")
        self.assertEqual(doc.select("div.article"), [])
        self.assertIsNone(doc.select_one("div.article"))
        self.assertEqual(doc.find_all("article"), [])
        self.assertIsNone(doc.find("article"))

    def test_invalid_selector_raises_selectorerror(self):
        doc = nettle.parse("<p>x</p>")
        for bad in (":bogus(", "div[", "p::before", "a:lang(es)"):
            with self.assertRaises(SelectorError):
                doc.select(bad)

    def test_doubled_combinator_raises_selectorerror(self):
        # regression: 'p > > a' used to be silently accepted as 'p > a'
        doc = nettle.parse("<div><p><a>x</a></p></div>")
        self.assertEqual(len(doc.select("p > a")), 1)
        for bad in ("p > > a", "p >> a", "div ~ ~ span", "p + + a"):
            with self.assertRaises(SelectorError) as cm:
                doc.select(bad)
            self.assertIn("combinator", str(cm.exception))


class TestTruncatedJson(unittest.TestCase):
    def test_truncated_embedded_json_does_not_crash(self):
        with open("tests/fixtures/truncated_json.html", encoding="utf-8") as f:
            doc = nettle.parse(f.read())
        # must not raise; broken blobs are skipped or kept raw, never crash
        blobs = nettle.sniff_embedded_json(doc)
        self.assertIsInstance(blobs, list)

    def test_truncated_json_response_raises_jsonbodyerror_with_context(self):
        # build a Response directly (no network)
        from nettle.http import Response
        r = Response(url="https://api.test/x", status=200,
                     headers={"Content-Type": "application/json"},
                     body=b'{"a": [1, 2,', method="GET")
        with self.assertRaises(JsonBodyError) as cm:
            r.json()
        msg = str(cm.exception)
        self.assertIn("not valid JSON", msg)
        self.assertIn("api.test/x", msg)


class TestProbeRobustness(unittest.TestCase):
    def test_probe_timeout_returns_error_entries(self):
        # a server that accepts and never answers -> per-candidate error, no raise
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]

        def slow_accept():
            try:
                while True:
                    c, _ = srv.accept()
                    time.sleep(30)
                    c.close()
            except OSError:
                pass

        import time
        threading.Thread(target=slow_accept, daemon=True).start()
        results = nettle.probe_apis(
            [f"http://127.0.0.1:{port}/slow"],
            timeout=1.0,
        )
        srv.close()
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["ok"])
        self.assertIn("error", results[0])
        self.assertIn("url", results[0])

    def test_probe_bad_candidate_shape(self):
        with self.assertRaises(ValueError) as cm:
            nettle.probe_apis([{"method": "GET"}])  # dict without url
        self.assertIn("url", str(cm.exception))

    def test_discover_dead_site_raises_clear_fetcherror(self):
        # A page that cannot be fetched at all is a FetchError naming the
        # host (the user asked for THAT page); it must not be a generic
        # urllib traceback nor take forever.
        import time
        t0 = time.time()
        with self.assertRaises(FetchError) as cm:
            nettle.discover_endpoints(
                "https://nx-host-zzq-8812.example/", probe_timeout=2
            )
        self.assertIn("nx-host-zzq-8812.example", str(cm.exception))
        self.assertLess(time.time() - t0, 30)


class TestCdpPortConflicts(unittest.TestCase):
    def test_port_occupied_by_non_cdp_app_is_skipped(self):
        # occupy two ports with plain listeners (NOT CDP endpoints)
        s1, s2 = socket.socket(), socket.socket()
        for s in (s1, s2):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s1.bind(("127.0.0.1", 9451))
        s2.bind(("127.0.0.1", 9452))
        s1.listen(1)
        s2.listen(1)
        try:
            # first free candidate after the occupied ones must be chosen
            picked = _pick_launch_port([9451, 9452, 9453])
            self.assertEqual(picked, 9453)
        finally:
            s1.close()
            s2.close()

    def test_all_ports_occupied_raises_clear_cdpererror(self):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 9461))
        s.listen(1)
        try:
            with self.assertRaises(CDPError) as cm:
                _pick_launch_port([9461])
            msg = str(cm.exception)
            self.assertIn("9461", msg)
            self.assertIn("registry.cdp", msg)  # tells the user the fix
        finally:
            s.close()

    def test_empty_port_list_raises(self):
        with self.assertRaises(CDPError):
            _pick_launch_port([])

    def test_bad_port_spec_raises_valueerror_named(self):
        with self.assertRaises(ValueError):
            _normalize_ports("9222-9230")  # strings are not a port spec


class TestParseErrors(unittest.TestCase):
    def test_on_error_raise_only_for_tokenizer_crashes(self):
        # the tokenizer is tolerant by design; well-formed input with
        # on_error="raise" must NOT raise
        doc = nettle.parse("<p>x</p>", on_error="raise")
        self.assertIn("x", doc.get_text())

    def test_bytes_unknown_fallback(self):
        # bytes without any declaration decode as utf-8 replacement
        doc = nettle.parse(b"<p>\xff\xfe raw bytes</p>")
        self.assertIn("raw bytes", doc.get_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
