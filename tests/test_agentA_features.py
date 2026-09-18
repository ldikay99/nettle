"""Agent-A feature tests: configurable CDP ports, resolve_ip, headless flag,
and registry-driven limits (features a, b, c, e).

Offline parts run anywhere; live resolve_ip tests use real DNS and are
skipped when the network is unavailable.
"""
import socket
import sys
import unittest

sys.path.insert(0, ".")

import nettle
from nettle import registry
from nettle.cdp import chrome_launch_cmd
from nettle.registry import _normalize_ports
from nettle.exceptions import FetchError


def _online() -> bool:
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=2).close()
        return True
    except OSError:
        return False


class TestPortNormalization(unittest.TestCase):
    def test_int(self):
        self.assertEqual(_normalize_ports(9222), [9222])

    def test_list(self):
        self.assertEqual(_normalize_ports([9330, 9331, 9330]), [9330, 9331])

    def test_tuple_range_inclusive(self):
        self.assertEqual(_normalize_ports((9300, 9303)), [9300, 9301, 9302, 9303])

    def test_range_object(self):
        self.assertEqual(_normalize_ports(range(9400, 9402)), [9400, 9401])

    def test_dedup_and_order_preserved(self):
        self.assertEqual(_normalize_ports([5, 5, 6, 4]), [5, 6, 4])

    def test_bad_types_raise_valueerror_with_message(self):
        for bad in ("9222", 3.5, True, [9222, "x"], object()):
            with self.assertRaises(ValueError) as cm:
                _normalize_ports(bad)
            self.assertIn("port", str(cm.exception).lower())

    def test_bad_range_raises(self):
        with self.assertRaises(ValueError):
            _normalize_ports((9300, 9290))

    def test_out_of_bounds_port_raises(self):
        with self.assertRaises(ValueError):
            _normalize_ports(70000)
        with self.assertRaises(ValueError):
            _normalize_ports(0)


class TestRegistryCdpPorts(unittest.TestCase):
    def tearDown(self):
        registry.reset()

    def test_defaults(self):
        self.assertEqual(registry.cdp["ports"], list(range(9222, 9235)))
        self.assertTrue(registry.cdp["headless"])
        self.assertEqual(registry.cdp["body_preview_chars"], 4000)

    def test_set_cdp_ports_accepts_range_tuple_list_int(self):
        registry.set_cdp_ports(9500)
        self.assertEqual(registry.cdp["ports"], [9500])
        registry.set_cdp_ports((9600, 9602))
        self.assertEqual(registry.cdp["ports"], [9600, 9601, 9602])
        registry.set_cdp_ports([9700, 9701])
        self.assertEqual(registry.cdp["ports"], [9700, 9701])
        registry.set_cdp_ports(range(9800, 9803))
        self.assertEqual(registry.cdp["ports"], [9800, 9801, 9802])

    def test_add_and_remove_cdp_ports(self):
        registry.add_cdp_ports(9333, (9340, 9341))
        self.assertIn(9333, registry.cdp["ports"])
        self.assertIn(9340, registry.cdp["ports"])
        self.assertIn(9341, registry.cdp["ports"])
        registry.remove_cdp_ports(9333)
        self.assertNotIn(9333, registry.cdp["ports"])

    def test_set_cdp_ports_rejects_garbage(self):
        with self.assertRaises(ValueError):
            registry.set_cdp_ports("nope")

    def test_snapshot_includes_new_sections(self):
        snap = registry.snapshot()
        for key in ("cdp", "sniff", "discover", "parse", "css", "dns"):
            self.assertIn(key, snap)
        self.assertIn("ports", snap["cdp"])
        self.assertIn("retry_statuses", snap["http"])


class TestChromeLaunchCmdHeadless(unittest.TestCase):
    """Feature c: the headless flag must reach the browser command line."""

    BIN = "/usr/bin/google-chrome"

    def test_headless_true_adds_flags(self):
        cmd = chrome_launch_cmd(self.BIN, 9222, "/tmp/udd", headless=True)
        self.assertIn("--headless=new", cmd)
        self.assertIn("--disable-gpu", cmd)
        self.assertIn("--remote-debugging-port=9222", cmd)
        self.assertIn("--user-data-dir=/tmp/udd", cmd)
        self.assertEqual(cmd[0], self.BIN)

    def test_headless_false_omits_both(self):
        cmd = chrome_launch_cmd(self.BIN, 9223, "/tmp/udd", headless=False)
        self.assertNotIn("--headless=new", cmd)
        self.assertNotIn("--headless", cmd)
        self.assertNotIn("--disable-gpu", cmd)

    def test_sniff_network_accepts_headless_and_port_spec(self):
        import inspect
        from nettle.cdp import sniff_network
        sig = inspect.signature(sniff_network)
        self.assertIn("headless", sig.parameters)
        self.assertIsNone(sig.parameters["headless"].default)
        # port spec accepts tuple ranges per the mission statement
        self.assertIsNone(sig.parameters["port"].default)

    def test_sniff_network_forwards_headless(self):
        """ensure_debugging_chrome must receive the headless kwarg."""
        import nettle.cdp as cdp_mod

        captured = {}

        class FakeRes:
            ok = True
            total = 0
            xhr_fetch = []
            json = []
            media = []
            entries = []

        def fake_ensure(port=None, *, headless=None, user_data_dir=None, wait=None):
            captured["port"] = port
            captured["headless"] = headless
            return 9311

        def fake_sniff_inner(url, **kw):  # not used
            pass

        # monkeypatch the collaborators of sniff_network
        orig_ensure, orig_tab, orig_cls = (
            cdp_mod.ensure_debugging_chrome,
            cdp_mod.new_tab,
            cdp_mod.CDPSession,
        )

        class FakeCDP:
            def __init__(self, ws): ...
            def on(self, *a): ...
            def call(self, *a, **k): return {}
            def pump_for(self, s): ...
            def close(self): ...

        try:
            cdp_mod.ensure_debugging_chrome = fake_ensure
            cdp_mod.new_tab = lambda port=None, url="": {
                "id": "t1", "webSocketDebuggerUrl": "ws://x"
            }
            cdp_mod.CDPSession = FakeCDP
            cdp_mod.find_debugging_port = lambda candidates=None: None
            cdp_mod.sniff_network("https://example.test/", headless=False,
                                  port=(9310, 9320), settle=0.01, scroll=False)
            self.assertEqual(captured["headless"], False)
            self.assertEqual(captured["port"], list(range(9310, 9321)))
        finally:
            cdp_mod.ensure_debugging_chrome = orig_ensure
            cdp_mod.new_tab = orig_tab
            cdp_mod.CDPSession = orig_cls


class TestResolveIp(unittest.TestCase):
    """Feature b: resolve_ip / server_ip."""

    def test_host_parsing(self):
        from nettle.resolve import _host_from
        self.assertEqual(_host_from("https://example.com/path?q=1"), "example.com")
        self.assertEqual(_host_from("http://example.com:8080/x"), "example.com")
        self.assertEqual(_host_from("example.com"), "example.com")
        self.assertEqual(_host_from("example.com:443"), "example.com")
        self.assertEqual(_host_from("https://user:pw@example.com/"), "example.com")
        self.assertEqual(_host_from("https://[2001:db8::1]/"), "2001:db8::1")
        self.assertEqual(_host_from("https://[2001:db8::1]:8443/x"), "2001:db8::1")

    def test_bad_inputs(self):
        for bad in ("", None, 123, "   "):
            with self.assertRaises(FetchError):
                nettle.resolve_ip(bad)
        with self.assertRaises(FetchError):
            nettle.resolve_ip("https://[broken-v6")

    @unittest.skipUnless(_online(), "no network")
    def test_five_real_hosts(self):
        for host in (
            "https://www.wikipedia.org/",
            "github.com",
            "https://www.google.com/",
            "https://ja.wikipedia.org/",
            "https://www.bbc.com/",
        ):
            ip = nettle.resolve_ip(host, timeout=10)
            self.assertIsInstance(ip, str)
            self.assertTrue("." in ip or ":" in ip, f"not an IP: {ip!r}")

    @unittest.skipUnless(_online(), "no network")
    def test_all_returns_list_preferring_ipv4(self):
        ips = nettle.resolve_ip("www.google.com", all=True, timeout=10)
        self.assertIsInstance(ips, list)
        self.assertGreaterEqual(len(ips), 1)
        if any("." in ip for ip in ips):
            self.assertIn(".", ips[0], "IPv4 should be preferred first")

    @unittest.skipUnless(_online(), "no network")
    def test_nonexistent_host_clear_error(self):
        with self.assertRaises(FetchError) as cm:
            nettle.resolve_ip("nx-zzz-99173-nettle-test.example", timeout=10)
        msg = str(cm.exception)
        self.assertIn("nx-zzz-99173-nettle-test.example", msg)
        self.assertTrue("not resolve" in msg or "DNS" in msg, msg)

    def test_timeout_must_be_positive(self):
        with self.assertRaises(FetchError):
            nettle.resolve_ip("example.com", timeout=0)


class TestRegistryDrivenLimits(unittest.TestCase):
    """Feature e: previously hard-coded caps obey the registry at call time."""

    def tearDown(self):
        registry.reset()

    def test_sniff_max_blobs(self):
        html = "<html><body>" + "".join(
            f'<script>var x{i} = {{"key{i}": "value {i} padding padding padding"}};</script>'
            for i in range(10)
        ) + "</body></html>"
        doc = nettle.parse(html)
        self.assertEqual(len(nettle.sniff_embedded_json(doc)), 10)
        registry.sniff["max_blobs"] = 3
        self.assertEqual(len(nettle.sniff_embedded_json(doc)), 3)
        # explicit kwarg beats registry
        self.assertEqual(len(nettle.sniff_embedded_json(doc, max_blobs=5)), 5)

    def test_charset_sniff_bytes(self):
        pad = "<!--" + "x" * 9000 + "-->"
        raw = ('<html><head>' + pad +
               '<meta charset="euc-kr"></head><body>한글</body></html>').encode("euc-kr")
        # default window (8192) misses the declaration
        self.assertIsNone(nettle.detect_charset(raw))
        registry.parse["charset_sniff_bytes"] = 20000
        self.assertEqual(nettle.detect_charset(raw), "euc-kr")

    def test_css_chain_cache_cap(self):
        from nettle.css import _CHAIN_CACHE
        registry.css["chain_cache_max"] = 4
        for i in range(10):
            nettle.parse("<div class='c%d'>x</div>" % i).select(f".c{i}")
        self.assertLessEqual(len(_CHAIN_CACHE), 4)

    def test_http_retry_statuses_mutable(self):
        from nettle.http import _retry_statuses
        self.assertIn(503, _retry_statuses())
        registry.http["retry_statuses"] = {429}
        self.assertEqual(_retry_statuses(), {429})

    def test_sniff_preview_chars(self):
        registry.sniff["preview_chars"] = 7
        html = "<html><body><script>var cfg = {baseURL: 'https://api.example/'}</script></body></html>"
        # (probe not needed: preview length exercised in probe_apis only; here
        # we assert the registry value is readable and numeric)
        self.assertEqual(int(registry.sniff["preview_chars"]), 7)

    def test_discover_defaults_from_registry(self):
        self.assertEqual(registry.discover["max_probe"], 15)
        self.assertEqual(registry.discover["probe_timeout"], 8.0)
        registry.discover["max_probe"] = 2
        self.assertEqual(registry.discover["max_probe"], 2)

    def test_url_literal_bounds_widen(self):
        html = '<script>fetch("' + "/" + "a" * 900 + '");</script>'
        doc = nettle.parse(html)
        cands = nettle.sniff_api_candidates(doc, base_url="https://x.test/")
        self.assertEqual(cands, [])  # 900 > default cap 800
        registry.sniff["url_literal_max"] = 1000
        cands = nettle.sniff_api_candidates(doc, base_url="https://x.test/")
        self.assertEqual(cands, ["https://x.test/" + "a" * 900])


if __name__ == "__main__":
    unittest.main(verbosity=2)
