"""Tests for http session headers + clean pipeline."""

import unittest
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nettle import CleanPipeline, clean_tree, Session
from nettle.http import BROWSER_HEADERS as BH, Response, DEFAULT_UA


class TestCleanPipeline(unittest.TestCase):
    def test_plain_recipe(self):
        pipe = CleanPipeline.plain()
        self.assertEqual(pipe("  a\xa0b  "), "a b")

    def test_nested(self):
        out = clean_tree({"t": "  x\xa0y ", "L": [" a ", " b "]}, mode="plain")
        self.assertEqual(out["t"], "x y")
        self.assertEqual(out["L"], ["a", "b"])


class TestHttpSpoof(unittest.TestCase):
    def test_browser_headers_present(self):
        self.assertIn("User-Agent", BH)
        self.assertIn("Mozilla", BH["User-Agent"])
        self.assertIn("Accept-Language", BH)

    def test_session_merges_headers(self):
        s = Session(spoof_browser=True, headers={"X-Test": "1"})
        self.assertEqual(s.headers["X-Test"], "1")
        self.assertIn("Mozilla", s.headers["User-Agent"])

    def test_response_json_and_text(self):
        r = Response(
            url="https://x.test/",
            status=200,
            headers={"Content-Type": "application/json; charset=utf-8"},
            body=b'{"ok": true}',
            encoding="utf-8",
        )
        self.assertEqual(r.text, '{"ok": true}')
        self.assertEqual(r.json(), {"ok": True})
        self.assertEqual(r.encoding, "utf-8")

    def test_response_doc(self):
        r = Response(
            url="https://x.test/page",
            status=200,
            headers={"Content-Type": "text/html"},
            body=b"<html><p>hi</p></html>",
        )
        self.assertEqual(r.doc.select_one("p").text, "hi")
        self.assertEqual(r.doc.base_url, "https://x.test/page")

    def test_fetch_uses_spoofed_ua(self):
        captured = {}

        class FakeResp:
            def __init__(self):
                self.headers = {"Content-Type": "text/plain"}
                self.status = 200
            def read(self):
                return b"ok"
            def geturl(self):
                return "https://example.com/"
            def getcode(self):
                return 200
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        def fake_open(req, timeout=None):
            captured["ua"] = req.get_header("User-agent") or req.headers.get("User-agent")
            # Request stores headers oddly; also check header_items
            captured["all"] = dict(req.header_items()) if hasattr(req, "header_items") else {}
            for k, v in getattr(req, "headers", {}).items():
                captured["all"][k] = v
            return FakeResp()

        s = Session(spoof_browser=True)
        with mock.patch.object(s._opener, "open", side_effect=fake_open):
            resp = s.get("https://example.com/")
        self.assertEqual(resp.status, 200)
        # UA should be modern chrome-like
        ua = captured.get("ua") or captured["all"].get("User-agent") or captured["all"].get("User-Agent")
        self.assertIsNotNone(ua)
        self.assertIn("Mozilla", ua)


if __name__ == "__main__":
    unittest.main()
