"""Agent-B round 3: UTF-16 without BOM detection, requests-style response
hooks, and get_text(types=) signature compat."""

from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from nettle import Comment, Text, detect_charset, parse

# ---------------------------------------------------------------------------
# UTF-16 without BOM
# ---------------------------------------------------------------------------

UTF16_DOC = (
    "<html><head><title>Böletín ñ</title></head><body>"
    "<p>Héllo wörld — ñáéíóú</p></body></html>"
)


class TestUtf16NoBom(unittest.TestCase):
    def test_detect_le_and_be(self):
        self.assertEqual(detect_charset(UTF16_DOC.encode("utf-16-le")), "utf-16-le")
        self.assertEqual(detect_charset(UTF16_DOC.encode("utf-16-be")), "utf-16-be")

    def test_leading_whitespace(self):
        src = "\n  " + UTF16_DOC
        self.assertEqual(detect_charset(src.encode("utf-16-le")), "utf-16-le")
        self.assertEqual(detect_charset(src.encode("utf-16-be")), "utf-16-be")

    def test_parse_roundtrip_both_endians(self):
        for enc in ("utf-16-le", "utf-16-be"):
            with self.subTest(encoding=enc):
                doc = parse(UTF16_DOC.encode(enc))
                self.assertEqual(doc.title, "Böletín ñ")
                self.assertEqual(doc.select_one("p").get_text(), "Héllo wörld — ñáéíóú")

    def test_bom_still_wins(self):
        self.assertEqual(detect_charset("﻿<p>x</p>".encode("utf-16")), "utf-16-le")
        self.assertEqual(detect_charset(b"\xfe\xff\x00<"), "utf-16-be")

    def test_no_false_positives(self):
        self.assertIsNone(detect_charset("<p>café ñ</p>".encode("latin-1")))
        self.assertIsNone(detect_charset(UTF16_DOC.encode("utf-8-sig").lstrip(b"\xef\xbb\xbf")))
        # UTF-32 has NULs on BOTH parities — must not fire
        self.assertIsNone(detect_charset(UTF16_DOC.encode("utf-32-le")))
        self.assertIsNone(detect_charset(UTF16_DOC.encode("utf-32-be")))
        # short and binary-ish inputs
        self.assertIsNone(detect_charset(b"<p>"))
        self.assertIsNone(detect_charset(b""))
        self.assertIsNone(detect_charset(b"\x00\x01\x02\x03\x04\x05\x06\x07"))

    def test_meta_charset_still_works(self):
        self.assertEqual(
            detect_charset(b"<meta charset='iso-8859-1'><p>x</p>"), "iso-8859-1"
        )


# ---------------------------------------------------------------------------
# requests-style hooks (Session + request())
# ---------------------------------------------------------------------------

def _serve():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/err":
                body = b"boom"
                self.send_response(503)
                self.send_header("Content-Type", "text/plain")
            else:
                body = b"<p>ok</p>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


class TestResponseHooks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = _serve()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def test_session_hook_registers_status(self):
        from nettle import Session
        log = []

        def register(resp):
            log.append((resp.status, resp.method))
            return resp

        s = Session(hooks={"response": register}, retries=0)
        r1 = s.get(self.base + "/")
        r2 = s.get(self.base + "/err")
        self.assertEqual(log, [(200, "GET"), (503, "GET")])  # error statuses too
        self.assertEqual(r1.status, 200)
        self.assertEqual(r2.status, 503)

    def test_hook_may_mutate_response(self):
        from nettle import Session
        s = Session(hooks={"response": lambda r: (setattr(r, "_seen", True), r)[1]}, retries=0)
        r = s.get(self.base + "/")
        self.assertTrue(getattr(r, "_seen", False))

    def test_hook_returning_none_keeps_response(self):
        from nettle import Session
        s = Session(hooks={"response": lambda r: None}, retries=0)
        self.assertEqual(s.get(self.base + "/").status, 200)

    def test_hook_can_replace_response(self):
        from nettle import Response, Session
        s = Session(
            hooks={"response": lambda r: Response(
                url="replaced://x", status=599, headers={}, body=b"swapped"
            )},
            retries=0,
        )
        r = s.get(self.base + "/")
        self.assertEqual((r.status, r.url, r.text), (599, "replaced://x", "swapped"))

    def test_hook_raising_aborts(self):
        from nettle import Session

        def guard(resp):
            if resp.status >= 500:
                raise RuntimeError("no 5xx allowed")

        s = Session(hooks={"response": guard}, retries=0)
        s.get(self.base + "/")  # fine
        with self.assertRaises(RuntimeError):
            s.get(self.base + "/err")

    def test_hook_bad_return_type(self):
        from nettle import Session
        s = Session(hooks={"response": lambda r: 42}, retries=0)
        with self.assertRaises(TypeError):
            s.get(self.base + "/")

    def test_per_request_hooks_and_order(self):
        from nettle import Session
        order = []

        def mk(name):
            def hook(resp):
                order.append(name)
                return resp
            return hook

        s = Session(hooks={"response": mk("session")}, retries=0)
        s.get(self.base + "/", hooks={"response": [mk("req1"), mk("req2")]})
        self.assertEqual(order, ["session", "req1", "req2"])  # requests order

    def test_top_level_request_hooks(self):
        from nettle import request
        seen = []
        request(
            "GET", self.base + "/",
            hooks={"response": lambda r: (seen.append(r.status), r)[1]},
            retries=0,
        )
        self.assertEqual(seen, [200])

    def test_hook_list_accepted_without_dict_wrapper(self):
        from nettle import Session
        calls = []
        s = Session(hooks={"response": [lambda r: (calls.append(1), r)[1]] * 1}, retries=0)
        s.get(self.base + "/")
        self.assertEqual(calls, [1])

    def test_validation(self):
        from nettle import Session
        with self.assertRaises(ValueError):
            Session(hooks={"request": lambda r: r})  # unsupported event
        with self.assertRaises(TypeError):
            Session(hooks={"response": 42})  # not callable
        with self.assertRaises(TypeError):
            Session(hooks=42)  # not a dict
        with self.assertRaises(TypeError):
            Session(hooks={"response": [lambda r: r, "nope"]})


# ---------------------------------------------------------------------------
# get_text(types=) — bs4 signature parity
# ---------------------------------------------------------------------------

TYPES_DOC = parse(
    "<div id='t'>text one<!--hidden comment--><p>para text</p>tail</div>"
)


class TestGetTextTypes(unittest.TestCase):
    def test_default_text_only(self):
        el = TYPES_DOC.select_one("#t")
        self.assertEqual(el.get_text(), "text onepara texttail")
        self.assertEqual(el.get_text(), el.get_text(types=None))

    def test_types_comment(self):
        el = TYPES_DOC.select_one("#t")
        self.assertEqual(el.get_text(types=Comment), "hidden comment")

    def test_types_tuple(self):
        el = TYPES_DOC.select_one("#t")
        self.assertEqual(
            el.get_text(types=(Text, Comment)),
            "text onehidden commentpara texttail",
        )

    def test_types_never_instantiated_subclass_excludes(self):
        # a user subclass of Text is a VALID type, but no node is an
        # INSTANCE of it — bs4 isinstance semantics: contributes nothing
        class MyText(Text):
            pass

        el = TYPES_DOC.select_one("#t")
        self.assertEqual(el.get_text(types=MyText), "")
        self.assertEqual(el.get_text(types=(MyText, Comment)), "hidden comment")

    def test_types_invalid_raises_typeerror(self):
        el = TYPES_DOC.select_one("#t")
        for bad in (int, str, (Text, 42), "Text", ()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    el.get_text(types=bad)

    def test_text_node_get_text_accepts_same_kwargs(self):
        node = TYPES_DOC.select_one("p")._children[0]
        self.assertEqual(node.get_text(), "para text")
        self.assertEqual(node.get_text(strip=True), "para text")
        self.assertEqual(node.get_text(types=Comment), "")

    def test_positional_style_still_works(self):
        el = TYPES_DOC.select_one("#t")
        self.assertEqual(el.get_text(" | "), el.get_text(sep=" | "))
        self.assertEqual(el.get_text(" ", True), el.get_text(sep=" ", strip=True))


if __name__ == "__main__":
    unittest.main()
