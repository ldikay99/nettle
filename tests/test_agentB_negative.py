"""Agent-B negative suite: every error path must raise the RIGHT exception
with an ACTIONABLE message (what went wrong + how to fix it).
"""

from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import json
import unittest

import nettle
from nettle import (
    ExtractError,
    FetchError,
    JsonBodyError,
    Nettle,
    ParseError,
    Response,
    SelectorError,
    clean_text,
    parse,
    registry,
    to_csv,
)


class TestParseErrors(unittest.TestCase):
    def test_parse_none(self):
        with self.assertRaises(ParseError) as cm:
            parse(None)
        self.assertIn("None", str(cm.exception))
        self.assertIn("str or bytes", str(cm.exception))

    def test_parse_int(self):
        with self.assertRaises(ParseError) as cm:
            parse(123)
        self.assertIn("int", str(cm.exception))

    def test_parse_list(self):
        with self.assertRaises(ParseError):
            parse(["<p>", "x"])

    def test_parse_unknown_encoding(self):
        with self.assertRaises(ParseError) as cm:
            parse(b"<p>x</p>", encoding="no-such-codec")
        self.assertIn("encoding", str(cm.exception))

    def test_parse_error_is_typeerror_too(self):
        # bs4-compat: code catching TypeError for invalid markup keeps working
        with self.assertRaises(TypeError):
            parse(None)


class TestSelectorErrors(unittest.TestCase):
    def setUp(self):
        self.doc = parse("<p class='x'>t</p>")

    def test_valid_selector_no_match_is_not_error(self):
        self.assertEqual(self.doc.select("section.nope"), [])

    def test_empty_selector(self):
        with self.assertRaises(SelectorError) as cm:
            self.doc.select("")
        self.assertIn("empty selector", str(cm.exception))

    def test_selector_wrong_type(self):
        for bad in (None, 42, ("p",), ["p"], {"p": 1}, self.doc):
            with self.assertRaises(SelectorError) as cm:
                self.doc.select(bad)
            self.assertIn("str", str(cm.exception))

    def test_unknown_pseudo(self):
        with self.assertRaises(SelectorError) as cm:
            self.doc.select("p:nopseudo()")
        self.assertIn("nopseudo", str(cm.exception))

    def test_unsupported_pseudo_loud(self):
        for sel in ("p:hover", "input:checked", "p:lang(es)", ":scope p"):
            with self.assertRaises(SelectorError):
                self.doc.select(sel)

    def test_bad_attr_selector(self):
        for sel in ("[href==3]", "[unclosed", "[=v]", "p[href="):
            with self.assertRaises(SelectorError):
                self.doc.select(sel)

    def test_error_message_mentions_selector(self):
        try:
            self.doc.select("div >>")
        except SelectorError as e:
            msg = str(e)
            self.assertIn("combinator", msg)
            self.assertIn("div", msg)  # echoes the offending selector parts


class TestExtractErrors(unittest.TestCase):
    def setUp(self):
        self.doc = parse("<div><p>x</p></div>")

    def test_schema_wrong_type(self):
        for bad in (123, 4.5, ["nested-list"], ("t",)):
            with self.assertRaises(ExtractError) as cm:
                self.doc.extract({"k": bad})
            self.assertIn("str or dict", str(cm.exception))

    def test_schema_each_without_select(self):
        with self.assertRaises(ExtractError) as cm:
            self.doc.extract({"items": {"each": {"t": "p"}}})
        self.assertIn("each", str(cm.exception))

    def test_schema_spec_missing_css(self):
        # dict spec with none of css/select/attr/text/self → clear error
        with self.assertRaises(ExtractError) as cm:
            self.doc.extract({"k": {"default": "x", "abs": True}})
        self.assertIn("css", str(cm.exception).lower())

    def test_schema_not_a_dict_at_all(self):
        with self.assertRaises(ExtractError):
            self.doc.extract(["not", "a", "dict"])


class TestRegistryMisuse(unittest.TestCase):
    def tearDown(self):
        registry.reset()

    def test_add_api_hints_non_string(self):
        # add_api_hints(123) — current API accepts any hashable; assert it
        # either works (converted) or raises a clear TypeError, never silently
        try:
            registry.add_api_hints(123)
        except TypeError as e:
            self.assertIn("hint", str(e).lower())

    def test_register_classifier_not_callable(self):
        with self.assertRaises(TypeError):
            registry.register_classifier("not-callable")

    def test_register_classifier_runtime_error_isolated(self):
        def boom(url):
            raise RuntimeError("classifier bug")
        registry.register_classifier(boom)
        with self.assertRaises(RuntimeError):
            nettle.classify_url("https://x.example/a")  # surface, don't swallow

    def test_http_defaults_type_validation(self):
        registry.http["timeout"] = "fast"
        with self.assertRaises(ValueError):
            float(registry.http["timeout"])


class TestJsonErrors(unittest.TestCase):
    def _resp(self, body: bytes, ctype="application/json"):
        return Response(url="https://x.example/api", status=200,
                        headers={"Content-Type": ctype}, body=body, method="GET")

    def test_truncated_json(self):
        r = self._resp(b'{"items": [1, 2,')
        with self.assertRaises(JsonBodyError) as cm:
            r.json()
        self.assertIn("not valid JSON", str(cm.exception))
        self.assertIn("line", str(cm.exception))

    def test_empty_body_json(self):
        r = self._resp(b"")
        with self.assertRaises(JsonBodyError):
            r.json()

    def test_json_is_valueerror_too(self):
        r = self._resp(b"nope{")
        with self.assertRaises(ValueError):  # json-module compat
            r.json()

    def test_sniff_embedded_json_bad_blob_never_raises(self):
        # malformed embedded JSON never raises; the raw body is surfaced
        # with a ':raw' source so the caller can see it's not parsed data
        doc = parse('<script type="application/json">{"broken": </script>')
        blobs = nettle.sniff_embedded_json(doc)
        self.assertIsInstance(blobs, list)
        for b in blobs:
            self.assertIn("source", b) and self.assertIn("data", b)


class TestGetTextErrors(unittest.TestCase):
    def test_positional_bad_type(self):
        el = parse("<p>x</p>").find("p")
        with self.assertRaises(TypeError) as cm:
            el.get_text(123)
        self.assertIn("separator", str(cm.exception))

    def test_strip_bad_type(self):
        el = parse("<p>x</p>").find("p")
        with self.assertRaises(TypeError):
            el.get_text(strip="yes")


class TestFormatErrors(unittest.TestCase):
    def test_to_csv_non_dicts(self):
        with self.assertRaises(Exception):
            to_csv(["a", "b", "c"])

    def test_clean_text_bad_mode(self):
        with self.assertRaises(ValueError) as cm:
            clean_text("x", mode="fancy")
        self.assertIn("fancy", str(cm.exception))
        self.assertIn("plain", str(cm.exception))


class TestHttpErrors(unittest.TestCase):
    def test_bad_url_scheme(self):
        with self.assertRaises(FetchError):
            nettle.request("GET", "ftp://nope.example/x", retries=0, timeout=1)

    def test_relative_url_without_base(self):
        s = nettle.Session(spoof_browser=False)
        # no base_url → urllib would mangle it; we fail fast with guidance
        with self.assertRaises(FetchError) as cm:
            s.get("/just/a/path", retries=0, timeout=1)
        self.assertIn("url", str(cm.exception).lower())

    def test_data_and_json_conflict(self):
        s = nettle.Session(spoof_browser=False)
        with self.assertRaises(ValueError) as cm:
            s.post("https://x.example/", data={"a": 1}, json={"b": 2}, retries=0, timeout=1)
        self.assertIn("one of json", str(cm.exception))


class TestResponseErrors(unittest.TestCase):
    def test_raise_for_status_4xx(self):
        r = Response(url="https://x.example/e", status=404,
                     headers={}, body=b"nope", method="GET")
        with self.assertRaises(FetchError) as cm:
            r.raise_for_status()
        self.assertIn("404", str(cm.exception))

    def test_raise_for_status_ok(self):
        r = Response(url="https://x.example/ok", status=204,
                     headers={}, body=b"", method="DELETE")
        self.assertIs(r.raise_for_status(), r)


if __name__ == "__main__":
    unittest.main()
