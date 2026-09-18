"""Agent-B tests for the migration API surface added on top of 0.6.0.

Covers: find_next/find_previous/_sibling(s), copy.copy semantics,
Session(base_url=...), Session(auth=...), legacy no-';' entities,
bs4 multi-value class matching, Nettle.get_text positional,
full-HTML5 entity table, :has() relative selectors.
"""

from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import base64
import copy
import re
import unittest

import nettle
from nettle import Element, Nettle, ParseError, Session, Text, parse


class TestFindNextFamily(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = parse(
            "<div><p id='p1'>one</p>mid-text<b>two</b><p class='x'>three</p>"
            "</div><span>after</span><section><i>deep</i></section>"
        )

    def test_find_next_tag(self):
        b = self.doc.find("b")
        self.assertEqual(b.find_next("p").get_text(), "three")
        self.assertEqual(b.find_next("span").get_text(), "after")

    def test_find_previous_tag(self):
        span = self.doc.find("span")
        self.assertEqual(span.find_previous("p").get_text(), "three")
        self.assertEqual(span.find_previous("b").get_text(), "two")

    def test_find_next_with_attrs(self):
        b = self.doc.find("b")
        self.assertEqual(b.find_next("p", class_="x").get_text(), "three")
        self.assertIsNone(b.find_next("p", class_="nope"))

    def test_find_all_next(self):
        b = self.doc.find("b")
        self.assertEqual([e.tag for e in b.find_all_next()], ["p", "span", "section", "i"])
        self.assertEqual([e.tag for e in b.find_all_next("p")], ["p"])

    def test_find_all_previous_limit(self):
        span = self.doc.find("span")
        got = span.find_all_previous(limit=2)
        self.assertEqual([e.tag for e in got], ["p", "b"])

    def test_find_next_sibling_element(self):
        p1 = self.doc.find("p")
        # 'mid-text' Text sits between p1 and b — next ELEMENT sibling is b
        self.assertEqual(p1.find_next_sibling("b").get_text(), "two")
        # p.x is a LATER sibling of p1 inside the same div
        self.assertEqual(p1.find_next_sibling("p").get_text(), "three")

    def test_find_next_sibling_string(self):
        p1 = self.doc.find("p")
        sib = p1.find_next_sibling(string="mid-text")
        self.assertIsInstance(sib, Text)
        self.assertEqual(sib.content, "mid-text")

    def test_find_previous_sibling(self):
        p2 = self.doc.select_one("p.x")
        self.assertEqual(p2.find_previous_sibling("b").get_text(), "two")

    def test_find_next_siblings_all(self):
        p1 = self.doc.find("p")
        sibs = p1.find_next_siblings("p")
        self.assertEqual([s.tag for s in sibs], ["p"])
        self.assertEqual(sibs[0].get_text(), "three")

    def test_from_text_node(self):
        # navigation now works on Text nodes too (bs4 PageElement parity)
        t = [n for n in self.doc.find("div").descendants if isinstance(n, Text)][0]
        self.assertEqual(t.content, "one")
        self.assertEqual(t.find_next("b").get_text(), "two")
        # document order: after "one" comes the sibling text "mid-text"
        self.assertIsInstance(t.next_element, Text)
        self.assertEqual(t.next_element.content, "mid-text")
        self.assertEqual([p.tag for p in t.parents][0], "p")

    def test_string_navigation(self):
        doc = parse("<p>a</p>")
        t = doc.find("p").children[0]
        # "a" is the last node in document order
        self.assertIsNone(t.next_element)
        self.assertEqual(t.previous_element.tag, "p")


class TestCopySemantics(unittest.TestCase):
    def test_shallow_copy_attr_independence(self):
        doc = parse("<div id='q' class='c'><p>hi</p></div>")
        orig = doc.find("div")
        c = copy.copy(orig)
        c.attrs["id"] = "changed"
        c.attrs["class"] = "z"
        self.assertEqual(orig.attrs["id"], "q")
        self.assertEqual(c.attrs["class"], "z")

    def test_shallow_copy_children_list_independence(self):
        doc = parse("<div><p>a</p><p>b</p></div>")
        orig = doc.find("div")
        c = copy.copy(orig)
        c.append(Element("span"))
        c.find("p").decompose()
        self.assertEqual(len(orig.select("p")), 2)
        self.assertEqual(len(c.select("p")), 1)

    def test_copy_document(self):
        doc = parse("<!DOCTYPE html><html><body><p>x</p></body></html>")
        c = copy.copy(doc)
        self.assertEqual(c.doctype, doc.doctype)
        self.assertEqual(c.select_one("p").get_text(), "x")


class TestSessionBaseUrl(unittest.TestCase):
    def test_resolution_matrix(self):
        s = Session(base_url="https://api.example.com/v1", spoof_browser=False)
        self.assertEqual(s._resolve_url("/items"), "https://api.example.com/items")
        self.assertEqual(s._resolve_url("items"), "https://api.example.com/v1/items")
        self.assertEqual(s._resolve_url("items?page=2"), "https://api.example.com/v1/items?page=2")
        self.assertEqual(s._resolve_url("https://other.example/x"), "https://other.example/x")
        self.assertEqual(s._resolve_url("//cdn.example/lib.js"), "//cdn.example/lib.js")

    def test_base_url_with_trailing_slash(self):
        s = Session(base_url="https://api.example.com/v1/", spoof_browser=False)
        self.assertEqual(s._resolve_url("items"), "https://api.example.com/v1/items")

    def test_relative_base_url_rejected(self):
        with self.assertRaises(nettle.FetchError):
            Session(base_url="api.example.com/v1")

    def test_registry_base_url(self):
        nettle.registry.reset()
        nettle.registry.http["base_url"] = "https://reg.example.com/api"
        try:
            s = Session()
            self.assertEqual(s._resolve_url("/x"), "https://reg.example.com/x")
        finally:
            nettle.registry.reset()

    def test_bad_url_type(self):
        s = Session(spoof_browser=False)
        for bad in (None, "", 42):
            with self.assertRaises(nettle.FetchError):
                s._resolve_url(bad)


class TestSessionAuth(unittest.TestCase):
    def test_basic_auth_header(self):
        s = Session(auth=("user", "pass"), spoof_browser=False)
        expected = "Basic " + base64.b64encode(b"user:pass").decode()
        self.assertEqual(s._auth_header, expected)

    def test_bearer(self):
        s = Session(auth=("token", "abc123"), auth_scheme="bearer", spoof_browser=False)
        self.assertEqual(s._auth_header, "Bearer abc123")

    def test_bad_auth_shape(self):
        with self.assertRaises(nettle.FetchError):
            Session(auth=("only-user",))

    def test_bad_scheme(self):
        with self.assertRaises(nettle.FetchError):
            Session(auth=("u", "p"), auth_scheme="digest")

    def test_registry_auth(self):
        nettle.registry.reset()
        nettle.registry.http["auth"] = ("ru", "rp")
        try:
            s = Session(spoof_browser=False)
            self.assertTrue(s._auth_header.startswith("Basic "))
        finally:
            nettle.registry.reset()

    def test_auth_reaches_request_headers(self):
        # offline proof: the header is merged into outgoing headers
        import nettle.http as H
        s = Session(auth=("u", "p"), spoof_browser=False)
        captured = {}

        class _FakeOpener:
            def open(self, req, timeout=None):
                captured["headers"] = dict(req.header_items())
                raise OSError("offline")

        orig_build = s._build_opener
        s._build_opener = lambda tracker: _FakeOpener()
        try:
            s.get("https://x.example/", retries=0, timeout=1)
        except nettle.FetchError:
            pass
        finally:
            s._build_opener = orig_build
        auth = {k.lower(): v for k, v in captured.get("headers", {}).items()}.get("authorization")
        self.assertIsNotNone(auth, "Authorization header missing")
        self.assertTrue(auth.startswith("Basic "))


class TestLegacyEntities(unittest.TestCase):
    def test_text_decodes(self):
        self.assertEqual(parse("<p>&copy 2024</p>").get_text(), "© 2024")
        self.assertEqual(parse("<p>x &amp y</p>").get_text(), "x & y")

    def test_longest_match_notit(self):
        self.assertEqual(parse("<p>&notit;</p>").get_text(), "¬it;")

    def test_no_double_decode(self):
        self.assertEqual(parse("<p>&amp;copy;</p>").get_text(), "&copy;")

    def test_attribute_safe(self):
        doc = parse("<a href='https://s.example/?q=1&copy=2'>x</a>")
        self.assertEqual(doc.find("a").get("href"), "https://s.example/?q=1&copy=2")

    def test_numeric_without_semicolon(self):
        self.assertEqual(parse("<p>&#97&#x62;</p>").get_text(), "ab")

    def test_full_html5_named(self):
        self.assertEqual(parse("<p>&frac13;&hellip;&notin;</p>").get_text(), "⅓…∉")


class TestClassMultiValue(unittest.TestCase):
    HTML = "<p class='a b c'>x</p><p class='b'>y</p><p class='a c'>z</p>"

    def test_string_single_token_any(self):
        doc = parse(self.HTML)
        self.assertEqual([e.get_text() for e in doc.find_all("p", class_="b")], ["x", "y"])

    def test_string_multi_token_exact(self):
        doc = parse(self.HTML)
        self.assertEqual([e.get_text() for e in doc.find_all("p", class_="a c")], ["z"])
        self.assertEqual([e.get_text() for e in doc.find_all("p", class_="c a")], [])

    def test_list_any_of(self):
        doc = parse(self.HTML)
        self.assertEqual(
            [e.get_text() for e in doc.find_all("p", class_=["a", "c"])], ["x", "z"]
        )

    def test_regex_joined(self):
        doc = parse(self.HTML)
        self.assertEqual(
            [e.get_text() for e in doc.find_all("p", class_=re.compile(r"^a c$"))], ["z"]
        )


class TestNettleWrapperGetText(unittest.TestCase):
    def test_positional_bs4_style(self):
        n = Nettle("<div><p>a</p><p>b</p></div>")
        self.assertEqual(n.get_text(" | "), "a | b")
        self.assertEqual(n.get_text(" | ", True), "a | b")


class TestHasRelative(unittest.TestCase):
    HTML = (
        "<div class=a><p><b>x</b></p></div>"
        "<div class=b><section><div class=a><i>y</i></div></section></div>"
        "<ul><li>1</li><li>2</li><li>3</li></ul>"
    )

    def test_has_child_combinator(self):
        doc = parse(self.HTML)
        self.assertEqual([e.attrs["class"] for e in doc.select("div:has(> p)")], ["a"])
        self.assertEqual([e.attrs["class"] for e in doc.select("div:has(> i)")], ["a"])

    def test_has_sibling_combinators(self):
        doc = parse(self.HTML)
        self.assertEqual([e.get_text() for e in doc.select("li:has(+ li)")], ["1", "2"])
        self.assertEqual([e.get_text() for e in doc.select("li:has(~ .sel)")], [])
        doc2 = parse("<ul><li>1</li><li class=sel>2</li><li>3</li></ul>")
        self.assertEqual([e.get_text() for e in doc2.select("li:has(~ .sel)")], ["1"])

    def test_has_no_self_leak(self):
        # regression: div:has(div:has(i)) must NOT match the inner div itself
        doc = parse(self.HTML)
        self.assertEqual([e.attrs["class"] for e in doc.select("div:has(div:has(i))")], ["b"])

    def test_has_invalid_arg_raises(self):
        doc = parse(self.HTML)
        with self.assertRaises(nettle.SelectorError):
            doc.select("div:has(>)")
        with self.assertRaises(nettle.SelectorError):
            doc.select("div:has()")


class TestSelectStrictness(unittest.TestCase):
    def test_empty_selector_raises(self):
        doc = parse("<p>x</p>")
        for bad in ("", "   ", None, 123):
            with self.assertRaises(nettle.SelectorError):
                doc.select(bad)

    def test_stray_comma_raises(self):
        doc = parse("<p>x</p>")
        for bad in ("div,", ",div", "div,,p", "p:not(div,)", "p:is(,)"):
            with self.assertRaises(nettle.SelectorError):
                doc.select(bad)

    def test_nth_whitespace_tolerated(self):
        doc = parse("<ul><li>1</li><li>2</li><li>3</li></ul>")
        for sel in ("li:nth-child( 2n + 1 )", "li:nth-child(2n+1)", "li:nth-child( -n + 2 )"):
            self.assertEqual(len(doc.select(sel)), 2, sel)


if __name__ == "__main__":
    unittest.main()
