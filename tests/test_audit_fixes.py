"""Regression tests for every issue found by the two audit agents (0.5.0 → 0.6.0)."""

import gzip as _gzip
import re
import sys
import time
import unittest

sys.path.insert(0, ".")

from nettle import Nettle, parse, clean_text, to_csv, registry, Session, exceptions
from nettle.exceptions import SelectorError


class TestCssAuditFixes(unittest.TestCase):
    HTML = '<ul><li class="a">1</li><li class="b">2</li><li class="c">3</li></ul>'

    def test_not_selector_list_or_semantics(self):
        d = parse(self.HTML)
        self.assertEqual([e.get_text() for e in d.select("li:not(.a, .b)")], ["3"])

    def test_not_complex_selector(self):
        d = parse("<section><div>in</div></section><div>out</div>")
        self.assertEqual([e.get_text() for e in d.select("div:not(section div)")], ["out"])

    def test_not_nested_parens(self):
        d = parse("<div><div><span>x</span></div><div>y</div></div>")
        self.assertEqual([e.get_text() for e in d.select("div:not(:has(span))")], ["y"])

    def test_is_where(self):
        d = parse(self.HTML)
        self.assertEqual(len(d.select(":is(li, p)")), 3)
        self.assertEqual(len(d.select(":where(li.b)")), 1)

    def test_document_order_sibling_combinators(self):
        d = parse("<div><h2>A</h2><p>1</p><div><h2>B</h2><p>i1</p></div><p>2</p></div>")
        self.assertEqual([e.get_text() for e in d.select("h2 ~ p")], ["1", "i1", "2"])
        self.assertEqual([e.get_text() for e in d.select("h2 + p")], ["1", "i1"])

    def test_nth_last_variants(self):
        d = parse("<div><p>1</p><p>2</p><p>3</p></div>")
        self.assertEqual(d.select_one("p:nth-last-child(1)").get_text(), "3")
        self.assertEqual(d.select_one("p:nth-last-child(3)").get_text(), "1")

    def test_attr_case_insensitive_flag(self):
        d = parse('<A HREF="/es/y">s</A>')
        self.assertEqual(len(d.select('[href="/es/y" i]')), 1)
        self.assertEqual(len(d.select('[href="/es/Y"]')), 0)

    def test_invalid_selectors_raise(self):
        d = parse(self.HTML)
        for bad in ["li:[bad", "li[class", "p:(", "<<<", "p >>>", "p > ",
                    "> p", "p::before", ":hover", "p:boguspseudo", "li.", "p:nth-child(x)"]:
            with self.assertRaises(SelectorError, msg=bad):
                d.select(bad)

    def test_selector_cache_speed(self):
        big = parse("<div>" + "<p>x</p>" * 3000 + "</div>")
        t0 = time.perf_counter()
        self.assertEqual(len(big.select("p:nth-child(2n)")), 1500)
        self.assertLess(time.perf_counter() - t0, 1.0)  # was ~3s in 0.5.0


class TestDoubleDecodeFix(unittest.TestCase):
    def test_literal_entity_preserved_in_pipeline(self):
        d = parse("<p>Usa &amp;nbsp; para espacio</p>")
        self.assertEqual(d.clean_text(), "Usa &nbsp; para espacio")

    def test_url_query_not_corrupted(self):
        d = Nettle('<a href="/s?q=1&copy=2">x</a>', base_url="https://x.com")
        self.assertEqual(d.extract({"u": {"css": "a", "attr": "href"}})["u"], "/s?q=1&copy=2")

    def test_standalone_clean_still_decodes(self):
        self.assertEqual(
            clean_text("Hello\xa0world&#39;s   &amp;  friends"),
            "Hello world's & friends",
        )

    def test_real_parser_nbsp_still_collapses(self):
        self.assertEqual(parse("<p>a&nbsp;b</p>").clean_text(), "a b")

    def test_invalid_clean_mode_raises(self):
        with self.assertRaises(ValueError):
            clean_text("x", mode="bogus")


class TestParseAuditFixes(unittest.TestCase):
    def test_duplicate_attr_first_wins(self):
        self.assertEqual(parse("<a href='/one' href='/two'>x</a>").find("a").get("href"), "/one")

    def test_unquoted_attr_with_slash(self):
        self.assertEqual(
            parse('<a href=/foo/bar class=btn>x</a>').find("a").get("href"), "/foo/bar"
        )

    def test_bom_stripped(self):
        self.assertEqual(parse("\ufeffhi".encode("utf-8")).get_text(), "hi")

    def test_deep_tree_no_recursion_error(self):
        n = 2500
        d = parse("<div>" * n + "x" + "</div>" * n)
        self.assertTrue(str(d))          # serialize
        self.assertTrue(d.get_text())    # text walk
        self.assertEqual(len(d.select("div")), n)


class TestBs4CompatAPI(unittest.TestCase):
    def test_get_text_positional_bs4_style(self):
        d = parse("<div><p>Hola</p><p>Mundo</p></div>")
        self.assertEqual(d.get_text(" "), "Hola Mundo")
        self.assertEqual(d.get_text(" | ", True), "Hola | Mundo")

    def test_get_text_bad_type_raises(self):
        with self.assertRaises(TypeError):
            parse("<p>x</p>").get_text(123)

    def test_find_all_bs4_kwargs(self):
        d = parse('<div><a href="https://e.com/x">1</a><a href="/y">2</a><b>bold</b></div>')
        self.assertEqual(len(d.find_all("a", {"href": re.compile(r"e\.com")})), 1)
        self.assertEqual(len(d.find_all(["a", "b"])), 3)
        self.assertEqual(len(d.find_all(re.compile(r"^b$"))), 1)
        d2 = parse("<div><b>1</b><span><b>2</b></span></div>")
        self.assertEqual(len(d2.find("div").find_all("b", recursive=False)), 1)
        self.assertEqual(len(d2.find_all("b", recursive=False)), 0)  # bs4: none at doc level
        self.assertEqual(d2.find_all("b", limit=0), [])
        self.assertEqual(d2.find_all(string="2"), [d2.select_one("span b")])

    def test_navigation_and_surgery(self):
        d = parse("<div><section><p>hi <b>there</b></p></section></div>")
        p = d.find("p")
        self.assertEqual([e.tag for e in p.parents], ["section", "div"])
        self.assertIsNone(p.string)  # bs4: two children → None
        self.assertEqual(d.find("b").string, "there")
        self.assertEqual(parse("<p>solo</p>").find("p").string, "solo")
        self.assertEqual(list(p.stripped_strings), ["hi", "there"])
        self.assertEqual(p.contents[0].content, "hi ")
        self.assertEqual(d.title, None)
        sec = d.find("section")
        sec.unwrap()
        self.assertNotIn("<section>", str(d))
        b = d.find("b")
        from nettle.nodes import Element
        b.wrap(Element("em"))
        self.assertIn("<em><b>", str(d))
        b.decompose()
        self.assertNotIn("<b>", str(d))

    def test_document_shortcuts_and_lists(self):
        d = parse("<html><head><title>T</title></head><body><ul><li>a</li></ul></body></html>")
        self.assertEqual(d.title, "T")
        self.assertEqual(d.head.tag, "head")
        self.assertEqual(d.body.tag, "body")
        self.assertEqual(d.lists(), [["a"]])

    def test_attr_without_css_reads_self(self):
        r = parse('<article data-id="7"><h3>t</h3></article>').extract(
            {"items": {"select": "article", "each": {"id": {"attr": "data-id"}}}})
        self.assertEqual(r["items"][0]["id"], "7")

    def test_nested_table_rows_not_mixed(self):
        html = ('<table><tr><th>Outer</th></tr>'
                '<tr><td><table><tr><th>In</th></tr><tr><td>x</td></tr></table></td></tr></table>')
        self.assertEqual(len(parse(html).table("table")), 1)

    def test_script_serialize_unescaped(self):
        self.assertEqual(
            str(parse('<script>if (a<b && c>d) f("x");</script>')),
            '<script>if (a<b && c>d) f("x");</script>',
        )


class TestHttpAuditFixes(unittest.TestCase):
    def test_requote_uri(self):
        from nettle.http import _requote_uri
        self.assertEqual(_requote_uri("https://x.com/a b"), "https://x.com/a%20b")
        u = _requote_uri("https://ja.wikipedia.org/wiki/東京都")
        self.assertTrue(u.startswith("https://ja.wikipedia.org/wiki/%E6%9D%B1"))
        self.assertEqual(_requote_uri("https://x.com/already%20quoted"), "https://x.com/already%20quoted")

    def test_gzip_decode(self):
        from nettle.http import _decode_body
        raw = _gzip.compress('{"ok": true}'.encode())
        self.assertEqual(_decode_body(raw, "gzip"), b'{"ok": true}')
        self.assertEqual(_decode_body(b"plain", ""), b"plain")

    def test_registry_defaults_apply_to_request(self):
        registry.http["retries"] = 0
        registry.http["timeout"] = 0.001
        try:
            from nettle import request
            t0 = time.perf_counter()
            with self.assertRaises(exceptions.FetchError):
                request("GET", "https://httpbin.org/delay/5")  # would take >5s if ignored
            self.assertLess(time.perf_counter() - t0, 4.0)
        finally:
            registry.reset()

    def test_response_history_and_raise(self):
        from nettle.http import Response
        r = Response(url="u", status=404, headers={}, body=b"", history=("a", "b"))
        self.assertEqual(r.history, ("a", "b"))
        with self.assertRaises(exceptions.FetchError):
            r.raise_for_status()
        Response(url="u", status=200, headers={}, body=b"").raise_for_status()

    def test_session_verify_and_proxies(self):
        s = Session(verify=False, proxies={"https": "http://127.0.0.1:1"})
        self.assertFalse(s.verify)
        self.assertEqual(s.proxies["https"], "http://127.0.0.1:1")
        self.assertIsNotNone(s.cookies)  # inspectable cookiejar

    def test_excel_safe_csv(self):
        out = to_csv([{"c": '=CMD("del")'}], excel_safe=True)
        self.assertIn("'=CMD", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
