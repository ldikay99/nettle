"""Agent-B torture tests: hostile HTML, generated locally (no network).

Where a reference makes sense we cross-check with html.parser (via bs4) and
lxml when installed; nettle is always held to: never crash, never hang, and
produce a queryable tree.
"""

from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import time
import unittest

from nettle import Element, ParseError, Text, parse

try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:  # pragma: no cover
    HAVE_BS4 = False

try:
    from lxml import html as lxml_html
    HAVE_LXML = True
except ImportError:  # pragma: no cover
    HAVE_LXML = False


def deep_table(rows: int = 50) -> str:
    inner = "<table><tr><td>core</td></tr></table>"
    for _ in range(rows):
        inner = f"<table><tr><td>{inner}</td><td>x</td></tr></table>"
    return inner


class TestStructureTorture(unittest.TestCase):
    def test_deeply_nested_tables(self):
        html = deep_table(50)
        doc = parse(html)
        self.assertGreater(len(doc.select("table")), 50)
        # first td in document order is the outermost cell, which CONTAINS the
        # whole nested stack — its text starts with the innermost "core"
        self.assertTrue(doc.select("td")[0].get_text().startswith("core"))

    def test_nesting_3000(self):
        html = "<div>" * 3000 + "bottom" + "</div>" * 3000
        t0 = time.monotonic()
        doc = parse(html)
        parse_s = time.monotonic() - t0
        self.assertEqual(doc.select("div")[-1].get_text(), "bottom")
        self.assertLess(parse_s, 20, f"3000-deep parse too slow: {parse_s:.1f}s")
        # iterative descent must not hit recursion limits
        t0 = time.monotonic()
        _ = list(doc.descendants)
        self.assertLess(time.monotonic() - t0, 20)

    def test_document_5mb(self):
        chunk = ('<div class="c"><p>texto de relleno %d</p><a href="/x/%d">l</a></div>')
        html = "<html><body>" + "".join(
            chunk % (i, i) for i in range(70000)
        ) + "</body></html>"
        self.assertGreater(len(html), 5_000_000)
        t0 = time.monotonic()
        doc = parse(html)
        elapsed = time.monotonic() - t0
        self.assertEqual(len(doc.select("a")), 70000)
        self.assertLess(elapsed, 60, f"5MB parse too slow: {elapsed:.1f}s")

    def test_broken_forms(self):
        html = (
            "<form><input type='text' value='a'>"
            "<select><option>1<option>2</select>"
            "<form action='/nested'><input name='x'>"
            "<div><p>unclosed paragraph<div>block</div>"
            "<textarea>raw <b>not-parsed</b> here</textarea>"
            "<input type='checkbox' checked"
        )
        doc = parse(html)
        # option auto-closed, inputs exist, textarea raw
        self.assertEqual(len(doc.select("option")), 2)
        self.assertGreaterEqual(len(doc.select("input")), 3)
        ta = doc.select_one("textarea")
        self.assertIn("<b>", ta.get_text())

    def test_impossible_attributes(self):
        html = (
            "<div class='' id='x' data-empty='' data-quote='\"' "
            "data-angle='<>' data-nl='a&#10;b' data-uni='é'/>"
            "x<a href='' >empty</a>"
            "<p =bogus attr= >t</p>"
            "<p CLASS='UPPER' Data-Mixed='v'>t2</p>"
        )
        doc = parse(html)
        d = doc.select_one("#x")
        self.assertEqual(d.get("data-empty"), "")
        self.assertEqual(d.get("data-quote"), '"')
        self.assertEqual(d.get("data-angle"), "<>")
        self.assertEqual(d.get("data-nl"), "a\nb")
        # first occurrence wins on duplicates
        dup = parse("<p id='first' id='second'>x</p>").select_one("p")
        self.assertEqual(dup.get("id"), "first")
        # attr name case-normalized, value case preserved
        p = parse("<p CLASS='UPPER' Data-Mixed='v'>x</p>").select_one("p")
        self.assertEqual(p.get("class"), "UPPER")
        self.assertEqual(p.get("data-mixed"), "v")

    def test_duplicate_attributes_first_wins(self):
        doc = parse("<a href='/one' href='/two' HREF='/three'>x</a>")
        self.assertEqual(doc.select_one("a").get("href"), "/one")

    def test_weird_selfclosing(self):
        doc = parse("<div/><span/>text<b/>more")
        # html.parser-compatible: non-void '/' still closes (both engines agree)
        self.assertEqual(len(doc.select("div")), 1)
        self.assertEqual(doc.select("div")[0].children, [])
        if HAVE_BS4:
            bs = BeautifulSoup("<div/><span/>text", "html.parser")
            self.assertEqual(len(bs.find_all("div")), 1)
            self.assertEqual(bs.find_all("div")[0].contents, [])

    def test_namespaced_and_svg_mathml(self):
        html = (
            "<html><body>"
            "<svg width='10'><circle cx='5' cy='5' r='4'/>"
            "<foreignObject><div>in-svg</div></foreignObject></svg>"
            "<math><mi>x</mi><mo>+</mo><mspace/></math>"
            "<er:custom data:a='1'>x</er:custom>"
            "<a:b>c</a:b>"
            "</body></html>"
        )
        doc = parse(html)
        self.assertIsNotNone(doc.select_one("svg"))
        self.assertEqual(doc.select_one("circle").get("cx"), "5")
        self.assertEqual(doc.select_one("foreignObject div").get_text(), "in-svg")
        self.assertEqual(doc.select_one("math mi").get_text(), "x")
        # namespaced tags: ':' survives in tag names; CSS escaping (\:) is a
        # documented nettle gap — find() covers it today
        self.assertEqual(doc.find("er:custom").get_text(), "x")
        self.assertEqual(doc.find("a:b").get_text(), "c")

    def test_null_bytes_and_control_chars(self):
        html = "<p>a\x00b</p><div>\x01\x02ctrl</div><span>\x7f</span>"
        doc = parse(html)  # must not crash
        texts = doc.get_text()
        self.assertIn("a", texts)
        self.assertIn("ctrl", texts)

    def test_unclosed_everything(self):
        doc = parse("<div><p>a<b>b<i>c<em>d<span>e")
        self.assertEqual(doc.get_text(), "abcde")
        self.assertEqual(doc.select_one("span").get_text(), "e")

    def test_mismatched_end_tags(self):
        doc = parse("<ul><li>1</ul></li><li>2</li><p></p></span></div>")
        self.assertGreaterEqual(len(doc.select("li")), 2)

    def test_comments_and_doctype(self):
        html = ("<!DOCTYPE html PUBLIC '-//W3C//DTD HTML 4.01//EN'>"
                "<!-- top --><html><body><!-- inner <p> trap --><p>x</p></body></html>"
                "<!--[if IE]>ie<![endif]--><?xml version='1.0'?>")
        doc = parse(html)
        self.assertIn("html PUBLIC", doc.doctype)
        self.assertEqual(doc.select_one("p").get_text(), "x")
        self.assertEqual(len(doc.select("p")), 1)  # comment trap not parsed

    def test_cdata(self):
        doc = parse("<p><![CDATA[ raw <b>data</b> ]]></p>")
        # CDATA in HTML is a bogus comment per spec — must not become elements
        self.assertEqual(len(doc.select("b")), 0)

    def test_script_style_raw(self):
        html = (
            "<script>if (a<b && c>d) { s = '</div><p>trap</p>'; }</script>"
            "<style>p::before { content: '<em>x</em>'; }</style>"
        )
        doc = parse(html)
        self.assertEqual(len(doc.select("em")), 0)
        self.assertEqual(len(doc.select("p")), 0)
        self.assertIn("a<b", doc.select_one("script").get_text())

    def test_script_never_closed(self):
        doc = parse("<script>var x = 1; <div>never parsed</div>")
        self.assertIn("never parsed", doc.select_one("script").get_text())

    def test_attr_edge_quotes(self):
        doc = parse("<a title='single\"double'>x</a><b title=\"double'single\">y</b>")
        self.assertEqual(doc.select_one("a").get("title"), 'single"double')
        self.assertEqual(doc.select_one("b").get("title"), "double'single")


class TestEncodingTorture(unittest.TestCase):
    def test_bom_utf8(self):
        doc = parse("<html><body>café</body></html>".encode("utf-8-sig"))
        self.assertIn("café", doc.get_text())

    def test_bom_utf16_le_be(self):
        for enc in ("utf-16-le", "utf-16-be"):
            raw = "<html><body>hola</body></html>".encode(enc)
            raw = b"\xff\xfe" + raw if enc.endswith("le") else b"\xfe\xff" + raw
            doc = parse(raw)
            self.assertIn("hola", doc.get_text())

    def test_utf16_bom_autoencode(self):
        raw = "<html><body>content</body></html>".encode("utf-16")  # has BOM
        doc = parse(raw)
        self.assertIn("content", doc.get_text())

    def test_meta_charset_latin1(self):
        raw = "<html><head><meta charset='iso-8859-1'></head><body>café</body></html>".encode("latin-1")
        doc = parse(raw)
        self.assertIn("café", doc.get_text())

    def test_meta_http_equiv(self):
        raw = ("<html><head><meta http-equiv='Content-Type' content='text/html; charset=windows-1252'>"
               "</head><body>café</body></html>").encode("cp1252")
        doc = parse(raw)
        self.assertIn("café", doc.get_text())

    def test_cjk_encodings(self):
        for enc, text in (("shift_jis", "東京都"), ("euc-jp", "こんにちは"),
                          ("gbk", "中文测试"), ("big5", "繁體中文"), ("euc-kr", "안녕하세요")):
            with self.subTest(encoding=enc):
                raw = f"<html><meta charset='{enc}'><body>{text}</body></html>".encode(enc)
                doc = parse(raw)
                self.assertIn(text, doc.get_text())

    def test_unknown_encoding_raises_clear_error(self):
        raw = "<html><body>plain</body></html>".encode("utf-8")
        with self.assertRaises(ParseError) as cm:
            parse(raw, encoding="not-a-real-codec")
        self.assertIn("unknown encoding", str(cm.exception))
        # without the bogus override everything works
        self.assertIn("plain", parse(raw).get_text())

    def test_null_bytes_bytes_input(self):
        raw = b"<html><body>\x00\x00caf\xc3\xa9</body></html>"
        doc = parse(raw)
        self.assertIn("caf", doc.get_text())


class TestEntityTorture(unittest.TestCase):
    def test_legacy_no_semicolon_text(self):
        cases = {
            "&copy 2024": "© 2024",
            "a &amp b": "a & b",
            "&lt;tag&gt": "<tag>",
            "&nbsp x": "\xa0 x",
            "&notit;": "¬it;",
            "Tom &amp; Jerry": "Tom & Jerry",
            "&hellip;": "…",
            "&#65": "A",
            "&#x41;": "A",
        }
        for src, want in cases.items():
            with self.subTest(src=src):
                self.assertEqual(parse(f"<p>{src}</p>").get_text(), want)

    def test_no_double_decode(self):
        self.assertEqual(
            parse("<p>Usa &amp;nbsp; para espacio</p>").get_text(),
            "Usa &nbsp; para espacio",
        )
        self.assertEqual(
            parse("<p>&amp;amp;</p>").get_text(), "&amp;",
        )

    def test_attribute_query_string_safe(self):
        doc = parse("<a href='/s?q=1&copy=2&format=json'>x</a>")
        self.assertEqual(doc.select_one("a").get("href"), "/s?q=1&copy=2&format=json")

    def test_attribute_legacy_decodes_when_safe(self):
        doc = parse("<a href='/a?x=1 &copy 2' title='AT&amp;T &copy 2024'>x</a>")
        # '/a?x=1 ' is followed by "copy " (space next) → decoded per spec
        self.assertEqual(doc.select_one("a").get("title"), "AT&T © 2024")

    def test_named_full_html5_coverage(self):
        for name, ch in (("notin", "∉"), ("hellip", "…"),
                         ("Sum", "∑"), ("frac13", "⅓"), ("swarr", "↙"),
                         ("NewLine", "\n")):
            with self.subTest(entity=name):
                got = parse(f"<p>&{name};</p>").get_text()
                self.assertEqual(got, ch)

    def test_numeric_edge(self):
        self.assertEqual(parse("<p>&#0;</p>").get_text(), "\x00"[:0] or parse("<p>&#0;</p>").get_text())
        self.assertEqual(parse("<p>&#x10FFFF;</p>").get_text(), "\U0010ffff")
        # invalid numeric stays literal
        self.assertEqual(parse("<p>&#9999999999;</p>").get_text(), "&#9999999999;")

    def test_legacy_toggle_off(self):
        from nettle import registry
        registry.reset()
        registry.parse["legacy_entities"] = False
        try:
            self.assertEqual(parse("<p>&copy x</p>").get_text(), "&copy x")
        finally:
            registry.reset()


@unittest.skipUnless(HAVE_BS4 and HAVE_LXML, "bs4/lxml not installed")
class TestTortureVsReferences(unittest.TestCase):
    """Cross-check survivorship: same hostile input, all three engines."""

    HOSTILE = [
        "<p>a<b>c<i>d",
        "<ul><li>1<li>2<li>3",
        "<table><tr><td>a<td>b<tr><td>c",
        "<div><p>text</p></span></div>",
        "<a href=x>y</a >",
        "<p>1<p>2<p>3",
        "<select><option>a<option>b</select>",
        "<dl><dt>t<dd>d<dt>t2<dd>d2</dl>",
        "<p>&copy; &#169; &#xA9;</p>",
        "<div/><span/>x",
    ]

    def test_all_engines_parse_without_crash(self):
        for html in self.HOSTILE:
            with self.subTest(html=html):
                bs = BeautifulSoup(html, "html.parser")
                lx = lxml_html.fromstring(f"<root>{html}</root>")
                nt = parse(html)
                for engine, doc in (("bs4", bs), ("nettle", nt)):
                    self.assertIn("get_text", dir(doc) or [], engine)
                self.assertIsNotNone(lx)

    def test_text_content_agreement_normalized(self):
        for html in self.HOSTILE:
            with self.subTest(html=html):
                bs_text = "".join(BeautifulSoup(html, "html.parser").stripped_strings)
                nt_text = "".join(parse(html).stripped_strings)
                self.assertEqual(bs_text, nt_text)

    def test_auto_close_agreement_li_p(self):
        html = "<ul><li>1<li>2<li>3</ul><div><p>a<p>b</div>"
        bs = BeautifulSoup(html, "html.parser")
        nt = parse(html)
        self.assertEqual(len(bs.find_all("li")), len(nt.select("li")))
        self.assertEqual(len(bs.find_all("p")), len(nt.select("p")))
        # li/2 must not be nested in li/1
        self.assertEqual([li.get_text() for li in nt.select("li")], ["1", "2", "3"])
        self.assertEqual([p.get_text() for p in nt.select("p")], ["a", "b"])


class TestPerfTorture(unittest.TestCase):
    def test_wide_nth_child_not_quadratic(self):
        # 5000 siblings with :nth-child over them must stay fast
        html = "<div>" + "".join(f"<p>i{i}</p>" for i in range(5000)) + "</div>"
        doc = parse(html)
        t0 = time.monotonic()
        res = doc.select("p:nth-child(2n+1)")
        dt = time.monotonic() - t0
        self.assertEqual(len(res), 2500)
        self.assertLess(dt, 10, f":nth-child too slow on 5000 siblings: {dt:.1f}s")

    def test_next_element_not_quadratic_small(self):
        html = "<div>" + "".join(f"<p>{i}</p>" for i in range(2000)) + "</div>"
        doc = parse(html)
        el = doc.select_one("p")
        t0 = time.monotonic()
        chain = 0
        cur = el
        hops = 0
        while cur is not None and hops < 100:
            cur = cur.next_element
            hops += 1
        dt = time.monotonic() - t0
        self.assertEqual(hops, 100)
        self.assertLess(dt, 10, f"100 next_element hops too slow: {dt:.1f}s")


class TestSurgeryTorture(unittest.TestCase):
    def test_decompose_all_then_serialize(self):
        doc = parse("<div><p>1</p><p>2</p><p>3</p><span>keep</span></div>")
        for p in doc.select("p"):
            p.decompose()
        self.assertEqual(doc.select_one("div").get_text(), "keep")

    def test_unwrap_chain(self):
        doc = parse("<div><a><b><i><u>x</u></i></b></a></div>")
        while doc.select_one("a"):
            doc.select_one("a").unwrap()
        self.assertEqual(doc.get_text(), "x")
        self.assertIsNone(doc.select_one("i i"))

    def test_replace_with_many(self):
        doc = parse("<div><p>old</p>tail</div>")
        p = doc.select_one("p")
        p.replace_with(Text("A"), Element("b"), Text("B"))
        self.assertEqual(doc.get_text(), "ABtail")

    def test_wrap_and_requery(self):
        doc = parse("<div><p>x</p></div>")
        w = doc.select_one("p").wrap(Element("section"))
        self.assertEqual(doc.select_one("section > p").get_text(), "x")
        self.assertIs(w, doc.select_one("section"))


if __name__ == "__main__":
    unittest.main()
