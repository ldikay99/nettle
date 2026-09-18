"""Agent-B round 3: prettify(bs4_compat=True) / get_text(bs4_compat=True)
self-contained invariants (bs4 byte-identity is in test_agentB_diff_bs4.py).

Documents the exact bs4 behaviors replicated:
  * one-space indent, "\n" after every piece, strings .strip()-ed
  * <pre>/<textarea> contents verbatim (string-literal mode)
  * attrs sorted alphabetically, class lists joined with " "
  * void elements as <br/> (minimal formatter slash)
  * quoting: "..." normally, '...' when value has ", &quot; when both
  * whitespace-only runs ("\n  ") collapse to "\n" in get_text compat,
    NOT in prettify-compat text (bs4 strips those runs away entirely)
"""

from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from nettle import parse, registry


class TestPrettifyBs4CompatShape(unittest.TestCase):
    def test_basic_shape(self):
        out = parse("<div><p>hi</p></div>").prettify(bs4_compat=True)
        self.assertEqual(out, "<div>\n <p>\n  hi\n </p>\n</div>\n")

    def test_default_single_space_indent(self):
        out = parse("<a><b><c>x</c></b></a>").prettify(bs4_compat=True)
        self.assertEqual(
            out, "<a>\n <b>\n  <c>\n   x\n  </c>\n </b>\n</a>\n"
        )

    def test_void_slash_and_attr_sort(self):
        out = parse("<img src='b' alt='a' id='z'><br>").prettify(bs4_compat=True)
        self.assertEqual(out, '<img alt="a" id="z" src="b"/>\n<br/>\n')

    def test_attribute_value_quoting(self):
        # value with " only → single quotes; with both → &quot; + double
        out = parse(
            "<a title=\"Bob's\" u='say \"hi\"' b=\"a&quot;b'c\">x</a>"
        ).prettify(bs4_compat=True)
        self.assertIn("title=\"Bob's\"", out)
        self.assertIn("u='say \"hi\"'", out)
        self.assertIn('b="a&quot;b\'c"', out)

    def test_class_value_keeps_source_order(self):
        # bs4 sorts attribute KEYS, never class VALUES: 'b a' stays 'b a'
        out = parse("<p class='b a'>x</p>").prettify(bs4_compat=True)
        self.assertIn('<p class="b a">', out)

    def test_pre_verbatim(self):
        out = parse("<div><pre>keep\n  me</pre></div>").prettify(bs4_compat=True)
        self.assertEqual(out, "<div>\n <pre>keep\n  me</pre>\n</div>\n")

    def test_textarea_verbatim(self):
        out = parse("<textarea>  a\n b  </textarea>").prettify(bs4_compat=True)
        self.assertEqual(out, "<textarea>  a\n b  </textarea>\n")

    def test_script_stripped_indented_not_escaped(self):
        out = parse("<script>if (a<b && c) {}</script>").prettify(bs4_compat=True)
        self.assertEqual(out, "<script>\n if (a<b && c) {}\n</script>\n")

    def test_style_not_escaped(self):
        out = parse("<style>a > b { }</style>").prettify(bs4_compat=True)
        self.assertEqual(out, "<style>\n a > b { }\n</style>\n")

    def test_text_escaped(self):
        out = parse("<p>a &amp; b &lt;c&gt;</p>").prettify(bs4_compat=True)
        self.assertIn("a &amp; b &lt;c&gt;", out)

    def test_comment(self):
        out = parse("<!-- hi --><p>x</p>").prettify(bs4_compat=True)
        self.assertEqual(out, "<!-- hi -->\n<p>\n x\n</p>\n")

    def test_doctype(self):
        out = parse("<!DOCTYPE html><p>x</p>").prettify(bs4_compat=True)
        self.assertTrue(out.startswith("<!DOCTYPE html>\n"))

    def test_whitespace_only_strings_vanish(self):
        out = parse("<div><p>a</p>\n   <p>b</p></div>").prettify(bs4_compat=True)
        self.assertEqual(out, "<div>\n <p>\n  a\n </p>\n <p>\n  b\n </p>\n</div>\n")

    def test_empty_and_ws_only_text_elements(self):
        self.assertEqual(parse("<p> </p>").prettify(bs4_compat=True), "<p>\n</p>\n")
        self.assertEqual(parse("<p></p>").prettify(bs4_compat=True), "<p>\n</p>\n")

    def test_fragment_and_element_forms(self):
        self.assertEqual(parse("<p>x</p>").prettify(bs4_compat=True), "<p>\n x\n</p>\n")
        el = parse("<div><p>x</p></div>").select_one("p")
        self.assertEqual(el.prettify(bs4_compat=True), "<p>\n x\n</p>\n")

    def test_nettle_default_mode_untouched(self):
        # default (compat off): source attr ORDER, <br> (no slash), 2-space
        out = parse("<img src='b' alt='a'><br>").prettify()
        self.assertIn('<img src="b" alt="a">', out)  # order preserved
        self.assertIn("<br>", out)
        self.assertNotIn("<br/>", out)

    def test_registry_default_toggles_compat(self):
        src = "<div><p>hi</p></div>"
        want = "<div>\n <p>\n  hi\n </p>\n</div>\n"
        registry.serialize["prettify_bs4_compat"] = True
        try:
            self.assertEqual(parse(src).prettify(), want)
            self.assertEqual(parse(src).prettify(bs4_compat=False),
                             "<div>\n  <p>hi</p>\n</div>")
        finally:
            registry.serialize["prettify_bs4_compat"] = False

    def test_deep_tree_no_recursion(self):
        html = "<div>" * 400 + "x" + "</div>" * 400
        out = parse(html).prettify(bs4_compat=True)
        self.assertTrue(out.endswith("</div>\n"))
        self.assertEqual(out.count("<div>"), 400)


class TestGetTextBs4Compat(unittest.TestCase):
    def test_whitespace_only_collapse(self):
        html = "<div><p>a</p>  <p>b</p>\n  <p>c</p></div>"
        el = parse(html).select_one("div")
        # bs4: "  " → " ", "\n  " → "\n"
        self.assertEqual(el.get_text("|", bs4_compat=True), "a| |b|\n|c")
        # source preserved by default
        self.assertEqual(el.get_text("|"), "a|  |b|\n  |c")

    def test_pre_not_collapsed(self):
        html = "<pre>a  \n  b</pre>"
        self.assertEqual(
            parse(html).select_one("pre").get_text(bs4_compat=True), "a  \n  b"
        )

    def test_textarea_not_collapsed(self):
        html = "<textarea>x \n y</textarea>"
        self.assertEqual(
            parse(html).select_one("textarea").get_text(bs4_compat=True), "x \n y"
        )

    def test_strip_agrees_both_modes(self):
        html = "<div><p>a</p>  <p>b</p></div>"
        el = parse(html).select_one("div")
        self.assertEqual(
            el.get_text("|", strip=True), el.get_text("|", True, bs4_compat=True)
        )

    def test_registry_flag(self):
        # only WHITESPACE-ONLY runs collapse ("  " between tags → " ");
        # text like "a  " (not all-whitespace) is preserved in both modes
        html = "<div>a<p>b</p>  <i>c</i></div>"
        el = parse(html).select_one("div")
        registry.text["get_text_bs4_compat"] = True
        try:
            self.assertEqual(el.get_text(), "ab c")  # "  " → " " quirk
        finally:
            registry.text["get_text_bs4_compat"] = False
        self.assertEqual(el.get_text(), "ab  c")

    def test_docstring_difference_documented(self):
        import nettle.nodes as nodes_mod
        doc = nodes_mod.Element.get_text.__doc__
        self.assertIn("bs4_compat", doc)
        self.assertIn("whitespace", doc.lower())
        self.assertIn("types=", doc)


if __name__ == "__main__":
    unittest.main()
