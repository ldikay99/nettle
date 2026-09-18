"""Agent-B round 3: CSS escape support (soupsieve parity) — pure nettle.

Escape grammar implemented in nettle/css.py:
  \\<char>   → that char (\: \. \+ \( \  …) in tags/classes/ids/attr names
  \\<hex>{1,6} + one optional ws → codepoint (\3A  → ':')
  \ at EOF   → empty (no error — soupsieve behavior)
  ns|tag / *|tag / |tag — namespace syntax on namespace-less documents
Strictness: unquoted attribute values must be identifiers (soupsieve rule).
"""

from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from nettle import SelectorError, parse

DOC = parse(
    "<er:custom class='x y'>A</er:custom>"
    "<a class='btn primary'>B</a>"
    "<a class='btn.primary'>C</a>"
    "<div id='we:ird'>D</div>"
    "<span data:weird='1' class='foo+bar'>E</span>"
    "<p class='x y'>F</p>"
    "<a href='/a(b)'>paren</a>"
)


class TestEscapedIdents(unittest.TestCase):
    def test_escaped_colon_tag(self):
        self.assertEqual([el.tag for el in DOC.select(r"er\:custom")], ["er:custom"])

    def test_escaped_colon_tag_case_insensitive(self):
        self.assertEqual([el.tag for el in DOC.select(r"ER\:CUSTOM")], ["er:custom"])

    def test_hex_escape_in_tag(self):
        self.assertEqual([el.tag for el in DOC.select(r"er\3A custom")], ["er:custom"])
        self.assertEqual([el.tag for el in DOC.select(r"\65 r\:custom")], ["er:custom"])
        self.assertEqual([el.tag for el in DOC.select(r"\73 pan")], ["span"])

    def test_dotted_class(self):
        self.assertEqual([el.get_text() for el in DOC.select(r"a.btn\.primary")], ["C"])
        self.assertEqual([el.get_text() for el in DOC.select(r".btn\.primary")], ["C"])

    def test_plain_class_unaffected(self):
        self.assertEqual(len(DOC.select("a.btn")), 1)  # 'btn primary', not 'btn.primary'

    def test_escaped_plus_class(self):
        self.assertEqual([el.tag for el in DOC.select(r".foo\+bar")], ["span"])

    def test_escaped_dot_makes_part_of_ident(self):
        # span\.foo\+bar is a TAG named 'span.foo+bar' — matches nothing
        self.assertEqual(DOC.select(r"span\.foo\+bar"), [])

    def test_escaped_colon_id(self):
        self.assertEqual([el.tag for el in DOC.select(r"#we\:ird")], ["div"])
        self.assertEqual([el.tag for el in DOC.select(r"div#we\:ird")], ["div"])

    def test_escaped_space_class(self):
        # '.x\ y' asks for the single token "x y" — class lists split on
        # whitespace, so this can never match (bs4/soupsieve agree: [])
        self.assertEqual(DOC.select(r".x\ y"), [])

    def test_nonexistent_escaped_class(self):
        self.assertEqual(DOC.select(r".x\:y"), [])
        self.assertEqual(DOC.select(r"a\.btn"), [])


class TestEscapedAttributes(unittest.TestCase):
    def test_attr_name_colon(self):
        self.assertEqual([el.tag for el in DOC.select(r"[data\:weird]")], ["span"])
        self.assertEqual(
            [el.tag for el in DOC.select(r"[data\:weird='1']")], ["span"]
        )

    def test_attr_name_hex_colon(self):
        self.assertEqual([el.tag for el in DOC.select(r"[data\3a weird]")], ["span"])

    def test_quoted_value_escapes(self):
        self.assertEqual([el.tag for el in DOC.select(r"[href='/a\(b\)']")], ["a"])
        self.assertEqual([el.tag for el in DOC.select(r'[href="/a\28 b\29"]')], ["a"])
        self.assertEqual([el.tag for el in DOC.select(r'a[href^="/a\("]')], ["a"])

    def test_attr_namespace_forms(self):
        self.assertEqual(len(DOC.select("[*|class]")), DOC.select("[class]").__len__())
        self.assertEqual(len(DOC.select("[|class]")), len(DOC.select("[class]")))
        self.assertEqual(DOC.select("[ns|class]"), [])  # no namespace → no match

    def test_unquoted_values_must_be_idents(self):
        for bad in (r"[href^=/]", r"[data-x=1]", r"a[href==3]", r"[href*=/a(]"):
            with self.subTest(selector=bad):
                with self.assertRaises(SelectorError):
                    DOC.select(bad)


class TestTagNamespaces(unittest.TestCase):
    def test_star_namespace_matches(self):
        self.assertEqual(len(DOC.select("*|span")), len(DOC.select("span")))

    def test_named_namespace_never_matches(self):
        self.assertEqual(DOC.select("svg|circle"), [])
        self.assertEqual(DOC.select("er|custom"), [])

    def test_empty_namespace_never_matches(self):
        # soupsieve parity on html.parser (no element carries a namespace)
        self.assertEqual(DOC.select("|span"), [])

    def test_star_then_ident_is_error(self):
        with self.assertRaises(SelectorError):
            DOC.select(r"*\.x")
        with self.assertRaises(SelectorError):
            DOC.select("*span")


class TestEscapeEdges(unittest.TestCase):
    def test_lone_and_trailing_backslash_no_error(self):
        # soupsieve returns [] for both — no exception
        self.assertEqual(DOC.select("\\"), [])
        self.assertEqual(DOC.select(r"a\.b\\"), [])

    def test_zero_and_surrogate_replacement(self):
        doc = parse("<p>a</p>")
        # \0 → U+FFFD (never a NUL byte in the parsed selector)
        self.assertEqual(doc.select(r"p\0 "), [])
        self.assertEqual(doc.select(r"\fffffffd "), [])  # > 0x10FFFF → FFFD

    def test_id_digit_start_lenience(self):
        doc = parse("<a id='5x'>L</a>")
        self.assertEqual([el.tag for el in doc.select("#5x")], ["a"])

    def test_escapes_inside_functional_pseudos(self):
        doc = parse(
            "<er:custom class='x'>A</er:custom>"
            "<a class='btn.primary'>C</a>"
            "<section><er:custom class='nested'>G</er:custom></section>"
        )
        self.assertEqual(
            [el.tag for el in doc.select(r":is(er\:custom, section)")],
            ["er:custom", "section", "er:custom"],
        )
        self.assertEqual(len(doc.select(r":not(er\:custom)")), 2)
        self.assertEqual([el.tag for el in doc.select(r"section:has(er\:custom)")], ["section"])

    def test_matches_with_escapes(self):
        self.assertTrue(DOC.select_one("#we\:ird").matches(r"div#we\:ird"))
        self.assertFalse(DOC.select_one("span").matches(r"er\:custom"))

    def test_find_still_works_unescaped(self):
        # pre-existing find() path for namespaced tags keeps working
        doc = parse("<er:custom class='x'>A</er:custom>")
        self.assertIsNotNone(doc.find("er:custom"))
        self.assertEqual(doc.find("er:custom").get_text(), "A")


if __name__ == "__main__":
    unittest.main()
