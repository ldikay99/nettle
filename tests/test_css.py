"""Tests for the CSS selector engine."""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nettle import parse


HTML = """
<html>
<body id="top">
  <div class="wrap main" data-x="1">
    <p class="intro" id="p1">Hello</p>
    <ul>
      <li class="item">one</li>
      <li class="item active">two</li>
      <li class="item">three</li>
    </ul>
    <a href="https://example.com/page">link</a>
    <a href="/relative">rel</a>
    <span class="note">n</span>
    <div class="box"><span>inner</span></div>
  </div>
  <p class="outro">bye</p>
</body>
</html>
"""


class TestCSSSelectors(unittest.TestCase):
    def setUp(self):
        self.doc = parse(HTML)

    def test_tag(self):
        self.assertEqual(len(self.doc.select("li")), 3)

    def test_star(self):
        self.assertGreater(len(self.doc.select("*")), 5)

    def test_id(self):
        el = self.doc.select_one("#p1")
        self.assertIsNotNone(el)
        self.assertEqual(el.tag, "p")

    def test_class(self):
        self.assertEqual(len(self.doc.select(".item")), 3)
        self.assertEqual(len(self.doc.select(".active")), 1)

    def test_tag_class(self):
        self.assertEqual(len(self.doc.select("li.item")), 3)
        self.assertEqual(len(self.doc.select("li.active")), 1)

    def test_tag_id(self):
        self.assertEqual(self.doc.select_one("p#p1").text, "Hello")

    def test_descendant(self):
        self.assertEqual(len(self.doc.select("div.wrap li")), 3)
        self.assertEqual(len(self.doc.select("ul span")), 0)

    def test_child(self):
        self.assertEqual(len(self.doc.select("ul > li")), 3)
        self.assertEqual(len(self.doc.select("div.wrap > li")), 0)
        self.assertEqual(len(self.doc.select("div.wrap > p")), 1)

    def test_adjacent(self):
        # p.intro + ul
        els = self.doc.select("p.intro + ul")
        self.assertEqual(len(els), 1)
        self.assertEqual(els[0].tag, "ul")

    def test_sibling(self):
        els = self.doc.select("p.intro ~ a")
        self.assertGreaterEqual(len(els), 1)

    def test_attr_exists(self):
        self.assertEqual(len(self.doc.select("[href]")), 2)

    def test_attr_equals(self):
        self.assertEqual(len(self.doc.select('[href="/relative"]')), 1)

    def test_attr_prefix(self):
        self.assertEqual(len(self.doc.select('[href^="https"]')), 1)

    def test_attr_suffix(self):
        self.assertEqual(len(self.doc.select('[href$="page"]')), 1)

    def test_attr_contains(self):
        self.assertEqual(len(self.doc.select('[href*="example"]')), 1)

    def test_attr_word(self):
        self.assertEqual(len(self.doc.select('[class~="active"]')), 1)
        self.assertEqual(len(self.doc.select('[class~="main"]')), 1)

    def test_first_child(self):
        els = self.doc.select("li:first-child")
        self.assertEqual(len(els), 1)
        self.assertEqual(els[0].text, "one")

    def test_last_child(self):
        els = self.doc.select("li:last-child")
        self.assertEqual(len(els), 1)
        self.assertEqual(els[0].text, "three")

    def test_nth_child(self):
        els = self.doc.select("li:nth-child(2)")
        self.assertEqual(len(els), 1)
        self.assertEqual(els[0].text, "two")

    def test_nth_odd_even(self):
        odds = self.doc.select("li:nth-child(odd)")
        evens = self.doc.select("li:nth-child(even)")
        self.assertEqual(len(odds), 2)
        self.assertEqual(len(evens), 1)

    def test_not(self):
        els = self.doc.select("li:not(.active)")
        self.assertEqual(len(els), 2)

    def test_comma(self):
        els = self.doc.select("p.intro, p.outro")
        self.assertEqual(len(els), 2)

    def test_matches(self):
        el = self.doc.select_one("li.active")
        self.assertTrue(el.matches("li.item"))
        self.assertTrue(el.matches(".active"))
        self.assertFalse(el.matches("p"))

    def test_multi_class(self):
        self.assertEqual(len(self.doc.select("div.wrap.main")), 1)


if __name__ == "__main__":
    unittest.main()
