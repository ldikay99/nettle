"""Tests for the high-level Nettle API."""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nettle import parse, Nettle, Document, Element


class TestAPI(unittest.TestCase):
    def test_parse_returns_document(self):
        doc = parse("<p>x</p>")
        self.assertIsInstance(doc, Document)

    def test_nettle_alias(self):
        n = Nettle("<div class='q'><span>hi</span></div>")
        self.assertEqual(n.select_one("div.q span").text, "hi")
        self.assertEqual(len(n.select("span")), 1)

    def test_el_attrs_access(self):
        doc = parse('<div class="a b" id="d1" data-n="9"></div>')
        el = doc.select_one("#d1")
        self.assertEqual(el["class"], "a b")
        self.assertEqual(el.attrs["id"], "d1")
        self.assertEqual(el.get("data-n"), "9")
        self.assertIsNone(el.get("missing"))
        self.assertIn("class", el)

    def test_children_descendants(self):
        doc = parse("<div><p>a</p><p>b<span>c</span></p></div>")
        div = doc.find("div")
        self.assertEqual(len(div.children), 2)
        descs = list(div.descendants)
        self.assertGreaterEqual(len(descs), 4)

    def test_find_find_all(self):
        doc = parse("<div><a href='1'>a</a><a href='2'>b</a><span>c</span></div>")
        div = doc.find("div")
        self.assertEqual(div.find("a")["href"], "1")
        self.assertEqual(len(div.find_all("a")), 2)
        self.assertIsNone(div.find("table"))

    def test_find_with_attrs(self):
        doc = parse('<p class="x">1</p><p class="y">2</p>')
        el = doc.find("p", class_="y")
        self.assertEqual(el.text, "2")

    def test_html_property(self):
        doc = parse('<p class="t">z</p>')
        p = doc.find("p")
        self.assertEqual(p.html, str(p))
        self.assertIn("z", p.html)

    def test_bytes_input(self):
        n = Nettle(b"<p>bytes</p>")
        self.assertEqual(n.find("p").text, "bytes")

    def test_select_one_none(self):
        doc = parse("<p></p>")
        self.assertIsNone(doc.select_one("div.missing"))


if __name__ == "__main__":
    unittest.main()
