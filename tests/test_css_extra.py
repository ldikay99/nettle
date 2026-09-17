"""Extra CSS selector tests: nth-of-type, empty, has, attr|="""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nettle import parse


class TestCSSExtra(unittest.TestCase):
    def test_nth_of_type(self):
        doc = parse("<div><p>a</p><span>s</span><p>b</p><p>c</p></div>")
        els = doc.select("p:nth-of-type(2)")
        self.assertEqual(len(els), 1)
        self.assertEqual(els[0].text, "b")

    def test_first_last_of_type(self):
        doc = parse("<div><p>a</p><span>s</span><p>b</p></div>")
        self.assertEqual(doc.select_one("p:first-of-type").text, "a")
        self.assertEqual(doc.select_one("p:last-of-type").text, "b")

    def test_empty(self):
        doc = parse("<div><p></p><p>x</p><p>  </p></div>")
        empties = doc.select("p:empty")
        self.assertEqual(len(empties), 2)

    def test_has(self):
        doc = parse("<div><section><span class='x'>1</span></section><section>no</section></div>")
        els = doc.select("section:has(.x)")
        self.assertEqual(len(els), 1)

    def test_attr_pipe(self):
        doc = parse('<div lang="en-US"></div><div lang="en"></div><div lang="fr"></div>')
        els = doc.select('[lang|="en"]')
        self.assertEqual(len(els), 2)


class TestSerialize(unittest.TestCase):
    def test_prettify(self):
        doc = parse("<div><p>a</p><p>b</p></div>")
        pretty = doc.prettify()
        self.assertIn("\n", pretty)
        self.assertIn("<div>", pretty)


class TestParseCharset(unittest.TestCase):
    def test_bytes_meta(self):
        from nettle import detect_charset, parse
        raw = b'<meta charset="utf-8"><p>ok</p>'
        self.assertEqual(detect_charset(raw), "utf-8")
        self.assertEqual(parse(raw).find("p").text, "ok")


if __name__ == "__main__":
    unittest.main()
