"""Tests for nettle.text cleaning."""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nettle.text import (
    clean_text, collapse_ws, decode_entities, remove_invisible,
    normalize_unicode, strip_noise,
)


class TestDecodeEntities(unittest.TestCase):
    def test_named(self):
        self.assertEqual(decode_entities("a&amp;b"), "a&b")
        self.assertEqual(decode_entities("&lt;x&gt;"), "<x>")
        self.assertEqual(decode_entities("&nbsp;"), "\u00a0")
        self.assertEqual(decode_entities("&euro;"), "\u20ac")
        self.assertEqual(decode_entities("&eacute;"), "\u00e9")

    def test_numeric(self):
        self.assertEqual(decode_entities("&#39;"), "'")
        self.assertEqual(decode_entities("&#x27;"), "'")
        self.assertEqual(decode_entities("&#160;"), "\u00a0")

    def test_optional_semicolon(self):
        self.assertEqual(decode_entities("a&nbsp;b"), "a\u00a0b")


class TestCleanText(unittest.TestCase):
    def test_plain_nbsp_and_ws(self):
        s = "  Hello\u00a0\u00a0world  "
        self.assertEqual(clean_text(s, mode="plain"), "Hello world")

    def test_plain_entities(self):
        self.assertEqual(clean_text("A&nbsp;B&amp;C", mode="plain"), "A B&C")

    def test_invisible(self):
        s = "a\u200b\ufeffb"
        self.assertEqual(clean_text(s), "ab")

    def test_keep_newlines(self):
        s = "a  \n\n\n  b\t\tc"
        out = clean_text(s, mode="keep_newlines")
        self.assertIn("\n", out)
        self.assertEqual(out.split("\n")[0], "a")

    def test_strict(self):
        s = "ok\x00bad"
        self.assertEqual(clean_text(s, mode="strict"), "okbad")

    def test_raw(self):
        self.assertEqual(clean_text("&amp;", mode="raw"), "&")

    def test_none_mode(self):
        self.assertEqual(clean_text("  x  ", mode="none"), "  x  ")

    def test_none_input(self):
        self.assertEqual(clean_text(None), "")


class TestHelpers(unittest.TestCase):
    def test_collapse(self):
        self.assertEqual(collapse_ws("a   b"), "a b")

    def test_remove_invisible(self):
        self.assertEqual(remove_invisible("a\u200bb"), "ab")

    def test_normalize(self):
        # composed vs decomposed e+acute
        self.assertEqual(normalize_unicode("e\u0301"), "\u00e9")

    def test_strip_noise(self):
        self.assertEqual(strip_noise("a\u200bb"), "ab")


if __name__ == "__main__":
    unittest.main()
