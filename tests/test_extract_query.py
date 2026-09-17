"""Tests for extract / query DSL."""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nettle import parse, extract, fields, records, values, to_json


FIXTURE = """
<html><body>
<div class="quote">
  <span class="text">"Hello&nbsp;world"</span>
  <small class="author">  Einstein  </small>
  <div class="tags">
    <a class="tag" href="/tag/change/">change</a>
    <a class="tag" href="/tag/deep/">deep</a>
  </div>
</div>
<div class="quote">
  <span class="text">Second</span>
  <small class="author">Rowling</small>
</div>
</body></html>
"""


class TestExtractSchema(unittest.TestCase):
    def test_each(self):
        doc = parse(FIXTURE)
        data = doc.extract({
            "quotes": {
                "select": "div.quote",
                "each": {
                    "text": {"css": "span.text", "clean": "plain"},
                    "author": {"css": "small.author", "clean": "plain"},
                    "tags": {"css": "div.tags a.tag", "all": True, "clean": "plain"},
                },
            }
        })
        self.assertEqual(len(data["quotes"]), 2)
        self.assertEqual(data["quotes"][0]["author"], "Einstein")
        self.assertNotIn("\xa0", data["quotes"][0]["text"])
        self.assertEqual(data["quotes"][0]["tags"], ["change", "deep"])
        self.assertEqual(data["quotes"][1]["tags"], [])

    def test_shorthand(self):
        doc = parse(FIXTURE)
        data = extract(doc, {"author": "small.author"})
        self.assertEqual(data["author"], "Einstein")

    def test_attr_abs(self):
        doc = parse(FIXTURE)
        doc.base_url = "https://quotes.toscrape.com/"
        data = doc.extract({
            "hrefs": {"css": "a.tag", "attr": "href", "all": True, "abs": True}
        })
        self.assertTrue(data["hrefs"][0].startswith("https://"))

    def test_record_values(self):
        doc = parse(FIXTURE)
        q = doc.select_one("div.quote")
        rec = q.record({
            "text": {"css": "span.text", "clean": "plain"},
            "author": "small.author",
        })
        self.assertEqual(rec["author"], "Einstein")
        self.assertEqual(q.values("small.author"), "Einstein")

    def test_fields_records(self):
        doc = parse(FIXTURE)
        rows = records(doc, "div.quote", {
            "author": {"css": "small.author", "clean": "plain"},
        })
        self.assertEqual(len(rows), 2)


if __name__ == "__main__":
    unittest.main()
