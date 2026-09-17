"""Tests for format + table."""

import unittest
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nettle import parse, to_json, to_csv, to_tsv, to_dicts, pretty
from nettle.table import parse_table


class TestFormat(unittest.TestCase):
    def test_to_json_utf8(self):
        s = to_json({"n": "café"}, ensure_ascii=False)
        self.assertIn("café", s)
        json.loads(s)

    def test_to_csv(self):
        rows = [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}]
        csv = to_csv(rows)
        self.assertIn("a,b", csv)
        self.assertIn("1,x", csv)

    def test_to_tsv(self):
        self.assertIn("\t", to_tsv([{"a": "1", "b": "2"}]))

    def test_to_dicts_unwrap(self):
        self.assertEqual(to_dicts({"items": [{"a": 1}]}), [{"a": 1}])

    def test_list_cell(self):
        csv = to_csv([{"tags": ["a", "b"]}])
        self.assertIn("a|b", csv)


class TestTable(unittest.TestCase):
    def test_basic(self):
        doc = parse("""
        <table id="t">
          <tr><th>Name</th><th>Age</th></tr>
          <tr><td>Ada</td><td>36</td></tr>
          <tr><td>Grace</td><td>85</td></tr>
        </table>
        """)
        rows = doc.table("table#t")
        self.assertEqual(rows[0]["Name"], "Ada")
        self.assertEqual(len(rows), 2)

    def test_colspan(self):
        doc = parse("""
        <table>
          <tr><th>A</th><th>B</th><th>C</th></tr>
          <tr><td colspan="2">xy</td><td>z</td></tr>
        </table>
        """)
        rows = doc.table("table")
        self.assertEqual(rows[0]["A"], "xy")
        self.assertEqual(rows[0]["B"], "xy")
        self.assertEqual(rows[0]["C"], "z")

    def test_nbsp_cleaned(self):
        doc = parse("<table><tr><th>H</th></tr><tr><td>a&nbsp;b</td></tr></table>")
        rows = doc.table()
        self.assertEqual(rows[0]["H"], "a b")


if __name__ == "__main__":
    unittest.main()
