"""Agent-A: regression tests for bugs found in the real-world battery.

Bug #1 (found live on https://www.boe.es/): <title>/<textarea> are RCDATA
per HTML5 — entities must be decoded. nettle 0.6.0 shipped them raw
('Bolet&iacute;n' mojibake).
"""
import sys
import unittest

sys.path.insert(0, ".")

import nettle
from nettle import parse


class TestRcdataEntityDecoding(unittest.TestCase):
    def test_title_entities_decoded(self):
        doc = parse("<html><head><title>Bolet&iacute;n &amp; m&aacute;s</title></head></html>")
        self.assertEqual(doc.title, "Boletín & más")

    def test_textarea_entities_decoded(self):
        doc = parse("<html><body><textarea>Tom&aacute;s &lt;consulta&gt;</textarea></body></html>")
        self.assertEqual(doc.select_one("textarea").get_text(), "Tomás <consulta>")

    def test_numeric_entities_in_title(self):
        doc = parse("<title>&#x4eac;&#37117;</title>")
        self.assertEqual(doc.title, "京都")

    def test_script_stays_raw(self):
        doc = parse("<script>if (a &amp;&amp; b) { x = '</div>'; }</script>")
        body = doc.select_one("script").get_text()
        self.assertIn("&amp;&amp;", body, "script must keep entities untouched")

    def test_style_stays_raw(self):
        doc = parse("<style>a::before { content: '&amp;'; }</style>")
        self.assertIn("&amp;", doc.select_one("style").get_text())

    def test_serialize_round_trip_escapes_rcdata(self):
        html = "<title>a &amp; b</title><textarea>x &lt; y</textarea>"
        doc = parse(html)
        out = str(doc)
        # re-parse the serialization: entities must survive the round trip
        doc2 = parse(out)
        self.assertEqual(doc2.title, "a & b")
        self.assertEqual(doc2.select_one("textarea").get_text(), "x < y")

    def test_real_world_boe_pattern(self):
        with open("tests/fixtures/special_boe_es.html", encoding="utf-8") as f:
            doc = parse(f.read())
        self.assertIn("Boletín Oficial", doc.title)
        # description meta also entity-decoded via attribute decoding
        meta = doc.find("meta", attrs={"name": "description"})
        self.assertIn("Boletín", meta.get("content"))


class TestSerializationRegression(unittest.TestCase):
    def test_textarea_child_text_is_escaped_on_serialize(self):
        doc = parse("<textarea>1 &lt; 2</textarea>")
        self.assertIn("&lt;", str(doc))

    def test_title_child_text_is_escaped_on_serialize(self):
        doc = parse("<title>R&amp;D</title>")
        self.assertIn("&amp;", str(doc))


class TestUnicodeUrlFetchRegression(unittest.TestCase):
    """nettle must accept unicode (IRI) URLs everywhere — found while
    battery-testing ja/zh/ko/ar wiki pages with unicode paths."""

    def test_requote_uri_handles_unicode_path(self):
        from nettle.http import _requote_uri
        out = _requote_uri("https://ja.wikipedia.org/wiki/東京都")
        self.assertEqual(out, "https://ja.wikipedia.org/wiki/%E6%9D%B1%E4%BA%AC%E9%83%BD")
        # already-escaped URLs untouched
        out2 = _requote_uri("https://ja.wikipedia.org/wiki/%E6%9D%B1")
        self.assertEqual(out2, "https://ja.wikipedia.org/wiki/%E6%9D%B1")


class TestClassifyUrlRealWorld(unittest.TestCase):
    def test_youtube_internal_api(self):
        self.assertEqual(
            nettle.classify_url("https://www.youtube.com/youtubei/v1/player?key=1"),
            "api",
        )

    def test_twitch_gql(self):
        self.assertEqual(nettle.classify_url("https://gql.twitch.tv/gql"), "api")

    def test_wikipedia_static(self):
        self.assertEqual(
            nettle.classify_url("https://en.wikipedia.org/static/favicon.ico"),
            "asset",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
