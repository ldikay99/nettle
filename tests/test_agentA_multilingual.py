"""Agent-A: offline multilingual battery — 12 real pages in 10+ languages,
plus legacy single-byte/multi-byte encodings (EUC-KR, BIG5, windows-1256,
KOI8-R, GB2312) generated from real content. Verifies: no mojibake, titles
extract, links/select work, RTL intact.
"""
import os
import sys
import unittest

sys.path.insert(0, ".")

import nettle
from nettle import parse

FIX = os.path.join(os.path.dirname(__file__), "fixtures")

# fixture -> (language, must-appear-in-text substrings, title substring or None)
CASES = [
    ("wiki_ja.html", "ja", ["東京都"], "東京都"),
    ("wiki_zh.html", "zh", ["爬虫", "维基"], None),
    ("wiki_ko.html", "ko", ["크롤러"], None),
    ("wiki_ar.html", "ar", ["ويكيبيديا", "الويب"], None),
    ("wiki_ru.html", "ru", ["скрейпинг"], "Веб-скрейпинг"),
    ("wiki_hi.html", "hi", ["विकिपीडिया"], "विकिपीडिया"),
    ("wiki_th.html", "th", ["ประเทศไทย"], None),
    ("vnexpress_vi.html", "vi", ["VnExpress"], None),
    ("elpais_es.html", "es", ["España", "EL PAÍS"], None),
    ("uol_pt.html", "pt", ["UOL"], None),
    ("asahi_ja.html", "ja", ["朝日新聞"], None),
    ("aljazeera_ar.html", "ar", ["الجزيرة"], None),
]

LEGACY_CASES = [
    # fixture, declared encoding, language, sample text that must survive
    ("legacy_euckr_ko.html", "euc-kr", "ko", "크롤러"),
    ("legacy_big5_zh.html", "big5", "zh", "爬蟲"),
    ("legacy_gb2312_zh.html", "gb2312", "zh", "爬虫"),
    ("legacy_cp1256_ar.html", "windows-1256", "ar", "الويب"),
    ("legacy_koi8r_ru.html", "koi8-r", "ru", "скрейпинг"),
]


class TestMultilingualUtf8(unittest.TestCase):
    def _doc(self, name):
        with open(os.path.join(FIX, name), encoding="utf-8") as f:
            return parse(f.read())

    def test_titles_and_text_no_mojibake(self):
        langs = set()
        for name, lang, needles, title_part in CASES:
            with self.subTest(fixture=name):
                doc = self._doc(name)
                langs.add(lang)
                text = doc.get_text()
                self.assertGreater(len(text), 500, "content too small — fixture or parse broke")
                for needle in needles:
                    self.assertIn(needle, text)
                if title_part:
                    self.assertIn(title_part, doc.title or "")
                links = doc.select("a[href]")
                self.assertGreater(len(links), 3)
                urls = doc.urls()
                self.assertGreater(len(urls), len(links) - 5)
        self.assertGreaterEqual(len(langs), 9)

    def test_extract_schema_works_per_language(self):
        for name, lang, needles, _ in CASES[:6]:
            with self.subTest(fixture=name):
                doc = self._doc(name)
                data = doc.extract({
                    "title": "title",
                    "canonical": {"css": 'link[rel="canonical"]', "attr": "href"},
                    "first_links": {"css": "a[href]", "all": True, "attr": "href"},
                })
                self.assertTrue(data["title"])
                self.assertIsInstance(data["first_links"], list)


class TestLegacyEncodings(unittest.TestCase):
    def test_detect_charset_from_meta(self):
        from nettle.parse import detect_charset
        for name, enc, _, _ in LEGACY_CASES:
            with self.subTest(fixture=name):
                raw = open(os.path.join(FIX, name), "rb").read()
                self.assertEqual(detect_charset(raw), enc)

    def test_parse_bytes_decodes_correctly(self):
        for name, enc, lang, sample in LEGACY_CASES:
            with self.subTest(fixture=name):
                raw = open(os.path.join(FIX, name), "rb").read()
                doc = parse(raw)
                text = doc.get_text()
                # no mojibake markers (replacement chars / control junk)
                self.assertNotIn("\ufffd", text[:3000],
                                 f"replacement chars: {enc} decode failed")
                self.assertIn(sample, text)
                self.assertIsNotNone(doc.title)

    def test_explicit_encoding_override(self):
        raw = open(os.path.join(FIX, "legacy_koi8r_ru.html"), "rb").read()
        doc = parse(raw, encoding="koi8-r")
        self.assertIn("скрейпинг", doc.get_text())


class TestSpecialPatterns(unittest.TestCase):
    """meta refresh, iframes, lazy-load data-src, inline data: URIs."""

    def setUp(self):
        with open(os.path.join(FIX, "special_boe_es.html"), encoding="utf-8") as f:
            self.doc = nettle.Nettle(f.read(), base_url="https://www.boe.es/")

    def test_title_entities_decoded(self):
        self.assertEqual(
            self.doc.title,
            "BOE.es - Agencia Estatal Boletín Oficial del Estado",
        )

    def test_meta_refresh_url_found(self):
        urls = self.doc.urls()
        self.assertIn("https://www.boe.es/boe/dias/2026/09/17/", urls)

    def test_iframe_src_found(self):
        urls = self.doc.urls()
        self.assertTrue(any("iframe" in u or "buscar" in u for u in urls))
        self.assertTrue(any(u.endswith("/buscar/iframe.php") for u in urls))

    def test_lazy_data_src_found_and_data_uri_skipped(self):
        urls = self.doc.urls()
        self.assertIn("https://www.boe.es/img/logo_largo.png", urls)
        self.assertFalse(any(u.startswith("data:") for u in urls))

    def test_data_api_attr_is_endpoint_candidate(self):
        cands = nettle.sniff_api_candidates(self.doc, base_url="https://www.boe.es/")
        self.assertIn("https://www.boe.es/api/v1/sumario?d=20260917", cands)

    def test_embedded_json_blobs(self):
        blobs = nettle.sniff_embedded_json(self.doc)
        sources = {b["source"] for b in blobs}
        self.assertIn("ld+json", sources)
        # pageData is a registry state-global accelerator -> bare-name source
        self.assertIn("pageData", sources)

    def test_relative_link_absolutized(self):
        a = self.doc.select_one("a[href]")
        self.assertEqual(
            a.abs_url(a.get("href")),
            "https://www.boe.es/boe/dias/2026/09/16/",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
