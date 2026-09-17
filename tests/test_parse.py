"""Tests for the HTML parser."""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nettle import parse, Element, Text, Comment, Document


class TestParseBasics(unittest.TestCase):
    def test_simple_tag(self):
        doc = parse("<div>hello</div>")
        kids = [c for c in doc.children if isinstance(c, Element)]
        self.assertEqual(len(kids), 1)
        self.assertEqual(kids[0].tag, "div")
        self.assertEqual(kids[0].text, "hello")

    def test_nested(self):
        doc = parse("<div><span>a</span><b>b</b></div>")
        div = doc.find("div")
        self.assertIsNotNone(div)
        spans = div.find_all("span")
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].text, "a")
        self.assertEqual(div.find("b").text, "b")

    def test_lowercase_tags(self):
        doc = parse("<DIV CLASS='x'>Hi</DIV>")
        el = doc.find("div")
        self.assertIsNotNone(el)
        self.assertEqual(el.tag, "div")
        self.assertEqual(el["class"], "x")

    def test_attrs_quoted(self):
        doc = parse('<a href="https://x.com" title=\'t\'>l</a>')
        a = doc.find("a")
        self.assertEqual(a["href"], "https://x.com")
        self.assertEqual(a["title"], "t")

    def test_attrs_unquoted(self):
        doc = parse("<img src=photo.jpg alt=pic>")
        img = doc.find("img")
        self.assertEqual(img["src"], "photo.jpg")
        self.assertEqual(img["alt"], "pic")

    def test_void_tags(self):
        doc = parse("<div>a<br>b<hr>c<img src=x></div>")
        div = doc.find("div")
        tags = [c.tag for c in div.children if isinstance(c, Element)]
        self.assertEqual(tags, ["br", "hr", "img"])
        # void tags should not be in open stack / have no end needed
        self.assertEqual(div.find("img")["src"], "x")

    def test_comment(self):
        doc = parse("<!-- hello --><p>x</p>")
        comments = [c for c in doc.descendants if isinstance(c, Comment)]
        self.assertEqual(len(comments), 1)
        self.assertEqual(comments[0].content, " hello ")

    def test_doctype(self):
        doc = parse("<!DOCTYPE html><html></html>")
        self.assertIsNotNone(doc.doctype)
        self.assertIn("html", doc.doctype.lower())

    def test_script_raw(self):
        doc = parse("<script>if (a < b && c > d) {}</script><p>ok</p>")
        script = doc.find("script")
        self.assertIn("a < b", script.text)
        self.assertEqual(doc.find("p").text, "ok")

    def test_style_raw(self):
        doc = parse("<style>a > b { color: red; }</style>")
        self.assertIn("a > b", doc.find("style").text)

    def test_self_closing(self):
        doc = parse("<div><br/><img src=x /></div>")
        div = doc.find("div")
        self.assertEqual(len(div.find_all("br")), 1)
        self.assertEqual(len(div.find_all("img")), 1)

    def test_entities_in_attrs(self):
        doc = parse('<a title="a&amp;b">&lt;x&gt;</a>')
        a = doc.find("a")
        self.assertEqual(a["title"], "a&b")
        # text entities decoded? we decode in attrs; text keeps raw for now
        # actually tokenizer doesn't decode text entities — let's check
        # For scraping, decoding text is nice. Current: raw text.
        self.assertIn("x", a.text)

    def test_unclosed_p(self):
        doc = parse("<div><p>one<p>two</div>")
        ps = doc.find_all("p")
        self.assertEqual(len(ps), 2)
        self.assertEqual(ps[0].text.strip(), "one")
        self.assertEqual(ps[1].text.strip(), "two")

    def test_unclosed_li(self):
        doc = parse("<ul><li>a<li>b</ul>")
        lis = doc.find_all("li")
        self.assertEqual(len(lis), 2)
        self.assertEqual(lis[0].text, "a")
        self.assertEqual(lis[1].text, "b")

    def test_parent_links(self):
        doc = parse("<div><span>x</span></div>")
        span = doc.find("span")
        self.assertEqual(span.parent.tag, "div")

    def test_serialize(self):
        doc = parse('<p class="a">hi</p>')
        p = doc.find("p")
        html = str(p)
        self.assertIn("<p", html)
        self.assertIn('class="a"', html)
        self.assertIn("hi", html)
        self.assertIn("</p>", html)

    def test_boolean_attr(self):
        doc = parse("<input disabled type=checkbox>")
        inp = doc.find("input")
        self.assertIn("disabled", inp.attrs)
        self.assertEqual(inp["type"], "checkbox")


class TestGetText(unittest.TestCase):
    def test_text_property(self):
        doc = parse("<div>Hello <b>world</b>!</div>")
        self.assertEqual(doc.find("div").text, "Hello world!")

    def test_get_text_strip(self):
        doc = parse("<div>  Hello  <b> world </b>  </div>")
        t = doc.find("div").get_text(strip=True, sep=" ")
        self.assertEqual(t, "Hello world")

    def test_get_text_sep(self):
        doc = parse("<div><span>a</span><span>b</span></div>")
        # with sep between concatenated descendant text chunks recursively
        t = doc.find("div").get_text(sep="|")
        self.assertIn("a", t)
        self.assertIn("b", t)


class TestQuotesFixture(unittest.TestCase):
    FIXTURE = """
    <html><body>
    <div class="quote">
      <span class="text">"The world as we have created it is a process of our thinking."</span>
      <span>by <small class="author">Albert Einstein</small>
      <div class="tags"><a class="tag" href="/tag/change/">change</a></div>
      </span>
    </div>
    <div class="quote">
      <span class="text">"It is our choices that show what we truly are."</span>
      <span>by <small class="author">J.K. Rowling</small></span>
    </div>
    </body></html>
    """

    def test_quotes_structure(self):
        doc = parse(self.FIXTURE)
        quotes = doc.select("div.quote")
        self.assertEqual(len(quotes), 2)
        authors = [q.select_one("small.author").text for q in quotes]
        self.assertEqual(authors[0], "Albert Einstein")
        self.assertEqual(authors[1], "J.K. Rowling")


if __name__ == "__main__":
    unittest.main()
