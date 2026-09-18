"""Agent-B4: torture fresco de la fusión — inputs adversariales generados.

Combina EN EL MISMO DOCUMENTO: entidades legacy + RCDATA (title/textarea) +
BOMs + UTF-16 sin BOM + anidamiento 3000 + atributos duplicados + namespaces
SVG/math + CDATA + null bytes + template-literals JS con ${} y escapes \\'
+ pre/textarea whitespace + </script> dentro de strings JS.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nettle import parse

try:
    from lxml import etree  # noqa: F401
    HAVE_LXML = True
except ImportError:
    HAVE_LXML = False

BACKENDS = ("pure", "lxml") if HAVE_LXML else ("pure",)


class TestLegacyEntitiesRcdata(unittest.TestCase):
    def test_title_textarea_entities(self):
        for backend in BACKENDS:
            with self.subTest(backend=backend):
                h = ("<html><head><title>Precio &copy 2024 &amp; m&aacute;s</title></head>"
                     "<body><textarea rows=3>Costo &pound 50 &amp;&copy;</textarea>"
                     "<p title='AT&amp;T &copy 2024'>t&copy 2024</p></body></html>")
                n = parse(h, backend=backend)
                self.assertEqual(n.title, "Precio © 2024 & más")
                self.assertEqual(n.find("textarea").get_text(), "Costo £ 50 &©")
                self.assertEqual(n.find("p").get("title"), "AT&T © 2024")
                self.assertEqual(n.find("p").get_text(), "t© 2024")

    def test_rcdata_serialization_roundtrip(self):
        h = "<html><head><title>A &amp; B &lt;tag&gt;</title></head><body><textarea>A &amp; B &lt;x&gt; &copy;</textarea></body></html>"
        for backend in BACKENDS:
            with self.subTest(backend=backend):
                n = parse(h, backend=backend)
                # RCDATA: entidades decodificadas al parsear, re-escapadas al serializar
                self.assertEqual(n.find("title").get_text(), "A & B <tag>")
                self.assertEqual(str(n.find("title")), "<title>A &amp; B &lt;tag&gt;</title>")
                self.assertEqual(str(n.find("textarea")), "<textarea>A &amp; B &lt;x&gt; ©</textarea>")

    def test_title_nested_lookalike_not_parsed(self):
        h = "<html><head><title>a <b> not parsed</b> </title></head><body>y</body></html>"
        for backend in BACKENDS:
            with self.subTest(backend=backend):
                n = parse(h, backend=backend)
                self.assertEqual(len(n.find_all("b")), 0)


class TestBomsAndUtf16(unittest.TestCase):
    def test_boms(self):
        for bom, enc in [(b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le"),
                         (b"\xfe\xff", "utf-16-be")]:
            with self.subTest(enc=enc):
                raw = bom + "<html><body><p>café naïve 東京</p></body></html>".encode(enc)
                n = parse(raw)
                self.assertEqual(n.find("p").get_text(), "café naïve 東京")

    def test_utf16_no_bom_heuristic(self):
        for enc in ("utf-16-le", "utf-16-be"):
            with self.subTest(enc=enc):
                raw = "<html><body><p>café 東京</p></body></html>".encode(enc)
                n = parse(raw)
                self.assertEqual(n.find("p").get_text(), "café 東京")

    def test_utf32_not_misdetected(self):
        # UTF-32 tiene NULs en AMBAS paridades — la heurística no debe disparar
        raw = "<html><body><p>x</p></body></html>".encode("utf-32-le")
        # (sin BOM y sin meta, decodifica como utf-8 con replace → basura,
        # pero NUNCA debe crashear ni confundirse con utf-16)
        n = parse(raw)
        self.assertIsNotNone(n)


class TestDeepNestingAndAttrs(unittest.TestCase):
    def test_3000_levels_all_backends(self):
        h = "<html><body>" + "<div>" * 3000 + "deep" + "</div>" * 3000 + "</body></html>"
        for backend in BACKENDS:
            with self.subTest(backend=backend):
                n = parse(h, backend=backend)
                self.assertEqual(str(n).count("<div>"), 3000)

    def test_duplicate_attrs_first_wins(self):
        h = "<html><body><p id='first' id='second' class='a' class='b'>x</p></body></html>"
        for backend in BACKENDS:
            with self.subTest(backend=backend):
                n = parse(h, backend=backend)
                self.assertEqual(n.find("p").get("id"), "first")  # regla HTML5
                self.assertEqual(n.find("p").get("class"), "a")

    def test_svg_math_namespaces(self):
        h = ("<html><body><svg viewBox='0 0 10 10' xmlns='http://www.w3.org/2000/svg'>"
             "<circle cx='5' cy='5' r='4'/><path d='M0 0L10 10'/></svg>"
             "<math xmlns='http://www.w3.org/1998/Math/MathML'><mi>x</mi></math></body></html>")
        for backend in BACKENDS:
            with self.subTest(backend=backend):
                n = parse(h, backend=backend)
                self.assertEqual(len(n.select("svg circle")), 1)
                self.assertEqual(len(n.select("*|circle")), 1)
                self.assertEqual(len(n.select("mi")), 1)

    def test_cdata_and_null_bytes(self):
        h = "<html><body><![CDATA[ raw <b>not-parsed</b> ]]>after<p>null\x00byte</p></body></html>"
        n = parse(h, backend="pure")
        self.assertIn("null\x00byte", n.find("p").get_text())
        # no crashea, árbol consultable
        self.assertIsNotNone(n.find("body"))

    def test_3000_siblings(self):
        h = "<html><body><ul>" + "".join(f"<li data-i='{i}'>{i}</li>" for i in range(3000)) + "</ul></body></html>"
        for backend in BACKENDS:
            with self.subTest(backend=backend):
                n = parse(h, backend=backend)
                self.assertEqual(len(n.select("li:nth-child(2n+1)")), 1500)
                self.assertEqual(len(n.select("li:last-child")), 1)
                self.assertEqual(len(n.select("li + li")), 2999)


class TestScriptTorture(unittest.TestCase):
    def test_template_literals_and_escapes(self):
        h = ("<html><head><script>var x = `template ${'a' + \"b\"}`;"
             " var y = 'it\\'s'; var z = 1;</script>"
             "<script type='application/json'>{\"k\": \"v &amp; w\"}</script>"
             "</head><body><p>ok</p></body></html>")
        n = parse(h, backend="pure")
        scripts = n.find_all("script")
        self.assertEqual(len(scripts), 2)
        self.assertIn("`template ${'a' + \"b\"}`", scripts[0].get_text())
        self.assertIn("\\'s", scripts[0].get_text())

    def test_script_close_tag_inside_string(self):
        # '</script>' dentro de un string JS corta el script — como los navegadores
        h = ("<html><head><script>var s = '</scr' + 'ipt>';\n"
             "var t = \"</script> en string\"; var u = 2;</script></head>"
             "<body><p>x</p></body></html>")
        n = parse(h, backend="pure")
        scripts = n.find_all("script")
        self.assertEqual(len(scripts), 1)
        # corta en el </script> DENTRO del string — como los navegadores y bs4;
        # lo que sigue queda como texto suelto tras el script
        self.assertEqual(scripts[0].get_text(), "var s = '</scr' + 'ipt>';\nvar t = \"")
        self.assertNotIn("var u = 2;", scripts[0].get_text())

    def test_style_and_script_raw_serialize(self):
        h = "<html><head><style>a > b { content: '<' }</style><script>if (a < b && c > d) x</script></head><body></body></html>"
        n = parse(h, backend="pure")
        self.assertEqual(str(n.find("style")), "<style>a > b { content: '<' }</style>")
        self.assertEqual(str(n.find("script")), "<script>if (a < b && c > d) x</script>")


class TestPreTextareaWhitespace(unittest.TestCase):
    def test_whitespace_preserved(self):
        h = ("<html><body><pre>  line1\n  line2\ttab  </pre>"
             "<textarea>  keep\n  ws  </textarea></body></html>")
        n = parse(h, backend="pure")
        self.assertEqual(n.find("pre").get_text(), "  line1\n  line2\ttab  ")
        self.assertEqual(n.find("textarea").get_text(), "  keep\n  ws  ")

    def test_get_text_compat_preserves_pre(self):
        h = "<html><body><p>a</p>  <pre>  x\n  </pre></body></html>"
        n = parse(h, backend="pure")
        # el pre se preserva; el whitespace-only FUERA del pre colapsa como bs4
        self.assertEqual(n.get_text(bs4_compat=True), "a   x\n  ")  # == bs4


class TestCombinedTortureDoc(unittest.TestCase):
    def _doc(self):
        parts = ["<!DOCTYPE html><html><head><meta charset='utf-8'>"
                 "<title>T&iacute;tulo &copy 2024</title>",
                 "<script>var cfg = {url: 'https://x/api?a=1&copy=2', tpl: `${x}`};</script>",
                 "<style>a[href$='.com']::after { content: '&copy'; }</style></head><body>"]
        for i in range(200):
            parts.append(
                f"<div class='row r{i%7}' id='row{i}' data-v='&amp;v{i}'>"
                f"<p class='a'>texto {i} &copy 2024 &amp; more</p>"
                f"<a href='/item/{i}?x=1&copy=2&y=&amp;z'>link {i}</a>"
                f"<img src='i{i}.png' srcset='i{i}@2x.png 2x' alt='img {i}' loading='lazy'>"
                "</div>")
        parts.append("<svg viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'>"
                     "<circle cx='50' cy='50' r='40' fill='red'/></svg>")
        parts.append("<ul>" + "".join(f"<li data-i='{i}'>item {i}</li>" for i in range(100)) + "</ul>")
        parts.append("<textarea>code &lt;div&gt; &amp; &copy; keep</textarea>")
        parts.append("<script>var tpl = `x${y}z`; var esc = 'q\\'w';</script>")
        parts.append("</body></html>")
        return "".join(parts)

    def test_torture_backends_agree(self):
        h = self._doc()
        n1 = parse(h, backend="pure")
        n2 = parse(h, backend="lxml")

        def sig(el):
            return (el.tag, tuple(sorted(el.attrs.items())), el.get_text(bs4_compat=True))
        self.assertEqual(n1.title, n2.title, "Título © 2024")
        self.assertEqual([sig(e) for e in n1.select("div.row")],
                         [sig(e) for e in n2.select("div.row")])
        self.assertEqual([sig(e) for e in n1.select("ul li:nth-child(3n)")],
                         [sig(e) for e in n2.select("ul li:nth-child(3n)")])

    def test_torture_selects(self):
        n = parse(self._doc(), backend="pure")
        self.assertEqual(len(n.select("div.row p.a")), 200)
        self.assertEqual(len(n.select("a[href*='copy=2']")), 200)  # URL intacta
        self.assertEqual(len(n.select("ul li:nth-child(2n+1)")), 50)
        self.assertEqual(len(n.select("svg circle[fill='red']")), 1)
        self.assertEqual(len(n.select("textarea")), 1)
        self.assertEqual(n.select_one("textarea").get_text(), "code <div> & © keep")
        # JS intacto dentro del script
        self.assertIn("`${x}`", n.find_all("script")[0].get_text())
        self.assertIn("'q\\'w'", n.find_all("script")[-1].get_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
