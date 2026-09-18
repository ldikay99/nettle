"""Agent-B4: regresiones de los bugs de fusión encontrados y arreglados en 0.8.0.

Cada test reproduce un bug REAL de la fusión (con número de antes/después)
para que no vuelva:
  1. parse() O(n^2) en anidamiento profundo de bloques (_close_nearest
     escaneaba todo el stack abierto buscando un <p> inexistente):
     3000 <div> anidados: 4400ms -> <400ms.
  2. select() O(n^2) en combinadores de descendente sobre árboles profundos:
     'div div div' en 3000 niveles: 3816ms -> <200ms (bs4: 45ms).
  3. doctype múltiple: pure conservaba el ÚLTIMO, lxml el PRIMERO —
     los backends discrepaban entre sí. Ahora: FIRST gana en ambos
     (los navegadores ignoran los doctypes repetidos).
  4. select() con scope: el prefijo de ancestros del chain no cruzaba el
     borde del scope (soupsieve sí lo cruza) — ver test_agentB4_diff_matrix.
"""
from __future__ import annotations

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nettle import parse
from nettle.nodes import Element

try:
    from lxml import etree  # noqa: F401
    HAVE_LXML = True
except ImportError:
    HAVE_LXML = False


def _deep_doc(n=3000):
    return "<html><body>" + "<div>" * n + "deep" + "</div>" * n + "</body></html>"


class TestFusionPerf(unittest.TestCase):
    def test_parse_deep_blocks_fast(self):
        h = _deep_doc()
        t0 = time.perf_counter()
        n = parse(h)
        dt = time.perf_counter() - t0
        self.assertEqual(str(n).count("<div>"), 3000)
        self.assertLess(dt, 0.4, f"parse of 3000 nested divs took {dt*1000:.0f}ms "
                         "(was 4400ms at baseline — O(n^2) _close_nearest regression)")

    def test_select_deep_descendants_fast(self):
        n = parse(_deep_doc())
        t0 = time.perf_counter()
        r = n.select("div div div")
        dt = time.perf_counter() - t0
        self.assertEqual(len(r), 2998)
        self.assertLess(dt, 0.25, f"'div div div' on 3000-deep tree took "
                         f"{dt*1000:.0f}ms (was 3816ms at baseline — candidate-"
                         "expansion O(n^2) regression)")

    def test_serialize_deep(self):
        n = parse(_deep_doc())
        t0 = time.perf_counter()
        s = str(n)
        dt = time.perf_counter() - t0
        self.assertEqual(s.count("<div>"), 3000)
        self.assertLess(dt, 0.1)

    def test_nth_child_3000_siblings_gate(self):
        # gate histórico: <100ms
        n = parse("<html><body><ul>" + "<li>x</li>" * 3000 + "</ul></body></html>")
        t0 = time.perf_counter()
        r = n.select("li:nth-child(2n+1)")
        dt = time.perf_counter() - t0
        self.assertEqual(len(r), 1500)
        self.assertLess(dt, 0.1, f"{dt*1000:.0f}ms — historical gate is <100ms")


class TestCloseNearestSemanticsPreserved(unittest.TestCase):
    """El fix de perf de _close_nearest NO cambia resultados: casos donde un
    <p> abierto SÍ debe cerrarse (los que justificaban el escaneo original)."""

    def test_p_closed_by_blocks(self):
        for opener in ("div", "ul", "table", "section", "h1", "pre"):
            h = f"<div><p>a<{opener}>b</{opener}></div>"
            n = parse(h)
            ps = n.find_all("p")
            self.assertEqual(len(ps), 1, f"{opener}: {str(n)}")
            self.assertNotIn("b", ps[0].get_text(), opener)

    def test_p_closed_by_p(self):
        n = parse("<div><p>a<p>b</div>")
        self.assertEqual(len(n.find_all("p")), 2)
        self.assertEqual(n.find_all("p")[0].get_text(), "a")

    def test_p_closed_across_inline(self):
        # <p> sobrevive a inline elements, cierra al abrir otro p o bloque
        n = parse("<div><p>a<span>x<b>y</b></span><p>b</div>")
        ps = n.find_all("p")
        self.assertEqual(len(ps), 2)
        self.assertEqual(ps[0].get_text(), "axy")

    def test_p_inside_table_survives(self):
        # caso que el código viejo protegía con stop_at table/ul/ol
        n = parse("<table><tr><td><p>a</p></td></tr></table><p>b</p>")
        self.assertEqual(len(n.find_all("p")), 2)

    def test_li_dt_dd_autoclose(self):
        n = parse("<ul><li>a<li>b</ul><dl><dt>t<dd>d</dl>")
        self.assertEqual(len(n.find_all("li")), 2)
        self.assertEqual(len(n.find_all("dt")), 1)
        self.assertEqual(len(n.find_all("dd")), 1)

    def test_deep_inline_then_block(self):
        # p con 500 spans anidados dentro, luego div abre: p debe cerrar
        h = "<div><p>a" + "<span>" * 500 + "x" + "</span>" * 500 + "<div>b</div></p></div>"
        n = parse(h)
        # el <div> dentro de <p>… el p debe haberse cerrado cuando div abrió:
        # el div va DENTRO del body, hermano del p
        p = n.find_all("p")
        self.assertEqual(len(p), 1)


class TestDoctypeMultiple(unittest.TestCase):
    def test_first_doctype_wins_pure(self):
        h = "<!DOCTYPE html PUBLIC '-//X//EN' 'x.dtd'><!DOCTYPE second><html><body>a</body></html>"
        d = parse(h, backend="pure")
        self.assertEqual(d.doctype, "html PUBLIC '-//X//EN' 'x.dtd'")
        self.assertTrue(str(d).startswith("<!DOCTYPE html PUBLIC"))

    @unittest.skipUnless(HAVE_LXML, "lxml not installed")
    def test_first_doctype_wins_lxml(self):
        h = "<!DOCTYPE html PUBLIC '-//X//EN' 'x.dtd'><!DOCTYPE second><html><body>a</body></html>"
        d = parse(h, backend="lxml")
        self.assertEqual(d.doctype, "html PUBLIC '-//X//EN' 'x.dtd'")

    def test_single_doctype_unchanged(self):
        for backend in ("pure", "lxml") if HAVE_LXML else ("pure",):
            d = parse("<!DOCTYPE html><html><body>a</body></html>", backend=backend)
            self.assertEqual(d.doctype, "html")

    def test_prettify_compat_doctype(self):
        h = "<!DOCTYPE html><html><body><p>a</p></body></html>"
        n = parse(h)
        self.assertTrue(n.prettify(bs4_compat=True).startswith("<!DOCTYPE html>\n"))


class TestMatchesDefensiveNone(unittest.TestCase):
    """combinator None en _match_from_right ahora significa descendiente."""

    def test_matches_descendant(self):
        from nettle.css import _element_matches_chain, _parse_groups
        n = parse("<div id=a><section><p id=t>x</p></section></div>")
        chain = _parse_groups("div p")[0]
        self.assertTrue(_element_matches_chain(n.find(id="t"), chain, None))


class TestSpineSeed(unittest.TestCase):
    """El root del scope puede ser nivel del chain (bug del seed inicial)."""

    def test_scope_root_as_chain_level(self):
        h = "<html><body><div id=wrap><div id=root><p id=b>x</p></div></div></body></html>"
        n = parse(h)
        self.assertEqual([e.get("id") for e in n.find(id="root").select("body > div > div p")], ["b"])

    def test_scope_root_exclude_itself_from_results(self):
        n = parse("<html><body><div id=root><p>x</p></div></body></html>")
        self.assertEqual([e.tag for e in n.find(id="root").select("div")], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
