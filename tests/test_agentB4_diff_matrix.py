"""Agent-B4: harness diferencial AMPLIADO — subsistemas combinados, matriz pure vs lxml.

Nuevo en esta ronda (sobre test_agentB_diff_bs4.py):
  * ≥30 casos que combinan escapes CSS + :has relativo + :is anidado en la
    MISMA consulta, comparados contra bs4+soupsieve reales.
  * Matriz de backends: los selectores del harness original corren en
    parse(backend="pure") y parse(backend="lxml") y deben dar lo mismo.
  * get_text/prettify(bs4_compat) sobre árboles lxml.
  * find_next familia tras cirugía (decompose/unwrap/replace_with/wrap).
  * copy.copy + unwrap + re-serializar.
  * Entidades legacy + escapes CSS sobre valores de atributos resultantes.
  * select con scope: prefijos de ancestros cruzan el borde (paridad soupsieve).

La comparación usa firmas canónicas (tag + attrs con class normalizada a
tokens) para no confundir diferencias de SERIALIZACIÓN (bs4 reordena attrs,
nettle no) con diferencias de SELECCIÓN.
"""
from __future__ import annotations

import copy as copy_mod
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

bs4 = None
try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:  # pragma: no cover
    HAVE_BS4 = False

from nettle import Element, parse

try:
    from test_agentB_diff_bs4 import DOC as BASE_DOC, SELECTORS as BASE_SELECTORS
except ImportError:  # pragma: no cover - direct execution from tests dir
    from test_agentB_diff_bs4 import DOC as BASE_DOC, SELECTORS as BASE_SELECTORS

DOC = """<html><head><title>T&amp;co</title></head><body>
<div id='main' class='wrap box' data-x='Hello World'>
<p class='a'>one <b>bold</b> two</p>
<p class='b'>three</p>
<ul><li>l1</li><li class='sel'>l2</li><li>l3</li></ul>
<section><article class='a c'>art1</article><article class='b'>art2</article></section>
<a href='/x?a=1&copy=2'>q</a>
<a href="https://ex.com/y?u=nam&amp;e">ext</a>
<div class="btn.primary">dotted</div>
<er:custom data-weird='1'>ns</er:custom>
<svg viewBox='0 0 10 10'><circle cx='5' cy='5' r='4'/></svg>
</div><footer>foot</footer></body></html>"""

# Documento SIN la URL con &copy= (evita la divergencia intencional #6 de la
# tabla del README: bs4 corrompe '?a=1&copy=2' a '©=2' y los selectores de
# substring sobre ese atributo divergen por el ÁRBOL, no por el motor).
DOC_SAFE = DOC.replace("/x?a=1&copy=2", "/x?a=1&amp;z=2")


def _sig(el):
    """Firma canónica: tag + attrs (class como tokens) + texto."""
    if el is None:
        return None
    tag = getattr(el, "tag", None) or getattr(el, "name", None)
    # bs4 trata class/rel/rev/accept-charset/headers/accesskey como
    # multi-valued (listas); nettle guarda strings — se normaliza a tokens
    _MULTI = ("class", "rel", "rev", "accept-charset", "headers", "accesskey")
    attrs = {}
    for k, v in (el.attrs or {}).items():
        if isinstance(v, list):
            attrs[k] = tuple(v) if v else ()
        elif k in _MULTI:
            attrs[k] = tuple(str(v).split())
        else:
            attrs[k] = v
    return (tag, tuple(sorted(attrs.items())), el.get_text("|", strip=True))


def _sigs(els):
    return [_sig(e) for e in els]


@unittest.skipUnless(HAVE_BS4, "bs4 not installed")
class TestCrossSubsystemSelect(unittest.TestCase):
    """Escapes + :has relativo + :is anidado + entidades en la MISMA consulta."""

    COMBOS = [
        # escapes + :has relativo + :is — la zona fusionada de css.py
        "div:has(> p + p)",
        "div:has(p):has(ul > li.sel)",
        "section:has(> article + article)",
        "div:is(.wrap, .zzz)",
        ":is(div, section):has(> :is(p, article))",
        ":where(div, section):has(article:not(.b))",
        "div:not(:has(svg))",
        "div:not(:has(> ul li.sel))",
        ".btn\\.primary",
        "[data-x='Hello World']:has(+ ul)",
        "div:has(> .btn\\.primary)",
        "div:has(p.a b)",
        "div:has(~ footer)",
        "p:has(+ p)",
        "ul:has(> li:nth-child(2n+1))",
        "div > :is(p, ul, section) + :is(ul, section)",
        "body :is(div p, ul li).sel",
        "[data-x='hello world' i]:has(+ ul)",
        "div:is([data-x='Hello World']) ul li:not(.sel)",
        "section article:not(:first-child)",
        "*|div:has(er\\:custom)",
        "[data\\-x]",
        "div:has(er\\:custom)",
        "er\\:custom",
        "*|circle",
        "svg circle",
        "li:nth-child( 2n + 1 )",
        "li:nth-last-child(-n+2)",
        "div:has(> :is(.btn\\.primary, .nope))",
        ":is(.btn\\.primary, .sel)",
    ]

    def test_combos_match_bs4(self):
        b = BeautifulSoup(DOC_SAFE, "html.parser")
        n = parse(DOC_SAFE)
        for sel in self.COMBOS:
            with self.subTest(sel=sel):
                self.assertEqual(
                    _sigs(n.select(sel)), _sigs(b.select(sel)),
                    f"selector diverged: {sel}",
                )

    def test_combos_pure_vs_lxml_identical(self):
        np = parse(DOC_SAFE, backend="pure")
        nl = parse(DOC_SAFE, backend="lxml")
        for sel in self.COMBOS:
            with self.subTest(sel=sel):
                self.assertEqual(_sigs(np.select(sel)), _sigs(nl.select(sel)),
                                 f"backend divergence: {sel}")


@unittest.skipUnless(HAVE_BS4, "bs4 not installed")
class TestScopedSelectParity(unittest.TestCase):
    """soupsieve: el prefijo de ancestros del chain puede cruzar el scope."""

    def test_ancestor_prefix_crosses_scope(self):
        h = "<div id=outer><p id=a>1</p><div id=root><p id=b>2</p><p id=c>3</p></div></div>"
        b = BeautifulSoup(h, "html.parser")
        n = parse(h)
        for sel in ("#outer p", "div p", "body p" if False else "div p"):
            with self.subTest(sel=sel):
                self.assertEqual(
                    [e.get("id") for e in n.find(id="root").select(sel)],
                    [e.get("id") for e in b.find(id="root").select(sel)],
                )

    def test_multilevel_prefix_outside_scope(self):
        h = "<html><body><div id=wrap><div id=root><p id=b>x</p></div></div></body></html>"
        b = BeautifulSoup(h, "html.parser")
        n = parse(h)
        for sel in ("html p", "body > div p", "body > div > div p"):
            with self.subTest(sel=sel):
                self.assertEqual(
                    [e.get("id") for e in n.find(id="root").select(sel)],
                    [e.get("id") for e in b.find(id="root").select(sel)],
                )

    def test_sibling_never_crosses_scope(self):
        # el primer hijo del scope no tiene hermano previo aunque el scope
        # tenga hermanos — soupsieve está de acuerdo
        h = "<div><p id=a>1</p><div id=root><p id=b>2</p><p id=c>3</p></div></div>"
        b = BeautifulSoup(h, "html.parser")
        n = parse(h)
        self.assertEqual(
            [e.get("id") for e in n.find(id="root").select("p + p")],
            [e.get("id") for e in b.find(id="root").select("p + p")],
        )


@unittest.skipUnless(HAVE_BS4, "bs4 not installed")
class TestCompatOnLxmlTree(unittest.TestCase):
    """get_text/prettify(bs4_compat) sobre árboles construidos con backend=lxml."""

    def test_get_text_compat_lxml(self):
        n = parse(DOC_SAFE, backend="lxml")
        b = BeautifulSoup(DOC_SAFE, "html.parser")
        self.assertEqual(n.get_text(bs4_compat=True), b.get_text())

    def test_get_text_compat_pure(self):
        n = parse(DOC_SAFE, backend="pure")
        b = BeautifulSoup(DOC_SAFE, "html.parser")
        self.assertEqual(n.get_text(bs4_compat=True), b.get_text())

    def test_prettify_compat_lxml(self):
        n = parse(DOC_SAFE, backend="lxml")
        b = BeautifulSoup(DOC_SAFE, "html.parser")
        self.assertEqual(n.prettify(bs4_compat=True), b.prettify())

    def test_prettify_compat_pre_textarea_entities(self):
        h = ("<html><body><pre>  keep\n  ws &amp; &copy;  </pre>"
             "<textarea>code &lt;div&gt; &amp; &copy; keep</textarea>"
             "<a href='/a?x=1&amp;y=2'>l</a><p title='a&amp;b'>t</p></body></html>")
        for backend in ("pure", "lxml"):
            with self.subTest(backend=backend):
                n = parse(h, backend=backend)
                b = BeautifulSoup(h, "html.parser")
                self.assertEqual(n.prettify(bs4_compat=True), b.prettify())
                self.assertEqual(n.get_text(bs4_compat=True), b.get_text())


@unittest.skipUnless(HAVE_BS4, "bs4 not installed")
class TestNavigationAfterSurgery(unittest.TestCase):
    DOC2 = ("<html><body><div><p id='p1'>a</p><p id='p2'>b</p>"
            "<span>s</span><p id='p3'>c</p></div></body></html>")

    def test_find_next_after_decompose(self):
        n = parse(self.DOC2)
        b = BeautifulSoup(self.DOC2, "html.parser")
        n.find("p", id="p2").decompose()
        b.find("p", id="p2").decompose()
        nn, bn = n.find("p", id="p1"), b.find("p", id="p1")
        self.assertEqual(nn.find_next("p").get("id"), bn.find_next("p").get("id"))
        self.assertEqual([e.get("id") for e in nn.find_all_next("p")],
                         [e.get("id") for e in bn.find_all_next("p")])
        self.assertEqual(nn.find_next_sibling().tag, bn.find_next_sibling().name)
        self.assertEqual(nn.find_previous("p"), None)
        self.assertEqual(bn.find_previous("p"), None)

    def test_select_after_decompose_nth(self):
        h = ("<html><body><ul><li id=1>1</li><li id=2>2</li><li id=3>3</li></ul>"
             "<ol><li id=4>4</li></ol></body></html>")
        n = parse(h)
        b = BeautifulSoup(h, "html.parser")
        n.find("li", id="2").decompose()
        b.find("li", id="2").decompose()
        for sel in ("ul > li:nth-child(2)", "li + li", "li:last-child"):
            with self.subTest(sel=sel):
                self.assertEqual([e.get("id") for e in n.select(sel)],
                                 [e.get("id") for e in b.select(sel)])

    def test_find_next_after_unwrap(self):
        n = parse(self.DOC2)
        b = BeautifulSoup(self.DOC2, "html.parser")
        n.find("div").unwrap()
        b.find("div").unwrap()
        nn, bn = n.find("p"), b.find("p")
        self.assertEqual([e.get("id") for e in nn.find_all_next("p")],
                         [e.get("id") for e in bn.find_all_next("p")])
        self.assertEqual(str(n), str(b))

    def test_select_after_wrap_and_replace(self):
        h = "<html><body><ul><li id=1>1</li></ul></body></html>"
        n = parse(h)
        b = BeautifulSoup(h, "html.parser")
        n.find("ul").wrap(Element("section"))
        b.find("ul").wrap(b.new_tag("section"))
        self.assertEqual([e.get("id") for e in n.select("section ul li")],
                         [e.get("id") for e in b.select("section ul li")])
        n.find("li", id="1").replace_with(Element("li", {"id": "9"}))
        b.find("li", id="1").replace_with(b.new_tag("li", attrs={"id": "9"}))
        self.assertEqual([e.get("id") for e in n.select("li")],
                         [e.get("id") for e in b.select("li")])
        # el cache de selectores NO debe servir resultados rancios tras mutar
        self.assertEqual([e.get("id") for e in n.select("section ul li")], ["9"])


@unittest.skipUnless(HAVE_BS4, "bs4 not installed")
class TestCopyUnwrapReserialize(unittest.TestCase):
    def test_copy_clones_and_isolates(self):
        h = "<html><body><div><p id='p1'>a</p><p id='p2'>b</p></div></body></html>"
        n = parse(h)
        b = BeautifulSoup(h, "html.parser")
        nc = copy_mod.copy(n.find("div"))
        bc = copy_mod.copy(b.find("div"))
        self.assertEqual(str(nc), str(bc))
        nc.find("p").decompose()
        bc.find("p").decompose()
        # el original queda intacto en ambos
        self.assertEqual(str(n.find("div")), str(b.find("div")))
        self.assertEqual(len(n.select("p")), len(b.select("p")))

    def test_copy_append_into_tree(self):
        h = "<html><body><div><span>s</span></div></body></html>"
        n = parse(h)
        b = BeautifulSoup(h, "html.parser")
        nn = copy_mod.copy(n.find("span"))
        nnb = copy_mod.copy(b.find("span"))
        n.find("body").append(nn)
        b.find("body").append(nnb)
        self.assertEqual(str(n), str(b))
        # unwrap dentro del árbol copiado + re-serializar
        n2 = parse(h)
        n2.find("div").unwrap()
        self.assertEqual(str(n2), "<html><body><span>s</span></body></html>")


@unittest.skipUnless(HAVE_BS4, "bs4 not installed")
class TestEntitiesWithCssEscapes(unittest.TestCase):
    """Entidades legacy decodificadas + escapes CSS sobre los valores RESULTANTES.

    La divergencia de ÁRBOL en URLs ('?a=1&copy=2' — bs4 la corrompe a '©=2',
    nettle la preserva por la regla de atributo HTML5) está documentada como
    divergencia intencional #6; aquí se verifica el lado nettle y los casos
    donde bs4 NO corrompe.
    """

    def test_url_entities_preserved_and_selectable(self):
        h = ("<html><body><a href='/x?a=1&copy=2&copy;=3'>1</a>"
             "<a href='t?x=&notit;'>2</a>"
             "<a href='u?a=&amp;b=2'>4</a></body></html>")
        n = parse(h)
        # regla de atributo HTML5: &copy=2 y &notit; quedan literales
        self.assertEqual(n.find_all("a")[0].get("href"), "/x?a=1&copy=2©=3")
        self.assertEqual(n.find_all("a")[1].get("href"), "t?x=&notit;")
        # &amp; SIEMPRE decodifica
        self.assertEqual(n.find_all("a")[2].get("href"), "u?a=&b=2")
        # escapes CSS operan sobre el valor DECODIFICADO
        self.assertEqual(len(n.select("a[href='u?a=&b=2']")), 1)
        self.assertEqual(len(n.select("a[href*='copy=2']")), 1)
        self.assertEqual(len(n.select("a[href$='&b=2']")), 1)

    def test_text_legacy_entities(self):
        h = "<p title='AT&T &copy 2024'>t&copy 2024 &notit; &amp;copy</p>"
        n = parse(h)
        b = BeautifulSoup(h, "html.parser")
        # title: ambos decodifican igual (bs4 no corrompe este caso)
        self.assertEqual(n.find("p").get("title"), b.find("p").get("title"))
        # texto: nettle aplica longest-match HTML5 (&notit; → ¬it;)
        self.assertEqual(n.find("p").get_text(), "t© 2024 ¬it; &copy")

    def test_escaped_class_and_attr_names_select(self):
        h = ("<html><body><div class='btn.primary'>d</div>"
             "<div data-weird='1'>w</div></body></html>")
        n = parse(h)
        b = BeautifulSoup(h, "html.parser")
        for sel in (".btn\\.primary", "[class='btn.primary']", "[data\\-weird='1']",
                    "[data\\-weird]", "div\\.nothing"):
            with self.subTest(sel=sel):
                self.assertEqual(_sigs(n.select(sel)), _sigs(b.select(sel)))


@unittest.skipUnless(HAVE_BS4, "bs4 not installed")
class TestBackendMatrixOriginal129(unittest.TestCase):
    """La matriz completa: los selectores del harness original en pure y lxml
    deben devolver exactamente lo mismo (mismo árbol, mismo motor CSS)."""

    def test_matrix_pure_vs_lxml(self):
        np = parse(BASE_DOC, backend="pure")
        nl = parse(BASE_DOC, backend="lxml")
        ran = 0
        for sel in BASE_SELECTORS:
            with self.subTest(sel=sel):
                rp = [str(e) for e in np.select(sel)]
                rl = [str(e) for e in nl.select(sel)]
                self.assertEqual(rp, rl, f"backend divergence on {sel}")
                ran += 1
        self.assertGreater(ran, 50, "expected the full selector corpus")

    def test_matrix_nettle_vs_bs4(self):
        # doc seguro (sin la URL que bs4 corrompe) — paridad completa
        b = BeautifulSoup(BASE_DOC.replace("/x?a=1&copy=2", "/x?z=2"), "html.parser")
        n = parse(BASE_DOC.replace("/x?a=1&copy=2", "/x?z=2"))
        for sel in BASE_SELECTORS:
            with self.subTest(sel=sel):
                self.assertEqual(_sigs(n.select(sel)), _sigs(b.select(sel)),
                                 f"diverged: {sel}")


@unittest.skipUnless(HAVE_BS4, "bs4 not installed")
class TestStringsCompat(unittest.TestCase):
    def test_strings_bs4_compat(self):
        h = ("<html><body><p>alpha</p>\n   <p>beta  gamma</p>  <div>  "
             "<pre>  x\n  </pre></div></body></html>")
        n = parse(h)
        b = BeautifulSoup(h, "html.parser")
        self.assertEqual(list(n.strings(bs4_compat=True)), list(b.strings))
        self.assertEqual(list(n.stripped_strings), list(b.stripped_strings))
        # default: source-faithful (divergencia documentada #3)
        self.assertNotEqual(list(n.strings), list(b.strings))
        self.assertIn("\n   ", list(n.strings))

    def test_strings_registry_default(self):
        from nettle import registry
        h = "<div><p>a</p>\n   <p>b</p></div>"
        n = parse(h)
        b = BeautifulSoup(h, "html.parser")
        try:
            registry.text["strings_bs4_compat"] = True
            self.assertEqual(list(n.strings), list(b.strings))
        finally:
            registry.text["strings_bs4_compat"] = False


if __name__ == "__main__":
    unittest.main(verbosity=2)
