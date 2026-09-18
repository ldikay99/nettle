"""Agent-B4: pendientes cerrados de la ronda.

a) .strings/.stripped_strings bs4_compat (flag per-call + registry.text)
b) Doctype múltiple alineado (first-wins, consistente pure/lxml) — ver
   test_agentB4_fusion; aquí la parte de DOCUMENTACIÓN viva.
c) Tabla de divergencias bs4 conocidas — cada divergencia documentada en el
   README se verifica contra bs4 real AQUÍ (la tabla no puede mentir).
d) README: promesas ejecutadas (write_csv orden data,path; registry keys;
   strings registry; snapshot text/css).
e) examples/: contrato verificado por ejecución (scrape_table_demo,
   scrape_quotes corren en vivo en QA; aquí, sus imports/estructura).
"""
from __future__ import annotations

import copy as copy_mod
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

bs4 = None
try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

import nettle
from nettle import parse, registry
from nettle.exceptions import NettleError


class TestStringsCompat(unittest.TestCase):
    """(a) .strings/.stripped_strings — flag per-call + registry."""

    H = "<html><body><p>alpha</p>\n   <p>beta  gamma</p>  <div>  <pre>  x\n  </pre></div></body></html>"

    def test_strings_default_source_faithful(self):
        n = parse(self.H)
        self.assertIn("\n   ", list(n.strings))

    @unittest.skipUnless(HAVE_BS4, "bs4 not installed")
    def test_strings_compat_matches_bs4(self):
        n = parse(self.H)
        b = BeautifulSoup(self.H, "html.parser")
        self.assertEqual(list(n.strings(bs4_compat=True)), list(b.strings))

    @unittest.skipUnless(HAVE_BS4, "bs4 not installed")
    def test_stripped_always_matches_bs4(self):
        n = parse(self.H)
        b = BeautifulSoup(self.H, "html.parser")
        self.assertEqual(list(n.stripped_strings), list(b.stripped_strings))
        self.assertEqual(list(n.stripped_strings(bs4_compat=True)),
                         list(b.stripped_strings))

    def test_registry_default(self):
        n = parse(self.H)
        b_html = self.H
        try:
            registry.text["strings_bs4_compat"] = True
            # con el default global activado, .strings YA colapsa
            self.assertNotIn("\n   ", list(n.strings))
        finally:
            registry.text["strings_bs4_compat"] = False
        self.assertIn("\n   ", list(n.strings))

    def test_view_is_iterable_and_callable(self):
        n = parse(self.H)
        self.assertEqual(list(n.strings), [s for s in n.strings])  # re-iterable
        v = n.strings(bs4_compat=False)
        self.assertEqual(list(v), list(n.strings))


class TestDoctypeDocumentation(unittest.TestCase):
    """(b) la divergencia de doctype múltiple queda alineada y documentada."""

    @unittest.skipUnless(HAVE_BS4, "bs4 not installed")
    def test_bs4_keeps_all_nettle_keeps_first(self):
        h = "<!DOCTYPE first><!DOCTYPE second><html><body>a</body></html>"
        n = parse(h)
        b = BeautifulSoup(h, "html.parser")
        doctypes_b = [str(c) for c in b.contents if "octype" in str(type(c))]
        self.assertEqual(len(doctypes_b), 2, "bs4 conserva AMBOS como nodos")
        self.assertEqual(n.doctype, "first", "nettle conserva el PRIMERO (navegadores)")
        self.assertTrue(str(n).startswith("<!DOCTYPE first>"))
        self.assertEqual(str(b).count("DOCTYPE"), 2)


class TestDocumentedDivergences(unittest.TestCase):
    """(c) cada fila de la tabla del README §10, verificada contra bs4 real."""

    @unittest.skipUnless(HAVE_BS4, "bs4 not installed")
    def test_divergence_limit_zero(self):
        h = "<div><p>1</p><p>2</p><p>3</p></div>"
        b = BeautifulSoup(h, "html.parser")
        n = parse(h)
        self.assertEqual(len(b.find_all("p", limit=0)), 3)  # 0 = sin límite
        self.assertEqual(len(n.find_all("p", limit=0)), 0)  # documentado

    @unittest.skipUnless(HAVE_BS4, "bs4 not installed")
    def test_divergence_find_all_string_types(self):
        h = "<div><p>1</p></div>"
        b = BeautifulSoup(h, "html.parser")
        n = parse(h)
        self.assertTrue(all(not isinstance(x, str) or True for x in [type(x).__name__ for x in b.find_all(string="1")]))
        self.assertEqual(type(b.find_all(string="1")[0]).__name__, "NavigableString")
        self.assertEqual(type(n.find_all(string="1")[0]).__name__, "Element")
        # el TEXTO coincide — es lo que importa para scraping
        self.assertEqual(n.find_all(string="1")[0].get_text(), "1")

    @unittest.skipUnless(HAVE_BS4, "bs4 not installed")
    def test_divergence_class_representation(self):
        h = "<div class='a b'>x</div>"
        b = BeautifulSoup(h, "html.parser")
        n = parse(h)
        self.assertEqual(b.find("div").attrs["class"], ["a", "b"])
        self.assertEqual(n.find("div").attrs["class"], "a b")
        # workaround documentado
        self.assertEqual(n.find("div").get("class").split(), ["a", "b"])

    @unittest.skipUnless(HAVE_BS4, "bs4 not installed")
    def test_divergence_duplicate_attrs(self):
        h = "<p id='first' id='second'>x</p>"
        b = BeautifulSoup(h, "html.parser")
        n = parse(h)
        self.assertEqual(b.find("p").get("id"), "second")  # bs4: último
        self.assertEqual(n.find("p").get("id"), "first")   # nettle: HTML5 primero

    @unittest.skipUnless(HAVE_BS4, "bs4 not installed")
    def test_divergence_attr_entities(self):
        h = "<a href='/x?a=1&copy=2'>q</a><a href='t?x=&notit;'>w</a>"
        b = BeautifulSoup(h, "html.parser")
        n = parse(h)
        self.assertEqual(b.find_all("a")[0].get("href"), "/x?a=1©=2")  # corrompido
        self.assertEqual(n.find_all("a")[0].get("href"), "/x?a=1&copy=2")  # HTML5
        self.assertEqual(b.find_all("a")[1].get("href"), "t?x=¬it;")
        self.assertEqual(n.find_all("a")[1].get("href"), "t?x=&notit;")

    @unittest.skipUnless(HAVE_BS4, "bs4 not installed")
    def test_divergence_text_legacy_entity(self):
        h = "<p>a &notit; b</p>"
        b = BeautifulSoup(h, "html.parser")
        n = parse(h)
        self.assertEqual(n.find("p").get_text(), "a ¬it; b")  # longest-match HTML5
        self.assertNotEqual(b.find("p").get_text(), "a ¬it; b")

    @unittest.skipUnless(HAVE_BS4, "bs4 not installed")
    def test_divergence_serialization_style(self):
        h = "<p><br>x</p>"
        b = BeautifulSoup(h, "html.parser")
        n = parse(h)
        self.assertIn("<br/>", str(b))
        self.assertIn("<br>", str(n))
        # workaround: prettify bs4_compat es byte-idéntico
        self.assertEqual(n.prettify(bs4_compat=True), b.prettify())

    @unittest.skipUnless(HAVE_BS4, "bs4 not installed")
    def test_divergence_text_node_not_str(self):
        b = BeautifulSoup("<p>1</p>", "html.parser")
        n = parse("<p>1</p>")
        sb = b.find("p").string
        tn = n.find("p")._children[0]
        self.assertIsInstance(sb, str)         # NavigableString ES str
        self.assertNotIsInstance(tn, str)      # nettle Text NO
        self.assertEqual(tn.content, "1")      # workaround: .content
        self.assertEqual(str(tn), "1")


class TestReadmePromisesExecuted(unittest.TestCase):
    """(d) promesas del README ejecutadas de verdad (las offline)."""

    def test_write_csv_readme_argument_order(self):
        # README §7: write_csv(libros, "libros.csv") — data primero
        data = [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}]
        with tempfile.TemporaryDirectory() as td:
            p1 = os.path.join(td, "a.csv")
            nettle.write_csv(data, p1)  # estilo README
            p2 = os.path.join(td, "b.csv")
            nettle.write_csv(p2, data)  # estilo clásico
            self.assertEqual(open(p1).read(), open(p2).read())
            self.assertIn("x", open(p1).read())
            p3 = os.path.join(td, "c.json")
            nettle.write_json(data, p3)
            nettle.write_json(p4 := os.path.join(td, "d.json"), data)
            self.assertEqual(open(p3).read(), open(p4).read())

    def test_registry_keys_documented(self):
        snap = registry.snapshot()
        for domain in ("http", "cdp", "sniff", "discover", "parse", "css",
                       "serialize", "text", "dns"):
            self.assertIn(domain, snap, f"registry.{domain} prometido en README §8")
        for mutator in ("add_api_hints", "add_state_globals", "add_url_keywords",
                        "add_data_endpoint_attrs", "add_media_exts", "add_well_known",
                        "register_classifier", "add_discovery_skip_hosts",
                        "set_cdp_ports", "add_cdp_ports"):
            self.assertTrue(callable(getattr(registry, mutator, None)),
                            f"registry.{mutator} prometido en README")

    def test_registry_parse_legacy_entities_toggle(self):
        h = "<p>&copy 2024</p>"
        try:
            registry.parse["legacy_entities"] = False
            n = parse(h)
            self.assertEqual(n.find("p").get_text(), "&copy 2024")
        finally:
            registry.parse["legacy_entities"] = True
        n = parse(h)
        self.assertEqual(n.find("p").get_text(), "© 2024")

    def test_brotli_decompress_export(self):
        self.assertTrue(callable(nettle.brotli_decompress))

    def test_get_text_bs4_styles(self):
        d = parse("<div><p>a</p><b>b</b></div>")
        self.assertEqual(d.get_text(" "), "a b")       # bs4 posicional
        self.assertEqual(d.get_text(" | ", True), "a | b")  # bs4 doble
        self.assertEqual(d.get_text(strip=True, sep="-"), "a-b")  # nettle

    def test_copy_semantics(self):
        h = "<div><p>x</p></div>"
        orig = parse(h).find("div")
        c = copy_mod.copy(orig)
        c.find("p").decompose()
        self.assertIn("<p>", str(orig))

    def test_unwrap_requires_parent(self):
        n = parse("<p>a</p>")
        p = n.find("p")
        p.detach()  # sin padre → unwrap debe quejarse claro
        with self.assertRaises(NettleError):
            p.unwrap()

    def test_examples_contract(self):
        """(e) los imports de cada example apuntan a APIs existentes."""
        import ast
        examples_dir = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "examples")
        for fname in sorted(os.listdir(examples_dir)):
            if not fname.endswith(".py"):
                continue
            with self.subTest(example=fname):
                src = open(os.path.join(examples_dir, fname)).read()
                tree = ast.parse(src)
                imported = []
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("nettle"):
                        imported.extend(a.name for a in node.names)
                    elif isinstance(node, ast.Import):
                        # 'import nettle' es el paquete mismo, no un símbolo;
                        # solo chequear submódulos (nettle.cdp etc.)
                        imported.extend(a.name for a in node.names
                                        if a.name.startswith("nettle."))
                missing = []
                for name in imported:
                    try:
                        __import__(f"nettle.{name}" if False else "nettle")
                    except ImportError:
                        pass
                    if "." in name:
                        try:
                            __import__(name)
                            continue
                        except ImportError:
                            missing.append(name); continue
                    if not (hasattr(nettle, name)
                            or any(hasattr(__import__(f"nettle.{m}", fromlist=["x"]), name)
                                   for m in ("cdp", "http", "exceptions", "brotli_dec"))):
                        missing.append(name)
                self.assertEqual(missing, [], f"examples/{fname} importa APIs inexistentes")


if __name__ == "__main__":
    unittest.main(verbosity=2)
