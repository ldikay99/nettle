"""Agent-B differential harness: nettle vs REAL bs4+soupsieve, both executing.

Runs the same HTML + the same query through BeautifulSoup(html.parser) and
nettle, comparing results exactly. Skipped when bs4 is not installed.

Documented intentional differences (asserted separately, not as parity):
  * bs4's html.parser builder collapses whitespace-only text runs
    ("\n  " → "\n", "  " → " ") — a bs4 quirk; nettle preserves the source
    like lxml and browsers. get_text on pretty-printed markup differs only
    in whitespace-only strings.
  * find_all(string=...) returns the matching ELEMENTS in nettle (documented
    API), bs4 returns NavigableString nodes. Text content is compared here.
  * find_all(string=...) in nettle matches direct text; bs4 matches .string.
  * select("") raises in both now (bs4: SelectorSyntaxError, nettle: SelectorError).
  * void serialization: bs4 <br/>, nettle <br> — normalized before compare.
"""

from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import re
import unittest

bs4 = pytest_import = None
try:
    import bs4  # noqa: F401
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:  # pragma: no cover
    HAVE_BS4 = False

import nettle
from nettle import Element, Text, parse

# Fixture chosen so text nodes never are whitespace-only (dodges the
# documented bs4 endData quirk; that quirk has its own test below).
DOC = (
    "<html><head><title>Nettle vs bs4</title></head><body>"
    "<div id='main' class='wrap box' data-x='Hello World'>"
    "<p class='a'>one <b>bold</b> two</p>"
    "<p class='b'>three</p>"
    "<span data-x='hello world'>s1</span>"
    "<ul><li>l1</li><li class='sel'>l2</li><li>l3</li><li>l4</li><li>l5</li></ul>"
    "<a href='/x' rel='nofollow'>link</a>"
    "<a href='https://ex.com/y'>ext</a>"
    "<section><article class='a c'>art1</article><article class='b'>art2</article></section>"
    "<table><tr><th>h1</th><th>h2</th></tr><tr><td colspan='2'>d1</td></tr></table>"
    "<input type='text' disabled>"
    "<img src='a.png' srcset='b.png 2x, c.png 3x'>"
    "<em></em><i> </i>"
    "</div><footer>foot</footer></body></html>"
)

# 60+ selectors exercising every supported feature + exotic edges
SELECTORS = [
    # basics (8)
    "p", "div", "*", "#main", ".wrap", ".wrap.box", "p.a", "span#nope",
    # combinators (10)
    "div p", "div > p", "p ~ span", "p + p", "ul > li", "body *", "div > *",
    "section article.a", "html > body > div", "li + li + li",
    # chained combinators (4)
    "body > div ul > li.sel", "div p b", "section > article + article",
    "html body div ul li",
    # attributes (12)
    "[data-x]", "[data-x='Hello World']", "[data-x='hello world' i]",
    "[data-x='HELLO WORLD' s]", "[href^='/']", "[href$='.com/y']",
    "[href*='x']", "[class~='box']", "[lang|='en']", "a[rel='nofollow']",
    "[data-x='hello world' I]", "img[srcset]",
    # nth (12)
    "li:nth-child(1)", "li:nth-child(2)", "li:nth-child(odd)", "li:nth-child(even)",
    "li:nth-child(2n)", "li:nth-child(2n+1)", "li:nth-child(3n-1)",
    "li:nth-child(-n+3)", "li:nth-child(0n+2)", "li:nth-last-child(2)",
    "li:nth-last-child(-n+2)", "li:nth-of-type(3)",
    # nth exotic An+B (8)
    "li:nth-child(n)", "li:nth-child(n+2)", "li:nth-child(-2n+5)",
    "li:nth-child(+2n-1)", "li:nth-child( 2n + 1 )", "li:nth-child( +1 )",
    "li:nth-last-of-type(2n+1)", "article:nth-of-type(odd)",
    # structural (8)
    "li:first-child", "li:last-child", "p:first-of-type", "b:only-child",
    "span:only-of-type", "em:empty", "i:not(:empty)", "title:only-child",
    # :not (6)
    "p:not(.b)", "p:not(.b, .c)", "li:not(.sel)", "li:not(:first-child)",
    "li:not(:nth-child(2))", "article:not(.a, .b)",
    # :is/:where (4)
    "p:is(.a, .b)", "p:where(.a)", "li:is(.sel, .nope)", "article:is(.a):not(.b)",
    # :has (5)
    "div:has(b)", "div:has(> ul)", "ul:has(> li.sel)", "div:has(p b)",
    "section:has(article.b)",
    # groups + case (5)
    "p, span", "footer, em", "DIV P", "P.A", "li:nth-child(2), li:nth-child(4)",
]


def _bs(html: str):
    return BeautifulSoup(html, "html.parser")


def _sel_bs(soup, selector):
    """bs4 select → normalized [(name, text)] (or ('ERR', type))."""
    try:
        return [(el.name, el.get_text()) for el in soup.select(selector)]
    except Exception as e:
        return ("ERR", type(e).__name__)


def _sel_nt(doc, selector):
    try:
        return [(el.tag, el.get_text()) for el in doc.select(selector)]
    except Exception as e:
        return ("ERR", type(e).__name__)


@unittest.skipUnless(HAVE_BS4, "beautifulsoup4 not installed")
class TestSelectorParity(unittest.TestCase):
    """The SAME input and the SAME selector through both engines."""

    @classmethod
    def setUpClass(cls):
        cls.soup = _bs(DOC)
        cls.doc = parse(DOC)

    def _check(self, selector):
        b = _sel_bs(self.soup, selector)
        n = _sel_nt(self.doc, selector)
        self.assertEqual(
            b, n,
            f"selector {selector!r}: bs4={b} nettle={n}"
        )

    def test_01_all_selectors_parity(self):
        b_fails = n_fails = both = mismatches = 0
        for sel in SELECTORS:
            b = _sel_bs(self.soup, sel)
            n = _sel_nt(self.doc, sel)
            if isinstance(b, tuple):
                b_fails += 1
            if isinstance(n, tuple):
                n_fails += 1
            if b == n:
                both += 1
            else:
                mismatches += 1
        # scoreboard is asserted via subTest-free loop; strict parity expected
        self.assertEqual(
            (mismatches, b_fails, n_fails), (0, 0, 0),
            f"{mismatches} selector mismatches (bs4 raised {b_fails}, nettle {n_fails})"
        )
        self.assertGreaterEqual(both, 60)

    def test_02_each_selector_individually(self):
        for sel in SELECTORS:
            with self.subTest(selector=sel):
                self._check(sel)

    def test_03_scoped_select_excludes_self(self):
        inner_bs = self.soup.select_one("#main")
        inner_nt = self.doc.select_one("#main")
        self.assertEqual(
            [e.name for e in inner_bs.select("div")],
            [e.tag for e in inner_nt.select("div")],
        )
        self.assertEqual(inner_bs.select("#main"), [])
        self.assertEqual(inner_nt.select("#main"), [])

    def test_04_invalid_selectors_agree_on_error(self):
        bad = [
            ">", "div >", "p >>", "::before", ":unknown()", ":nth-child(2n+)",
            ":nth-child(foo)", "[unclosed", "p:has()", "***", "p!",
            "div,", ",div", "div,,p", "a[href==3]", "div:has(>)",
        ]
        for sel in bad:
            with self.subTest(selector=sel):
                b = _sel_bs(self.soup, sel)
                n = _sel_nt(self.doc, sel)
                self.assertEqual(
                    isinstance(b, tuple), isinstance(n, tuple),
                    f"{sel!r}: bs4={b} nettle={n} (one raised, other didn't)"
                )

    def test_05_empty_selector_raises_like_bs4(self):
        with self.assertRaises(nettle.SelectorError):
            self.doc.select("")
        with self.assertRaises(nettle.SelectorError):
            self.doc.select("   ")
        with self.assertRaises(nettle.SelectorError):
            self.doc.select(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# find / find_all parity
# ---------------------------------------------------------------------------

FIND_CASES = [
    # (label, callable(soup_or_doc) -> normalized list[str])
    ("tag str", lambda s: _tags(s.find_all("p"))),
    ("tag none", lambda s: _tags(s.find_all())),
    ("list tags", lambda s: _tags(s.find_all(["p", "b", "span"]))),
    ("tuple tags", lambda s: _tags(s.find_all(("li", "em")))),
    ("regex tag", lambda s: _tags(s.find_all(re.compile(r"^a$|p")))),
    ("callable tag", lambda s: _tags(s.find_all(lambda t: _name(t) in ("p", "li")))),
    ("attrs dict", lambda s: _texts(s.find_all("a", {"href": "/x"}))),
    ("kwargs attr", lambda s: _texts(s.find_all("a", href="https://ex.com/y"))),
    ("class_ single", lambda s: _texts(s.find_all("p", class_="a"))),
    ("class_ multi exact", lambda s: _texts(s.find_all("article", class_="a c"))),
    ("class_ list anyof", lambda s: _texts(s.find_all("article", class_=["a", "b"]))),
    ("class_ regex", lambda s: _texts(s.find_all("article", class_=re.compile(r"^a")))),
    ("class_ regex full", lambda s: _texts(s.find_all("article", class_=re.compile(r"^a c$")))),
    ("attr true", lambda s: _tags(s.find_all(href=True))),
    ("attr regex", lambda s: _texts(s.find_all("a", href=re.compile(r"^/")))),
    ("limit 2", lambda s: _texts(s.find_all("li", limit=2))),
    ("attr true", lambda s: _tags(s.find_all(href=True))),
    ("string str", lambda s: _strfind(s, "three")),
    ("string regex", lambda s: _strfind(s, re.compile(r"^l[0-9]$"))),
    ("string callable", lambda s: _strfind(s, lambda t: "l" in t)),
    ("tag+string", lambda s: _texts(s.find_all("p", string="three"))),
    ("find first", lambda s: [_name_or_text(s.find("p"))]),
    ("find missing", lambda s: [s.find("nope") is None]),
    ("find_parent", lambda s: [_ptag(s.select_one("b"), "find_parent", "div")]),
    ("attrs nested dict", lambda s: _texts(s.find_all("img", attrs={"src": "a.png"}))),
    ("id kwarg", lambda s: _texts(s.find_all(id="main"))),
    ("id kwarg missing", lambda s: _texts(s.find_all(id="nope"))),
    ("data attr kwarg", lambda s: _texts(s.find_all("span", **{"data-x": "hello world"}))),
    ("combined tag+class+limit", lambda s: _texts(s.find_all("li", class_=re.compile(r"sel"), limit=1))),
    ("rel kwarg", lambda s: _texts(s.find_all("a", rel="nofollow"))),
]


def _name(el):
    """bs4 passes the Tag; nettle passes the tag name as str — accept both."""
    if isinstance(el, str):
        return el
    return el.name if el is not None else None


def _name_or_text(el):
    return el.name if el is not None else None


def _tag_of(x):
    return x.name if hasattr(x, "name") else None


def _tags(els):
    return [e.name for e in els]


def _texts(els):
    return [e.get_text() for e in els]


def _ptag(el, method, *args, **kw):
    p = getattr(el, method)(*args, **kw)
    return p.name if p is not None else None


def _strfind(soup_or_doc, matcher):
    """find_all(string=) — nettle returns elements; compare their full text
    against the matching strings bs4 returns."""
    if isinstance(soup_or_doc, nettle.nodes.Element) or isinstance(soup_or_doc, nettle.Document):
        return [e.get_text() for e in soup_or_doc.find_all(string=matcher)]
    return [str(x) for x in soup_or_doc.find_all(string=matcher)]


@unittest.skipUnless(HAVE_BS4, "beautifulsoup4 not installed")
class TestFindParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.soup = _bs(DOC)
        cls.doc = parse(DOC)

    def test_all_find_cases(self):
        checked = 0
        for label, fn in FIND_CASES:
            with self.subTest(case=label):
                try:
                    b = fn(self.soup)
                except Exception as e:
                    b = f"ERR {type(e).__name__}"
                try:
                    n = fn(self.doc)
                except Exception as e:
                    n = f"ERR {type(e).__name__}"
                self.assertEqual(b, n, f"find case {label!r}: bs4={b} nettle={n}")
                checked += 1
        self.assertGreaterEqual(checked, 30)

    def test_documented_bs4_limit0_quirk(self):
        # bs4 treats limit=0 as "no limit" (returns everything!); nettle's
        # documented behavior is limit<=0 → [] (safer: a typo can't crawl
        # the whole document). Kept as intentional difference.
        soup = _bs(DOC)
        doc = parse(DOC)
        self.assertEqual(len(soup.find_all("li", limit=0)), 5)
        self.assertEqual(doc.find_all("li", limit=0), [])

    def test_recursive_false_on_element(self):
        div_bs = self.soup.select_one("#main")
        div_nt = self.doc.select_one("#main")
        self.assertEqual(
            [e.name for e in div_bs.find_all("p", recursive=False)],
            [e.tag for e in div_nt.find_all("p", recursive=False)],
        )
        self.assertEqual(
            [e.name for e in div_bs.find_all("ul", recursive=False)],
            [e.tag for e in div_nt.find_all("ul", recursive=False)],
        )


# ---------------------------------------------------------------------------
# navigation parity
# ---------------------------------------------------------------------------

NAV_HTML = (
    "<html><body><div id='d0'>"
    "text-a<p id='p1'>one<b id='b1'>bold</b>tail</p>"
    "text-b<span id='s1'>three</span>text-c"
    "<ul id='u1'><li>1</li><li>2</li></ul>"
    "</div>text-d</body></html>"
)


def _node_repr(node):
    """Normalize a node across engines: ('#text', content) / (tag,)."""
    if node is None:
        return None
    if isinstance(node, nettle.Text):
        return ("#text", str(node))
    if isinstance(node, str):
        # bs4 NavigableString is a str subclass; nettle .strings yields str
        if "Comment" in type(node).__name__:
            return ("#comment", str(node))
        return ("#text", str(node))
    return (getattr(node, "name", None) or getattr(node, "tag", None),)


def _parents_repr(nodes):
    """bs4's .parents includes the soup document node; nettle's excludes the
    document root by design — drop document-level entries from both."""
    return [r for r in (_node_repr(x) for x in nodes)
            if r is not None and r[0] not in ("[document]", "#document")]


@unittest.skipUnless(HAVE_BS4, "beautifulsoup4 not installed")
class TestNavigationParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.soup = _bs(NAV_HTML)
        cls.doc = parse(NAV_HTML)

    def _pair(self, bs_sel, nt_sel):
        return self.soup.select_one(bs_sel), self.doc.select_one(nt_sel)

    def test_navigation_matrix(self):
        cases = []
        for start in ("#p1", "#b1", "#s1", "#u1", "#d0"):
            b, n = self._pair(start, start)
            cases += [
                (f"{start}.next_element", b.next_element, n.next_element),
                (f"{start}.previous_element", b.previous_element, n.previous_element),
                (f"{start}.next_sibling", b.next_sibling, n.next_sibling),
                (f"{start}.previous_sibling", b.previous_sibling, n.previous_sibling),
                (f"{start}.parents", _parents_repr(list(b.parents)), _parents_repr(list(n.parents))),
                (f"{start}.strings", list(b.strings), list(n.strings)),
                (f"{start}.stripped", list(b.stripped_strings), list(n.stripped_strings)),
                (f"{start}.string", b.string, n.string),
            ]
        for label, b_node, n_node in cases:
            with self.subTest(case=label):
                if isinstance(b_node, list):
                    self.assertEqual(
                        [_node_repr(x) for x in b_node],
                        [_node_repr(x) for x in n_node],
                        label,
                    )
                else:
                    self.assertEqual(_node_repr(b_node), _node_repr(n_node), label)
        self.assertGreaterEqual(len(cases), 20)

    def test_find_next_family(self):
        for start, method, arg in [
            ("#b1", "find_next", "ul"),
            ("#b1", "find_next", "li"),
            ("#p1", "find_next", "li"),
            ("#s1", "find_previous", "b"),
            ("#s1", "find_next_sibling", None),
            ("#p1", "find_next_sibling", "span"),
            ("#p1", "find_previous_sibling", None),
            ("#b1", "find_all_next", "li"),
            ("#u1", "find_all_previous", "p"),
        ]:
            with self.subTest(start=start, method=method):
                b, n = self._pair(start, start)
                bres = getattr(b, method)(arg) if arg else getattr(b, method)()
                nres = getattr(n, method)(arg) if arg else getattr(n, method)()
                norm = (lambda xs: [_node_repr(x) for x in xs]) if isinstance(bres, list) else _node_repr
                self.assertEqual(norm(bres), norm(nres), f"{start}.{method}({arg})")


# ---------------------------------------------------------------------------
# surgery parity
# ---------------------------------------------------------------------------

def _norm_html(s: str) -> str:
    return s.replace("/>", ">")


SURGERY_HTML = (
    "<div id='root'><u><b>x</b><i>y</i><p>z</p><em>e1</em></u>"
    "<ul><li>1</li><li>2</li></ul></div>"
)


def _run_surgery_bs(which: str):
    s = _bs(SURGERY_HTML)
    root = s.select_one("#root")
    u = root.select_one("u")
    if which == "decompose":
        u.select_one("p").decompose()
    elif which == "unwrap":
        u.select_one("b").unwrap()
    elif which == "unwrap_i":
        u.select_one("i").unwrap()
    elif which == "replace":
        em = s.new_tag("strong")
        em.string = "R"
        u.select_one("i").replace_with(em)
    elif which == "replace_multi":
        s1 = s.new_tag("x1"); s1.string = "1"
        s2 = s.new_tag("x2"); s2.string = "2"
        u.select_one("p").replace_with(s1, s2)
    elif which == "wrap":
        w = s.new_tag("section")
        u.select_one("i").wrap(w)
    elif which == "clear":
        u.clear()
    elif which == "chain":
        u.select_one("p").decompose()
        u.select_one("b").unwrap()
        em = s.new_tag("strong"); em.string = "R"
        u.select_one("i").replace_with(em)
    elif which == "decompose_li":
        root.select("li")[0].decompose()
    return str(root)


def _run_surgery_nt(which: str):
    s = parse(SURGERY_HTML)
    root = s.select_one("#root")
    u = root.select_one("u")

    def new_el(tag, text=None):
        el = Element(tag)
        if text is not None:
            el.append(Text(text))
        return el

    if which == "decompose":
        u.select_one("p").decompose()
    elif which == "unwrap":
        u.select_one("b").unwrap()
    elif which == "unwrap_i":
        u.select_one("i").unwrap()
    elif which == "replace":
        u.select_one("i").replace_with(new_el("strong", "R"))
    elif which == "replace_multi":
        u.select_one("p").replace_with(new_el("x1", "1"), new_el("x2", "2"))
    elif which == "wrap":
        u.select_one("i").wrap(new_el("section"))
    elif which == "clear":
        u.clear()
    elif which == "chain":
        u.select_one("p").decompose()
        u.select_one("b").unwrap()
        u.select_one("i").replace_with(new_el("strong", "R"))
    elif which == "chain2":
        u.select_one("p").decompose()
        u.select_one("b").unwrap()
        u.select_one("i").replace_with(new_el("strong", "R"))
    elif which == "decompose_li":
        root.select("li")[0].decompose()
    return str(root)


@unittest.skipUnless(HAVE_BS4, "beautifulsoup4 not installed")
class TestSurgeryParity(unittest.TestCase):
    CASES = [
        "decompose", "unwrap", "unwrap_i", "replace", "replace_multi",
        "wrap", "clear", "chain", "decompose_li",
    ]

    def test_surgery_roundtrips(self):
        count = 0
        for which in self.CASES:
            with self.subTest(case=which):
                b = _norm_html(_run_surgery_bs(which))
                n = _norm_html(_run_surgery_nt(which))
                self.assertEqual(b, n, f"surgery {which!r}")
                count += 1
        self.assertGreaterEqual(count, 9)

    def test_surgery_errors_match(self):
        from nettle import NettleError
        # unwrap on a ROOTLESS node: bs4 raises ValueError, nettle a clear
        # NettleError. (On a document-child node bs4 silently splices into
        # the soup; nettle also splices into the Document — both no-op-ish.)
        bs_rootless = BeautifulSoup("<p>x</p>", "html.parser").select_one("p")
        bs_rootless.extract()
        with self.assertRaises(ValueError):
            bs_rootless.unwrap()
        nt_rootless = parse("<p>x</p>").select_one("p")
        nt_rootless.detach()
        with self.assertRaises(NettleError):
            nt_rootless.unwrap()

    def test_surgery_stability_after_ops(self):
        # operations keep the tree coherent: siblings/parents still resolve
        b = _bs(SURGERY_HTML); n = parse(SURGERY_HTML)
        b.select_one("b").decompose(); n.select_one("b").decompose()
        self.assertEqual(_norm_html(str(b.select_one("#root"))),
                         _norm_html(str(n.select_one("#root"))))
        self.assertEqual(
            [e.name for e in b.select("u > *")],
            [e.tag for e in n.select("u > *")],
        )


# ---------------------------------------------------------------------------
# get_text matrix
# ---------------------------------------------------------------------------

GT_HTML = "<div id='gt'><p>Alpha <b>Beta</b></p><span>Gamma</span><em></em>delta</div>"

GT_CASES = [
    (),
    (" | ",),
    (" | ", True),
    ("",),
    ("-", True),
]


@unittest.skipUnless(HAVE_BS4, "beautifulsoup4 not installed")
class TestGetTextMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bs_el = _bs(GT_HTML).select_one("#gt")
        cls.nt_el = parse(GT_HTML).select_one("#gt")

    def test_matrix(self):
        for args in GT_CASES:
            with self.subTest(args=args):
                self.assertEqual(
                    self.bs_el.get_text(*args),
                    self.nt_el.get_text(*args),
                )

    def test_kwarg_forms(self):
        self.assertEqual(self.bs_el.get_text(separator=" / "), self.nt_el.get_text(sep=" / "))
        self.assertEqual(self.bs_el.get_text(strip=True), self.nt_el.get_text(strip=True))

    def test_nettle_wrapper_positional(self):
        doc = nettle.Nettle(GT_HTML)
        self.assertEqual(doc.get_text(" | "), parse(GT_HTML).get_text(" | "))

    def test_documented_bs4_whitespace_quirk(self):
        # bs4's html.parser collapses whitespace-only strings ("\n  " → "\n",
        # "  " → " "); nettle preserves the source (lxml/browser behavior).
        html = "<div><p>a</p>  <p>b</p>\n  <p>c</p></div>"
        bs_out = _bs(html).select_one("div").get_text("|")
        nt_out = parse(html).select_one("div").get_text("|")
        self.assertEqual(bs_out, "a| |b|\n|c")     # bs4 quirk
        self.assertEqual(nt_out, "a|  |b|\n  |c")  # source preserved
        # with strip=True both agree (whitespace-only parts vanish)
        self.assertEqual(
            _bs(html).select_one("div").get_text("|", True),
            parse(html).select_one("div").get_text("|", True),
        )


# ---------------------------------------------------------------------------
# misc API parity added for migration
# ---------------------------------------------------------------------------

@unittest.skipUnless(HAVE_BS4, "beautifulsoup4 not installed")
class TestMiscParity(unittest.TestCase):
    def test_string_semantics(self):
        html = "<a>only</a><b><i>deep</i></b><c><i>x</i><i>y</i></c><d></d>"
        for tag in ("a", "b", "c", "d"):
            self.assertEqual(
                _bs(html).find(tag).string,
                parse(html).find(tag).string,
                f".string mismatch on <{tag}>",
            )

    def test_copy_semantics(self):
        import copy
        b = _bs("<div id=q><p>hi<b>x</b></p></div>").select_one("div")
        n = parse("<div id=q><p>hi<b>x</b></p></div>").select_one("div")
        bc = copy.copy(b)
        nc = copy.copy(n)
        # independent attrs
        bc["id"] = "bs4"; nc["id"] = "nt"
        self.assertEqual(b["id"], "q")
        self.assertEqual(n["id"], "q")
        # fresh child list: appending to the copy leaves the original alone
        em_b = _bs("<em></em>").select_one("em")
        bc.append(em_b)
        nc.append(Element("em"))
        self.assertNotIn("<em", str(b))
        self.assertNotIn("<em", str(n))

    def test_prettify_roundtrip_content(self):
        html = "<div><p>a<b>c</b></p><ul><li>1</li></ul></div>"
        p_nt = parse(html).prettify()
        # prettified output reparses to the same visible text (whitespace
        # layout is allowed to change — that's what prettify means)
        self.assertEqual(
            list(parse(p_nt).stripped_strings),
            list(parse(html).stripped_strings),
        )


if __name__ == "__main__":
    unittest.main()
