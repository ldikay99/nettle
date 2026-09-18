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


# ---------------------------------------------------------------------------
# Round 3 additions: CSS escapes (soupsieve parity), exotic :has(),
# prettify(bs4_compat=True) byte-identity, get_text(bs4_compat=True),
# and the full selector list re-run on the lxml-parsed fixture.
# ---------------------------------------------------------------------------

ESC_DOC = (
    "<er:custom class='x y' data:v='1'>A</er:custom>"
    "<a class='btn primary'>B</a>"
    "<a class='btn.primary' href='/a(b)'>C</a>"
    "<div id='wrap'><div id='we:ird' class='a b'>D</div></div>"
    "<span data:weird='1' class='foo+bar'>E</span>"
    "<p class='x y'>F</p>"
    "<section><er:custom class='nested'>G</er:custom></section>"
    "<svg:circle r='1'>H</svg:circle>"
    "<q class='a b'>q</q>"
)

# ~28 escape cases: \: \. \+ \  hex \3a /\3A/\65/\73, quoted-value escapes,
# namespace forms ns|tag / *|tag / |tag, escapes inside :not/:is/:has args
ESCAPE_SELECTORS = [
    r'er\:custom', r'a.btn\.primary', r'.btn\.primary', r'#we\:ird',
    r'[data\:weird="1"]', r'[data\3a weird]', r'er\3A custom', r'\65 r\:custom',
    r'.foo\+bar', r'span\.foo\+bar', r'div#we\:ird', r'section er\:custom',
    r'er\:custom.x', r'a:not(.btn\.primary)', r':is(er\:custom, span)',
    r'div:has(#we\:ird)', r'[href="/a\(b\)"]', r'[href="/a\28 b\29"]',
    r'.x\:y', r'a\.btn', 'svg|circle', '*|span', '|span', r'\73 pan',
    r'.x\ y', r'[class~="btn\.primary"]', r'a[href^="/a\("]',
]

ESCAPE_ERROR_SELECTORS = [
    r'*\.x',           # tag name after '*' — both raise
    r'[data\:weird=1]',  # unquoted digit value — both raise
    r'[href^=/]',     # unquoted non-ident value — both raise
]

# escape lenience documented for nettle only (soupsieve raises): '#5x'

HAS_DOC = (
    "<div id='d1'><p>1</p><p>2</p><span>z</span></div>"
    "<div id='d2'><p>only</p></div>"
    "<section id='s1'><span>q</span></section>"
    "<section id='s2'><b>b</b></section>"
    "<section id='s3'><span>x</span><span>y</span></section>"
    "<article id='a1'><div id='d3'><p>nested</p></div><span>sib</span></article>"
    "<ol><li>l1</li><li>l2</li><li>l3</li><li>l4</li></ol>"
)

# 20 exotic relative combinations inside :has()
HAS_EXOTIC_SELECTORS = [
    "div:has(> p + p)", "div:has(> p ~ p)", "section:has(~ section)",
    "section:has(+ section)", "div:has(:has(p))", "article:has(:has(p))",
    "div:has(> :is(p, span))", "div:has(p:nth-child(2))", "div:has(> p:nth-child(2))",
    "article:has(> div + span)", "article:has(span):has(div)",
    "ol:has(li:nth-child(2n+1))", "ol:has(> li + li + li)",
    "section:has(span):not(:has(b))", ":has(> p + p)", "div:has(> p, > span)",
    "section:has(> span + span)", "ol:has(> li:not(:first-child):not(:last-child))",
    "article:has(> div:has(p))", "div:has(> span + span)",
]

# 43 varied documents for prettify(bs4_compat=True) byte-identity
PRETTIFY_DOCS = [
    "<!DOCTYPE html><html><head><title>T</title></head><body><h1>Hi</h1><p>one <b>bold</b> two</p></body></html>",
    "<html><body><div id='main' class='wrap box' data-x='Hello'><p>a</p>  <p>b</p>\n  <p>c</p></div></body></html>",
    "<div><pre>keep\n  me   here</pre><textarea>a\n b</textarea></div>",
    "<ul><li>1</li><li>2</li><li>3</li></ul>",
    "<div><script>if (a<b && c>d) { x(); }</script><style>a > b { color: red }</style></div>",
    "<p>text</p><!-- a comment --><p>more</p>",
    "<img src='a.png' alt='A \"pic\"'><br><hr><input type='text' disabled>",
    "<div a='1' id='z' class='c b' href='/x' data-q='v&amp;w'>attrs</div>",
    "<table><thead><tr><th>H1</th><th>H2</th></tr></thead><tbody><tr><td>1</td><td>2</td></tr></tbody></table>",
    "<div><span>a</span><span>b</span><em></em><i> </i></div>",
    "<a href='/x?y=1&amp;z=2'>link &amp; text</a>",
    "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\"><html><body><p>old</p></body></html>",
    "<div><p>Ünïcödé texte — em dash & copy © &nbsp; entities</p></div>",
    "<body><form action='/post' method='post'><input name='a' value='1'><select><option value='1'>One</option><option value='2' selected>Two</option></select><textarea name='t'>raw</textarea></form></body>",
    "<div><p>  leading and trailing  </p><p>\tmixed\tws\n</p></div>",
    "<section><article><header><hgroup><h1>Deep</h1><h2>nesting</h2></hgroup></header></article></section>",
    "<div><code>a &lt; b</code><samp>out</samp><kbd>ctl</kbd></div>",
    "<video controls poster='p.jpg'><source src='v.mp4' type='video/mp4'></video>",
    "<div data-json='{\"k\": [1,2]}'>json attr</div>",
    "<p>unicode ¡¿ñáéíóú</p><p title='quotes \"both\" and &#39;single&#39;'>q</p>",
    "<html><body>" + "".join(
        f"<div class='c{i%3}'><a href='/l{i}'>link {i}</a></div>" for i in range(30)
    ) + "</body></html>",
    "<div><svg:circle r='1'></svg:circle></div>",
    "<figure><img src='x.png'><figcaption>Caption text</figcaption></figure>",
    "<div><pre>line1\n<b>bold in pre</b> line2\n   indented</pre></div>",
    "<div><script>var s = '</div> fake close'; /* <b> */</script></div>",
    "<div><p>&amp;amp; double</p><p>a &lt;tag&gt; &amp; b</p></div>",
    "<div><p>\xa0nbsp-padded\xa0</p><p>\xa0</p></div>",
    "<div>" * 120 + "deep" + "</div>" * 120,
    "<p>one</p><!-- outer --><div><!-- inner <p>not real</p> --></div>",
    "<div><span> </span><span>x</span></div>",
    "<ul>\n\n  <li>a</li>\n\n\n <li>b</li>\n  </ul>",
    "<textarea>  spaced\n\nnewlines  </textarea>",
    "<div><style>@media (max-width: 100px) { .a { content: '</style>' } }</style></div>",
    "<input value='' name='x' required><p>empty attr</p>",
    "<div class='a'><?xml version='1.0'?><p>pi inside</p></div>",  # PI→comment diverges
    "<img src='a' src='b'><p>dup attr</p>",                        # dup-attr diverges
    "<b>bold<i>both</i></b>",
    "<div><custom-tag custom-attr='1'>web component</custom-tag></div>",
    "<html><head><meta charset='utf-8'><title>x</title></head><body>y</body></html>",
    "<div><a href='#'>#</a><a href='?q=1&amp;r=2'>?</a></div>",
    "<p>t</p>" * 200,
    "<div><h1>A</h1><h2>B</h2><h3>C</h3><h4>D</h4><h5>E</h5><h6>F</h6></div>",
    "<div><abbr title='HyperText'>HT</abbr><q>quote</q><cite>cite</cite></div>",
]
# documents where the ENGINES' trees legitimately differ (documented):
# duplicate attributes (nettle keeps first per HTML5, bs4 keeps last) and
# processing instructions (nettle: comment; bs4: PI node).
PRETTIFY_KNOWN_DIVERGENT = {34, 35}

GET_TEXT_COMPAT_DOCS = [
    "<div><p>a</p>  <p>b</p>\n  <p>c</p></div>",
    "<div><pre>a  \n b</pre>  <span>x</span></div>",
    "<ul><li>one</li>\n\n<li>two</li></ul>",
    "<p>  padded  </p><p>\ttabs\t</p>",
    "<div><textarea>  keep\n  me  </textarea></div>",
]


@unittest.skipUnless(HAVE_BS4, "beautifulsoup4 not installed")
class TestEscapeParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.soup = _bs(ESC_DOC)
        cls.doc = parse(ESC_DOC)

    def test_escape_selectors_parity(self):
        checked = 0
        for sel in ESCAPE_SELECTORS:
            with self.subTest(selector=sel):
                self.assertEqual(_sel_bs(self.soup, sel), _sel_nt(self.doc, sel))
                checked += 1
        self.assertGreaterEqual(checked, 20)

    def test_escape_error_agreement(self):
        for sel in ESCAPE_ERROR_SELECTORS:
            with self.subTest(selector=sel):
                b = _sel_bs(self.soup, sel)
                n = _sel_nt(self.doc, sel)
                self.assertEqual(
                    isinstance(b, tuple), isinstance(n, tuple),
                    f"{sel!r}: bs4={b} nettle={n} (one raised, other didn't)"
                )

    def test_documented_id_digit_lenience(self):
        # nettle accepts '#5x' (soupsieve raises): strict superset, safe for
        # code migrating FROM bs4 (such code can never contain '#5x')
        self.assertEqual(_sel_nt(self.doc, "#5x"), [])
        self.assertIsInstance(_sel_bs(self.soup, "#5x"), tuple)


@unittest.skipUnless(HAVE_BS4, "beautifulsoup4 not installed")
class TestHasExoticParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.soup = _bs(HAS_DOC)
        cls.doc = parse(HAS_DOC)

    def test_has_exotic_parity(self):
        checked = 0
        for sel in HAS_EXOTIC_SELECTORS:
            with self.subTest(selector=sel):
                b = [(e.name, e.get("id")) for e in self.soup.select(sel)]
                n = [(e.tag, e.get("id")) for e in self.doc.select(sel)]
                self.assertEqual(b, n, f"selector {sel!r}")
                checked += 1
        self.assertGreaterEqual(checked, 15)


@unittest.skipUnless(HAVE_BS4, "beautifulsoup4 not installed")
class TestPrettifyBs4Compat(unittest.TestCase):
    def test_byte_identical_prettify(self):
        identical = 0
        divergent = 0
        for i, src in enumerate(PRETTIFY_DOCS):
            with self.subTest(doc=i):
                b = _bs(src).prettify()
                n = parse(src).prettify(bs4_compat=True)
                if i in PRETTIFY_KNOWN_DIVERGENT:
                    self.assertNotEqual(b, n)  # tree-level, documented
                    divergent += 1
                else:
                    self.assertEqual(b, n, f"prettify diverged on doc {i}")
                    identical += 1
        self.assertGreaterEqual(identical, 15)
        self.assertEqual(identical + divergent, len(PRETTIFY_DOCS))

    def test_element_prettify_and_indents(self):
        src = "<div id='d'><p>hello <b>world</b></p><ul><li>1</li></ul></div>"
        bs_el = _bs(src).select_one("div")
        nt_el = parse(src).select_one("div")
        self.assertEqual(bs_el.prettify(), nt_el.prettify(bs4_compat=True))
        try:
            from bs4.formatter import HTMLFormatter
            self.assertEqual(
                bs_el.prettify(formatter=HTMLFormatter(indent="    ")),
                nt_el.prettify(indent="    ", bs4_compat=True),
            )
            self.assertEqual(
                bs_el.prettify(formatter=HTMLFormatter(indent="\t")),
                nt_el.prettify(indent="\t", bs4_compat=True),
            )
        except ImportError:
            pass

    def test_registry_default(self):
        from nettle import registry
        src = "<div><p>a</p>\n  <p>b</p></div>"
        want = _bs(src).prettify()
        registry.serialize["prettify_bs4_compat"] = True
        try:
            self.assertEqual(parse(src).prettify(), want)
        finally:
            registry.serialize["prettify_bs4_compat"] = False

    def test_default_mode_unchanged(self):
        # nettle's own prettify (no compat): SOURCE attr order, <br> style
        out = parse("<img src='b' alt='a'><br>").prettify()
        self.assertIn('<img src="b" alt="a">', out)  # not alphabetized
        self.assertIn("<br>", out)                   # not <br/>


@unittest.skipUnless(HAVE_BS4, "beautifulsoup4 not installed")
class TestGetTextBs4Compat(unittest.TestCase):
    def test_compat_matrix(self):
        for i, src in enumerate(GET_TEXT_COMPAT_DOCS):
            bs_el = _bs(src)
            nt_el = parse(src)
            for kwargs_bs, kwargs_nt in [
                ({"separator": "|"}, {"sep": "|", "bs4_compat": True}),
                ({"separator": "|", "strip": True}, {"sep": "|", "strip": True, "bs4_compat": True}),
                ({}, {"bs4_compat": True}),
                ({"separator": "-"}, {"sep": "-", "bs4_compat": True}),
            ]:
                with self.subTest(doc=i, bs=kwargs_bs, nt=kwargs_nt):
                    self.assertEqual(
                        bs_el.get_text(**kwargs_bs),
                        nt_el.get_text(**kwargs_nt),
                    )

    def test_registry_flag(self):
        from nettle import registry
        src = "<div><p>a</p>  <p>b</p></div>"
        want = _bs(src).get_text("|")
        registry.text["get_text_bs4_compat"] = True
        try:
            self.assertEqual(parse(src).get_text("|"), want)
        finally:
            registry.text["get_text_bs4_compat"] = False
        self.assertNotEqual(parse(src).get_text("|"), want)  # source preserved


@unittest.skipUnless(HAVE_BS4, "beautifulsoup4 not installed")
class TestLxmlHarnessRun(unittest.TestCase):
    """The FULL selector corpus re-run on the lxml-tokenized nettle tree."""

    def test_all_selectors_on_lxml_tree(self):
        try:
            from nettle._lxml_backend import lxml_available
        except ImportError:
            self.skipTest("lxml backend module missing")
        if not lxml_available():
            self.skipTest("lxml not installed")
        from nettle import parse as _p
        doc_lxml = _p(DOC, backend="lxml")
        doc_pure = _p(DOC, backend="pure")
        for sel in SELECTORS:
            with self.subTest(selector=sel):
                self.assertEqual(
                    _sel_nt(doc_pure, sel), _sel_nt(doc_lxml, sel),
                    f"lxml tree diverges from pure on {sel!r}",
                )
        for sel in ESCAPE_SELECTORS:
            with self.subTest(selector=sel, fixture="escape"):
                self.assertEqual(
                    _sel_nt(_p(ESC_DOC, backend="pure"), sel),
                    _sel_nt(_p(ESC_DOC, backend="lxml"), sel),
                )
        for sel in HAS_EXOTIC_SELECTORS:
            with self.subTest(selector=sel, fixture="has-exotic"):
                self.assertEqual(
                    [(e.tag, e.get("id")) for e in _p(HAS_DOC, backend="pure").select(sel)],
                    [(e.tag, e.get("id")) for e in _p(HAS_DOC, backend="lxml").select(sel)],
                )


if __name__ == "__main__":
    unittest.main()
