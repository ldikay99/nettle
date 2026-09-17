"""CSS selector engine for Nettle (subset of CSS3).

Supported:
  *, tag, #id, .class, tag.class, tag#id
  descendant ( ), child (>), adjacent (+), sibling (~)
  [attr], [attr=val], [attr^=], [attr$=], [attr*=], [attr~=]
  :first-child, :last-child, :nth-child(n|odd|even), :nth-of-type(...)
  :first-of-type, :last-of-type, :empty, :root, :has(simple) basic
  :not(simple)
  [attr|=]
  comma groups
"""

from __future__ import annotations

import re
from typing import Callable, List, Optional, Tuple

from .nodes import Element, Node

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def select(root: Element, selector: str) -> List[Element]:
    """Return all Element descendants (and root if matching) for selector."""
    selector = selector.strip()
    if not selector:
        return []
    groups = _split_groups(selector)
    seen = set()
    results: List[Element] = []
    for group in groups:
        chain = _parse_selector(group.strip())
        for el in _query(root, chain):
            eid = id(el)
            if eid not in seen:
                seen.add(eid)
                results.append(el)
    return results


def matches(el: Element, selector: str) -> bool:
    """Return True if element matches any of the selector groups."""
    selector = selector.strip()
    if not selector:
        return False
    for group in _split_groups(selector):
        chain = _parse_selector(group.strip())
        if _element_matches_chain(el, chain):
            return True
    return False


# ---------------------------------------------------------------------------
# Selector parsing
# ---------------------------------------------------------------------------

# One compound: tag#id.class[attr]:pseudo...
# Combined with combinators into a chain: [(compound, combinator_before), ...]
# First has combinator None (or implicit descendant from root).

Compound = dict  # keys: tag, id, classes, attrs, pseudos, negate


def _split_groups(selector: str) -> List[str]:
    """Split on commas not inside (), [], or quotes."""
    groups: List[str] = []
    buf: List[str] = []
    depth_paren = 0
    depth_brack = 0
    quote: Optional[str] = None
    for ch in selector:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
            buf.append(ch)
            continue
        if ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren = max(0, depth_paren - 1)
        elif ch == "[":
            depth_brack += 1
        elif ch == "]":
            depth_brack = max(0, depth_brack - 1)
        if ch == "," and depth_paren == 0 and depth_brack == 0:
            groups.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if buf:
        groups.append("".join(buf))
    return groups


_COMB_RE = re.compile(r"\s*([>+~])\s*|\s+")


def _parse_selector(selector: str) -> List[Tuple[Optional[str], Compound]]:
    """Parse into list of (combinator, compound) where first combinator is None.

    Combinator is the relationship TO this compound FROM the previous one:
      None = start, ' ' = descendant, '>' = child, '+' = adjacent, '~' = sibling
    """
    tokens = _tokenize_selector(selector)
    return _parse_selector_tokens(tokens)


def _parse_selector_tokens(tokens: List[str]) -> List[Tuple[Optional[str], Compound]]:
    chain: List[Tuple[Optional[str], Compound]] = []
    expecting_compound = True
    combinator: Optional[str] = None
    for tok in tokens:
        if tok in (">", "+", "~", " "):
            if expecting_compound and chain:
                # double combinator — last wins
                combinator = tok
            else:
                combinator = tok
            expecting_compound = True
            continue
        compound = _parse_compound(tok)
        chain.append((combinator, compound))
        combinator = None
        expecting_compound = False
    return chain


def _tokenize_selector(selector: str) -> List[str]:
    """Split into compound strings and combinator tokens."""
    tokens: List[str] = []
    i = 0
    n = len(selector)
    while i < n:
        # skip whitespace — may be descendant combinator
        if selector[i] in " \t\n\r\f":
            while i < n and selector[i] in " \t\n\r\f":
                i += 1
            if i < n and selector[i] in ">+~":
                tokens.append(selector[i])
                i += 1
                while i < n and selector[i] in " \t\n\r\f":
                    i += 1
            elif i < n:
                tokens.append(" ")
            continue
        if selector[i] in ">+~":
            tokens.append(selector[i])
            i += 1
            while i < n and selector[i] in " \t\n\r\f":
                i += 1
            continue
        # read compound
        start = i
        depth_paren = 0
        depth_brack = 0
        quote: Optional[str] = None
        while i < n:
            ch = selector[i]
            if quote:
                if ch == quote:
                    quote = None
                i += 1
                continue
            if ch in ('"', "'"):
                quote = ch
                i += 1
                continue
            if ch == "[":
                depth_brack += 1
            elif ch == "]":
                depth_brack = max(0, depth_brack - 1)
            elif ch == "(":
                depth_paren += 1
            elif ch == ")":
                depth_paren = max(0, depth_paren - 1)
            elif depth_paren == 0 and depth_brack == 0:
                if ch in " \t\n\r\f>+~,":
                    break
            i += 1
        tokens.append(selector[start:i])
    return tokens


_ATTR_RE = re.compile(
    r"\[\s*([^\s\]\~\|\^\$\*=]+)\s*"
    r"(?:([~|^$*]?=)\s*(?:\"([^\"]*)\"|'([^']*)'|([^\]\s]+))\s*)?"
    r"\]"
)

_PSEUDO_RE = re.compile(
    r":([a-zA-Z0-9_-]+)(?:\(([^)]*)\))?"
)


def _parse_compound(s: str) -> Compound:
    """Parse a compound selector into structured dict."""
    compound: Compound = {
        "tag": None,
        "id": None,
        "classes": [],
        "attrs": [],  # list of (name, op, value)
        "pseudos": [],  # list of (name, arg)
        "nots": [],  # list of Compound for :not()
    }
    i = 0
    n = len(s)

    # tag or *
    if i < n and (s[i].isalpha() or s[i] == "*"):
        start = i
        if s[i] == "*":
            i += 1
            compound["tag"] = "*"
        else:
            while i < n and (s[i].isalnum() or s[i] in "-_"):
                i += 1
            compound["tag"] = s[start:i].lower()

    while i < n:
        ch = s[i]
        if ch == "#":
            i += 1
            start = i
            while i < n and (s[i].isalnum() or s[i] in "-_"):
                i += 1
            compound["id"] = s[start:i]
        elif ch == ".":
            i += 1
            start = i
            while i < n and (s[i].isalnum() or s[i] in "-_"):
                i += 1
            compound["classes"].append(s[start:i])
        elif ch == "[":
            m = _ATTR_RE.match(s, i)
            if not m:
                i += 1
                continue
            name = m.group(1).lower()
            op = m.group(2)
            val = m.group(3) if m.group(3) is not None else (
                m.group(4) if m.group(4) is not None else (
                    m.group(5).rstrip() if m.group(5) is not None else None
                )
            )
            compound["attrs"].append((name, op, val))
            i = m.end()
        elif ch == ":":
            m = _PSEUDO_RE.match(s, i)
            if not m:
                i += 1
                continue
            pname = m.group(1).lower()
            parg = m.group(2)
            if pname == "not" and parg is not None:
                compound["nots"].append(_parse_compound(parg.strip()))
            else:
                compound["pseudos"].append((pname, parg))
            i = m.end()
        else:
            i += 1
    return compound


# ---------------------------------------------------------------------------
# Matching / query
# ---------------------------------------------------------------------------

def _query(root: Element, chain: List[Tuple[Optional[str], Compound]]) -> List[Element]:
    if not chain:
        return []

    # Collect candidates: all elements under root (including root if Element
    # and not Document — Document has tag #document)
    candidates = list(_all_elements(root))

    # Progressive filtering through the chain
    # Start: match first compound against all candidates
    _, first = chain[0]
    matched = [el for el in candidates if _match_compound(el, first)]

    for combinator, compound in chain[1:]:
        next_matched: List[Element] = []
        seen = set()
        for el in matched:
            for cand in _combinator_targets(el, combinator or " "):
                if id(cand) in seen:
                    continue
                if _match_compound(cand, compound):
                    # ensure cand is under root
                    if _is_under(cand, root) or cand is root:
                        seen.add(id(cand))
                        next_matched.append(cand)
        matched = next_matched

    return matched


def _element_matches_chain(el: Element, chain: List[Tuple[Optional[str], Compound]]) -> bool:
    """Right-to-left match: el must match last compound, ancestors/siblings the rest."""
    if not chain:
        return False
    return _match_from_right(el, chain, len(chain) - 1)


def _match_from_right(el: Element, chain: List[Tuple[Optional[str], Compound]], idx: int) -> bool:
    combinator, compound = chain[idx]
    if not _match_compound(el, compound):
        return False
    if idx == 0:
        return True
    # chain[idx].combinator is the relationship FROM previous TO this:
    # walk relative to el using its inverse to find the previous match.
    if combinator is None:
        return True
    if combinator == " ":
        # el is descendant of some ancestor matching chain[idx-1]
        anc = el.parent
        while anc is not None:
            if isinstance(anc, Element) and anc.tag != "#document":
                if _match_from_right(anc, chain, idx - 1):
                    return True
            anc = anc.parent
        return False
    if combinator == ">":
        parent = el.parent
        if parent is None or not isinstance(parent, Element) or parent.tag == "#document":
            return False
        return _match_from_right(parent, chain, idx - 1)
    if combinator == "+":
        sib = el.previous_element_sibling
        if sib is None:
            return False
        return _match_from_right(sib, chain, idx - 1)
    if combinator == "~":
        # some preceding sibling
        if el.parent is None:
            return False
        for s in el.parent.child_elements:
            if s is el:
                break
            if _match_from_right(s, chain, idx - 1):
                return True
        return False
    return False


def _combinator_targets(el: Element, combinator: str) -> List[Element]:
    if combinator == " ":
        return [n for n in el.descendants if isinstance(n, Element)]
    if combinator == ">":
        return el.child_elements
    if combinator == "+":
        sib = el.next_element_sibling
        return [sib] if sib else []
    if combinator == "~":
        results: List[Element] = []
        if el.parent is None:
            return results
        found = False
        for s in el.parent.child_elements:
            if found:
                results.append(s)
            if s is el:
                found = True
        return results
    return []


def _all_elements(root: Element) -> List[Element]:
    out: List[Element] = []
    if root.tag != "#document":
        out.append(root)
    for n in root.descendants:
        if isinstance(n, Element):
            out.append(n)
    return out


def _is_under(el: Element, root: Element) -> bool:
    if el is root:
        return True
    p = el.parent
    while p is not None:
        if p is root:
            return True
        p = p.parent
    return False


def _match_compound(el: Element, c: Compound) -> bool:
    tag = c["tag"]
    if tag is not None and tag != "*" and el.tag != tag:
        return False
    if c["id"] is not None:
        if el.get("id") != c["id"]:
            return False
    if c["classes"]:
        classes = _class_list(el)
        for cls in c["classes"]:
            if cls not in classes:
                return False
    for name, op, val in c["attrs"]:
        if not _match_attr(el, name, op, val):
            return False
    for pname, parg in c["pseudos"]:
        if not _match_pseudo(el, pname, parg):
            return False
    for not_c in c["nots"]:
        if _match_compound(el, not_c):
            return False
    return True


def _class_list(el: Element) -> List[str]:
    raw = el.get("class", "")
    if isinstance(raw, list):
        return [str(x) for x in raw]
    return str(raw).split()


def _match_attr(el: Element, name: str, op: Optional[str], val: Optional[str]) -> bool:
    if name not in el.attrs:
        return False
    if op is None:
        return True
    actual = str(el.attrs[name])
    if val is None:
        val = ""
    if op == "=":
        return actual == val
    if op == "^=":
        return actual.startswith(val) if val else False
    if op == "$=":
        return actual.endswith(val) if val else False
    if op == "*=":
        return val in actual if val else False
    if op == "~=":
        return val in actual.split()
    if op == "|=":
        return actual == val or actual.startswith(val + "-")
    return False


def _match_pseudo(el: Element, name: str, arg: Optional[str]) -> bool:
    if name == "first-child":
        return _nth_among_siblings(el) == 1
    if name == "last-child":
        sibs = el.parent.child_elements if el.parent else []
        return bool(sibs) and sibs[-1] is el
    if name == "nth-child":
        return _match_nth(el, arg or "1", of_type=False)
    if name == "nth-of-type":
        return _match_nth(el, arg or "1", of_type=True)
    if name == "first-of-type":
        return _nth_of_type(el) == 1
    if name == "last-of-type":
        if el.parent is None:
            return True
        same = [s for s in el.parent.child_elements if s.tag == el.tag]
        return bool(same) and same[-1] is el
    if name == "empty":
        from .nodes import Text as _Text
        for c in el._children:
            if isinstance(c, Element):
                return False
            if isinstance(c, _Text) and c.content.strip():
                return False
        return True
    if name == "root":
        return el.parent is not None and getattr(el.parent, "tag", None) == "#document"
    if name == "has":
        # basic :has(simple) -- at least one descendant matches compound/selector
        if not arg:
            return False
        try:
            return bool(select(el, arg.strip()))
        except Exception:
            return False
    return False  # unknown pseudo -> no match


def _nth_among_siblings(el: Element) -> int:
    if el.parent is None:
        return 1
    n = 0
    for s in el.parent.child_elements:
        n += 1
        if s is el:
            return n
    return 1


def _nth_of_type(el: Element) -> int:
    if el.parent is None:
        return 1
    n = 0
    for s in el.parent.child_elements:
        if s.tag == el.tag:
            n += 1
            if s is el:
                return n
    return 1


def _match_nth(el: Element, arg: str, of_type: bool = False) -> bool:
    arg = arg.strip().lower()
    idx = _nth_of_type(el) if of_type else _nth_among_siblings(el)
    if arg == "odd":
        return idx % 2 == 1
    if arg == "even":
        return idx % 2 == 0
    # an+b or n or number
    m = re.match(r"^([+-]?\d*)n([+-]\d+)?$", arg)
    if m:
        a_s = m.group(1)
        if a_s in ("", "+"):
            a = 1
        elif a_s == "-":
            a = -1
        else:
            a = int(a_s)
        b = int(m.group(2) or 0)
        if a == 0:
            return idx == b
        # idx = a*n + b for n >= 0
        if (idx - b) % a == 0:
            n = (idx - b) // a
            return n >= 0
        return False
    try:
        return idx == int(arg)
    except ValueError:
        return False
