"""CSS selector engine for Nettle (CSS3 subset, strict parsing).

Supported:
  *, tag, #id, .class, tag.class, tag#id
  descendant ( ), child (>), adjacent (+), sibling (~)
  [attr], [attr=val], [attr^=], [attr$=], [attr*=], [attr~=], [attr|=]
  [attr="val" i] case-insensitive flag
  :first-child, :last-child, :nth-child(an+b|odd|even), :nth-last-child(...)
  :nth-of-type(...), :nth-last-of-type(...)
  :first-of-type, :last-of-type, :only-child, :only-of-type
  :empty, :root, :has(selector), :is(...), :where(...)
  :not(selector-list)  — comma lists and complex selectors allowed
  comma groups

Invalid or unsupported selectors raise SelectorError instead of silently
returning wrong results. Results are always in document order.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .exceptions import SelectorError
from .nodes import Element, Node

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Parsed-selector cache (selector string → list of group chains). Matching
# never mutates parsed structures, so sharing is safe. Capped, FIFO-flushed;
# the cap lives in registry.css["chain_cache_max"].
_CHAIN_CACHE: Dict[str, List[List[Tuple[Optional[str], dict]]]] = {}


def _chain_cache_max() -> int:
    from .registry import registry as _registry
    return int(_registry.css.get("chain_cache_max", 512))


def _require_selector_str(selector: Any) -> str:
    if not isinstance(selector, str):
        raise SelectorError(
            f"selector must be str, got {type(selector).__name__} — "
            "did you pass an element or None instead of a CSS string?"
        )
    s = selector.strip()
    if not s:
        raise SelectorError(
            "empty selector — pass a CSS expression like 'div.item > a[href]' "
            f"(got {selector!r})"
        )
    return s


def select(root: Element, selector: str) -> List[Element]:
    """Return all matching DESCENDANTS of *root* in document order.

    bs4/soupsieve semantics: the element select() is called on is never
    included in its own results (use Element.matches() for self-testing).
    """
    selector = _require_selector_str(selector)
    groups = _parse_groups(selector)
    candidates = list(_all_elements(root))
    order = {id(el): i for i, el in enumerate(candidates)}
    seen = set()
    results: List[Element] = []
    ctx: dict = {}
    for chain in groups:
        for el in _query(root, chain, candidates, ctx):
            eid = id(el)
            if eid not in seen and eid in order:
                seen.add(eid)
                results.append(el)
    results.sort(key=lambda el: order[id(el)])
    return results


def matches(el: Element, selector: str) -> bool:
    """Return True if element matches any of the selector groups."""
    selector = _require_selector_str(selector)
    for chain in _parse_groups(selector):
        if _element_matches_chain(el, chain, None):
            return True
    return False


def _parse_groups(selector: str) -> List[List[Tuple[Optional[str], dict]]]:
    cached = _CHAIN_CACHE.get(selector)
    if cached is not None:
        return cached
    groups: List[List[Tuple[Optional[str], dict]]] = []
    for group in _split_groups(selector):
        if not group.strip():
            raise SelectorError(
                f"empty selector group in {selector!r} — remove the stray ',' "
                "(e.g. 'div, span' not 'div,, span')"
            )
        chain = _parse_selector_tokens(_tokenize_selector(group.strip()))
        if chain:
            groups.append(chain)
    if len(_CHAIN_CACHE) >= _chain_cache_max():
        _CHAIN_CACHE.clear()
    _CHAIN_CACHE[selector] = groups
    return groups


# ---------------------------------------------------------------------------
# Selector parsing
# ---------------------------------------------------------------------------

Compound = dict  # keys: tag, id, classes, attrs, pseudos, nots, any_chains


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
    if buf or (groups and selector.rstrip().endswith(",")):
        groups.append("".join(buf))
    return groups


def _parse_selector_tokens(tokens: List[str]) -> List[Tuple[Optional[str], Compound]]:
    chain: List[Tuple[Optional[str], Compound]] = []
    expecting_compound = False
    combinator: Optional[str] = None
    first = True
    for tok in tokens:
        if tok in (">", "+", "~", " "):
            if first:
                raise SelectorError(
                    f"selector cannot start with a combinator ({tok!r}) "
                    f"in selector {' '.join(t for t in tokens if t)!r}"
                )
            if expecting_compound and tok in (">", "+", "~"):
                # doubled combinator ('p >> a', 'div > > span') — silently
                # treating it as a single combinator returns WRONG results
                raise SelectorError(
                    f"doubled combinator {tok!r} — write 'p > a' not 'p >> a' "
                    f"(selector {' '.join(tokens)!r})"
                )
            combinator = tok
            expecting_compound = True
            continue
        compound = _parse_compound(tok)
        chain.append((combinator, compound))
        combinator = None
        expecting_compound = False
        first = False
    if not chain:
        raise SelectorError("empty selector")
    if expecting_compound:
        raise SelectorError(
            "selector ends with a combinator — a compound is required after "
            f"it in selector {' '.join(tokens)!r}"
        )
    return chain


def _tokenize_selector(selector: str) -> List[str]:
    """Split into compound strings and combinator tokens."""
    tokens: List[str] = []
    i = 0
    n = len(selector)
    while i < n:
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
    r"(?:([~|^$*]?=)\s*(?:\"([^\"]*)\"|'([^']*)'|([^\]\s=][^\]\s]*))\s*([iIsS])?\s*)?"
    r"\]"
)

_PSEUDO_NAME_RE = re.compile(r":(-?[a-zA-Z][a-zA-Z0-9_-]*)")

_KNOWN_PSEUDOS = frozenset({
    "first-child", "last-child", "only-child",
    "nth-child", "nth-last-child", "nth-of-type", "nth-last-of-type",
    "first-of-type", "last-of-type", "only-of-type",
    "empty", "root", "has", "not", "is", "where", "matches",
})

# pseudo-classes we refuse loudly instead of silently returning nothing
_UNSUPPORTED_PSEUDOS = frozenset({
    "scope", "any", "lang", "dir", "hover", "focus", "active", "visited",
    "link", "target", "checked", "disabled", "enabled", "required",
    "optional", "read-only", "read-write", "default", "indeterminate",
    "placeholder-shown", "valid", "invalid", "in-range", "out-of-range",
})


def _read_pseudo(s: str, i: int) -> Tuple[str, Optional[str], int]:
    """Read :name or :name(balanced-arg) starting at s[i] == ':'."""
    m = _PSEUDO_NAME_RE.match(s, i)
    if not m:
        raise SelectorError(f"invalid pseudo-class at {s[i:i+12]!r} in {s!r}")
    name = m.group(1).lower()
    j = m.end()
    arg: Optional[str] = None
    if j < len(s) and s[j] == "(":
        depth = 1
        k = j + 1
        while k < len(s) and depth:
            if s[k] == "(":
                depth += 1
            elif s[k] == ")":
                depth -= 1
            k += 1
        if depth:
            raise SelectorError(f"unbalanced parentheses in :{name}(...) of {s!r}")
        arg = s[j + 1:k - 1]
        j = k
    if name.startswith("-"):
        raise SelectorError(f"unsupported pseudo-class {name!r} in {s!r}")
    return name, arg, j


def _parse_compound(s: str) -> Compound:
    """Parse a compound selector into a structured dict. Strict: raises SelectorError."""
    compound: Compound = {
        "tag": None,
        "id": None,
        "classes": [],
        "attrs": [],       # (name, op, value, flag_i)
        "pseudos": [],     # (name, arg)
        "nots": [],        # selector CHAINS excluded by :not() (any match → fail)
        "any_chains": [],  # :is()/:where() — list of chain-lists, match any
        "hass": [],        # :has() — list of (lead_combinator, chain), match any
    }
    i = 0
    n = len(s)

    if i < n and (s[i].isalpha() or s[i] == "*" or s[i] == "_"):
        start = i
        if s[i] == "*":
            i += 1
        else:
            while i < n and (s[i].isalnum() or s[i] in "-_"):
                i += 1
        compound["tag"] = s[start:i].lower()

    consumed = compound["tag"] is not None
    while i < n:
        ch = s[i]
        if ch == "#":
            i += 1
            start = i
            while i < n and (s[i].isalnum() or s[i] in "-_"):
                i += 1
            if start == i:
                raise SelectorError(f"empty id after '#' in {s!r}")
            compound["id"] = s[start:i]
            consumed = True
        elif ch == ".":
            i += 1
            start = i
            while i < n and (s[i].isalnum() or s[i] in "-_"):
                i += 1
            if start == i:
                raise SelectorError(f"empty class after '.' in {s!r}")
            compound["classes"].append(s[start:i])
            consumed = True
        elif ch == "[":
            m = _ATTR_RE.match(s, i)
            if not m:
                raise SelectorError(f"invalid attribute selector at {s[i:i+16]!r} in {s!r}")
            name = m.group(1).lower()
            op = m.group(2)
            val = m.group(3) if m.group(3) is not None else (
                m.group(4) if m.group(4) is not None else (
                    m.group(5).rstrip() if m.group(5) is not None else None
                )
            )
            flag_i = bool(m.group(6)) and m.group(6).lower() == "i"
            compound["attrs"].append((name, op, val, flag_i))
            i = m.end()
            consumed = True
        elif ch == ":":
            name, arg, j = _read_pseudo(s, i)
            if name not in _KNOWN_PSEUDOS:
                if name in _UNSUPPORTED_PSEUDOS:
                    raise SelectorError(f"unsupported pseudo-class :{name} in {s!r}")
                raise SelectorError(f"unknown pseudo-class :{name} in {s!r}")
            if name.startswith("nth") and arg is not None:
                a = _normalize_nth_arg(arg)
                if a not in ("odd", "even") and not re.match(r"^[+-]?\d*$", a) \
                        and not re.match(r"^[+-]?\d*n([+-]\d+)?$", a):
                    raise SelectorError(f"invalid nth argument {arg!r} in {s!r}")
            if name == "has":
                if not arg or not arg.strip():
                    raise SelectorError(":has() requires an argument")
                compound["hass"].extend(_parse_has_arg(arg))
                i = j
                consumed = True
                continue
            if name == "not":
                if arg is None:
                    raise SelectorError(":not() requires an argument")
                _groups = _split_groups(arg)
                if not [g for g in _groups if g.strip()]:
                    raise SelectorError(f":not() argument did not parse: {arg!r}")
                for g in _groups:
                    if not g.strip():
                        raise SelectorError(
                            f"empty selector group in :not({arg}) — stray ','"
                        )
                chains = [_parse_selector_tokens(_tokenize_selector(g.strip()))
                          for g in _groups]
                compound["nots"].extend(chains)
                i = j
                consumed = True
                continue
            elif name in ("is", "where", "matches"):
                if not arg or not arg.strip():
                    raise SelectorError(f":{name}() requires an argument")
                _groups = _split_groups(arg)
                if not [g for g in _groups if g.strip()]:
                    raise SelectorError(f":{name}() argument did not parse: {arg!r}")
                for g in _groups:
                    if not g.strip():
                        raise SelectorError(
                            f"empty selector group in :{name}({arg}) — stray ','"
                        )
                chains = [_parse_selector_tokens(_tokenize_selector(g.strip()))
                          for g in _groups]
                compound["any_chains"].append(chains)
                i = j
                consumed = True
                continue
            compound["pseudos"].append((name, arg))
            i = j
            consumed = True
        elif ch in " \t\n\r\f":
            break
        else:
            raise SelectorError(f"unexpected character {ch!r} in selector {s!r}")
    if not consumed:
        raise SelectorError(f"selector component {s!r} does not match any syntax")
    return compound


def _normalize_nth_arg(arg: str) -> str:
    """CSS An+B allows whitespace around '+'/'-' — '2n + 1' == '2n+1'."""
    return re.sub(r"\s+", "", arg).lower()


def _parse_has_arg(arg: str) -> List[Tuple[Optional[str], List[Tuple[Optional[str, Compound]]]]]:
    """:has() takes RELATIVE selectors — a leading combinator is allowed.

    ":has(> p)"   → children p      ":has(~ p)" → following-sibling p
    ":has(+ p)"   → next sibling p  ":has(p)"   / ":has( p)" → descendant p
    Parsed eagerly so invalid arguments raise SelectorError at parse time.
    """
    out: List[Tuple[Optional[str], List[Tuple[Optional[str, Compound]]]]] = []
    for group in _split_groups(arg):
        g = group.strip()
        if not g:
            raise SelectorError(f"empty group in :has() argument {arg!r}")
        toks = _tokenize_selector(g)
        lead: Optional[str] = None
        if toks and toks[0] in (">", "+", "~", " "):
            lead = toks[0]
            toks = toks[1:]
            if not toks:
                raise SelectorError(
                    f":has() combinator {lead!r} must be followed by a compound "
                    f"selector in {arg!r}"
                )
        out.append((lead, _parse_selector_tokens(toks)))
    if not out:
        raise SelectorError(f":has() argument did not parse: {arg!r}")
    return out


# ---------------------------------------------------------------------------
# Matching / query
# ---------------------------------------------------------------------------

def _query(
    root: Element,
    chain: List[Tuple[Optional[str], Compound]],
    candidates: List[Element],
    ctx: dict,
) -> List[Element]:
    if not chain:
        return []
    _, first = chain[0]
    matched = [el for el in candidates if _match_compound(el, first, ctx)]

    for combinator, compound in chain[1:]:
        next_matched: List[Element] = []
        seen = set()
        for el in matched:
            for cand in _combinator_targets(el, combinator or " "):
                if id(cand) in seen:
                    continue
                if _match_compound(cand, compound, ctx):
                    if _is_under(cand, root) or cand is root:
                        seen.add(id(cand))
                        next_matched.append(cand)
        matched = next_matched

    return matched


def _element_matches_chain(
    el: Element,
    chain: List[Tuple[Optional[str], Compound]],
    ctx: Optional[dict],
) -> bool:
    """Right-to-left match: el must match last compound, ancestors/siblings the rest."""
    if not chain:
        return False
    if ctx is None:
        ctx = {}
    return _match_from_right(el, chain, len(chain) - 1, ctx)


def _match_from_right(
    el: Element,
    chain: List[Tuple[Optional[str], Compound]],
    idx: int,
    ctx: dict,
) -> bool:
    combinator, compound = chain[idx]
    if not _match_compound(el, compound, ctx):
        return False
    if idx == 0:
        return True
    # chain[idx].combinator is the relationship FROM previous TO this:
    # walk relative to el using its inverse to find the previous match.
    if combinator is None:
        return True
    if combinator == " ":
        anc = el.parent
        while anc is not None:
            if isinstance(anc, Element) and anc.tag != "#document":
                if _match_from_right(anc, chain, idx - 1, ctx):
                    return True
            anc = anc.parent
        return False
    if combinator == ">":
        parent = el.parent
        if parent is None or not isinstance(parent, Element) or parent.tag == "#document":
            return False
        return _match_from_right(parent, chain, idx - 1, ctx)
    if combinator == "+":
        sib = el.previous_element_sibling
        if sib is None:
            return False
        return _match_from_right(sib, chain, idx - 1, ctx)
    if combinator == "~":
        if el.parent is None:
            return False
        for s in el.parent.child_elements:
            if s is el:
                break
            if _match_from_right(s, chain, idx - 1, ctx):
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
    """All ELEMENTS strictly below *root* (root itself excluded — bs4 semantics)."""
    out: List[Element] = []
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


# --- sibling index cache (fixes O(n^2) :nth-child on wide sibling sets) ----

def _parent_stats(el: Element, ctx: Optional[dict]) -> Optional[dict]:
    if ctx is None:
        return None
    p = el.parent
    if p is None:
        return None
    cache = ctx.setdefault("parents", {})
    stats = cache.get(id(p))
    if stats is None:
        idx_map: Dict[int, int] = {}
        tag_idx: Dict[str, Dict[int, int]] = {}
        tag_total: Dict[str, int] = {}
        n = 0
        for c in p._children:
            if isinstance(c, Element):
                n += 1
                idx_map[id(c)] = n
                d = tag_idx.setdefault(c.tag, {})
                d[id(c)] = len(d) + 1
                tag_total[c.tag] = len(d)
        stats = {"idx": idx_map, "total": n, "tag_idx": tag_idx, "tag_total": tag_total}
        cache[id(p)] = stats
    return stats


def _nth_among_siblings(el: Element, ctx: Optional[dict], from_last: bool = False) -> int:
    stats = _parent_stats(el, ctx)
    if stats is not None:
        idx = stats["idx"].get(id(el), 1)
        return stats["total"] - idx + 1 if from_last else idx
    if el.parent is None:
        return 1
    sibs = [c for c in el.parent._children if isinstance(c, Element)]
    try:
        idx = sibs.index(el) + 1
    except ValueError:
        return 1
    return len(sibs) - idx + 1 if from_last else idx


def _nth_of_type(el: Element, ctx: dict, from_last: bool = False) -> int:
    p = el.parent
    if p is None:
        return 1
    if ctx is not None:
        stats = _parent_stats(el, ctx)
        if stats is not None:
            idx = stats["tag_idx"].get(el.tag, {}).get(id(el), 1)
            total = stats["tag_total"].get(el.tag, 1)
            return total - idx + 1 if from_last else idx
    n = 0
    for c in p._children:
        if isinstance(c, Element) and c.tag == el.tag:
            n += 1
            if c is el:
                return n
    return 1


def _total_of_type(el: Element, ctx: dict) -> int:
    p = el.parent
    if p is None:
        return 1
    if ctx is not None:
        stats = _parent_stats(el, ctx)
        if stats is not None:
            return stats["tag_total"].get(el.tag, 1)
    return len([s for s in p._children if isinstance(s, Element) and s.tag == el.tag])


def _match_compound(el: Element, c: Compound, ctx: dict) -> bool:
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
    for name, op, val, flag_i in c["attrs"]:
        if not _match_attr(el, name, op, val, flag_i):
            return False
    for chains in c["any_chains"]:
        if not any(_element_matches_chain(el, ch, ctx) for ch in chains):
            return False
    for lead, chain in c["hass"]:
        if _has_matches(el, lead, chain, ctx):
            return True
    if c["hass"]:
        return False
    for pname, parg in c["pseudos"]:
        if not _match_pseudo(el, pname, parg, ctx):
            return False
    for chain in c["nots"]:
        if _element_matches_chain(el, chain, ctx):
            return False
    return True


def _class_list(el: Element) -> List[str]:
    raw = el.get("class", "")
    if isinstance(raw, list):
        return [str(x) for x in raw]
    return str(raw).split()


def _match_attr(
    el: Element,
    name: str,
    op: Optional[str],
    val: Optional[str],
    flag_i: bool = False,
) -> bool:
    if name not in el.attrs:
        return False
    if op is None:
        return True
    actual = str(el.attrs[name])
    if val is None:
        val = ""
    if flag_i:
        actual = actual.lower()
        val = val.lower()
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


def _has_matches(
    el: Element,
    lead: Optional[str],
    chain: List[Tuple[Optional[str], Compound]],
    ctx: dict,
) -> bool:
    """:has(<relative>) — does *el* contain/follow-sibling a match of *chain*?

    *lead* is the optional leading combinator of the relative selector:
    None/" " → descendants, ">" → child elements, "+" → next element
    sibling, "~" → all following element siblings.
    """
    if not chain:
        return False
    if lead in (None, " "):
        scope = [d for d in el.descendants if isinstance(d, Element)]
    elif lead == ">":
        scope = el.child_elements
    elif lead == "+":
        sib = el.next_element_sibling
        scope = [sib] if sib is not None else []
    elif lead == "~":
        scope = _combinator_targets(el, "~")
    else:
        return False
    matched = [c for c in scope if _match_compound(c, chain[0][1], ctx)]
    for combinator, compound in chain[1:]:
        nxt: List[Element] = []
        seen = set()
        for m in matched:
            for cand in _combinator_targets(m, combinator or " "):
                if id(cand) in seen:
                    continue
                if _match_compound(cand, compound, ctx):
                    seen.add(id(cand))
                    nxt.append(cand)
        matched = nxt
    return bool(matched)


def _match_pseudo(el: Element, name: str, arg: Optional[str], ctx: dict) -> bool:
    if name == "first-child":
        return _nth_among_siblings(el, ctx) == 1
    if name == "last-child":
        stats = _parent_stats(el, ctx)
        if stats is not None:
            return stats["idx"].get(id(el)) == stats["total"]
        if el.parent is None:
            return True
        sibs = [s for s in el.parent._children if isinstance(s, Element)]
        return bool(sibs) and sibs[-1] is el
    if name == "only-child":
        stats = _parent_stats(el, ctx)
        if stats is not None:
            return stats["total"] == 1
        if el.parent is None:
            return True
        return len([s for s in el.parent._children if isinstance(s, Element)]) == 1
    if name == "nth-child":
        return _match_nth(el, arg or "1", of_type=False, from_last=False, ctx=ctx)
    if name == "nth-last-child":
        return _match_nth(el, arg or "1", of_type=False, from_last=True, ctx=ctx)
    if name == "nth-of-type":
        return _match_nth(el, arg or "1", of_type=True, from_last=False, ctx=ctx)
    if name == "nth-last-of-type":
        return _match_nth(el, arg or "1", of_type=True, from_last=True, ctx=ctx)
    if name == "first-of-type":
        return _nth_of_type(el, ctx) == 1
    if name == "last-of-type":
        return _nth_of_type(el, ctx) == _total_of_type(el, ctx)
    if name == "only-of-type":
        return _total_of_type(el, ctx) == 1
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
        if not arg or not arg.strip():
            raise SelectorError(":has() requires an argument")
        return bool(select(el, arg.strip()))
    if name in ("is", "where", "matches"):
        raise SelectorError(f":{name}() requires parentheses with an argument")
    if name in _UNSUPPORTED_PSEUDOS:
        raise SelectorError(f"unsupported pseudo-class :{name}")
    raise SelectorError(f"unknown pseudo-class :{name}")


def _match_nth(
    el: Element,
    arg: str,
    of_type: bool = False,
    from_last: bool = False,
    ctx: Optional[dict] = None,
) -> bool:
    if ctx is None:
        ctx = {}
    arg = _normalize_nth_arg(arg)
    idx = _nth_of_type(el, ctx, from_last) if of_type else _nth_among_siblings(el, ctx, from_last)
    if arg == "odd":
        return idx % 2 == 1
    if arg == "even":
        return idx % 2 == 0
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
        if (idx - b) % a == 0:
            n = (idx - b) // a
            return n >= 0
        return False
    try:
        return idx == int(arg)
    except ValueError:
        raise SelectorError(f"invalid nth argument {arg!r}") from None
