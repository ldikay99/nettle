"""Text cleaning — Nettle's differentiator vs BeautifulSoup.

BeautifulSoup gives you raw DOM text; you still fight ``\\xa0``, entities,
invisible chars, and messy whitespace. Nettle cleans at extract time.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Optional

# ---------------------------------------------------------------------------
# Comprehensive named HTML entities (common HTML5 subset — stdlib only)
# ---------------------------------------------------------------------------

NAMED_ENTITIES: dict[str, str] = {
    # XML / core
    "amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'",
    # whitespace / punctuation
    "nbsp": "\u00a0", "ensp": "\u2002", "emsp": "\u2003", "thinsp": "\u2009",
    "zwnj": "\u200c", "zwj": "\u200d", "lrm": "\u200e", "rlm": "\u200f",
    "shy": "\u00ad",
    "ndash": "\u2013", "mdash": "\u2014", "horbar": "\u2015",
    "hellip": "\u2026", "middot": "\u00b7", "bull": "\u2022",
    "lsquo": "\u2018", "rsquo": "\u2019", "sbquo": "\u201a",
    "ldquo": "\u201c", "rdquo": "\u201d", "bdquo": "\u201e",
    "laquo": "\u00ab", "raquo": "\u00bb",
    "prime": "\u2032", "Prime": "\u2033",
    # currency / symbols
    "cent": "\u00a2", "pound": "\u00a3", "yen": "\u00a5", "euro": "\u20ac",
    "curren": "\u00a4", "copy": "\u00a9", "reg": "\u00ae", "trade": "\u2122",
    "sect": "\u00a7", "para": "\u00b6", "deg": "\u00b0", "plusmn": "\u00b1",
    "times": "\u00d7", "divide": "\u00f7", "frac12": "\u00bd",
    "frac14": "\u00bc", "frac34": "\u00be",
    "iexcl": "\u00a1", "iquest": "\u00bf", "brvbar": "\u00a6",
    "uml": "\u00a8", "not": "\u00ac", "macr": "\u00af", "acute": "\u00b4",
    "micro": "\u00b5", "cedil": "\u00b8", "ordf": "\u00aa", "ordm": "\u00ba",
    "sup1": "\u00b9", "sup2": "\u00b2", "sup3": "\u00b3",
    # arrows / math-ish
    "larr": "\u2190", "uarr": "\u2191", "rarr": "\u2192", "darr": "\u2193",
    "harr": "\u2194", "crarr": "\u21b5",
    "forall": "\u2200", "part": "\u2202", "exist": "\u2203", "empty": "\u2205",
    "nabla": "\u2207", "isin": "\u2208", "notin": "\u2209", "ni": "\u220b",
    "prod": "\u220f", "sum": "\u2211", "minus": "\u2212", "lowast": "\u2217",
    "radic": "\u221a", "prop": "\u221d", "infin": "\u221e", "ang": "\u2220",
    "and": "\u2227", "or": "\u2228", "cap": "\u2229", "cup": "\u222a",
    "int": "\u222b", "there4": "\u2234", "sim": "\u223c", "cong": "\u2245",
    "asymp": "\u2248", "ne": "\u2260", "equiv": "\u2261",
    "le": "\u2264", "ge": "\u2265", "sub": "\u2282", "sup": "\u2283",
    "nsub": "\u2284", "sube": "\u2286", "supe": "\u2287",
    "oplus": "\u2295", "otimes": "\u2297", "perp": "\u22a5", "sdot": "\u22c5",
    # Latin-1 letters (common named)
    "Agrave": "\u00c0", "Aacute": "\u00c1", "Acirc": "\u00c2", "Atilde": "\u00c3",
    "Auml": "\u00c4", "Aring": "\u00c5", "AElig": "\u00c6", "Ccedil": "\u00c7",
    "Egrave": "\u00c8", "Eacute": "\u00c9", "Ecirc": "\u00ca", "Euml": "\u00cb",
    "Igrave": "\u00cc", "Iacute": "\u00cd", "Icirc": "\u00ce", "Iuml": "\u00cf",
    "ETH": "\u00d0", "Ntilde": "\u00d1", "Ograve": "\u00d2", "Oacute": "\u00d3",
    "Ocirc": "\u00d4", "Otilde": "\u00d5", "Ouml": "\u00d6", "Oslash": "\u00d8",
    "Ugrave": "\u00d9", "Uacute": "\u00da", "Ucirc": "\u00db", "Uuml": "\u00dc",
    "Yacute": "\u00dd", "THORN": "\u00de", "szlig": "\u00df",
    "agrave": "\u00e0", "aacute": "\u00e1", "acirc": "\u00e2", "atilde": "\u00e3",
    "auml": "\u00e4", "aring": "\u00e5", "aelig": "\u00e6", "ccedil": "\u00e7",
    "egrave": "\u00e8", "eacute": "\u00e9", "ecirc": "\u00ea", "euml": "\u00eb",
    "igrave": "\u00ec", "iacute": "\u00ed", "icirc": "\u00ee", "iuml": "\u00ef",
    "eth": "\u00f0", "ntilde": "\u00f1", "ograve": "\u00f2", "oacute": "\u00f3",
    "ocirc": "\u00f4", "otilde": "\u00f5", "ouml": "\u00f6", "oslash": "\u00f8",
    "ugrave": "\u00f9", "uacute": "\u00fa", "ucirc": "\u00fb", "uuml": "\u00fc",
    "yacute": "\u00fd", "thorn": "\u00fe", "yuml": "\u00ff",
    "OElig": "\u0152", "oelig": "\u0153", "Scaron": "\u0160", "scaron": "\u0161",
    "Yuml": "\u0178", "fnof": "\u0192",
    # Greek (common)
    "Alpha": "\u0391", "Beta": "\u0392", "Gamma": "\u0393", "Delta": "\u0394",
    "Epsilon": "\u0395", "Zeta": "\u0396", "Eta": "\u0397", "Theta": "\u0398",
    "Iota": "\u0399", "Kappa": "\u039a", "Lambda": "\u039b", "Mu": "\u039c",
    "Nu": "\u039d", "Xi": "\u039e", "Omicron": "\u039f", "Pi": "\u03a0",
    "Rho": "\u03a1", "Sigma": "\u03a3", "Tau": "\u03a4", "Upsilon": "\u03a5",
    "Phi": "\u03a6", "Chi": "\u03a7", "Psi": "\u03a8", "Omega": "\u03a9",
    "alpha": "\u03b1", "beta": "\u03b2", "gamma": "\u03b3", "delta": "\u03b4",
    "epsilon": "\u03b5", "zeta": "\u03b6", "eta": "\u03b7", "theta": "\u03b8",
    "iota": "\u03b9", "kappa": "\u03ba", "lambda": "\u03bb", "mu": "\u03bc",
    "nu": "\u03bd", "xi": "\u03be", "omicron": "\u03bf", "pi": "\u03c0",
    "rho": "\u03c1", "sigmaf": "\u03c2", "sigma": "\u03c3", "tau": "\u03c4",
    "upsilon": "\u03c5", "phi": "\u03c6", "chi": "\u03c7", "psi": "\u03c8",
    "omega": "\u03c9",
}

# NOTE: the trailing ';' is REQUIRED. Text reaching this layer was usually
# entity-decoded already by the parser; decoding legacy no-semicolon forms
# again would corrupt data (e.g. URLs containing &copy=2 → ©=2).
_ENTITY_RE = re.compile(
    r"&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z][a-zA-Z0-9]+);"
)

_INVISIBLE_CHARS = (
    "\u00ad"
    "\u200b"
    "\u200c"
    "\u200d"
    "\u200e"
    "\u200f"
    "\u2060"
    "\ufeff"
    "\u180e"
)

_INVISIBLE_RE = re.compile("[" + re.escape(_INVISIBLE_CHARS) + "]")

_SPACE_LIKE = {
    "\u00a0": " ",
    "\u1680": " ",
    "\u2000": " ", "\u2001": " ", "\u2002": " ", "\u2003": " ",
    "\u2004": " ", "\u2005": " ", "\u2006": " ", "\u2007": " ",
    "\u2008": " ", "\u2009": " ", "\u200a": " ",
    "\u202f": " ", "\u205f": " ", "\u3000": " ",
}

_WS_RUN = re.compile(r"[ \t\f\v]+")
_NL_RUN = re.compile(r"\n{3,}")
_ALL_WS_RUN = re.compile(r"\s+")

_NOISE_PATTERNS = [
    re.compile(r"[\u200b-\u200f\ufeff]+"),
]


def decode_entities(s: str, keep_unknown: bool = True) -> str:
    """Decode named and numeric HTML entities comprehensively."""
    if not s or "&" not in s:
        return s

    def repl(m: re.Match) -> str:
        body = m.group(1)
        if body.startswith("#x") or body.startswith("#X"):
            try:
                return chr(int(body[2:], 16))
            except (ValueError, OverflowError):
                return m.group(0) if keep_unknown else ""
        if body.startswith("#"):
            try:
                return chr(int(body[1:]))
            except (ValueError, OverflowError):
                return m.group(0) if keep_unknown else ""
        if body in NAMED_ENTITIES:
            return NAMED_ENTITIES[body]
        low = body.lower()
        for k, v in NAMED_ENTITIES.items():
            if k.lower() == low:
                return v
        return m.group(0) if keep_unknown else ""

    return _ENTITY_RE.sub(repl, s)


def remove_invisible(s: str) -> str:
    """Strip zero-width / bidirectional / soft-hyphen / BOM characters."""
    if not s:
        return s
    return _INVISIBLE_RE.sub("", s)


def normalize_unicode(s: str, form: str = "NFC") -> str:
    """Normalize Unicode (NFC by default)."""
    if not s:
        return s
    return unicodedata.normalize(form, s)


def collapse_ws(s: str, keep_newlines: bool = False) -> str:
    """Collapse whitespace runs."""
    if not s:
        return s
    for ch, repl in _SPACE_LIKE.items():
        if ch in s:
            s = s.replace(ch, repl)
    if keep_newlines:
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        lines = []
        for line in s.split("\n"):
            line = _WS_RUN.sub(" ", line).strip()
            lines.append(line)
        s = "\n".join(lines)
        s = _NL_RUN.sub("\n\n", s)
        return s.strip("\n")
    return _ALL_WS_RUN.sub(" ", s).strip()


def strip_noise(s: str) -> str:
    """Remove common scrape noise (ZWSP leftovers, etc.)."""
    if not s:
        return s
    s = remove_invisible(s)
    for pat in _NOISE_PATTERNS:
        s = pat.sub("", s)
    return s


def clean_text(
    s: Optional[str],
    mode: str = "plain",
    *,
    decode: bool = True,
    unicode_form: str = "NFC",
) -> str:
    """Aggressively but controllably clean scraped text.

    Modes: plain | strict | keep_newlines | raw | none

    decode=True decodes HTML entities — use it for RAW external strings.
    Text coming from nettle's parser is already entity-decoded; pass
    decode=False there (nettle's extract pipeline does this) or literal
    text like "&nbsp;" would be decoded a second time and corrupted.
    """
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    if mode == "none":
        return s
    if mode not in ("plain", "strict", "keep_newlines", "raw"):
        raise ValueError(f"unknown clean mode {mode!r} (plain|strict|keep_newlines|raw|none)")

    if decode:
        s = decode_entities(s)

    if mode == "raw":
        return s

    s = remove_invisible(s)
    s = normalize_unicode(s, unicode_form)

    if mode == "strict":
        s = "".join(
            ch for ch in s
            if ch in "\t\n\r" or (unicodedata.category(ch)[0] != "C")
        )
        s = collapse_ws(s, keep_newlines=False)
        return s

    if mode == "keep_newlines":
        return collapse_ws(s, keep_newlines=True)

    return collapse_ws(s, keep_newlines=False)


def soft_strip(s: str) -> str:
    """Strip ends and replace nbsp with space — light cleanup."""
    if not s:
        return s
    return s.replace("\u00a0", " ").strip()
