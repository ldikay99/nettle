"""HTML tokenizer and tree builder (stdlib only).

Recovery strategy (documented, intentionally simple):
- Unclosed tags are closed when a parent end-tag is seen, or when an
  auto-close rule fires (p, li, td, tr, etc.).
- Void tags never get children.
- script/style/textarea/title content is treated as raw text until the
  matching closing tag (case-insensitive).
- Unknown / mismatched end tags are ignored if not on the open stack.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .nodes import (
    AUTO_CLOSE_ON_OPEN,
    BLOCK_CLOSES_P,
    VOID_TAGS,
    Comment,
    Document,
    Element,
    Text,
)

# Raw-text elements: content until closing tag, no nested parsing
RAW_TEXT_TAGS = frozenset({"script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes", "noscript"})

# RCDATA per the HTML5 spec: raw text BUT character references ARE processed.
# Found in the wild: <title>Bolet&iacute;n</title> on boe.es left mojibake
# when these were treated like script/style.
ESCAPABLE_RAW_TEXT_TAGS = frozenset({"textarea", "title"})

_WS = re.compile(r"\s+")


def parse(
    html: "str | bytes",
    *,
    encoding: str | None = None,
    on_error: str = "recover",
    backend: str | None = None,
) -> Document:
    """Parse HTML into a Document tree.

    Parameters
    ----------
    html:
        String or bytes. Bytes trigger charset sniffing (BOM / meta / fallback).
    encoding:
        Force decode encoding for bytes input.
    on_error:
        ``recover`` (default) builds a best-effort tree; ``raise`` re-raises
        unexpected tokenizer errors as ParseError.
    backend:
        ``"pure"`` — stdlib engine (default for small inputs).
        ``"lxml"`` — OPTIONAL accelerated tokenizer (lxml.etree if
        installed; silently falls back to ``"pure"`` otherwise, recording
        the outcome in ``registry.parse["prefer_lxml"]``). Same nettle
        nodes/API; see nettle/_lxml_backend.py for documented micro-
        divergences on malformed input.
        ``"auto"`` (also the default when omitted) — ``"lxml"`` for inputs
        of at least ``registry.parse["auto_lxml_threshold"]`` characters
        (factory 10 MB) when lxml is available and
        ``registry.parse["prefer_lxml"]`` is truthy; ``"pure"`` otherwise.
    """
    from .exceptions import ParseError

    if html is None:
        raise ParseError(
            "parse() input must be str or bytes, got None — "
            "did the fetch/HTTP call return None before parsing?"
        )
    size: int
    if isinstance(html, (bytes, bytearray)):
        html = bytes(html)
        size = len(html)
        enc = encoding or detect_charset(html) or "utf-8"
        try:
            html = html.decode(enc, errors="replace")
        except LookupError:
            raise ParseError(
                f"unknown encoding {enc!r} — pass a valid codec name "
                "(e.g. encoding='utf-8') or omit it to autodetect"
            ) from None
    elif not isinstance(html, str):
        if hasattr(html, "read"):
            try:
                html = html.read()
            except Exception as e:
                raise ParseError(f"could not read file-like input: {e}") from e
            return parse(html, encoding=encoding, on_error=on_error, backend=backend)
        raise ParseError(
            f"parse() input must be str or bytes, got {type(html).__name__} "
            f"(value {html!r:.60}) — convert it first: parse(str(x))"
        )
    else:
        size = len(html)
    if html.startswith("\ufeff"):  # strip BOM leftover after decode
        html = html[1:]

    if _use_lxml(backend, size):
        from ._lxml_backend import parse_with_lxml
        return parse_with_lxml(html, on_error=on_error)

    builder = TreeBuilder()
    tokenizer = Tokenizer(html, builder)
    try:
        tokenizer.run()
    except Exception as e:
        if on_error == "raise":
            raise ParseError(str(e)) from e
        # recover: return whatever was built
    # close remaining open elements (except document)
    while len(builder.open) > 1:
        builder.open.pop()
    return builder.document


def _use_lxml(backend: str | None, size: int) -> bool:
    """Resolve the backend request against availability + registry gates."""
    from .registry import registry as _registry

    mode = backend or "auto"
    if mode == "pure":
        return False
    if mode not in ("lxml", "auto"):
        from .exceptions import ParseError
        raise ParseError(
            f"parse(backend=...) must be 'pure', 'lxml' or 'auto', got {backend!r}"
        )
    from ._lxml_backend import lxml_available
    if not lxml_available():
        # silent fallback — record it so operators can see why big docs
        # are not accelerating
        _registry.parse["prefer_lxml"] = False
        return False
    if mode == "lxml":
        return True
    if not _registry.parse.get("prefer_lxml", True):
        return False
    return size >= int(_registry.parse.get("auto_lxml_threshold", 10 * 1024 * 1024))


_META_CHARSET_RE = re.compile(
    rb'<meta[^>]+charset\s*=\s*["\']?([\w\-]+)', re.I)
_META_HTTP_EQUIV_RE = re.compile(
    rb'<meta[^>]+http-equiv\s*=\s*["\']?content-type["\']?[^>]+content\s*=\s*["\']?[^"\']*charset=([\w\-]+)',
    re.I)
_META_HTTP_EQUIV_RE2 = re.compile(
    rb'<meta[^>]+content\s*=\s*["\']?[^"\']*charset=([\w\-]+)[^>]+http-equiv\s*=\s*["\']?content-type',
    re.I)


def detect_charset(data: bytes) -> str | None:
    """Sniff charset from BOM, UTF-16 null-byte pattern, or ``<meta charset>``
    / http-equiv in the first registry.parse["charset_sniff_bytes"] bytes
    (default 8192)."""
    from .registry import registry as _registry
    if not data:
        return None
    # BOM
    if data.startswith(b"\xef\xbb\xbf"):
        return "utf-8"
    if data.startswith(b"\xff\xfe"):
        return "utf-16-le"
    if data.startswith(b"\xfe\xff"):
        return "utf-16-be"
    # UTF-16 without BOM: ASCII-heavy markup turns into NUL at every other
    # byte ('<' = 3C 00 LE / 00 3C BE). Require an unambiguous pattern —
    # one parity full of NULs, the other NUL-free — so UTF-32 (NULs on both
    # parities) and binary never misfire.
    enc = _sniff_utf16_no_bom(data)
    if enc:
        return enc
    head = data[:int(_registry.parse["charset_sniff_bytes"])]
    m = _META_CHARSET_RE.search(head)
    if m:
        return m.group(1).decode("ascii", errors="ignore").lower()
    m = _META_HTTP_EQUIV_RE.search(head) or _META_HTTP_EQUIV_RE2.search(head)
    if m:
        return m.group(1).decode("ascii", errors="ignore").lower()
    return None


def _sniff_utf16_no_bom(data: bytes) -> str | None:
    """'utf-16-le' / 'utf-16-be' / None — null-byte parity heuristic."""
    window = data[:32]
    if len(window) < 4:
        return None
    even_nuls = sum(1 for i in range(0, len(window), 2) if window[i] == 0)
    odd_nuls = sum(1 for i in range(1, len(window), 2) if window[i] == 0)
    pairs = len(window) // 2
    if even_nuls >= max(2, pairs // 2) and odd_nuls == 0:
        return "utf-16-be"
    if odd_nuls >= max(2, pairs // 2) and even_nuls == 0:
        return "utf-16-le"
    return None


class TreeBuilder:
    def __init__(self, *, fixup: bool = True) -> None:
        self.document = Document()
        self.open: List[Element] = [self.document]
        self._raw_until: Optional[str] = None  # tag name awaiting close
        # fixup=False: the event source is already balanced (lxml backend) —
        # nettle's own auto-close recovery would only burn time scanning
        # the open stack on every start tag.
        self._fixup = fixup

    @property
    def current(self) -> Element:
        return self.open[-1]

    def handle_doctype(self, content: str) -> None:
        self.document.doctype = content.strip()

    def handle_comment(self, content: str) -> None:
        if self._raw_until:
            self._append_text(f"<!--{content}-->")
            return
        self.current.append(Comment(content))

    def handle_text(self, text: str, *, decoded: bool = False) -> None:
        """Feed a text run. decoded=True (accelerated backends) means
        character references were already resolved upstream — skip the
        entity pass (a second pass would corrupt ``&amp;copy`` → ``©``)."""
        if not text:
            return
        if not decoded and (not self._raw_until or self._raw_until in ESCAPABLE_RAW_TEXT_TAGS):
            # script/style/xmp/... stay raw (no entity processing); title and
            # textarea are RCDATA — browsers decode entities inside them.
            from .registry import registry as _registry
            if _registry.parse.get("legacy_entities", True):
                text = _decode_entities(text, legacy=True)
            else:
                text = _decode_entities(text)
        self._append_text(text)

    def _append_text(self, text: str) -> None:
        kids = self.current._children
        if kids and isinstance(kids[-1], Text):
            kids[-1].content += text
        else:
            self.current.append(Text(text))

    def handle_start(self, tag: str, attrs: Dict[str, str], self_closing: bool = False) -> None:
        tag = tag.lower()
        if self._raw_until:
            # emit as text
            attr_s = "".join(
                f' {k}="{v}"' if v else f" {k}" for k, v in attrs.items()
            )
            slash = "/" if self_closing else ""
            self._append_text(f"<{tag}{attr_s}{slash}>")
            return

        # Auto-close rules
        if self._fixup:
            self._auto_close_before_open(tag)

        el = Element(tag, attrs)
        self.current.append(el)

        is_void = tag in VOID_TAGS or self_closing
        if not is_void:
            self.open.append(el)
            if tag in RAW_TEXT_TAGS:
                self._raw_until = tag

    def handle_end(self, tag: str) -> None:
        tag = tag.lower()

        if self._raw_until:
            if tag == self._raw_until:
                self._raw_until = None
                # pop the raw element
                if len(self.open) > 1 and self.open[-1].tag == tag:
                    self.open.pop()
            else:
                self._append_text(f"</{tag}>")
            return

        # fast path: the usual case — the end tag matches the innermost
        # open element (always true for balanced event streams like lxml's)
        if len(self.open) > 1 and self.open[-1].tag == tag:
            self.open.pop()
            return

        # Find matching open element
        idx = None
        for i in range(len(self.open) - 1, 0, -1):  # skip document
            if self.open[i].tag == tag:
                idx = i
                break
        if idx is None:
            return  # ignore stray end tag

        # Close everything from current down to idx
        while len(self.open) > idx:
            self.open.pop()

    def _auto_close_before_open(self, tag: str) -> None:
        # Close an open <p> when another <p> or a block-level tag opens
        if tag == "p" or tag in BLOCK_CLOSES_P:
            self._close_nearest("p", stop_at=frozenset({
                "div", "td", "th", "li", "body", "html", "section", "article",
                "form", "blockquote", "table", "ul", "ol",
            }))

        targets = AUTO_CLOSE_ON_OPEN.get(tag)
        if not targets:
            return
        # Close nearest open conflicting tag without crossing structural parents
        stop_at = frozenset({
            "html", "body", "table", "ul", "ol", "menu", "dl", "select",
            "tbody", "thead", "tfoot", "tr", "div", "section", "article",
        })
        # For table cells / rows, allow closing inside table structures
        if tag in ("td", "th", "tr", "thead", "tbody", "tfoot"):
            stop_at = frozenset({"html", "body", "table"})
        if tag == "li":
            stop_at = frozenset({"html", "body", "ul", "ol", "menu"})
        if tag in ("dt", "dd"):
            stop_at = frozenset({"html", "body", "dl"})

        i = len(self.open) - 1
        while i > 0:
            cur = self.open[i].tag
            if cur in targets:
                while len(self.open) > i:
                    self.open.pop()
                return
            if cur in stop_at:
                return
            i -= 1

    def _close_nearest(self, tag: str, stop_at: frozenset) -> None:
        for i in range(len(self.open) - 1, 0, -1):
            cur = self.open[i].tag
            if cur == tag:
                while len(self.open) > i:
                    self.open.pop()
                return
            if cur in stop_at and cur != tag:
                # keep searching for p inside containers like div
                if tag == "p" and cur not in ("table", "ul", "ol"):
                    continue
                return


class Tokenizer:
    def __init__(self, html: str, builder: TreeBuilder) -> None:
        self.html = html
        self.pos = 0
        self.n = len(html)
        self.builder = builder

    def run(self) -> None:
        while self.pos < self.n:
            if self.builder._raw_until:
                self._consume_raw()
                continue
            ch = self.html[self.pos]
            if ch == "<":
                if self._try_comment_or_doctype():
                    continue
                if self._try_tag():
                    continue
                # literal <
                self.builder.handle_text("<")
                self.pos += 1
            else:
                self._consume_text()

    def _peek(self, n: int = 1) -> str:
        return self.html[self.pos:self.pos + n]

    def _consume_text(self) -> None:
        start = self.pos
        while self.pos < self.n and self.html[self.pos] != "<":
            self.pos += 1
        self.builder.handle_text(self.html[start:self.pos])

    def _consume_raw(self) -> None:
        """Consume until closing tag for raw-text element."""
        tag = self.builder._raw_until
        assert tag is not None
        # Find </tag> case-insensitive
        pattern = re.compile(r"</\s*" + re.escape(tag) + r"\s*>", re.IGNORECASE)
        m = pattern.search(self.html, self.pos)
        if m:
            text = self.html[self.pos:m.start()]
            if text:
                self.builder.handle_text(text)
            self.pos = m.end()
            self.builder.handle_end(tag)
        else:
            # rest is text, never closed
            text = self.html[self.pos:]
            if text:
                self.builder.handle_text(text)
            self.pos = self.n
            # leave raw mode; element stays open until EOF cleanup
            self.builder._raw_until = None

    def _try_comment_or_doctype(self) -> bool:
        if self._peek(4) == "<!--":
            self.pos += 4
            end = self.html.find("-->", self.pos)
            if end == -1:
                content = self.html[self.pos:]
                self.pos = self.n
            else:
                content = self.html[self.pos:end]
                self.pos = end + 3
            self.builder.handle_comment(content)
            return True

        # <!DOCTYPE ...> or <![CDATA[...]]> or other <!...>
        if self._peek(2) == "<!":
            upper = self.html[self.pos:self.pos + 9].upper()
            if upper.startswith("<!DOCTYPE"):
                self.pos += 2  # <!
                # read until >
                start = self.pos
                while self.pos < self.n and self.html[self.pos] != ">":
                    self.pos += 1
                content = self.html[start:self.pos]
                # strip DOCTYPE keyword
                content = re.sub(r"^DOCTYPE\s*", "", content, flags=re.IGNORECASE)
                if self.pos < self.n:
                    self.pos += 1
                self.builder.handle_doctype(content)
                return True
            # other declaration / bogus comment
            self.pos += 2
            start = self.pos
            while self.pos < self.n and self.html[self.pos] != ">":
                self.pos += 1
            content = self.html[start:self.pos]
            if self.pos < self.n:
                self.pos += 1
            self.builder.handle_comment(content)
            return True

        # processing instruction <?...?>
        if self._peek(2) == "<?":
            self.pos += 2
            start = self.pos
            while self.pos < self.n and self.html[self.pos] != ">":
                self.pos += 1
            content = self.html[start:self.pos]
            if self.pos < self.n:
                self.pos += 1
            self.builder.handle_comment("?" + content)
            return True

        return False

    def _try_tag(self) -> bool:
        # Must look like a tag: <name or </name
        if self.pos + 1 >= self.n:
            return False
        nxt = self.html[self.pos + 1]
        if not (nxt.isalpha() or nxt == "/"):
            return False

        self.pos += 1  # skip <
        is_end = False
        if self.pos < self.n and self.html[self.pos] == "/":
            is_end = True
            self.pos += 1

        # tag name
        start = self.pos
        while self.pos < self.n and _is_name_char(self.html[self.pos]):
            self.pos += 1
        if start == self.pos:
            # not a valid tag — rewind conceptually already past <
            # emit < as text by returning False after undoing — messy
            # restore: we already advanced; caller expects False to mean
            # not a tag. Rewind.
            self.pos = start - (2 if is_end else 1)
            return False

        tag = self.html[start:self.pos]

        if is_end:
            self._skip_ws()
            if self.pos < self.n and self.html[self.pos] == ">":
                self.pos += 1
            else:
                # skip until >
                while self.pos < self.n and self.html[self.pos] != ">":
                    self.pos += 1
                if self.pos < self.n:
                    self.pos += 1
            self.builder.handle_end(tag)
            return True

        # attributes
        attrs: Dict[str, str] = {}
        self_closing = False
        while self.pos < self.n:
            self._skip_ws()
            if self.pos >= self.n:
                break
            ch = self.html[self.pos]
            if ch == ">":
                self.pos += 1
                break
            if ch == "/":
                self.pos += 1
                self._skip_ws()
                if self.pos < self.n and self.html[self.pos] == ">":
                    self.pos += 1
                    self_closing = True
                    break
                continue
            # attribute name
            name, value = self._read_attr()
            if name is None:
                # skip garbage char
                self.pos += 1
                continue
            # HTML spec: on duplicate attributes the FIRST occurrence wins
            attrs.setdefault(name.lower(), value)

        self.builder.handle_start(tag, attrs, self_closing)
        return True

    def _skip_ws(self) -> None:
        while self.pos < self.n and self.html[self.pos] in " \t\n\r\f":
            self.pos += 1

    def _read_attr(self) -> Tuple[Optional[str], str]:
        start = self.pos
        while self.pos < self.n and _is_attr_name_char(self.html[self.pos]):
            self.pos += 1
        if start == self.pos:
            return None, ""
        name = self.html[start:self.pos]
        self._skip_ws()
        if self.pos >= self.n or self.html[self.pos] != "=":
            return name, ""
        self.pos += 1  # =
        self._skip_ws()
        if self.pos >= self.n:
            return name, ""
        ch = self.html[self.pos]
        if ch in ('"', "'"):
            quote = ch
            self.pos += 1
            vstart = self.pos
            while self.pos < self.n and self.html[self.pos] != quote:
                self.pos += 1
            value = self.html[vstart:self.pos]
            if self.pos < self.n:
                self.pos += 1
            return name, _decode_attr_value(value)
        # unquoted — per HTML spec, '/' is part of the value (href=/a/b works)
        vstart = self.pos
        while self.pos < self.n and self.html[self.pos] not in " \t\n\r\f>":
            self.pos += 1
        value = self.html[vstart:self.pos]
        return name, _decode_attr_value(value)


def _decode_attr_value(value: str) -> str:
    """Attribute context: legacy no-';' names decode only when NOT followed
    by '=' or an alphanumeric char (HTML5 tokenizer rule) — keeps URLs like
    '?a=1&copy=2' intact while still decoding 'title="AT&T &copy 2024"'."""
    from .registry import registry as _registry
    if _registry.parse.get("legacy_entities", True):
        return _decode_entities(value, legacy=True, attribute=True)
    return _decode_entities(value)


def _is_name_char(ch: str) -> bool:
    return ch.isalnum() or ch in "-:"


def _is_attr_name_char(ch: str) -> bool:
    return ch not in " \t\n\r\f/>=\"'" and ch != "<"


# ---------------------------------------------------------------------------
# Legacy named entities: HTML5 allows a fixed ~100-name subset to appear
# WITHOUT the trailing ';' (broken CMS output like "&copy 2024" is endemic).
# The table is the exact stdlib one (html.entities.html5 no-semicolon keys),
# so we stay spec-accurate without hardcoding anything.
# ---------------------------------------------------------------------------

_LEGACY_NAMED: Dict[str, str] = {}
_SEMI_ENTITIES: Dict[str, str] = {}
_LEGACY_SORTED: List[str] = []


def _legacy_tables() -> tuple:
    """Lazily build both entity tables from the stdlib HTML5 table (exact,
    nothing curated by hand):

    * _SEMI_ENTITIES — every ``name;`` form
    * _LEGACY_NAMED  — the legacy subset allowed WITHOUT ``;`` (``&copy 2024``)
    """
    global _LEGACY_NAMED, _LEGACY_SORTED, _SEMI_ENTITIES
    if not _LEGACY_SORTED:
        from html.entities import html5
        _SEMI_ENTITIES = {
            k[:-1]: v for k, v in html5.items() if k.endswith(";")
        }
        _LEGACY_NAMED = {
            k: v for k, v in html5.items() if not k.endswith(";")
        }
        _LEGACY_SORTED = sorted(_LEGACY_NAMED, key=len, reverse=True)
    return _LEGACY_NAMED, _LEGACY_SORTED


_ENTITY_TOKEN_RE = re.compile(
    r"&(#[xX][0-9a-fA-F]{1,8};?|#[0-9]{1,10};?|[a-zA-Z][a-zA-Z0-9]{0,30};?)"
)


def _decode_entities(s: str, legacy: bool = False, attribute: bool = False) -> str:
    """Decode character references in ONE pass (no re-scanning of output, so
    ``&amp;nbsp;`` stays ``&nbsp;`` exactly like browsers).

    With-';' forms always decode (full HTML5 table). When *legacy* is True
    (parser text nodes) the no-semicolon legacy forms decode too, longest
    match first: ``&copy 2024`` → ``© 2024``, ``&notit;`` → ``¬it;``.
    In *attribute* context a legacy name not followed by ';' is kept when the
    next char is '=' or alphanumeric, so ``?a=1&copy=2`` survives (browsers).
    """
    if "&" not in s:
        return s
    legacy_named, _unused = _legacy_tables()

    def repl(m: re.Match) -> str:
        raw = m.group(1)
        has_semi = raw.endswith(";")
        body = raw[:-1] if has_semi else raw
        if body.startswith("#"):
            try:
                ch = chr(int(body[2:], 16)) if body[1] in "xX" else chr(int(body[1:]))
            except (ValueError, OverflowError):
                return m.group(0)
            return ch if (has_semi or legacy) else m.group(0)
        if has_semi:
            v = _SEMI_ENTITIES.get(body)
            if v is not None:
                return v
        if not legacy:
            return m.group(0)
        # longest legacy name prefixing body (HTML5 tokenizer behavior)
        n = len(body)
        for i in range(min(n, 32), 1, -1):
            name = body[:i]
            if name in legacy_named:
                if attribute:
                    nxt = body[i] if i < n else m.string[m.end():m.end() + 1]
                    if nxt and (nxt.isalnum() or nxt == "="):
                        return m.group(0)
                if i == n:
                    return legacy_named[name]
                # prefix matched, remainder (plus an unconsumed ';') is text
                return legacy_named[name] + body[i:] + (";" if has_semi else "")
        return m.group(0)

    return _ENTITY_TOKEN_RE.sub(repl, s)
