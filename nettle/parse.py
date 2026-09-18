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

_WS = re.compile(r"\s+")


def parse(
    html: "str | bytes",
    *,
    encoding: str | None = None,
    on_error: str = "recover",
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
    """
    from .exceptions import ParseError

    if isinstance(html, bytes):
        enc = encoding or detect_charset(html) or "utf-8"
        try:
            html = html.decode(enc, errors="replace")
        except LookupError:
            html = html.decode("utf-8", errors="replace")
    elif not isinstance(html, str):
        html = str(html)
    if html.startswith("\ufeff"):  # strip BOM leftover after decode
        html = html[1:]

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


_META_CHARSET_RE = re.compile(
    rb'<meta[^>]+charset\s*=\s*["\']?([\w\-]+)', re.I)
_META_HTTP_EQUIV_RE = re.compile(
    rb'<meta[^>]+http-equiv\s*=\s*["\']?content-type["\']?[^>]+content\s*=\s*["\']?[^"\']*charset=([\w\-]+)',
    re.I)
_META_HTTP_EQUIV_RE2 = re.compile(
    rb'<meta[^>]+content\s*=\s*["\']?[^"\']*charset=([\w\-]+)[^>]+http-equiv\s*=\s*["\']?content-type',
    re.I)


def detect_charset(data: bytes) -> str | None:
    """Sniff charset from BOM or ``<meta charset>`` / http-equiv in the first 8KB."""
    if not data:
        return None
    # BOM
    if data.startswith(b"\xef\xbb\xbf"):
        return "utf-8"
    if data.startswith(b"\xff\xfe"):
        return "utf-16-le"
    if data.startswith(b"\xfe\xff"):
        return "utf-16-be"
    head = data[:8192]
    m = _META_CHARSET_RE.search(head)
    if m:
        return m.group(1).decode("ascii", errors="ignore").lower()
    m = _META_HTTP_EQUIV_RE.search(head) or _META_HTTP_EQUIV_RE2.search(head)
    if m:
        return m.group(1).decode("ascii", errors="ignore").lower()
    return None


class TreeBuilder:
    def __init__(self) -> None:
        self.document = Document()
        self.open: List[Element] = [self.document]
        self._raw_until: Optional[str] = None  # tag name awaiting close

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

    def handle_text(self, text: str) -> None:
        if not text:
            return
        if not self._raw_until:
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
            return name, _decode_entities(value)
        # unquoted — per HTML spec, '/' is part of the value (href=/a/b works)
        vstart = self.pos
        while self.pos < self.n and self.html[self.pos] not in " \t\n\r\f>":
            self.pos += 1
        value = self.html[vstart:self.pos]
        return name, _decode_entities(value)


def _is_name_char(ch: str) -> bool:
    return ch.isalnum() or ch in "-:"


def _is_attr_name_char(ch: str) -> bool:
    return ch not in " \t\n\r\f/>=\"'" and ch != "<"


_ENTITY_RE = re.compile(
    r"&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z][a-zA-Z0-9]+);"
)

def _named_entities() -> dict:
    try:
        from .text import NAMED_ENTITIES
        return NAMED_ENTITIES
    except Exception:
        return {
            "amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'",
            "nbsp": "\u00a0",
        }


_NAMED = None  # lazy


def _decode_entities(s: str) -> str:
    global _NAMED
    if _NAMED is None:
        _NAMED = _named_entities()

    def repl(m: re.Match) -> str:
        body = m.group(1)
        if body.startswith("#x") or body.startswith("#X"):
            try:
                return chr(int(body[2:], 16))
            except ValueError:
                return m.group(0)
        if body.startswith("#"):
            try:
                return chr(int(body[1:]))
            except ValueError:
                return m.group(0)
        if body in _NAMED:
            return _NAMED[body]
        return m.group(0)

    return _ENTITY_RE.sub(repl, s)
