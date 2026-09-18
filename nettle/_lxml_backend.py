"""OPTIONAL accelerated parsing backend driven by lxml (libxml2).

Never a hard dependency: everything here is imported lazily inside
try/except ImportError, and ``parse()`` silently falls back to the pure
stdlib engine when lxml is absent (recording the outcome in
``registry.parse["prefer_lxml"]``).

Design: lxml.etree.HTMLParser(target=...) is used purely as a C-speed
TOKENIZER (the streaming SAX-style equivalent of iterparse for HTML —
iterparse itself is XML-only). Its events feed the SAME nettle
TreeBuilder the pure engine uses, so the resulting tree is a real nettle
Document: same node classes, same API, same document-order guarantees.

Documented behavioral notes vs the pure engine (all verified against a
tree-differential corpus; see tests/test_agentB3_lxml_backend.py):

* Entities: on modern libxml2 (>= 2.11) references arrive pre-decoded,
  including legacy no-semicolon forms like ``&copy 2024`` — the same
  strings nettle's pure engine produces via its legacy table. Double
  escapes stay intact (``&amp;copy`` → ``&copy`` as literal text, one
  pass, no re-scanning). On OLD libxml2 (2.9.x, e.g. Debian bookworm)
  legacy forms arrive literal, so the adapter runs nettle's own legacy
  decoder (the ``&amp;copy`` double-escape edge then diverges — pure
  engine always exact). registry.parse["legacy_entities"]=False is not
  honored by this backend: libxml2 always applies HTML rules.
* ``<!DOCTYPE>``: the lxml target API has no doctype callback, so the
  doctype is regex-sniffed from the source head and handed to the
  builder — nettle keeps only the LAST doctype either way.
* Synthetic wrappers: libxml2 always wraps fragments in ``<html>`` /
  ``<body>`` (and may synthesize ``<head>``). The adapter strips every
  wrapper element that does not appear as a real tag in the source
  head, so fragments stay fragments.
* Divergences kept (rare, malformed-input corner cases; both engines always
  produce a queryable tree — measured: 27/27 benign docs and 26/30 torture
  docs build IDENTICAL trees, the cases below differ):
  - invalid character references (``&#0;``, out-of-range): libxml2 emits
    U+FFFD, the pure engine emits the decoded code point or keeps the
    literal source;
  - extra roots after ``</html>`` and whitespace-only fragments: libxml2
    re-parents/drops them differently than the pure recovery rules;
  - unquoted attribute garbage like ``<p title=he said "hi">`` produces
    slightly different junk attribute names;
  - pathological nesting (nested <form> + unclosed selects) can close at
    different points (both trees remain queryable).
  (NOT divergences, verified: duplicate attributes keep the FIRST value in
  both engines — the HTML5 rule; ``<div/>`` self-closing closes in both.)
"""

from __future__ import annotations

import re
from typing import List, Optional

_DOCTYPE_RE = re.compile(r"<!DOCTYPE\s+([^>]+)>", re.I)
_TAG_RES = {
    "html": re.compile(r"<html[\s>]", re.I),
    "head": re.compile(r"<head[\s>]", re.I),
    "body": re.compile(r"<body[\s>]", re.I),
}

# import success cached here (None = not probed yet)
_LXML_STATE: Optional[bool] = None

# Does the installed libxml2 decode legacy no-semicolon entities
# (&copy 2024 → © 2024)? Newer libxml2 (>= 2.11ish) does; Debian's 2.9.x
# does not. Probed once; when False the adapter routes data through
# nettle's own legacy decoder so both backends agree on the common cases.
_LEGACY_DECODE_STATE: Optional[bool] = None


def _libxml2_decodes_legacy() -> bool:
    global _LEGACY_DECODE_STATE
    if _LEGACY_DECODE_STATE is None:
        seen: List[str] = []

        class _Probe:
            def data(self, d):
                seen.append(str(d))

            def close(self):
                return None

        try:
            from lxml import etree
            p = etree.HTMLParser(target=_Probe(), recover=True)
            etree.fromstring("<p>&copy 2024</p>", parser=p)
            _LEGACY_DECODE_STATE = "©" in "".join(seen)
        except Exception:
            _LEGACY_DECODE_STATE = False
    return _LEGACY_DECODE_STATE


def lxml_available() -> bool:
    """Is lxml.etree importable? Result cached; never raises."""
    global _LXML_STATE
    if _LXML_STATE is None:
        try:
            from lxml import etree  # noqa: F401
            _LXML_STATE = True
        except ImportError:
            _LXML_STATE = False
    return _LXML_STATE


class _Target:
    """lxml target-parser → nettle TreeBuilder event adapter."""

    def __init__(self, builder, keep: dict) -> None:
        self.builder = builder
        self.keep = keep  # {"html": bool, "head": bool, "body": bool}
        self._buf: List[str] = []

    def _flush(self) -> None:
        """Coalesce consecutive data chunks into ONE handle_text call.

        libxml2 emits character data in chunks (notably around character
        references on old 2.9.x: '&copy' + ' 2024'); nettle's one-pass
        entity decoder needs the whole run to match entities correctly."""
        if self._buf:
            text = "".join(self._buf)
            self._buf.clear()
            # Modern libxml2 hands us references already resolved (incl.
            # legacy no-semicolon forms) — do NOT decode again. Old libxml2
            # (2.9.x) leaves "&copy 2024" literal, so nettle's own legacy
            # decoder runs (one pass, no re-scanning).
            self.builder.handle_text(
                text, decoded=_libxml2_decodes_legacy()
            )

    def _wanted(self, tag: str) -> bool:
        return self.keep.get(tag, True)

    def start(self, tag, attrib):
        self._flush()
        tag = str(tag)
        if tag in ("html", "head", "body") and not self._wanted(tag):
            return None  # synthetic wrapper: swallow (they never nest)
        attrs = {str(k): ("" if v is None else str(v)) for k, v in (attrib or {}).items()}
        if not _libxml2_decodes_legacy():
            # old libxml2 leaves "&copy 2024" literal in ATTRIBUTES too —
            # run nettle's attribute-context decoder (keeps '?a=1&copy=2')
            from .parse import _decode_attr_value
            attrs = {k: _decode_attr_value(v) for k, v in attrs.items()}
        self.builder.handle_start(tag, attrs)
        return None

    def end(self, tag):
        self._flush()
        tag = str(tag)
        if tag in ("html", "head", "body") and not self._wanted(tag):
            return None
        self.builder.handle_end(tag)
        return None

    def data(self, data):
        self._buf.append(str(data))
        return None

    def comment(self, text):
        self._flush()
        self.builder.handle_comment(str(text))
        return None

    def doctype(self, *args):  # pragma: no cover — HTML target never fires
        return None

    def pi(self, *args):  # libxml2 delivers PIs as comments already
        return None

    def close(self):
        self._flush()
        return self.builder.document


def parse_with_lxml(html: str, on_error: str = "recover"):
    """Build a nettle Document from *html* (a str) using lxml tokenization."""
    from .exceptions import ParseError
    from .parse import TreeBuilder

    try:
        from lxml import etree
    except ImportError:  # pragma: no cover — guarded by lxml_available()
        raise

    builder = TreeBuilder(fixup=False)  # lxml events arrive already balanced
    head = html[:65536]
    keep = {name: bool(rx.search(head)) for name, rx in _TAG_RES.items()}
    target = _Target(builder, keep)

    m = _DOCTYPE_RE.search(head)
    if m:
        builder.handle_doctype(m.group(1).strip())

    parser = etree.HTMLParser(target=target, recover=True)
    try:
        parser.feed(html)
        parser.close()
    except Exception as e:  # lxml rejected the input entirely
        if on_error == "raise":
            raise ParseError(f"lxml backend failed: {e}") from e
        # recover: fall through with whatever the builder produced

    while len(builder.open) > 1:
        builder.open.pop()
    return builder.document
