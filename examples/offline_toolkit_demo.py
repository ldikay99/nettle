#!/usr/bin/env python3
"""Offline tour of nettle's parsing toolkit — NO network needed.

Covers the 0.8.0 fusion zones: HTML5 entity engine (legacy `&copy 2024`),
RCDATA title/textarea, raw script/style, UTF-16 without BOM, the strict CSS
engine (escapes, :not(:has()), doubled-combinator errors), bs4-style
navigation, surgery, 3000-deep serialization, and to_har() timing math from
synthetic CDP timestamps. Run me anywhere:

    python3 examples/offline_toolkit_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nettle import parse, to_har
from nettle.css import SelectorError

HTML = """<!DOCTYPE html>
<html><head><title>Bolet&iacute;n &amp; informe</title>
<meta charset="utf-8"></head>
<body>
<textarea rows="2">café &amp; thé &copy; 2024</textarea>
<script>if (a < b) { emit('</p>'); }</script>
<a href='/x?a=1&amp;b=2' title='AT&amp;T &copy 2024'>link</a>
<a href='/y?a=1&copy=2'>&copy; sí &notit;</a>
<ul><li>one</li><li class='pick'>two</li><li>three</li></ul>
<div class='btn.primary'>dotted</div>
</body></html>"""


def main() -> None:
    doc = parse(HTML)

    # -- entity engine: RCDATA title/textarea decoded, script stays raw ------
    print("title      :", doc.title)
    print("textarea   :", doc.select_one("textarea").get_text(strip=True))
    print("script raw :", doc.select_one("script").get_text().strip())
    print("attr entity:", doc.select_one("a[title]")["title"])
    # legacy no-semicolon forms decode in TEXT but not mid-URL (browsers too)
    print("legacy text:", doc.select("a")[1].get_text(strip=True))
    print("url guarded:", doc.select("a")[1]["href"], "<- &copy=2 intact")

    # -- CSS engine: escapes, functional pseudos, strict errors --------------
    print("escape .btn\\.primary :", doc.select_one(".btn\\.primary").get_text())
    print(":not + :has          :", [li.get_text() for li in doc.select("ul li:not(.pick)")])
    print("li:has(~ .pick)      :", [li.get_text() for li in doc.select("li:has(+ li.pick)")])
    try:
        doc.select("ul >> li")
    except SelectorError as e:
        print("doubled combinator   : SelectorError ->", str(e)[:60], "...")

    # -- navigation + surgery ------------------------------------------------
    a = doc.select_one("a[title]")
    print("parent chain         :",
          " < ".join(el.tag for el in a.parents if el.tag in ("body", "html")))
    a.wrap(parse("<strong></strong>").child_elements[0])
    print("after wrap           :", doc.select_one("strong a") is not None)

    # -- encodings without network -------------------------------------------
    utf16 = "<html><body>日本語テスト</body></html>".encode("utf-16-le")
    print("utf-16le no BOM      :", parse(utf16).get_text(strip=True))

    deep = parse("<html><body>" + "<div>" * 3000 + "x" + "</div>" * 3000 + "</body></html>")
    print("3000-deep serialize  :", len(str(deep)), "chars, no RecursionError")

    # -- HAR timings from synthetic CDP events (what sniff_network stores) ---
    capture = {"page": "https://offline.test/", "entries": [{
        "url": "https://offline.test/data.json?q=1", "method": "GET",
        "headers": {}, "status": 200, "mime": "application/json",
        "wallTime": 1700000000.5,
        "cdpTimestamp": 100.0,           # Network.requestWillBeSent
        "cdpTimestampResponse": 100.250,  # Network.responseReceived
        "cdpTimestampFinished": 100.640,  # Network.loadingFinished
        "timing": {"dnsStart": 5, "dnsEnd": 25, "connectStart": 25, "connectEnd": 90,
                   "sslStart": 40, "sslEnd": 85, "sendStart": 95, "sendEnd": 100,
                   "receiveHeadersEnd": 250},
        "encodedDataLength": 51234,
    }]}
    entry = to_har(capture)["log"]["entries"][0]
    t = entry["timings"]
    print("har timings (ms)     : dns=%s connect=%s send=%s wait=%s receive=%s total=%s"
          % (t["dns"], t["connect"], t["send"], t["wait"], t["receive"], entry["time"]))
    print("har queryString      :", entry["request"]["queryString"])


if __name__ == "__main__":
    main()
