#!/usr/bin/env python3
"""SPA rendering demo — the same URL with plain fetch vs render=True (Chrome
CDP). Shows the JS-shell warning, before/after link counts, and extraction
from the RENDERED DOM. Needs Chrome/Chromium.

    python3 examples/render_spa_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import nettle

URL = "https://www.daum.net/"


def main() -> None:
    # 1) plain HTTP: daum's source is a JS shell — almost no <a>, many <script>
    with __import__("warnings").catch_warnings(record=True) as caught:
        __import__("warnings").simplefilter("always")
        raw = nettle.fetch(URL, retries=1)
    shell = getattr(raw, "spa_shell", False)
    print(f"raw fetch : {len(raw.select('a[href]'))} links, "
          f"spa_shell={shell}, warned={bool(caught)}")

    # 2) render=True: execute the app, parse document.documentElement.outerHTML
    doc = nettle.fetch(URL, render=True)
    links = doc.select("a[href]")
    print(f"rendered : {len(links)} links, title={doc.render_title!r}, "
          f"rendered={doc.rendered}")

    # 3) extract from the rendered DOM exactly like from any Nettle doc
    hrefs = [a["href"] for a in links if a.get("href", "").startswith("http")]
    print(f"absolute hrefs: {len(hrefs)}; first 3: {hrefs[:3]}")

    urls = nettle.find_urls(doc)
    api_like = nettle.classify_url(hrefs[0]) if hrefs else "-"
    print(f"find_urls: {len(urls)} · first link classifies as {api_like!r}")

    nettle.shutdown_chrome()


if __name__ == "__main__":
    main()
