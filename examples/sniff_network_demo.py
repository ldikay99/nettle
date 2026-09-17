#!/usr/bin/env python3
"""Demonstrate URL discovery + embedded JSON sniffing + spoofed fetch.

Uses a synthetic page (offline) plus an optional live fetch to httpbin.org
to show spoofed User-Agent headers.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nettle import (
    parse,
    find_urls,
    classify_url,
    sniff_embedded_json,
    sniff_api_candidates,
    probe_apis,
    fetch_response,
    to_json,
)

SAMPLE = """
<!doctype html>
<html>
<head>
  <base href="https://shop.example.com/">
  <link rel="stylesheet" href="/static/app.css">
  <script type="application/ld+json">
  {"@type":"Product","name":"Nettle","url":"https://shop.example.com/p/1"}
  </script>
  <script id="__NEXT_DATA__" type="application/json">
  {"props":{"pageProps":{"items":[{"id":1,"price":9.99}]},"apiBase":"/api/v1"}}
  </script>
</head>
<body>
  <a href="/products">Products</a>
  <img src="/img/hero.webp" srcset="/img/hero.webp 1x, /img/hero@2x.webp 2x">
  <div data-url="/api/v1/cart">cart</div>
  <script>
    fetch('/api/v1/items');
    axios.get('https://shop.example.com/api/v1/user');
    const gql = '/graphql';
  </script>
</body>
</html>
"""


def main() -> None:
    doc = parse(SAMPLE)
    doc.base_url = "https://shop.example.com/"

    print("=== find_urls ===")
    urls = find_urls(doc, base_url=doc.base_url)
    for u in urls:
        print(f"  [{classify_url(u):5}] {u}")

    print("\n=== sniff_embedded_json ===")
    blobs = sniff_embedded_json(doc)
    for b in blobs:
        print(f"  source={b['source']!r}")
        print(" ", to_json(b["data"], indent=None)[:120])

    print("\n=== sniff_api_candidates ===")
    apis = sniff_api_candidates(doc, base_url=doc.base_url)
    for a in apis:
        print(" ", a)

    print("\n=== extract with urls:True ===")
    data = doc.extract({
        "title_links": {"css": "a", "attr": "href", "all": True, "abs": True},
        "all_urls": {"urls": True, "same_host": True},
    })
    print(to_json(data))

    # Live spoofed fetch (optional — skip on network failure)
    print("\n=== spoofed fetch (httpbin) ===")
    try:
        resp = fetch_response(
            "https://httpbin.org/headers",
            spoof_browser=True,
            timeout=20,
        )
        print("status", resp.status, "final url", resp.url)
        hdrs = resp.json().get("headers", {})
        print("server saw UA:", hdrs.get("User-Agent", "")[:80])
        print("Accept-Language:", hdrs.get("Accept-Language"))
    except Exception as e:
        print("skipped live fetch:", e)


if __name__ == "__main__":
    main()
