#!/usr/bin/env python3
"""Compression + encodings demo: gzip / deflate / brotli / stacked / IRI,
including the RFC 9841 large-window error path and its remedy.

    python3 examples/compression_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import nettle
from nettle import fetch_response
from nettle.brotli_dec import BrotliLargeWindowError, decompress


def lw_header(lgwin: int = 30) -> bytes:
    """Hand-built RFC 9841 large-window stream header (marker 00010001)."""
    bits = "1" + "000" + "100" + "0" + format(lgwin, "06b")
    return bytes(int(bits[i:i + 8][::-1], 2) for i in range(0, 14, 8))


def main() -> None:
    for path, what in [
        ("/gzip", "gzip (httpbin)"),
        ("/deflate", "deflate (httpbin)"),
        ("/brotli", "brotli — decoded by nettle's pure-Python RFC 7932 decoder"),
    ]:
        r = fetch_response("https://httpbin.org" + path, retries=1)
        print(f"{what:<62} status={r.status} body={len(r.body)}B")

    # a CDN that negotiates br for plain GETs
    r = fetch_response("https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js",
                       retries=1)
    print(f"cdn.jsdelivr.net jquery (negotiated {r.headers.get('Content-Encoding')!r})"
          f"{'':<20} body={len(r.body)}B")

    # large-window brotli: what the specific error looks like and the remedy
    try:
        decompress(lw_header(30) + b"\0" * 8)
    except BrotliLargeWindowError as e:
        print("\nlarge-window stream detected:")
        print(" ", str(e).split("Remedy:")[0].strip())
        print("  Remedy:", str(e).split("Remedy:")[1].strip())

    # accept_encoding is tunable per call-time via the registry
    nettle.registry.http["accept_encoding"] = "gzip"
    s = nettle.Session()
    print("\nregistry.http['accept_encoding'] = 'gzip' ->",
          s.headers["Accept-Encoding"])
    nettle.registry.reset()


if __name__ == "__main__":
    main()
