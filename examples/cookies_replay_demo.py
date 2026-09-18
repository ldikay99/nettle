#!/usr/bin/env python3
"""Cookie replay bridge — adopt browser cookies via Chrome CDP, then replay
with plain HTTP. Demonstrates the 0.8.0 hardening warnings and CHIPS
handling. Needs Chrome/Chromium installed (headless is fine).

    python3 examples/cookies_replay_demo.py
"""

from __future__ import annotations

import sys
import tempfile
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import nettle

URL = "https://www.daum.net/"


def main() -> None:
    s = nettle.Session()

    # Warnings (Secure+HttpOnly session-bound cookies, CHIPS-partitioned
    # skips) surface here — they describe when replay can HARDEN a block.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        n = s.adopt_browser_cookies(URL, strict_replay=True)
    for w in caught:
        print("WARN:", str(w.message).splitlines()[0])

    print(f"imported {n} replayable cookies; UA now:",
          s.headers.get("User-Agent", "")[:60], "...")

    print("cookie dict:", sorted(s.get_cookie_dict(URL))[:8])

    # Netscape cookies.txt roundtrip (curl/wget interop; session cookies
    # written with expires=0 so curl keeps them; CHIPS cookies documented as
    # comments, never as bogus first-party rows).
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        path = f.name
    saved = s.save_cookies(path)
    s2 = nettle.Session()
    loaded = s2.load_cookies(path)
    print(f"cookies.txt roundtrip: saved={saved} loaded={loaded} "
          f"match={sorted(s.get_cookie_dict(URL)) == sorted(s2.get_cookie_dict(URL))}")

    # plain-HTTP replay with the adopted jar + matching UA
    resp = s.get(URL, retries=1)
    print("replay:", resp.status, resp.headers.get("Content-Type", ""))

    nettle.shutdown_chrome()  # leave nothing behind


if __name__ == "__main__":
    main()
