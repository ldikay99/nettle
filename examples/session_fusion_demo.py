#!/usr/bin/env python3
"""Session fusion demo — hooks + cookies + auth + base_url + deterministic
retries in ONE session (the nettle/http.py fusion zone, live).

    python3 examples/session_fusion_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import nettle
from nettle import Session


def main() -> None:
    seen = []

    def tap(resp):
        seen.append((resp.status, resp.url))
        return resp  # mutate-and-return, requests-style

    s = Session(
        base_url="https://httpbin.org",
        hooks={"response": [tap]},      # runs on EVERY response of the session
    )
    s.set_cookies({"demo": "0.8.0"})    # rides every matching request

    # relative URLs resolve against base_url
    cookies_page = s.get("/cookies").json()["cookies"]
    print("server saw cookies :", cookies_page)

    # per-request auth (basic) — session had none
    authed = s.get("/basic-auth/nettle/demo", auth=("nettle", "demo"))
    print("per-request auth   :", authed.json())

    # retries made deterministic for tests: jitter off, tight backoff
    nettle.registry.http["retry_jitter"] = False
    nettle.registry.http["retry_backoff"] = 0.2
    sd = Session()
    print("retry delays       :", [round(sd._retry_delay(i), 2) for i in range(4)],
          "(0.2 * 2^n, capped by retry_max_delay)")
    nettle.registry.reset()

    # duplicated query keys survive params merging (requests semantics)
    r = s.get("/get?a=1&a=2", params={"b": ["x", "y"]})
    print("query dup keys     :", r.json()["args"])

    # IRI / unicode URLs percent-encode transparently
    iri = nettle.fetch_response("https://ja.wikipedia.org/wiki/東京都", retries=1)
    print("IRI fetch          :", iri.status, len(iri.text), "chars")

    print("hook saw responses :", seen)


if __name__ == "__main__":
    main()
