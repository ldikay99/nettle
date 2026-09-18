#!/usr/bin/env python3
"""sniff_network + HAR 1.2 demo with REAL timings — DNS/connect/send/wait/
receive filled from CDP requestWillBeSent/responseReceived/loadingFinished
timestamps and response.timing. Also proves no Chrome process leaks.

    python3 examples/har_timings_demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import nettle

URL = "https://httpbin.org/"
HAR_OUT = Path(__file__).resolve().parent / "out_capture.har"


def main() -> None:
    cap = nettle.sniff_network(
        URL,
        har_path=str(HAR_OUT),
        cache_disabled=True,   # reproducible: no memory-cache entries
        scroll_steps=2,
        settle=3.0,
    )
    print(f"captured {cap['total']} requests "
          f"(xhr/fetch {len(cap['xhr_fetch'])}, json {len(cap['json'])})")

    har = json.loads(HAR_OUT.read_text())
    entries = har["log"]["entries"]
    for e in entries[:5]:
        t = e["timings"]
        print(f"{e['request']['method']:<4} {e['response']['status']:<4} "
              f"total={e['time']:>7.1f}ms "
              f"dns={t['dns']:>6} connect={t['connect']:>6} "
              f"send={t['send']:>5} wait={t['wait']:>7.1f} "
              f"recv={t['receive']:>7.1f}  {e['request']['url'][:50]}")

    timed = sum(1 for e in entries if e["time"] > 0)
    print(f"\n{timed}/{len(entries)} entries carry measured timings "
          f"(-1 = phase did not happen, HAR's N/A convention)")

    nettle.shutdown_chrome()
    print("chrome processes alive after shutdown:",
          nettle.chrome_processes_alive())


if __name__ == "__main__":
    main()
