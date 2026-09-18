#!/usr/bin/env python3
"""Table extraction demo — synthetic HTML, no network required."""

# Verified runnable with nettle 0.8.0 (QA round A4).

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nettle import parse, to_csv, to_json

HTML = """
<html><body>
<table id="prices">
  <tr><th>Product</th><th>Price</th><th>Stock</th></tr>
  <tr><td>Widget&nbsp;A</td><td>$10</td><td>5</td></tr>
  <tr><td>Gadget  B</td><td>$20</td><td>0</td></tr>
  <tr><td colspan="2">Bundle</td><td>3</td></tr>
</table>
</body></html>
"""


def main() -> None:
    doc = parse(HTML)
    rows = doc.table("table#prices")
    print("list[dict]:")
    print(to_json(rows))
    print("\nCSV:")
    print(to_csv(rows))


if __name__ == "__main__":
    main()
