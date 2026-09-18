#!/usr/bin/env python3
"""Scrape quotes.toscrape.com with extract + clean + format (stdlib only)."""

# Verified runnable with nettle 0.8.0 (QA round A4).

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nettle import fetch, to_json, write_json

URL = "https://quotes.toscrape.com/"
OUT = Path(__file__).resolve().parent / "out_quotes.json"

SCHEMA = {
    "quotes": {
        "select": "div.quote",
        "each": {
            "text": {"css": "span.text", "clean": "plain"},
            "author": {"css": "small.author", "clean": "plain"},
            "tags": {"css": "div.tags a.tag", "all": True, "clean": "plain"},
        },
    }
}


def main() -> None:
    doc = fetch(URL, spoof_browser=True)
    data = doc.extract(SCHEMA)
    quotes = data["quotes"]
    for q in quotes[:5]:
        print(f"- {q['author']}: {q['text'][:70]}...")
    write_json(str(OUT), quotes)
    print(f"\nSaved {len(quotes)} quotes -> {OUT}")
    print("\nSample JSON:")
    print(to_json(quotes[:2]))


if __name__ == "__main__":
    main()
