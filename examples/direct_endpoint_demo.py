#!/usr/bin/env python3
"""Endpoint directo: tú pasas la URL y el método. Sin /api/ mágico."""

# Verified runnable with nettle 0.8.0 (QA round A4).
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nettle import request, call_endpoint, FetchError

def main():
    print("=== Nettle · direct endpoint (any method / any path) ===\n")
    # GET a path that is NOT named /api/
    url = "https://dummyjson.com/products/1"
    try:
        r = request("GET", url)
        print(f"GET {url} -> {r.status}")
        print("title:", (r.json() or {}).get("title"))
    except FetchError as e:
        print("GET failed:", e)

    # POST JSON to whatever endpoint you have
    post_url = "https://dummyjson.com/products/add"
    try:
        r = request("POST", post_url, json={"title": "Nettle demo"})
        print(f"\nPOST {post_url} -> {r.status}")
        print(r.text[:200])
    except FetchError as e:
        print("POST failed:", e)

    # DELETE example (may 4xx on dummyjson — still shows the call works)
    try:
        r = call_endpoint("https://dummyjson.com/products/1", "DELETE")
        print(f"\nDELETE -> {r.status}")
    except FetchError as e:
        print("DELETE failed:", e)

if __name__ == "__main__":
    main()
