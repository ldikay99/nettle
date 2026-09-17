#!/usr/bin/env python3
"""Example real: Nettle extrae URLs de video / audio / imagen.

Páginas públicas de demo/tutorial:
  - https://www.w3schools.com/html/html5_video.asp   → video mp4/ogg
  - https://www.learningcontainer.com/sample-audio-file/ → audio mp3/ogg

Uso:
  PYTHONPATH=/workspace/nettle python3 examples/scrape_media_demo.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nettle import fetch_response, find_urls, filter_urls, classify_url
from nettle.exceptions import FetchError

OUT_JSON = Path(__file__).resolve().parent / "out_media.json"
OUT_IMG = Path(__file__).resolve().parent / "out_sample_image.png"

TARGETS = [
    {
        "url": "https://www.w3schools.com/html/html5_video.asp",
        "want": "video",
    },
    {
        "url": "https://www.learningcontainer.com/sample-audio-file/",
        "want": "audio",
    },
]


def uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def scrape_media(page_url: str) -> dict:
    resp = fetch_response(page_url, spoof_browser=True, timeout=25)
    doc = resp.doc
    base = resp.url

    extracted = doc.extract({
        "title": {"css": "title", "clean": "plain"},
        "videos": {
            "select": "video[src], video source[src]",
            "attr": "src",
            "all": True,
            "abs": True,
        },
        "audios": {
            "select": "audio[src], audio source[src]",
            "attr": "src",
            "all": True,
            "abs": True,
        },
        "images": {
            "select": "img[src]",
            "attr": "src",
            "all": True,
            "abs": True,
        },
        "poster": {"css": "video[poster]", "attr": "poster", "abs": True},
        "mp3_links": {
            "select": 'a[href*=".mp3"], a[href*=".wav"], a[href*=".ogg"]',
            "attr": "href",
            "all": True,
            "abs": True,
        },
    })

    discovered = find_urls(doc, base_url=base)
    media_urls = filter_urls(discovered, kind="media")

    videos = list(extracted.get("videos") or [])
    audios = list(extracted.get("audios") or []) + list(extracted.get("mp3_links") or [])
    images = list(extracted.get("images") or [])
    if extracted.get("poster"):
        images.append(extracted["poster"])

    for u in media_urls:
        path = u.lower().split("?", 1)[0]
        if path.endswith((".mp4", ".webm", ".ogv", ".mov", ".m4v")):
            videos.append(u)
        elif path.endswith((".mp3", ".wav", ".m4a", ".oga")):
            audios.append(u)
        elif path.endswith(".ogg"):
            # puede ser audio o video container
            if u in videos or u in audios:
                continue
            videos.append(u)
        elif path.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg")):
            images.append(u)

    videos, audios, images = uniq(videos), uniq(audios), uniq(images)
    return {
        "page": page_url,
        "final_url": base,
        "status": resp.status,
        "title": extracted.get("title"),
        "videos": videos,
        "audios": audios,
        "images_sample": images[:20],
        "totals": {
            "urls_found": len(discovered),
            "videos": len(videos),
            "audios": len(audios),
            "images": len(images),
        },
        "media_classified": [
            {"url": u, "kind": classify_url(u)} for u in media_urls[:25]
        ],
    }


def download_bytes(url: str, dest: Path) -> dict:
    req = Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            )
        },
    )
    with urlopen(req, timeout=30) as r:
        data = r.read()
        ctype = r.headers.get("Content-Type", "")
    dest.write_bytes(data)
    return {"saved": str(dest), "bytes": len(data), "content_type": ctype, "from": url}


def main():
    report = {"results": [], "errors": []}
    print("=== Nettle · scrape_media_demo ===\n")
    for t in TARGETS:
        url = t["url"]
        print(f"GET {url}")
        try:
            block = scrape_media(url)
        except FetchError as e:
            print(f"  ! skip: {e}")
            report["errors"].append({"page": url, "error": str(e)})
            print()
            continue
        report["results"].append(block)
        print(f"  [{block['status']}] {block['title']}")
        print(f"  videos ({block['totals']['videos']}):")
        for u in block["videos"][:10]:
            print(f"    • {u}")
        print(f"  audios ({block['totals']['audios']}):")
        for u in block["audios"][:10]:
            print(f"    • {u}")
        print(f"  images sample:")
        for u in block["images_sample"][:5]:
            print(f"    • {u}")
        print()

    # punta a punta: guardar una imagen scrapeda
    for block in report["results"]:
        for img in block["images_sample"]:
            if img.lower().split("?", 1)[0].endswith((".png", ".jpg", ".jpeg", ".webp")):
                print(f"SAVE image → {OUT_IMG.name}")
                try:
                    report["sample_image"] = download_bytes(img, OUT_IMG)
                    print(
                        f"  {report['sample_image']['bytes']} bytes · "
                        f"{report['sample_image']['content_type']}"
                    )
                except Exception as e:
                    print(f"  ! image download failed: {e}")
                    report["errors"].append({"image": img, "error": str(e)})
                break
        if report.get("sample_image"):
            break

    OUT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nJSON → {OUT_JSON}")
    if report["errors"]:
        print(f"warnings: {len(report['errors'])} error(s) recorded (see JSON)")


if __name__ == "__main__":
    main()
