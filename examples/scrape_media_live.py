#!/usr/bin/env python3
"""Demo EN VIVO: cada paso imprime qué encontró hasta descargar media."""
from __future__ import annotations

import sys
import time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nettle import fetch_response, find_urls, filter_urls, classify_url
from nettle.exceptions import FetchError
from nettle.http import Session

OUT = Path(__file__).resolve().parent
PAUSE = 0.8


def beat(title: str):
    print("\n" + "=" * 64)
    print(title)
    print("=" * 64, flush=True)
    time.sleep(PAUSE)


def main():
    page = "https://www.w3schools.com/html/html5_video.asp"
    beat("PASO 1 · Abrir página (fetch spoof browser)")
    print(f"URL: {page}", flush=True)
    resp = fetch_response(page, spoof_browser=True, timeout=25)
    print(f"status: {resp.status}", flush=True)
    print(f"final:  {resp.url}", flush=True)
    print(f"bytes:  {len(resp.body)}", flush=True)
    print(f"UA enviada: {resp.headers.get('content-type', '') and 'ok'} · Content-Type body page HTML", flush=True)
    time.sleep(PAUSE)

    beat("PASO 2 · Parse HTML con Nettle")
    doc = resp.doc
    title = doc.select_one("title")
    print(f"title: {title.get_text(strip=True) if title else '?'}", flush=True)
    print(f"nodos video:  {len(doc.select('video'))}", flush=True)
    print(f"nodos source: {len(doc.select('source'))}", flush=True)
    print(f"nodos img:    {len(doc.select('img'))}", flush=True)
    time.sleep(PAUSE)

    beat("PASO 3 · extract() sobre <video>/<source>/<img>")
    data = doc.extract({
        "title": {"css": "title", "clean": "plain"},
        "videos": {
            "select": "video[src], video source[src]",
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
    })
    print("extract videos:", flush=True)
    for u in data.get("videos") or []:
        print(f"  → {u}", flush=True)
    print("extract images (primeras 5):", flush=True)
    for u in (data.get("images") or [])[:5]:
        print(f"  → {u}", flush=True)
    time.sleep(PAUSE)

    beat("PASO 4 · find_urls() + classify/filter media")
    urls = find_urls(doc, base_url=resp.url)
    print(f"URLs totales descubiertas: {len(urls)}", flush=True)
    media = filter_urls(urls, kind="media")
    print(f"clasificadas como media: {len(media)}", flush=True)
    for u in media:
        print(f"  [{classify_url(u):5}] {u}", flush=True)
    time.sleep(PAUSE)

    beat("PASO 5 · Elegir el video .mp4")
    mp4s = [u for u in (data.get("videos") or []) if u.lower().endswith(".mp4")]
    if not mp4s:
        mp4s = filter_urls(urls, ext=".mp4")
    if not mp4s:
        raise SystemExit("No encontré mp4")
    video_url = mp4s[0]
    print(f"ELEGIDO: {video_url}", flush=True)
    time.sleep(PAUSE)

    beat("PASO 6 · Descargar el video a disco")
    dest = OUT / "out_live_video.mp4"
    session = Session(spoof_browser=True, timeout=60.0, retries=4, retry_backoff=1.0)
    print("GET bytes (con reintentos ante reset/timeout)...", flush=True)
    try:
        media = session.get(
            video_url,
            referer=resp.url,
            headers={
                "Accept": "video/mp4,video/*,*/*;q=0.8",
                "Connection": "close",
            },
        )
    except FetchError as e:
        raise SystemExit(f"No pude descargar el video tras reintentos: {e}") from e
    blob = media.body
    ctype = media.headers.get("Content-Type") or media.headers.get("content-type") or ""
    print(f"Content-Type: {ctype}", flush=True)
    print(f"Content-Length leído: {len(blob)} bytes", flush=True)
    dest.write_bytes(blob)
    print(f"GUARDADO: {dest}", flush=True)
    print(f"size on disk: {dest.stat().st_size} bytes", flush=True)
    time.sleep(PAUSE)

    beat("PASO 7 · Bonus: guardar también una imagen de la misma página")
    imgs = [
        u for u in (data.get("images") or [])
        if u.lower().split("?", 1)[0].endswith(".png") and not u.startswith("data:")
    ]
    if imgs:
        img_url = imgs[0]
        img_dest = OUT / "out_live_image.png"
        print(f"ELEGIDA: {img_url}", flush=True)
        try:
            img = session.get(img_url, referer=resp.url, timeout=30)
            img_dest.write_bytes(img.body)
            print(f"GUARDADO: {img_dest} ({img_dest.stat().st_size} bytes)", flush=True)
        except FetchError as e:
            print(f"imagen omitida tras error: {e}", flush=True)

    beat("LISTO · proceso completo")
    print("Archivos:", flush=True)
    for p in sorted(OUT.glob("out_live_*")):
        print(f"  {p.name:24} {p.stat().st_size:8} bytes", flush=True)


if __name__ == "__main__":
    main()
