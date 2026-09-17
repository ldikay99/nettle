#!/usr/bin/env python3
"""Demo EN VIVO: escanear como DevTools Network (CDP), no apuntar al DOM.

1) Abre Chrome vía debugging port
2) Navega
3) Imprime cada request/response como el panel Network
4) Separa media / xhr / json
5) Descarga el media encontrado SOLO desde la network
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nettle.cdp import sniff_network, ensure_debugging_chrome, CDPError
from nettle.http import Session
from nettle.exceptions import FetchError

OUT = Path(__file__).resolve().parent
PREFERRED_PORT = 9222


def beat(msg: str) -> None:
    print("\n" + "=" * 68)
    print(msg)
    print("=" * 68, flush=True)
    time.sleep(1.2)


def main() -> None:
    page = "https://www.w3schools.com/html/html5_video.asp"
    beat("PASO 1 · Conectar a Chrome DevTools (CDP) — como abrir Network")
    try:
        port = ensure_debugging_chrome(PREFERRED_PORT)
    except CDPError as e:
        raise SystemExit(f"No pude preparar Chrome CDP: {e}") from e
    print(f"debugging port: {port}", flush=True)
    print(f"navegar a: {page}", flush=True)
    print("NO uso selectores video/source del DOM.", flush=True)
    print("Solo escucho Network.requestWillBeSent / responseReceived.", flush=True)

    def on_event(kind: str, entry: dict) -> None:
        url = entry.get("url") or ""
        if kind == "request":
            method = entry.get("method") or "?"
            typ = entry.get("type") or "?"
            short = url if len(url) < 110 else url[:107] + "..."
            print(f"  → REQ  [{method:4}] ({typ}) {short}", flush=True)
        elif kind == "response":
            print(
                f"  ← RESP [{entry.get('status')}] {entry.get('mime')} | {url[:90]}",
                flush=True,
            )
        elif kind == "media":
            print(f"  ★ MEDIA en network: {url}", flush=True)
        elif kind == "body":
            body = entry.get("body") or ""
            preview = body.replace("\n", " ")[:120]
            print(f"  … BODY ({len(body)} chars): {preview}", flush=True)

    beat("PASO 2 · Navegar y sniffer Network en vivo")
    result = sniff_network(page, port=port, settle=6.0, on_event=on_event)

    beat("PASO 3 · Resumen como un humano mirando DevTools")
    print(f"total requests: {result['total']}", flush=True)
    print(f"media hallada:  {len(result['media'])}", flush=True)
    print(f"xhr/fetch:      {len(result['xhr_fetch'])}", flush=True)
    print(f"json-ish:       {len(result['json'])}", flush=True)

    print("\n-- MEDIA (desde Network, no DOM) --", flush=True)
    for e in result["media"]:
        print(f"  [{e.get('status')}] {e.get('mime')} {e.get('url')}", flush=True)

    print("\n-- XHR / FETCH --", flush=True)
    for e in result["xhr_fetch"][:20]:
        print(f"  [{e.get('status')}] {e.get('mime')} {e.get('url')}", flush=True)
    if not result["xhr_fetch"]:
        print("  (esta página tutorial casi no dispara XHR; el media sí viaja por Network)", flush=True)

    beat("PASO 4 · Segunda navegación: página que sí pega APIs JSON")
    api_page = "https://dummyjson.com/products?limit=3"
    print(f"navegar/capturar: {api_page}", flush=True)
    # direct product JSON endpoint as navigation also shows in network;
    # better: open docs homepage then evaluate fetch — use sniff on API URL first
    api = sniff_network(api_page, port=port, settle=3.0, on_event=on_event)
    print(f"\ntotal requests: {api['total']}", flush=True)
    print("-- JSON bodies capturados --", flush=True)
    json_hits = []
    for e in api["entries"]:
        body = e.get("body") or ""
        mime = (e.get("mime") or "").lower()
        if "json" in mime or body.lstrip()[:1] in "{[":
            json_hits.append(e)
            print(f"  URL: {e.get('url')}", flush=True)
            print(f"  status/mime: {e.get('status')} / {e.get('mime')}", flush=True)
            print(f"  payload preview: {body[:300].replace(chr(10),' ')}", flush=True)

    beat("PASO 5 · Elegir media SOLO del sniff Network y descargar")
    mp4 = None
    for e in result["media"]:
        u = e.get("url") or ""
        if u.lower().split("?", 1)[0].endswith(".mp4"):
            mp4 = u
            break
    if not mp4:
        # fallback: any entry url ending mp4
        for e in result["entries"]:
            u = (e.get("url") or "")
            if u.lower().split("?", 1)[0].endswith(".mp4"):
                mp4 = u
                break
    if not mp4:
        raise SystemExit("Network sniff no vio ningún mp4")

    print(f"ELEGIDO desde Network: {mp4}", flush=True)
    dest = OUT / "out_network_video.mp4"
    session = Session(spoof_browser=True, timeout=60.0, retries=4, retry_backoff=1.0)
    try:
        media = session.get(
            mp4,
            referer=page,
            headers={"Accept": "video/mp4,video/*,*/*;q=0.8", "Connection": "close"},
        )
    except FetchError as e:
        raise SystemExit(f"No pude descargar el mp4 tras reintentos: {e}") from e
    data = media.body
    print(f"Content-Type: {media.headers.get('Content-Type') or media.headers.get('content-type')}", flush=True)
    print(f"bytes: {len(data)}", flush=True)
    dest.write_bytes(data)
    print(f"GUARDADO: {dest}", flush=True)

    summary = {
        "page": page,
        "network_total": result["total"],
        "media_from_network": [
            {"url": e.get("url"), "status": e.get("status"), "mime": e.get("mime")}
            for e in result["media"]
        ],
        "api_page": api_page,
        "json_hits": len(json_hits),
        "downloaded": str(dest),
        "downloaded_bytes": dest.stat().st_size,
    }
    out_json = OUT / "out_network_sniff.json"
    out_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"JSON: {out_json}", flush=True)
    beat("LISTO · Network-first scrape")


if __name__ == "__main__":
    main()
