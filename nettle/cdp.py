"""Minimal Chrome DevTools Protocol client (stdlib only).

Talks WebSocket to Chrome --remote-debugging-port for Network sniffing
the same way DevTools Network panel does.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import selectors
import socket
import struct
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from .registry import registry as _registry
from urllib.request import urlopen


class CDPError(RuntimeError):
    pass


def _ws_connect(ws_url: str, timeout: float = 10.0) -> socket.socket:
    u = urlparse(ws_url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = u.path + (f"?{u.query}" if u.query else "")
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    sock = socket.create_connection((host, port), timeout=timeout)
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode()
    sock.sendall(req)
    # read HTTP response headers
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise CDPError("CDP websocket handshake closed early")
        buf += chunk
        if len(buf) > 65536:
            raise CDPError("CDP handshake too large")
    header, _ = buf.split(b"\r\n\r\n", 1)
    status = header.split(b"\r\n", 1)[0]
    if b"101" not in status:
        raise CDPError(f"CDP handshake failed: {status.decode('latin1', 'replace')}")
    expect = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    if expect.encode() not in header:
        # some chromes still work; keep soft
        pass
    sock.settimeout(0.3)
    return sock


def _ws_send(sock: socket.socket, payload: bytes, opcode: int = 0x1) -> None:
    mask_key = os.urandom(4)
    n = len(payload)
    header = bytearray([0x80 | opcode])
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", n))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", n))
    header.extend(mask_key)
    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    sock.sendall(header + masked)


def _ws_recv_frame(sock: socket.socket) -> Tuple[int, bytes]:
    def read_exact(n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            chunk = sock.recv(n - len(out))
            if not chunk:
                raise CDPError("CDP socket closed")
            out.extend(chunk)
        return bytes(out)

    sock.settimeout(30.0)
    h = read_exact(2)
    opcode = h[0] & 0x0F
    masked = (h[1] & 0x80) != 0
    n = h[1] & 0x7F
    if n == 126:
        n = struct.unpack("!H", read_exact(2))[0]
    elif n == 127:
        n = struct.unpack("!Q", read_exact(8))[0]
    mask = read_exact(4) if masked else b""
    payload = read_exact(n)
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    if opcode == 0x8:  # close
        raise CDPError("CDP closed")
    if opcode == 0x9:  # ping -> pong
        _ws_send(sock, payload, opcode=0xA)
        return _ws_recv_frame(sock)
    return opcode, payload


class CDPSession:
    def __init__(self, ws_url: str) -> None:
        self.ws_url = ws_url
        self.sock = _ws_connect(ws_url)
        self._id = 0
        self._pending: Dict[int, Any] = {}
        self.events: List[Dict[str, Any]] = []
        self._listeners: Dict[str, List[Callable[[dict], None]]] = {}

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def on(self, method: str, cb: Callable[[dict], None]) -> None:
        self._listeners.setdefault(method, []).append(cb)

    def _dispatch(self, msg: dict) -> None:
        if "id" in msg:
            self._pending[msg["id"]] = msg
            return
        method = msg.get("method")
        params = msg.get("params") or {}
        self.events.append(msg)
        for cb in self._listeners.get(method or "", []):
            cb(params)

    def _pump(self, wait_id: Optional[int] = None, deadline: float = 0.0) -> Optional[dict]:
        while True:
            if wait_id is not None and wait_id in self._pending:
                return self._pending.pop(wait_id)
            remaining = deadline - time.time()
            if remaining <= 0 and wait_id is None:
                return None
            if remaining <= 0 and wait_id is not None:
                # still try one nonblocking
                pass
            try:
                self.sock.settimeout(max(0.05, min(1.0, remaining if remaining > 0 else 0.05)))
                opcode, payload = _ws_recv_frame(self.sock)
            except (socket.timeout, TimeoutError):
                if wait_id is None:
                    return None
                if time.time() >= deadline:
                    raise CDPError(f"CDP timeout waiting for id={wait_id}")
                continue
            if opcode != 0x1:
                continue
            msg = json.loads(payload.decode("utf-8"))
            self._dispatch(msg)
            if wait_id is not None and wait_id in self._pending:
                return self._pending.pop(wait_id)

    def call(self, method: str, params: Optional[dict] = None, timeout: float = 20.0) -> Any:
        self._id += 1
        mid = self._id
        payload = {"id": mid, "method": method, "params": params or {}}
        _ws_send(self.sock, json.dumps(payload).encode("utf-8"))
        msg = self._pump(wait_id=mid, deadline=time.time() + timeout)
        if not msg:
            raise CDPError(f"No response for {method}")
        if "error" in msg:
            raise CDPError(f"{method}: {msg['error']}")
        return msg.get("result")

    def pump_for(self, seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            self._pump(wait_id=None, deadline=min(end, time.time() + 0.25))


def debugging_alive(port: int) -> bool:
    try:
        with urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1.5) as r:
            r.read(64)
        return True
    except Exception:
        return False


def find_debugging_port(candidates: Optional[List[int]] = None) -> Optional[int]:
    ports = candidates or list(range(9222, 9235))
    for p in ports:
        if debugging_alive(p):
            return p
    return None


def _chrome_binaries() -> List[str]:
    names = [
        "google-chrome-stable",
        "google-chrome",
        "chromium",
        "chromium-browser",
        "brave-browser",
    ]
    found: List[str] = []
    for n in names:
        from shutil import which
        path = which(n)
        if path:
            found.append(path)
    # common absolute paths
    for p in (
        "/usr/bin/google-chrome-stable",
        "/usr/bin/google-chrome",
        "/opt/brave.com/brave/brave",
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
    ):
        if os.path.isfile(p) and p not in found:
            found.append(p)
    return found


def ensure_debugging_chrome(
    port: int = 9222,
    *,
    user_data_dir: Optional[str] = None,
    headless: bool = True,
    wait: float = 12.0,
) -> int:
    """Return a live --remote-debugging-port, launching Chrome if needed.

    Uses a dedicated user-data-dir so it does not fight your daily browser profile.
    """
    existing = find_debugging_port([port] + list(range(9222, 9235)))
    if existing is not None:
        return existing

    bins = _chrome_binaries()
    if not bins:
        raise CDPError(
            "No Chrome/Chromium binary found. Install google-chrome or chromium, "
            "or start one with --remote-debugging-port=%d" % port
        )

    udd = user_data_dir or os.path.join(
        os.environ.get("TMPDIR") or "/tmp", f"nettle-chrome-cdp-{port}"
    )
    os.makedirs(udd, exist_ok=True)
    cmd = [
        bins[0],
        f"--remote-debugging-port={port}",
        f"--user-data-dir={udd}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-features=Translate,MediaRouter",
        "--mute-audio",
        "about:blank",
    ]
    if headless:
        cmd.insert(1, "--headless=new")
        cmd.insert(2, "--disable-gpu")

    # Detach so the demo owns a CDP endpoint without blocking.
    import subprocess

    subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.time() + wait
    while time.time() < deadline:
        if debugging_alive(port):
            return port
        time.sleep(0.25)
    raise CDPError(
        f"Started {bins[0]} with --remote-debugging-port={port} but "
        f"http://127.0.0.1:{port}/json/version never answered. "
        "Close other Chrome locks on that user-data-dir and retry."
    )


def list_targets(port: int = 9222) -> List[dict]:
    with urlopen(f"http://127.0.0.1:{port}/json/list", timeout=5) as r:
        return json.loads(r.read().decode())


def new_tab(port: int = 9222, url: str = "about:blank") -> dict:
    # Chrome accepts PUT /json/new?<url> (and some builds accept GET).
    from urllib.request import Request
    from urllib.error import URLError, HTTPError

    endpoint = f"http://127.0.0.1:{port}/json/new?{url}"
    last_err: Optional[Exception] = None
    for method in ("PUT", "GET"):
        try:
            req = Request(endpoint, method=method)
            with urlopen(req, timeout=5) as r:
                return json.loads(r.read().decode())
        except (URLError, HTTPError, TimeoutError, OSError) as e:
            last_err = e
            continue
    raise CDPError(f"Cannot open new tab on port {port}: {last_err}")


def sniff_network(
    url: str,
    *,
    port: Optional[int] = None,
    settle: float = 4.0,
    on_event: Optional[Callable[[str, dict], None]] = None,
    ensure_chrome: bool = True,
) -> Dict[str, Any]:
    """Open url in Chrome via CDP and capture Network requests/responses.

    Returns dict with requests list (method, url, status, mime, type, body preview for JSON).
    If ensure_chrome is True (default), auto-starts a dedicated headless Chrome when
    no debugging port is listening.
    """
    if port is None:
        port = find_debugging_port() or 9222
    if ensure_chrome:
        port = ensure_debugging_chrome(port)
    elif not debugging_alive(port):
        raise CDPError(
            f"Nothing listening on 127.0.0.1:{port}. "
            f"Start Chrome with --remote-debugging-port={port} "
            "or call ensure_debugging_chrome()."
        )
    tab = new_tab(port=port, url="about:blank")
    ws = tab.get("webSocketDebuggerUrl")
    if not ws:
        raise CDPError("No webSocketDebuggerUrl for new tab")
    cdp = CDPSession(ws)
    captured: Dict[str, Dict[str, Any]] = {}

    def req_sent(p: dict) -> None:
        req = p.get("request") or {}
        rid = p.get("requestId")
        entry = {
            "requestId": rid,
            "url": req.get("url"),
            "method": req.get("method"),
            "type": p.get("type") or req.get("mixedContentType"),
            "headers": req.get("headers") or {},
            "status": None,
            "mime": None,
            "body": None,
            "body_b64": False,
        }
        captured[rid] = entry
        if on_event:
            on_event("request", entry)

    def resp_recv(p: dict) -> None:
        rid = p.get("requestId")
        resp = p.get("response") or {}
        entry = captured.setdefault(rid, {"requestId": rid, "url": resp.get("url")})
        entry["status"] = resp.get("status")
        entry["mime"] = resp.get("mimeType")
        entry["url"] = entry.get("url") or resp.get("url")
        entry["type"] = entry.get("type") or p.get("type")
        if on_event:
            on_event("response", entry)

    def loading_finished(p: dict) -> None:
        rid = p.get("requestId")
        entry = captured.get(rid)
        if not entry:
            return
        mime = (entry.get("mime") or "").lower()
        url = (entry.get("url") or "").lower()
        rtype = (entry.get("type") or "").lower()
        # Prefer MIME + ResourceType (works on any site). Path hints are fallback only.
        want_body = (
            "json" in mime
            or rtype in ("xhr", "fetch")
            or url.endswith(".json")
            or "/api/" in url
            or "graphql" in url
            or "/wp-json/" in url
            or "/_next/data/" in url
            or mime.startswith("text/")
        )
        # also grab small media metadata only; bodies for mp4 skipped
        if any(url.split("?", 1)[0].endswith(ext) for ext in _registry.media_exts):
            entry["media"] = True
            if on_event:
                on_event("media", entry)
            return
        if not want_body:
            return
        try:
            result = cdp.call("Network.getResponseBody", {"requestId": rid}, timeout=5)
            body = result.get("body", "")
            if result.get("base64Encoded"):
                entry["body_b64"] = True
                try:
                    raw = base64.b64decode(body)
                    entry["body"] = raw.decode("utf-8", errors="replace")[:4000]
                except Exception:
                    entry["body"] = f"<base64 {len(body)} chars>"
            else:
                entry["body"] = (body or "")[:4000]
            if on_event:
                on_event("body", entry)
        except Exception as e:
            entry["body_error"] = str(e)

    cdp.on("Network.requestWillBeSent", req_sent)
    cdp.on("Network.responseReceived", resp_recv)
    cdp.on("Network.loadingFinished", loading_finished)

    cdp.call("Network.enable", {"maxPostDataSize": 65536})
    cdp.call("Page.enable")
    cdp.call("Page.navigate", {"url": url})
    cdp.pump_for(settle)

    # classify helpers
    entries = list(captured.values())
    media = [e for e in entries if e.get("media") or _is_media_url(e.get("url") or "")]
    jsonish = [
        e for e in entries
        if (e.get("mime") or "").lower().find("json") >= 0
        or (e.get("body") or "").lstrip()[:1] in "{["
    ]
    xhr = [e for e in entries if (e.get("type") or "").lower() in ("xhr", "fetch")]

    cdp.close()
    return {
        "ok": True,
        "page": url,
        "tabId": tab.get("id"),
        "total": len(entries),
        "entries": entries,
        "media": media,
        "json": jsonish,
        "xhr_fetch": xhr,
    }


def _is_media_url(url: str) -> bool:
    from .registry import registry as _registry
    path = url.lower().split("?", 1)[0]
    return path.endswith(tuple(_registry.media_exts | {".ts"}))
