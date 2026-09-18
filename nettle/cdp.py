"""Minimal Chrome DevTools Protocol client (stdlib only).

Talks WebSocket to Chrome --remote-debugging-port for Network sniffing
the same way DevTools Network panel does. Cross-platform: finds
Chrome/Chromium/Edge/Brave on Windows, macOS, Linux and Android (Termux);
override with the NETTLE_CHROME_BIN environment variable.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse
from .registry import registry as _registry
from .registry import _normalize_ports
from urllib.request import urlopen


class CDPError(RuntimeError):
    pass


def _ws_connect(ws_url: str, timeout: Optional[float] = None) -> socket.socket:
    if timeout is None:
        timeout = _registry.cdp["ws_connect_timeout"]
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
        chunk = sock.recv(int(_registry.cdp['ws_recv_chunk']))
        if not chunk:
            raise CDPError("CDP websocket handshake closed early")
        buf += chunk
        if len(buf) > int(_registry.cdp["ws_handshake_max"]):
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
    sock.settimeout(float(_registry.cdp["pump_for_slice"]) + 0.05)
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

    # NOTE: do not set a timeout here — the caller (_pump) controls socket
    # timing; a hard 30s recv would stall pumps that asked for 0.25-1s slices.
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
            _pump_min = float(_registry.cdp["pump_slice_min"])
            _pump_max = float(_registry.cdp["pump_slice_max"])
            try:
                self.sock.settimeout(max(_pump_min, min(_pump_max, remaining if remaining > 0 else _pump_min)))
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

    def call(self, method: str, params: Optional[dict] = None, timeout: Optional[float] = None) -> Any:
        if timeout is None:
            timeout = _registry.cdp["call_timeout"]
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
            self._pump(wait_id=None, deadline=min(end, time.time() + float(_registry.cdp['pump_for_slice'])))


# Every Chrome Nettle itself launched, keyed by debugging port. The legacy
# singular name is kept (read-only) for backwards compatibility.
_LAUNCHED_CHROMES: Dict[int, "subprocess.Popen"] = {}
_LAUNCHED_CHROME: Optional["subprocess.Popen"] = None  # most recent launch


def _register_launched(port: int, proc: "subprocess.Popen") -> None:
    global _LAUNCHED_CHROME
    _LAUNCHED_CHROMES[port] = proc
    _LAUNCHED_CHROME = proc


def _kill_process_tree(proc: "subprocess.Popen") -> None:
    """Terminate *proc* and its whole process group (zygote, gpu, renderers,
    crashpad). POSIX uses killpg on the detached session; Windows falls back
    to taskkill /T (tree kill). Guaranteed best-effort: never raises.
    """
    import signal
    import subprocess

    if os.name == "nt":
        # Theoretical Windows path: tree-kill via taskkill, then Popen calls.
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            capture_output=True,
        )
        try:
            proc.wait(timeout=float(_registry.cdp['kill_wait']))
        except Exception:
            pass
        return

    def _sig(signum: int) -> None:
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signum)
        except (OSError, PermissionError, ProcessLookupError):
            # group leader already gone — signal the leader directly
            try:
                if proc.poll() is None:
                    proc.send_signal(signum)
            except (OSError, ValueError):
                pass

    try:
        _sig(signal.SIGTERM)
        try:
            proc.wait(timeout=float(_registry.cdp['kill_wait']))
        except subprocess.TimeoutExpired:
            _sig(signal.SIGKILL)
            try:
                proc.wait(timeout=float(_registry.cdp['kill_wait']))
            except subprocess.TimeoutExpired:
                pass
        # final sweep in case some children ignored SIGTERM/SIGKILL delivery
        # raced (e.g. a renderer spawning crashpad mid-shutdown)
        _sig(signal.SIGKILL)
    except (OSError, ValueError):
        pass


def shutdown_chrome(port: Optional[int] = None) -> bool:
    """Terminate the Chrome instance(s) Nettle launched. Safe to call anytime.

    port=None terminates every browser Nettle launched on any port and closes
    their debugging ports. Pass a specific port to leave other instances
    running. Returns True if at least one process was killed. Repeated
    sniff_network() calls reuse a live browser — call this at the end of your
    session to leave nothing behind.
    """
    global _LAUNCHED_CHROME
    killed = False
    if port is None:
        targets = list(_LAUNCHED_CHROMES.items())
        _LAUNCHED_CHROMES.clear()
    else:
        proc = _LAUNCHED_CHROMES.pop(port, None)
        targets = [(port, proc)] if proc is not None else []
    _LAUNCHED_CHROME = None
    for _port, proc in targets:
        if proc is not None and proc.poll() is None:
            _kill_process_tree(proc)
            killed = True
    return killed


def chrome_processes_alive() -> int:
    """Count live Chrome processes Nettle launched (leader processes only).

    Useful for leak tests: compare before/after sniff_network().
    """
    return sum(
        1 for p in _LAUNCHED_CHROMES.values() if p.poll() is None
    )


def debugging_alive(port: int) -> bool:
    try:
        with urlopen(
            f"http://127.0.0.1:{port}/json/version",
            timeout=_registry.cdp["alive_timeout"],
        ) as r:
            r.read(64)
        return True
    except Exception:
        return False


def find_debugging_port(candidates: Optional[List[int]] = None) -> Optional[int]:
    """Return the first port in *candidates* with a live CDP endpoint.

    candidates=None → registry.cdp["ports"] (default 9222-9234; extend with
    registry.add_cdp_ports() or replace with registry.set_cdp_ports()).
    """
    ports = _normalize_ports(candidates) if candidates is not None else \
        _normalize_ports(_registry.cdp["ports"], _source="registry.cdp['ports']")
    for p in ports:
        if debugging_alive(p):
            return p
    return None


def _chrome_binaries() -> List[str]:
    """Locate a Chromium-based browser on Windows / macOS / Linux / Termux.

    Priority: NETTLE_CHROME_BIN env var, then PATH lookups, then well-known
    install locations per platform. Any Chromium (Chrome, Chromium, Edge,
    Brave) works — CDP is the same protocol.
    """
    from shutil import which
    from sys import platform as _plat

    found: List[str] = []

    env_bin = os.environ.get("NETTLE_CHROME_BIN")
    if env_bin and os.path.isfile(env_bin):
        found.append(env_bin)

    # Android/Termux installs live under $PREFIX (usually not on PATH)
    prefix = os.environ.get("PREFIX", "")
    if prefix:
        for n in ("chromium", "chrome", "google-chrome", "chrome-browser"):
            p = os.path.join(prefix, "bin", n)
            if os.path.isfile(p):
                found.append(p)

    names = [
        "google-chrome-stable", "google-chrome", "chromium", "chromium-browser",
        "brave-browser", "msedge", "microsoft-edge",
    ]
    if os.name == "nt":
        names += ["chrome", "msedge"]
    for n in names:
        path = which(n)
        if path and path not in found:
            found.append(path)

    candidates: List[str] = []
    home = os.path.expanduser("~")
    if os.name == "nt":
        for env in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            base = os.environ.get(env)
            if not base:
                continue
            candidates += [
                os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"),
                os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
                os.path.join(base, "Chromium", "Application", "chrome.exe"),
                os.path.join(base, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
            ]
    elif _plat == "darwin":
        candidates += [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            os.path.join(home, "Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        ]
    else:
        candidates += [
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/usr/bin/brave-browser",
            "/usr/bin/microsoft-edge",
            "/snap/bin/chromium",
            "/data/data/com.termux/files/usr/bin/chromium",
        ]
    for p in candidates:
        if os.path.isfile(p) and p not in found:
            found.append(p)
    return found


def _port_is_free(port: int) -> bool:
    """True if nothing is listening on 127.0.0.1:*port* right now."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            return True
    except OSError:
        return False


def _pick_launch_port(spec: Optional[Union[int, List[int], Tuple[int, int]]]) -> int:
    """Resolve *spec* to the port a NEW Chrome should listen on.

    Order: (1) any candidate already alive is reused; (2) otherwise the
    first candidate that is actually free to bind — so a port occupied by a
    NON-CDP app is skipped instead of producing a Chrome that silently runs
    without debugging. Raises CDPError when no candidate works.
    """
    ports = _normalize_ports(spec) if spec is not None else \
        _normalize_ports(_registry.cdp["ports"], _source="registry.cdp['ports']")
    if not ports:
        raise CDPError(
            "Empty CDP candidate port list. Pass port=9222, or set "
            "registry.cdp['ports'] to a non-empty list."
        )
    for p in ports:
        if debugging_alive(p):
            return p
    for p in ports:
        if p not in _LAUNCHED_CHROMES and _port_is_free(p):
            return p
    raise CDPError(
        f"No usable CDP port among {ports}: all are occupied by other "
        "processes. Free one, or set registry.cdp['ports'] = [your_ports] "
        "/ call sniff_network(port=(lo, hi)) with a free range."
    )


def chrome_launch_cmd(
    binary: str,
    port: int,
    user_data_dir: str,
    *,
    headless: bool = True,
    extra_args: Optional[List[str]] = None,
) -> List[str]:
    """Build the Chrome command line for a dedicated debugging instance.

    Pure function (no side effects) so tests can assert flag handling:
    headless=True adds ``--headless=new --disable-gpu``; headless=False
    omits both so the window is VISIBLE on the user's desktop.
    """
    cmd = [
        binary,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={user_data_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-features=Translate,MediaRouter",
        "--mute-audio",
    ]
    if headless:
        cmd.insert(1, "--headless=new")
        cmd.insert(2, "--disable-gpu")
    if extra_args:
        cmd.extend(extra_args)
    cmd.append("about:blank")
    return cmd


def ensure_debugging_chrome(
    port: Optional[Union[int, List[int], Tuple[int, int]]] = None,
    *,
    user_data_dir: Optional[str] = None,
    headless: Optional[bool] = None,
    wait: Optional[float] = None,
) -> int:
    """Return a live --remote-debugging-port, launching Chrome if needed.

    port may be a single int, a list of ints, or a (lo, hi) inclusive tuple;
    None → registry.cdp["ports"]. An already-alive candidate is reused; a
    candidate occupied by a non-CDP app is skipped. headless=None →
    registry.cdp["headless"] (True by default; False launches a VISIBLE
    browser). Uses a dedicated user-data-dir so it does not fight your
    daily browser profile. Works on Windows, macOS, Linux and Termux.
    """
    import tempfile

    if headless is None:
        headless = bool(_registry.cdp["headless"])
    if wait is None:
        wait = float(_registry.cdp["launch_wait"])

    chosen = _pick_launch_port(port)

    bins = _chrome_binaries()
    if not bins:
        raise CDPError(
            "No Chrome/Chromium/Edge/Brave binary found. Install one, or point "
            "NETTLE_CHROME_BIN at the executable, or start a browser with "
            f"--remote-debugging-port={chosen}"
        )

    udd = user_data_dir or os.path.join(
        tempfile.gettempdir(), f"nettle-chrome-cdp-{chosen}"
    )
    os.makedirs(udd, exist_ok=True)
    cmd = chrome_launch_cmd(bins[0], chosen, udd, headless=headless)

    # Detach so the caller owns a CDP endpoint without blocking.
    import subprocess

    popen_kwargs: dict = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if os.name == "nt":
        popen_kwargs["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        )
    else:
        popen_kwargs["start_new_session"] = True
    proc = subprocess.Popen(cmd, **popen_kwargs)
    _register_launched(chosen, proc)

    deadline = time.time() + wait
    while time.time() < deadline:
        if debugging_alive(chosen):
            return chosen
        if proc.poll() is not None:
            _LAUNCHED_CHROMES.pop(chosen, None)
            raise CDPError(
                f"{bins[0]} exited immediately (code {proc.returncode}) with "
                f"--remote-debugging-port={chosen}. Close other browser locks "
                "on that user-data-dir and retry."
            )
        time.sleep(float(_registry.cdp["launch_poll_interval"]))
    raise CDPError(
        f"Started {bins[0]} with --remote-debugging-port={chosen} but "
        f"http://127.0.0.1:{chosen}/json/version never answered within "
        f"{wait}s. Close other browser locks on that user-data-dir and retry."
    )


def list_targets(port: int = 9222) -> List[dict]:
    with urlopen(
        f"http://127.0.0.1:{port}/json/list",
        timeout=_registry.cdp["http_timeout"],
    ) as r:
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
            with urlopen(req, timeout=_registry.cdp["http_timeout"]) as r:
                return json.loads(r.read().decode())
        except (URLError, HTTPError, TimeoutError, OSError) as e:
            last_err = e
            continue
    raise CDPError(f"Cannot open new tab on port {port}: {last_err}")


def sniff_network(
    url: str,
    *,
    port: Optional[Union[int, List[int], Tuple[int, int]]] = None,
    headless: Optional[bool] = None,
    settle: Optional[float] = None,
    on_event: Optional[Callable[[str, dict], None]] = None,
    ensure_chrome: bool = True,
    scroll: bool = True,
    scroll_steps: Optional[int] = None,
    scroll_pause: Optional[float] = None,
    keep_chrome: bool = False,
) -> Dict[str, Any]:
    """Open url in Chrome via CDP and capture Network requests/responses.

    Returns {"entries": [...], "xhr_fetch": [...], "json": [...], "media": [...]}.
    Each entry: {requestId, url, method, type, headers, status, mime,
    body?, body_b64?, media?} — body previews capped at
    registry.cdp["body_preview_chars"] (default 4000).

    port may be a single int, a list, or a (lo, hi) inclusive tuple; None →
    registry.cdp["ports"] (default 9222-9234, extend with
    registry.add_cdp_ports()). headless=None → registry.cdp["headless"]
    (True default); pass headless=False to launch the Chrome window VISIBLE
    so you can watch what the sniffer is doing.

    scroll=True scrolls the page (scroll_steps × scroll_pause) to trigger
    lazy-loading/XHR before the final pump. ensure_chrome=True auto-starts
    a dedicated Chrome when no debugging port is listening; every browser
    we launched is terminated at the end unless keep_chrome=True (leave it
    True to reuse across repeated sniffs; finish with shutdown_chrome()).
    """
    if settle is None:
        settle = float(_registry.cdp["settle"])
    if scroll_steps is None:
        scroll_steps = int(_registry.cdp["scroll_steps"])
    if scroll_pause is None:
        scroll_pause = float(_registry.cdp["scroll_pause"])
    body_cap = int(_registry.cdp["body_preview_chars"])
    body_url_hints = tuple(_registry.cdp["body_url_hints"])

    chosen: Optional[int] = None
    if port is None:
        chosen = find_debugging_port()
        if chosen is None:
            if not ensure_chrome:
                ports = _normalize_ports(_registry.cdp["ports"])
                raise CDPError(
                    "No live CDP endpoint in registry.cdp['ports'] "
                    f"({ports[:6]}{'…' if len(ports) > 6 else ''}). Start Chrome "
                    "with --remote-debugging-port=<port>, or call "
                    "ensure_debugging_chrome(), or pass ensure_chrome=True."
                )
            chosen = ensure_debugging_chrome(None, headless=headless)
    else:
        ports = _normalize_ports(port, _source="sniff_network(port=...)")
        if ensure_chrome:
            chosen = ensure_debugging_chrome(ports, headless=headless)
        else:
            chosen = find_debugging_port(ports)
            if chosen is None:
                raise CDPError(
                    f"Nothing CDP-alive among ports {ports}. Start Chrome with "
                    "--remote-debugging-port=<one of them> or pass "
                    "ensure_chrome=True."
                )
    port = chosen

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
            or any(h in url for h in body_url_hints)
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
            result = cdp.call(
                "Network.getResponseBody",
                {"requestId": rid},
                timeout=min(5.0, float(_registry.cdp["call_timeout"])),
            )
            body = result.get("body", "")
            if result.get("base64Encoded"):
                entry["body_b64"] = True
                try:
                    raw = base64.b64decode(body)
                    entry["body"] = raw.decode("utf-8", errors="replace")[:body_cap]
                except Exception:
                    entry["body"] = f"<base64 {len(body)} chars>"
            else:
                entry["body"] = (body or "")[:body_cap]
            if on_event:
                on_event("body", entry)
        except Exception as e:
            entry["body_error"] = str(e)

    cdp.on("Network.requestWillBeSent", req_sent)
    cdp.on("Network.responseReceived", resp_recv)
    cdp.on("Network.loadingFinished", loading_finished)

    launched_here = port in _LAUNCHED_CHROMES
    try:
        cdp.call(
            "Network.enable",
            {"maxPostDataSize": int(_registry.cdp["max_post_data_size"])},
        )
        cdp.call("Page.enable")
        cdp.call("Page.navigate", {"url": url})
        cdp.pump_for(settle)
        if scroll:
            for _ in range(max(1, scroll_steps)):
                try:
                    cdp.call("Runtime.evaluate", {
                        "expression": "window.scrollBy(0, Math.max(600, document.body.scrollHeight * 0.5));",
                        "returnByValue": True,
                    }, timeout=float(_registry.cdp["runtime_eval_timeout"]))
                except Exception:
                    pass
                cdp.pump_for(scroll_pause)
            try:
                cdp.call("Runtime.evaluate", {
                    "expression": "window.scrollTo(0, 0);", "returnByValue": True,
                }, timeout=float(_registry.cdp["runtime_eval_timeout"]))
            except Exception:
                pass
            cdp.pump_for(settle)
    finally:
        cdp.close()
        _close_tab_quietly(port, tab.get("id"))
        if launched_here and not keep_chrome:
            shutdown_chrome(port)

    # classify helpers
    entries = list(captured.values())
    media = [e for e in entries if e.get("media") or _is_media_url(e.get("url") or "")]
    jsonish = [
        e for e in entries
        if (e.get("mime") or "").lower().find("json") >= 0
        or (e.get("body") or "").lstrip()[:1] in "{["
    ]
    xhr = [e for e in entries if (e.get("type") or "").lower() in ("xhr", "fetch")]

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


def _close_tab_quietly(port: int, tab_id: Optional[str]) -> None:
    """Best-effort close of a CDP tab so browsers don't accumulate tabs."""
    if not tab_id:
        return
    try:
        urlopen(
            f"http://127.0.0.1:{port}/json/close/{tab_id}",
            timeout=_registry.cdp["tab_close_timeout"],
        ).read()
    except Exception:
        pass


def _is_media_url(url: str) -> bool:
    from .registry import registry as _registry
    path = url.lower().split("?", 1)[0]
    return path.endswith(tuple(_registry.media_exts | {".ts"}))
