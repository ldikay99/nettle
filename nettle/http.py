"""HTTP client via urllib — any method, any endpoint the user passes.

Stdlib only. No path heuristics: if you have a URL, call it.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit, parse_qsl
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener

from .exceptions import FetchError
from .parse import detect_charset

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36"
)

# Alternating real-browser profiles (UA + matching Sec-Ch-Ua) so successive
# requests don't all carry the identical fingerprint. Users can override
# everything with Session(user_agent=..., headers=...).
UA_PROFILES = (
    (
        DEFAULT_UA,
        '"Chromium";v="140", "Not?A_Brand";v="99", "Google Chrome";v="140"',
        '"Windows"',
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/140.0.0.0 Safari/537.36",
        '"Chromium";v="140", "Not.A/Brand";v="99", "Google Chrome";v="140"',
        '"Linux"',
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
        '"Chromium";v="139", "Not;A=Brand";v="99", "Google Chrome";v="139"',
        '"macOS"',
    ),
)

BROWSER_HEADERS = {
    "User-Agent": DEFAULT_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
              "image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
    # urllib has no transparent gzip decoding — never advertise compression.
    "Accept-Encoding": "identity",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

JsonBody = Any
DataBody = Union[bytes, str, Mapping[str, Any], Sequence[Tuple[str, Any]], None]


class Response:
    """urllib response wrapper with .text, .json(), .doc, .headers, .url, .ok."""

    def __init__(
        self,
        *,
        url: str,
        status: int,
        headers: Dict[str, str],
        body: bytes,
        encoding: Optional[str] = None,
        method: str = "GET",
    ) -> None:
        self.url = url
        self.status = status
        self.headers = {k: v for k, v in headers.items()}
        self.body = body
        self.content = body
        self.method = method.upper()
        self._encoding = encoding
        self._text: Optional[str] = None
        self._doc = None

    @property
    def ok(self) -> bool:
        return 200 <= int(self.status) < 400

    @property
    def encoding(self) -> str:
        if self._encoding:
            return self._encoding
        ctype = self.headers.get("Content-Type") or self.headers.get("content-type") or ""
        m = re.search(r"charset=([\w\-]+)", ctype, re.I)
        if m:
            self._encoding = m.group(1)
            return self._encoding
        sniffed = detect_charset(self.body)
        self._encoding = sniffed or "utf-8"
        return self._encoding

    @property
    def text(self) -> str:
        if self._text is None:
            enc = self.encoding
            try:
                self._text = self.body.decode(enc, errors="replace")
            except LookupError:
                self._text = self.body.decode("utf-8", errors="replace")
        return self._text

    def json(self) -> Any:
        return json.loads(self.text)

    @property
    def doc(self):
        """Parse body as HTML into a Nettle document (lazy)."""
        if self._doc is None:
            from .soup import Nettle
            self._doc = Nettle(self.text, base_url=self.url)
        return self._doc

    def __repr__(self) -> str:
        return f"<Response [{self.status}] {self.method} {self.url!r}>"


def _merge_params(url: str, params: Optional[Mapping[str, Any]]) -> str:
    if not params:
        return url
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    for k, v in params.items():
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            # last-wins for simplicity; encode repeats via urlencode doseq below
            q[k] = v
        else:
            q[k] = v
    # rebuild with doseq
    flat: List[Tuple[str, Any]] = []
    for k, v in q.items():
        if isinstance(v, (list, tuple)):
            for item in v:
                flat.append((k, item))
        else:
            flat.append((k, v))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(flat, doseq=True), parts.fragment))


def _encode_body(
    *,
    json_body: Any = None,
    data: DataBody = None,
    headers: Dict[str, str],
) -> Optional[bytes]:
    if json_body is not None and data is not None:
        raise ValueError("Pass only one of json= or data=")
    if json_body is not None:
        raw = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers.setdefault("Content-Type", "application/json; charset=utf-8")
        return raw
    if data is None:
        return None
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, Mapping):
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
        return urlencode({k: v for k, v in data.items() if v is not None}, doseq=True).encode("utf-8")
    if isinstance(data, (list, tuple)):
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
        return urlencode(list(data), doseq=True).encode("utf-8")
    raise TypeError(f"Unsupported data type: {type(data)!r}")


class Session:
    """Spoofable HTTP session: any method, cookies, retries, user-supplied URLs.

    Any default left as None is read from nettle.registry.http at construction,
    so `registry.http["timeout"] = 10` re-tunes every future Session/request.
    """

    def __init__(
        self,
        *,
        user_agent: Optional[str] = None,
        headers: Optional[dict] = None,
        spoof_browser: Optional[bool] = None,
        rotate_fingerprint: Optional[bool] = None,
        timeout: Optional[float] = None,
        retries: Optional[int] = None,
        retry_backoff: Optional[float] = None,
    ) -> None:
        from .registry import registry as _registry
        rh = _registry.http
        spoof_browser = rh["spoof_browser"] if spoof_browser is None else spoof_browser
        rotate_fingerprint = rh["rotate_fingerprint"] if rotate_fingerprint is None else rotate_fingerprint
        user_agent = user_agent if user_agent is not None else rh["user_agent"]
        if headers is None:
            headers = dict(rh["headers"])
        else:
            headers = {**rh["headers"], **headers}
        self.timeout = rh["timeout"] if timeout is None else timeout
        self.retries = max(0, rh["retries"] if retries is None else int(retries))
        self.retry_backoff = float(rh["retry_backoff"] if retry_backoff is None else retry_backoff)
        self.headers: Dict[str, str] = {}
        if spoof_browser:
            self.headers.update(BROWSER_HEADERS)
            ua, sec_ch_ua, platform = UA_PROFILES[0]
            if rotate_fingerprint:
                import random
                ua, sec_ch_ua, platform = UA_PROFILES[random.randrange(len(UA_PROFILES))]
            self.headers["User-Agent"] = user_agent or ua
            if user_agent is None:
                self.headers["Sec-Ch-Ua"] = sec_ch_ua
                self.headers["Sec-Ch-Ua-Mobile"] = "?0"
                self.headers["Sec-Ch-Ua-Platform"] = platform
        elif user_agent:
            self.headers["User-Agent"] = user_agent
        if headers:
            self.headers.update(headers)
        self._opener = build_opener(HTTPCookieProcessor(), HTTPRedirectHandler())

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict] = None,
        params: Optional[Mapping[str, Any]] = None,
        data: DataBody = None,
        json: Any = None,  # noqa: A002 — matches requests API
        referer: Optional[str] = None,
        timeout: Optional[float] = None,
        retries: Optional[int] = None,
    ) -> Response:
        """Send an HTTP request to *any* URL the caller provides.

        No discovery, no /api/ assumptions — you pass the endpoint.
        """
        method_u = (method or "GET").upper()
        target = _merge_params(url, params)
        hdrs = dict(self.headers)
        if referer:
            hdrs["Referer"] = referer
        if headers:
            hdrs.update(headers)
        body = _encode_body(json_body=json, data=data, headers=hdrs)
        # urllib forbids body on GET/HEAD unless we still allow user override
        if method_u in ("GET", "HEAD") and body is not None:
            # still send if user insisted (some APIs abuse GET+body); keep bytes
            pass
        to = self.timeout if timeout is None else timeout
        attempts = self.retries if retries is None else max(0, int(retries))
        last_err: Optional[BaseException] = None

        for attempt in range(attempts + 1):
            req = Request(target, data=body, headers=hdrs, method=method_u)
            try:
                with self._opener.open(req, timeout=to) as resp:
                    raw = resp.read()
                    rh: Dict[str, str] = {k: v for k, v in resp.headers.items()}
                    final_url = resp.geturl()
                    status = getattr(resp, "status", None) or resp.getcode() or 200
                    charset = None
                    try:
                        charset = resp.headers.get_content_charset()
                    except Exception:
                        pass
                    return Response(
                        url=final_url,
                        status=int(status),
                        headers=rh,
                        body=raw,
                        encoding=charset,
                        method=method_u,
                    )
            except HTTPError as e:
                raw = e.read() if hasattr(e, "read") else b""
                rh = {}
                if e.headers:
                    for k, v in e.headers.items():
                        rh[k] = v
                if e.code in (408, 425, 429, 500, 502, 503, 504) and attempt < attempts:
                    last_err = e
                    time.sleep(self.retry_backoff * (2 ** attempt))
                    continue
                if raw or e.code:
                    return Response(
                        url=e.geturl() if hasattr(e, "geturl") else target,
                        status=e.code,
                        headers=rh,
                        body=raw or b"",
                        method=method_u,
                    )
                raise FetchError(f"HTTP {e.code} for {target}: {e.reason}") from e
            except (URLError, TimeoutError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
                last_err = e
                if attempt < attempts:
                    time.sleep(self.retry_backoff * (2 ** attempt))
                    continue
                if isinstance(e, TimeoutError):
                    raise FetchError(f"Timeout fetching {target}") from e
                reason = getattr(e, "reason", e)
                raise FetchError(f"URL error for {target}: {reason}") from e

        raise FetchError(f"URL error for {target}: {last_err}")

    def get(self, url: str, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Response:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:
        return self.request("OPTIONS", url, **kwargs)


def request(
    method: str,
    url: str,
    *,
    timeout: float = 30.0,
    user_agent: Optional[str] = None,
    headers: Optional[dict] = None,
    spoof_browser: bool = True,
    retries: int = 3,
    **kwargs: Any,
) -> Response:
    """One-shot request to a user-supplied endpoint (any method).

    Example:
        from nettle import request
        request("POST", "https://shop.example/catalog/load", json={"q": "x"})
        request("DELETE", "https://shop.example/items/42")
    """
    session = Session(
        user_agent=user_agent,
        headers=headers,
        spoof_browser=spoof_browser,
        timeout=timeout,
        retries=retries,
    )
    return session.request(method, url, **kwargs)


call = request  # alias


def fetch_response(
    url: str,
    *,
    method: str = "GET",
    timeout: float = 30.0,
    user_agent: Optional[str] = None,
    headers: Optional[dict] = None,
    spoof_browser: bool = True,
    referer: Optional[str] = None,
    retries: int = 3,
    params: Optional[Mapping[str, Any]] = None,
    data: DataBody = None,
    json: Any = None,  # noqa: A002
) -> Response:
    """Fetch URL → Response. Defaults to GET; pass method=/json=/data= freely."""
    return request(
        method,
        url,
        timeout=timeout,
        user_agent=user_agent,
        headers=headers,
        spoof_browser=spoof_browser,
        retries=retries,
        referer=referer,
        params=params,
        data=data,
        json=json,
    )


def fetch(
    url: str,
    *,
    timeout: float = 30.0,
    user_agent: Optional[str] = None,
    headers: Optional[dict] = None,
    spoof_browser: bool = True,
    encoding: Optional[str] = None,
    referer: Optional[str] = None,
    **kwargs: Any,
):
    """Fetch URL and return a Nettle document (encoding auto-detected)."""
    resp = fetch_response(
        url,
        timeout=timeout,
        user_agent=user_agent,
        headers=headers,
        spoof_browser=spoof_browser,
        referer=referer,
        **kwargs,
    )
    from .soup import Nettle
    text = resp.text
    if encoding:
        try:
            text = resp.body.decode(encoding, errors="replace")
        except LookupError:
            pass
    return Nettle(text, base_url=resp.url)


def fetch_bytes(
    url: str,
    *,
    timeout: float = 30.0,
    user_agent: Optional[str] = None,
    headers: Optional[dict] = None,
    spoof_browser: bool = True,
    **kwargs: Any,
) -> Tuple[bytes, Optional[str]]:
    """Fetch URL; return (body_bytes, charset_or_None)."""
    resp = fetch_response(
        url,
        timeout=timeout,
        user_agent=user_agent,
        headers=headers,
        spoof_browser=spoof_browser,
        **kwargs,
    )
    return resp.body, resp._encoding or resp.encoding


def fetch_html(url: str, **kwargs: Any) -> str:
    """Fetch and return decoded HTML string."""
    return fetch_response(url, **kwargs).text
