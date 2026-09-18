"""HTTP client via urllib — any method, any endpoint the user passes.

Stdlib only. No path heuristics: if you have a URL, call it.
"""

from __future__ import annotations

import codecs
import gzip
import json
import re
import ssl
import time
import zlib
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit, parse_qsl
from urllib.request import (
    HTTPSHandler,
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    Request,
    build_opener,
)

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
    # gzip/deflate/br are all decoded by nettle itself in Session.request
    # (stdlib urllib does not decompress). 'br' is handled by the pure-Python
    # RFC 7932 decoder in nettle.brotli_dec. The value here is a fallback;
    # the live source is registry.http["accept_encoding"].
    "Accept-Encoding": "gzip, deflate, br",
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


def _cookie_path_ok(cookie_path: Optional[str], request_path: str) -> bool:
    """RFC 6265 path-match: equal, or cookie path is a prefix on a '/' bondary."""
    cp = cookie_path or "/"
    if not cp.startswith("/"):
        cp = "/" + cp
    if request_path == cp:
        return True
    return request_path.startswith(cp if cp.endswith("/") else cp + "/")


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
        header_encoding: Optional[str] = None,
        method: str = "GET",
        history: Tuple[str, ...] = (),
    ) -> None:
        self.url = url
        self.status = status
        self.headers = {k: v for k, v in headers.items()}
        self.body = body
        self.content = body
        self.method = method.upper()
        self.history = tuple(history)
        self._encoding = encoding  # explicit user override, wins over everything
        self._header_encoding = header_encoding  # charset= from Content-Type
        self._enc_cache: Optional[str] = None
        self._text: Optional[str] = None
        self._doc = None

    @property
    def ok(self) -> bool:
        return 200 <= int(self.status) < 400

    def raise_for_status(self) -> "Response":
        """requests-style: raise FetchError on 4xx/5xx, return self otherwise."""
        if not self.ok:
            raise FetchError(
                f"{self.status} error for {self.method} {self.url}"
            )
        return self

    @property
    def encoding(self) -> str:
        """Charset used by .text. Priority: explicit override > BOM in body >
        <meta charset> in body > Content-Type header charset > sniff > utf-8.

        BOM/meta beat the header because servers frequently mislabel legacy
        pages (a UTF-8 BOM with a stale charset=iso-8859-1 header must not
        produce mojibake).
        """
        if self._enc_cache:
            return self._enc_cache
        candidates: List[str] = []
        if self._encoding:
            candidates.append(self._encoding)
        # 1) BOM in the body
        if self.body.startswith(b"\xef\xbb\xbf"):
            candidates.append("utf-8-sig")
        elif self.body.startswith(b"\xff\xfe") or self.body.startswith(b"\xfe\xff"):
            candidates.append("utf-16")
        # 2) <meta charset> / http-equiv in the first bytes of the body
        meta = _meta_charset_from_body(self.body)
        if meta:
            candidates.append(meta)
        # 3) Content-Type header
        if self._header_encoding:
            candidates.append(self._header_encoding)
        else:
            ctype = self.headers.get("Content-Type") or self.headers.get("content-type") or ""
            m = re.search(r"charset=([\w\-]+)", ctype, re.I)
            if m:
                candidates.append(m.group(1))
        # 4) sniff (BOM + meta again, then defaults)
        sniffed = detect_charset(self.body)
        if sniffed:
            candidates.append(sniffed)
        candidates.append("utf-8")
        for enc in candidates:
            try:
                codecs.lookup(enc)
            except LookupError:
                continue
            self._enc_cache = enc
            return enc
        self._enc_cache = "utf-8"
        return "utf-8"

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
        try:
            return json.loads(self.text)
        except json.JSONDecodeError as e:
            from .exceptions import JsonBodyError
            raise JsonBodyError(
                f"Response body is not valid JSON ({self.method} {self.url}: "
                f"{e.msg} at line {e.lineno} col {e.colno}). "
                "Check Response.text / Response.headers['Content-Type']."
            ) from e

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
    """Merge *params* into *url*'s query string (requests semantics).

    Existing query pairs are preserved VERBATIM — including repeated keys
    (?cat=1&cat=2 stays intact; a scraper's filters must not be collapsed)
    — and the new params are appended, so `params={"a": 2}` on `?a=1`
    yields `?a=1&a=2` exactly like requests. List/tuple values expand to
    repeated keys; None values are dropped.
    """
    if not params:
        return url
    parts = urlsplit(url)
    base_pairs = parse_qsl(parts.query, keep_blank_values=True)
    flat: List[Tuple[str, Any]] = []
    for k, v in params.items():
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            flat.extend((k, item) for item in v)
        else:
            flat.append((k, v))
    return urlunsplit((
        parts.scheme, parts.netloc, parts.path,
        urlencode(base_pairs + flat, doseq=True),
        parts.fragment,
    ))


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


_REQUOTE_SAFE_PATH = "/%:@!$&'()*+,;=~[]"
_REQUOTE_SAFE_QUERY = "%:@!$&'()*+,;=~/?="


def _requote_uri(url: str) -> str:
    """Percent-encode non-ASCII URL characters (IRI → URI), preserving
    existing %-escapes. What requests' requote_uri does — lets
    fetch("https://ja.wikipedia.org/wiki/東京都") just work."""
    try:
        url.encode("ascii")
        if " " not in url and "\t" not in url and "\n" not in url:
            return url  # pure ASCII, nothing to fix
    except UnicodeEncodeError:
        pass
    from urllib.parse import quote, urlsplit, urlunsplit
    parts = urlsplit(url)
    netloc = parts.netloc
    try:
        netloc = netloc.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        netloc = quote(netloc, safe=":@[]")
    return urlunsplit((
        parts.scheme,
        netloc,
        quote(parts.path, safe=_REQUOTE_SAFE_PATH),
        quote(parts.query, safe=_REQUOTE_SAFE_QUERY),
        quote(parts.fragment, safe=_REQUOTE_SAFE_QUERY),
    ))


_META_CHARSET_BODY_RE = re.compile(
    rb'<meta[^>]+charset\s*=\s*["\']?([\w\-]+)', re.I)
_META_HTTP_EQUIV_BODY_RE = re.compile(
    rb'<meta[^>]+http-equiv\s*=\s*["\']?content-type["\']?[^>]+'
    rb'content\s*=\s*["\']?[^"\']*charset=([\w\-]+)', re.I)


def _meta_charset_from_body(body: bytes) -> Optional[str]:
    """<meta charset> (or http-equiv) declared inside the HTML itself."""
    if not body:
        return None
    head = body[:8192]
    m = _META_CHARSET_BODY_RE.search(head) or _META_HTTP_EQUIV_BODY_RE.search(head)
    if m:
        try:
            candidate = m.group(1).decode("ascii", "replace")
            codecs.lookup(candidate)
            return candidate
        except (LookupError, UnicodeDecodeError):
            return None
    return None


def _brotli_decompress(raw: bytes) -> bytes:
    """Pure-Python RFC 7932 decode; FetchError with remedy on failure."""
    from .brotli_dec import (
        BrotliError,
        BrotliLargeWindowError,
        decompress as _dec,
    )
    from .registry import registry as _registry
    try:
        return _dec(raw)
    except BrotliLargeWindowError as e:
        # lgwin > 24 needs RFC 9841 semantics this decoder doesn't implement.
        # The C brotli module, when installed, is used as an OPTIONAL
        # accelerator — default behavior (pure decoder) is unchanged.
        try:
            import brotli as _cbrotli  # type: ignore
        except ImportError:
            _cbrotli = None
        if _cbrotli is not None:
            try:
                return _cbrotli.decompress(raw)
            except Exception:
                pass
        raise FetchError(
            f"{e}. This site served a large-window brotli stream, which only "
            "the C brotli module can decode: 'pip install brotli' and retry, "
            "or stop advertising br via "
            "registry.http['accept_encoding'] = 'gzip, deflate'."
        ) from e
    except BrotliError as e:
        remedy = (
            "Set registry.http['accept_encoding'] = 'gzip, deflate' to stop "
            "advertising br, or decode Response.body with your own brotli."
        )
        pref = _registry.http.get("accept_encoding")
        if pref and "br" not in str(pref):
            remedy = (
                f"Server sent Content-Encoding: br even though accept_encoding="
                f"{pref!r} does not advertise it. Decode Response.body with "
                "your own brotli install."
            )
        raise FetchError(
            f"brotli decoding failed ({e}). {remedy}"
        ) from e


def _decode_body(raw: bytes, content_encoding: str) -> bytes:
    """Decode Content-Encoding: gzip / deflate / br (also comma stacks)."""
    enc = (content_encoding or "").strip().lower()
    if not raw or not enc or enc == "identity":
        return raw
    # stacked encodings ("gzip, br"): they were applied left-to-right,
    # so peel them off right-to-left.
    layers = [l.strip() for l in enc.split(",") if l.strip()]
    for layer in reversed(layers):
        if layer in ("", "identity"):
            continue
        try:
            if layer == "gzip":
                raw = gzip.decompress(raw)
            elif layer == "deflate":
                try:
                    raw = zlib.decompress(raw)
                except zlib.error:
                    raw = zlib.decompress(raw, -zlib.MAX_WBITS)
            elif layer == "br":
                raw = _brotli_decompress(raw)
            else:
                # unknown layer (e.g. zstd): leave the rest as bytes
                return raw
        except FetchError:
            raise
        except (OSError, zlib.error, EOFError):
            return raw  # leave bytes as-is rather than crash
    return raw


HookList = List[Callable[["Response"], "Response"]]


def _normalize_hooks(hooks: Optional[Mapping[str, Any]], *, where: str) -> Dict[str, HookList]:
    """requests-style hooks: {'response': fn} or {'response': [fn, ...]}.
    Only the 'response' event exists in nettle; anything else fails loudly."""
    out: Dict[str, HookList] = {}
    if not hooks:
        return out
    if not isinstance(hooks, Mapping):
        raise TypeError(
            f"{where}: hooks must be a dict like {{'response': fn}}, "
            f"got {type(hooks).__name__}"
        )
    for event, fns in hooks.items():
        if event != "response":
            raise ValueError(
                f"{where}: unknown hook event {event!r} — nettle supports "
                "only {'response': fn} (fn(resp) -> resp)"
            )
        if callable(fns):
            fns = [fns]
        if not isinstance(fns, (list, tuple)):
            raise TypeError(
                f"{where}: hooks['{event}'] must be a callable or list of "
                f"callables, got {type(fns).__name__}"
            )
        for fn in fns:
            if not callable(fn):
                raise TypeError(
                    f"{where}: hooks['{event}'] contains a non-callable: {fn!r}"
                )
        out[event] = list(fns)
    return out


def _dispatch_hooks(resp: "Response", hooks: HookList) -> "Response":
    """Run response hooks (requests semantics): each hook receives the
    Response and returns it (or a replacement) — raising aborts the call."""
    for fn in hooks:
        result = fn(resp)
        if result is None:
            continue  # hook mutated in place and returned None — keep resp
        if not isinstance(result, Response):
            raise TypeError(
                f"response hook {getattr(fn, '__name__', fn)!r} must return "
                f"the Response (or None), got {type(result).__name__}"
            )
        resp = result
    return resp


def _retry_statuses() -> set:
    """Retry-worthy HTTP statuses — registry.http['retry_statuses'] read at
    call time (default {408, 425, 429, 500, 502, 503, 504})."""
    from .registry import registry as _registry
    return set(_registry.http.get("retry_statuses") or ())


class _RedirectTracker(HTTPRedirectHandler):
    """Records the redirect chain so Response.history can expose it."""

    def __init__(self) -> None:
        super().__init__()
        self.chain: List[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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
        verify: Optional[bool] = None,
        proxies: Optional[Dict[str, str]] = None,
        base_url: Optional[str] = None,
        auth: Optional[Tuple[str, str]] = None,
        auth_scheme: str = "basic",
        hooks: Optional[Dict[str, Any]] = None,
    ) -> None:
        import base64 as _b64
        import http.cookiejar
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
        # Retry pacing (429/503 storms): exponential backoff with jitter so
        # parallel clients don't hammer the server in lockstep.
        self.retry_jitter = rh.get("retry_jitter", True)
        self.retry_max_delay = float(rh.get("retry_max_delay", 30.0))
        # What we advertise we can decode. "br" is backed by nettle.brotli_dec
        # (pure Python); drop it here if you'd rather never receive brotli.
        self.accept_encoding = str(rh.get("accept_encoding") or BROWSER_HEADERS["Accept-Encoding"])
        self.verify = rh.get("verify", True) if verify is None else verify
        self.proxies: Dict[str, str] = dict(rh.get("proxies") or {})
        if proxies:
            self.proxies.update(proxies)
        # Session(base_url="https://api.example.com") → session.get("/items")
        # resolves against it, requests-toolbelt / httpx style.
        self.base_url: Optional[str] = base_url or rh.get("base_url") or None
        self._base_host: Optional[str] = None
        if self.base_url:
            parts = urlsplit(self.base_url)
            if not parts.scheme:
                raise FetchError(
                    f"Session base_url must be absolute (include scheme), "
                    f"got {self.base_url!r}"
                )
            self.base_url = self.base_url.rstrip("/")
            self._base_host = f"{parts.scheme}://{parts.netloc}"
        # auth=(user, password) — HTTP Basic by default
        self.auth: Optional[Tuple[str, str]] = auth or rh.get("auth") or None
        self._auth_header: Optional[str] = None
        if self.auth is not None:
            try:
                user, password = self.auth
            except (TypeError, ValueError):
                raise FetchError(
                    f"auth must be a (user, password) tuple, got {self.auth!r}"
                ) from None
            if auth_scheme.lower() in ("basic", "bearer"):
                scheme = auth_scheme.lower()
            else:
                raise FetchError(
                    f"auth_scheme must be 'basic' or 'bearer', got {auth_scheme!r}"
                )
            if scheme == "basic":
                token = _b64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
                self._auth_header = f"Basic {token}"
            else:  # bearer: tuple is (name, token)
                self._auth_header = f"Bearer {password}"
        self.cookies = http.cookiejar.CookieJar()
        # requests-style response hooks: Session(hooks={'response': fn})
        self.hooks: Dict[str, HookList] = _normalize_hooks(
            hooks, where="Session(hooks=...)"
        )
        self._ssl_ctx: Optional[ssl.SSLContext] = None
        if self.verify is False:
            self._ssl_ctx = ssl._create_unverified_context()
        self.headers: Dict[str, str] = {}
        if spoof_browser:
            self.headers.update(BROWSER_HEADERS)
            # profiles are user-extendable via registry.http["ua_profiles"];
            # module-level UA_PROFILES is the built-in default (kept for
            # backwards compatibility of `from nettle.http import UA_PROFILES`)
            profiles = tuple(rh.get("ua_profiles") or UA_PROFILES)
            ua, sec_ch_ua, platform = profiles[0]
            if rotate_fingerprint:
                import random
                ua, sec_ch_ua, platform = profiles[random.randrange(len(profiles))]
            self.headers["User-Agent"] = user_agent or ua
            if user_agent is None:
                self.headers["Sec-Ch-Ua"] = sec_ch_ua
                self.headers["Sec-Ch-Ua-Mobile"] = "?0"
                self.headers["Sec-Ch-Ua-Platform"] = platform
        elif user_agent:
            self.headers["User-Agent"] = user_agent
        if headers:
            self.headers.update(headers)
        # Accept-Encoding always follows the registry value (default
        # "gzip, deflate, br" — brotli is decoded by nettle.brotli_dec).
        self.headers["Accept-Encoding"] = str(headers.get("Accept-Encoding") or self.accept_encoding) if headers else self.accept_encoding

    def _build_opener(self, tracker: "_RedirectTracker"):
        handlers = [
            HTTPCookieProcessor(self.cookies),
            tracker,
            HTTPRedirectHandler(),
        ]
        if self.proxies:
            from urllib.request import ProxyHandler
            handlers.append(ProxyHandler(self.proxies))
        https_handler = (
            HTTPSHandler(context=self._ssl_ctx) if self._ssl_ctx is not None
            else HTTPSHandler()
        )
        handlers.append(https_handler)
        return build_opener(*handlers)

    # --- first-class cookies (insert / extract / persist) -------------------

    _IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")  # v4; v6 has ':'

    @classmethod
    def _cookie_domain_form(cls, domain: str) -> str:
        """Domain cookies get a leading dot (RFC 6265 subdomain match) —
        EXCEPT IP literals: http.cookiejar never dot-prefixes IP request
        hosts, so a cookie stored as ``.127.0.0.1`` silently never matches
        and is never sent. Host-only form for IPs."""
        if not domain:
            return domain
        if cls._IP_HOST_RE.match(domain) or ":" in domain:
            return domain.lstrip(".")
        return domain if domain.startswith(".") else "." + domain

    def _host_of(self, url_or_domain: str) -> str:
        from urllib.parse import urlsplit
        s = str(url_or_domain).strip()
        if "://" in s:
            return (urlsplit(s).hostname or "").lower()
        d = s.split("/")[0]
        return d.lstrip(".").lower()

    @staticmethod
    def _default_domain(session_base: Optional[str], domain: Optional[str]) -> str:
        if domain:
            return Session._cookie_domain_form(domain)
        if session_base:
            from urllib.parse import urlsplit
            host = urlsplit(session_base).hostname or ""
            return Session._cookie_domain_form(host) if host else host
        raise FetchError(
            "set_cookies() needs a domain= (or Session(base_url=...) so one "
            "can be derived). Cookies are domain-scoped by RFC 6265."
        )

    def set_cookies(
        self,
        cookies: Mapping[str, Any],
        *,
        domain: Optional[str] = None,
        path: str = "/",
        expires: Optional[float] = None,
        secure: bool = False,
        httponly: bool = False,
    ) -> int:
        """Insert cookies into the session jar (they ride every request).

            session.set_cookies({"session": "abc", "lang": "es"}, domain="example.com")

        domain defaults to the session base_url host. expires is a unix
        timestamp (None = session cookie). Returns the number stored.
        """
        import http.cookiejar
        dom = self._default_domain(self.base_url, domain)
        n = 0
        for name, value in (cookies or {}).items():
            self.cookies.set_cookie(http.cookiejar.Cookie(
                version=0,
                name=str(name),
                value="" if value is None else str(value),
                port=None,
                port_specified=False,
                domain=dom,
                domain_specified=True,
                domain_initial_dot=dom.startswith("."),
                path=path or "/",
                path_specified=True,
                secure=bool(secure),
                expires=float(expires) if expires else None,
                discard=expires is None,
                comment=None,
                comment_url=None,
                rest={"HttpOnly": ""} if httponly else {},
                rfc2109=False,
            ))
            n += 1
        return n

    def get_cookie_dict(self, url_or_domain: str) -> Dict[str, str]:
        """Cookies that WOULD be sent to *url_or_domain*: {name: value}.

        Includes everything the server set via Set-Cookie plus whatever you
        inserted with set_cookies()/request(cookies=...) for that domain.
        """
        from urllib.request import Request as _Req
        target = str(url_or_domain).strip()
        if "://" not in target:
            target = "https://" + target.lstrip(".")
        req = _Req(target)
        self.cookies.add_cookie_header(req)
        header = req.get_header("Cookie") or ""
        out: Dict[str, str] = {}
        for part in header.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def cookie_report(self, url_or_domain: str) -> List[Dict[str, Any]]:
        """Full inspection of matching cookies: name/value/domain/path/
        expires/secure/httponly (plus raw expiry as ISO-ish string)."""
        from urllib.parse import urlsplit
        target = str(url_or_domain).strip()
        if "://" not in target:
            target = "https://" + target.lstrip(".")
        parts = urlsplit(target)
        host = (parts.hostname or "").lower()
        scheme = parts.scheme or "https"
        path = parts.path or "/"
        out: List[Dict[str, Any]] = []
        for c in self.cookies:
            dom = c.domain or ""
            d = dom[1:] if dom.startswith(".") else dom
            if d and d != host and not host.endswith("." + d):
                continue
            if not _cookie_path_ok(c.path, path):
                continue
            if c.secure and scheme != "https":
                continue
            out.append({
                "name": c.name,
                "value": c.value,
                "domain": c.domain,
                "path": c.path,
                "expires": c.expires,
                "secure": bool(c.secure),
                "httponly": bool(c.get_nonstandard_attr("HttpOnly", False)) or bool(c.has_nonstandard_attr("HttpOnly")),
            })
        out.sort(key=lambda d: d["name"])
        return out

    def save_cookies(self, path: str) -> int:
        """Write the jar to *path* as Netscape cookies.txt (curl/wget-able).

        Written by hand instead of cookiejar.MozillaCookieJar because the
        stdlib emits an EMPTY expires column for session cookies, which curl
        silently drops — we write 0 (the interoperable session marker).
        """
        lines = [
            "# Netscape HTTP Cookie File",
            "# https://curl.se/docs/http-cookies.html",
            "",
        ]
        n = 0
        for c in self.cookies:
            domain = c.domain or ""
            if not domain or not c.name:
                continue
            flag = "TRUE" if domain.startswith(".") else "FALSE"
            exp = str(int(c.expires)) if c.expires else "0"
            lines.append("\t".join((
                domain, flag, c.path or "/",
                "TRUE" if c.secure else "FALSE",
                exp, c.name, c.value or "",
            )))
            n += 1
        with open(str(path), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return n

    def load_cookies(self, path: str) -> int:
        """Load Netscape cookies.txt (curl/wget compatible) into the jar.

        expires=0 rows become session cookies (expires=None).
        """
        import http.cookiejar
        n = 0
        with open(str(path), encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n").rstrip("\r")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) < 7:
                    continue
                domain, _flag, cpath, secure, expires, name, value = parts[:7]
                if not domain or not name:
                    continue
                try:
                    exp = int(float(expires))
                except (TypeError, ValueError):
                    exp = 0
                self.cookies.set_cookie(http.cookiejar.Cookie(
                    version=0, name=name, value=value,
                    port=None, port_specified=False,
                    domain=domain,
                    domain_specified=True,
                    domain_initial_dot=domain.startswith("."),
                    path=cpath or "/",
                    path_specified=True,
                    secure=secure.upper() == "TRUE",
                    expires=float(exp) if exp > 0 else None,
                    discard=exp <= 0,
                    comment=None, comment_url=None, rest={}, rfc2109=False,
                ))
                n += 1
        return n

    def adopt_browser_cookies(
        self,
        url: str,
        *,
        port: Optional[int] = None,
        headless: Optional[bool] = None,
        settle: Optional[float] = None,
        keep_chrome: bool = False,
        strict_replay: bool = False,
    ) -> int:
        """Run *url* through real Chrome (CDP) and import every cookie it
        earned — the bridge that beats JS cookie challenges (WAFs that 403
        plain HTTP clients). Afterwards replay with pure HTTP from this
        Session. Returns the number of replayable cookies imported
        (CHIPS-partitioned cookies are skipped — see below).

        When the replay can HURT: cookies marked Secure+HttpOnly are often
        bound server-side to the browsing session that earned them (TLS/JA3
        fingerprint, JS execution, IP rotation cadence). Presenting one
        without its session context can make a WAF flag the token as stolen
        and ENDURE the block for that cookie jar — replaying with no cookie
        at all can be safer. A UserWarning is emitted whenever imported
        cookies include Secure+HttpOnly ones so this failure mode is visible.

        strict_replay=True also adopts the exact Chrome User-Agent that
        earned the cookies (and drops nettle's Sec-Ch-Ua client hints, which
        would contradict it), so the replay fingerprint is at least
        header-consistent. It cannot fix TLS/JA3 mismatches — for those,
        replay through the browser itself (fetch(url, render=True)).

        CHIPS-partitioned cookies (partitionKey, RFC 6265bis) are skipped:
        they are scoped to the first-party site that created them and have
        no faithful first-party replay. save_cookies()/export_browser_cookies
        document them as comments in the cookies.txt instead of data rows.
        """
        import warnings
        from .cdp import browser_cookies as _bcookies
        out = _bcookies(
            url, port=port, headless=headless, settle=settle,
            keep_chrome=keep_chrome, fingerprint=strict_replay,
        )
        ua = ""
        if isinstance(out, dict):
            ua = str(out.get("user_agent") or "")
            cookies = out.get("cookies") or []
        else:
            cookies = out or []
        n_replayable = self._ingest_cdp_cookies(cookies)
        n_partitioned = sum(1 for c in cookies if c.get("partitionKey") or c.get("sameParty"))
        if strict_replay and ua:
            self.headers["User-Agent"] = ua
            for h in ("Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform"):
                self.headers.pop(h, None)
        hard_bound = [
            c for c in cookies
            if c.get("secure") and c.get("httpOnly")
            and not (c.get("partitionKey") or c.get("sameParty"))
        ]
        if hard_bound:
            warnings.warn(
                f"adopt_browser_cookies({url}): {len(hard_bound)} of the "
                "imported cookies are Secure+HttpOnly. These are frequently "
                "BOUND to the browsing session that earned them; replaying "
                "them over plain HTTP (different TLS/JA3 fingerprint) can "
                "make the site flag the token and harden the block for the "
                "whole jar. If replay starts failing, retry WITHOUT these "
                "cookies or use fetch(url, render=True) to stay inside the "
                "browser. Pass strict_replay=True to at least match Chrome's "
                "User-Agent on replay.",
                UserWarning,
                stacklevel=2,
            )
        if n_partitioned:
            warnings.warn(
                f"adopt_browser_cookies({url}): {n_partitioned} CHIPS-"
                "partitioned cookie(s) were NOT imported (first-party-scoped, "
                "no faithful plain-HTTP replay); they are documented as "
                "comments when you save_cookies()/export_browser_cookies().",
                UserWarning,
                stacklevel=2,
            )
        return n_replayable

    def _ingest_cdp_cookies(self, cookies: List[Dict[str, Any]]) -> int:
        """Import CDP cookie dicts into the jar (partitioned ones skipped)."""
        import http.cookiejar
        n = 0
        for c in cookies or []:
            name = c.get("name")
            if not name:
                continue
            if c.get("partitionKey") or c.get("sameParty"):
                continue  # CHIPS: first-party-scoped, no faithful replay
            domain = c.get("domain") or self._host_of(c.get("sourceURL") or "")
            if not domain:
                continue
            dom = self._cookie_domain_form(domain)
            expires = c.get("expires")
            expires_f = float(expires) if expires and float(expires) > 0 else None
            self.cookies.set_cookie(http.cookiejar.Cookie(
                version=0,
                name=str(name),
                value=str(c.get("value", "")),
                port=None,
                port_specified=False,
                domain=dom,
                domain_specified=True,
                domain_initial_dot=dom.startswith("."),
                path=c.get("path") or "/",
                path_specified=True,
                secure=bool(c.get("secure")),
                expires=expires_f,
                discard=expires_f is None,
                comment=None,
                comment_url=None,
                rest={"HttpOnly": ""} if c.get("httpOnly") else {},
                rfc2109=False,
            ))
            n += 1
        return n

    def _retry_delay(self, attempt: int, remaining: Optional[float] = None) -> float:
        """Exponential backoff with jitter for retry-worthy failures.

        Delay = backoff * 2**attempt, randomized ("equal jitter": half fixed,
        half uniform) so a fleet of clients doesn't retry in lockstep — the
        thundering-herd problem on 429/503. Capped by retry_max_delay and by
        *remaining* seconds of the caller's total_timeout budget.
        Set registry.http['retry_jitter'] = False for deterministic tests.
        """
        import random
        base = self.retry_backoff * (2 ** max(0, attempt))
        base = min(base, self.retry_max_delay)
        if self.retry_jitter:
            base = base * 0.5 + random.uniform(0, base * 0.5)
        if remaining is not None:
            base = min(base, max(0.0, remaining))
        return base

    def _resolve_url(self, url: str) -> str:
        """Resolve *url* against the session's base_url when relative.

        session = Session(base_url="https://api.example.com/v1")
        session.get("/items")       → https://api.example.com/items
        session.get("items?page=2") → https://api.example.com/v1/items?page=2
        Absolute URLs pass through untouched.
        """
        if not isinstance(url, str) or not url.strip():
            raise FetchError(
                f"request URL must be a non-empty str, got {url!r}"
            )
        if self.base_url and not url.startswith(("http://", "https://", "//")):
            base = self.base_url if self.base_url.endswith("/") else self.base_url + "/"
            return urljoin(base, url)
        return url

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
        total_timeout: Optional[float] = None,
        auth: Optional[Tuple[str, str]] = None,
        cookies: Optional[Mapping[str, Any]] = None,
        hooks: Optional[Dict[str, Any]] = None,
    ) -> Response:
        """Send an HTTP request to *any* URL the caller provides.

        No discovery, no /api/ assumptions — you pass the endpoint.
        total_timeout caps the WHOLE operation (all retries + backoff);
        timeout is per socket attempt. Response.history carries redirects.
        auth=(user, password) overrides the session-level auth for this call.
        cookies={"k": "v"} inserts per-request cookies scoped to the target
        host (requests-style; they persist in the session jar afterwards).
        hooks={'response': fn} runs after the final response (session hooks
        run first, then per-request hooks — requests order).
        """
        # per-request hooks run AFTER session-level hooks (requests order)
        call_hooks: HookList = list(self.hooks.get("response", []))
        call_hooks.extend(_normalize_hooks(
            hooks, where="request(hooks=...)"
        ).get("response", []))
        import base64 as _b64
        method_u = (method or "GET").upper()
        # Resolve relative URLs against the session base FIRST, then fail
        # fast with a HELPFUL message on scheme-less/non-HTTP results
        # (urllib's "unknown url type" is cryptic AND gets retried slowly).
        url = self._resolve_url(url)
        if "://" not in str(url):
            hint = ""
            if self.base_url:
                hint = f" (session base_url={self.base_url!r} did not apply?)"
            raise FetchError(
                f"URL is missing a scheme: {url!r}. Use 'https://...' or "
                f"'http://...'{hint} — a bare host/path is not routable."
            )
        _head = str(url).split("://", 1)[0].lower()
        if _head not in ("http", "https"):
            raise FetchError(
                f"Unsupported URL scheme {_head!r} in {url!r} (nettle speaks "
                "http/https). For files use open(), for ftp use ftplib."
            )
        target = _requote_uri(_merge_params(url, params))
        hdrs = dict(self.headers)
        if cookies:
            host = (urlsplit(str(target)).hostname or "").lower()
            if host:
                self.set_cookies(cookies, domain=host)
        if auth is not None:
            try:
                a_user, a_pass = auth
                hdrs["Authorization"] = "Basic " + _b64.b64encode(
                    f"{a_user}:{a_pass}".encode("utf-8")
                ).decode("ascii")
            except (TypeError, ValueError):
                raise FetchError(
                    f"auth must be a (user, password) tuple, got {auth!r}"
                ) from None
        elif self._auth_header:
            hdrs.setdefault("Authorization", self._auth_header)
        if referer:
            hdrs["Referer"] = referer
        hdrs.setdefault("Accept-Encoding", self.accept_encoding)
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
        started = time.monotonic()
        tracker = _RedirectTracker()
        opener = self._build_opener(tracker)

        def _elapsed_ok() -> bool:
            return total_timeout is None or (time.monotonic() - started) < total_timeout

        def _remaining_budget() -> Optional[float]:
            if total_timeout is None:
                return None
            return max(0.0, total_timeout - (time.monotonic() - started))

        for attempt in range(attempts + 1):
            if not _elapsed_ok():
                raise FetchError(
                    f"total_timeout={total_timeout}s exceeded for {target}"
                ) from last_err
            try:
                req = Request(target, data=body, headers=hdrs, method=method_u)
            except (ValueError, TypeError) as e:
                raise FetchError(f"Invalid request for {target!r}: {e}") from e
            try:
                with opener.open(req, timeout=to) as resp:
                    raw = resp.read()
                    rh: Dict[str, str] = {k: v for k, v in resp.headers.items()}
                    final_url = resp.geturl()
                    status = getattr(resp, "status", None) or resp.getcode() or 200
                    charset = None
                    try:
                        charset = resp.headers.get_content_charset()
                    except Exception:
                        pass
                    raw = _decode_body(
                        raw,
                        rh.get("Content-Encoding") or rh.get("content-encoding") or "",
                    )
                    return _dispatch_hooks(Response(
                        url=final_url,
                        status=int(status),
                        headers=rh,
                        body=raw,
                        header_encoding=charset,
                        method=method_u,
                        history=tuple(tracker.chain),
                    ), call_hooks)
            except HTTPError as e:
                raw = e.read() if hasattr(e, "read") else b""
                rh = {}
                if e.headers:
                    for k, v in e.headers.items():
                        rh[k] = v
                from .registry import registry as _registry
                retry_statuses = tuple(_registry.http.get("retry_statuses") or ())
                if e.code in retry_statuses and attempt < attempts:
                    last_err = e
                    time.sleep(self._retry_delay(attempt, _remaining_budget()))
                    continue
                if raw or e.code:
                    raw = _decode_body(raw or b"", (rh or {}).get("Content-Encoding", ""))
                    return _dispatch_hooks(Response(
                        url=e.geturl() if hasattr(e, "geturl") else target,
                        status=e.code,
                        headers=rh,
                        body=raw,
                        method=method_u,
                        history=tuple(tracker.chain),
                    ), call_hooks)
                raise FetchError(f"HTTP {e.code} for {target}: {e.reason}") from e
            except ValueError as e:
                # malformed URL / request — retrying cannot help
                raise FetchError(f"Invalid URL or request for {target!r}: {e}") from e
            except (URLError, TimeoutError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
                last_err = e
                if attempt < attempts:
                    time.sleep(self._retry_delay(attempt, _remaining_budget()))
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
    timeout: Optional[float] = None,
    user_agent: Optional[str] = None,
    headers: Optional[dict] = None,
    spoof_browser: Optional[bool] = None,
    retries: Optional[int] = None,
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
    timeout: Optional[float] = None,
    user_agent: Optional[str] = None,
    headers: Optional[dict] = None,
    spoof_browser: Optional[bool] = None,
    referer: Optional[str] = None,
    retries: Optional[int] = None,
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


def _looks_like_js_shell(doc: Any) -> bool:
    """True when the raw HTML is a JS app shell: almost no links but lots of
    <script> (daum.net, twitch.tv, SPAs). Thresholds are
    registry.http['spa_shell'] = {'max_links': 3, 'min_scripts': 5}."""
    from .registry import registry as _registry
    conf = _registry.http.get("spa_shell") or {}
    try:
        max_links = int(conf.get("max_links", 3))
        min_scripts = int(conf.get("min_scripts", 5))
    except (AttributeError, TypeError, ValueError):
        max_links, min_scripts = 3, 5
    if max_links <= 0 or min_scripts <= 0:
        return False  # detection disabled via registry
    root = doc.document if hasattr(doc, "document") else doc
    try:
        n_links = len(root.select("a[href]"))
        n_scripts = len(root.select("script"))
    except Exception:
        return False
    return n_links <= max_links and n_scripts >= min_scripts


def fetch(
    url: str,
    *,
    timeout: Optional[float] = None,
    user_agent: Optional[str] = None,
    headers: Optional[dict] = None,
    spoof_browser: Optional[bool] = None,
    encoding: Optional[str] = None,
    referer: Optional[str] = None,
    render: bool = False,
    scroll: bool = True,
    keep_chrome: bool = False,
    fresh_profile: bool = False,
    **kwargs: Any,
):
    """Fetch URL and return a Nettle document (encoding auto-detected).

    render=True loads the page in real Chrome via CDP and parses the
    RENDERED DOM (document.documentElement.outerHTML) instead of the raw
    HTML — the fix for JS-shell SPAs (twitch.tv, daum.net, …) whose source
    has no <a> content. The returned doc carries .rendered=True,
    doc.cookies (CDP cookie list) and a synthetic doc.response.
    scroll=True scrolls before capture to trigger lazy loads.
    """
    if render:
        from .cdp import render_page
        from .registry import registry as _registry
        headless = bool(_registry.cdp.get("headless", True))
        out = render_page(url, headless=headless, scroll=scroll,
                          keep_chrome=keep_chrome, fresh_profile=fresh_profile)
        from .soup import Nettle
        doc = Nettle(out["html"] or "", base_url=out["url"] or url)
        resp = Response(
            url=out["url"] or url,
            status=200,
            headers={"Content-Type": "text/html; charset=utf-8", "X-Nettle-Render": "chrome-cdp"},
            body=(out["html"] or "").encode("utf-8", "replace"),
            method="GET",
        )
        doc.response = resp
        doc._doc.response = resp
        doc.rendered = True
        doc.cookies = out.get("cookies") or []
        doc.render_title = out.get("title") or ""
        return doc

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
    doc = Nettle(text, base_url=resp.url)
    doc.response = resp
    doc._doc.response = resp
    doc.rendered = False
    if _looks_like_js_shell(doc):
        doc.spa_shell = True
        import warnings
        warnings.warn(
            f"{url} looks like a JS app shell (almost no <a> links, many "
            "<script> tags): the data is rendered by JavaScript at runtime. "
            "Re-run with  nettle.fetch(url, render=True)  to get the rendered "
            "DOM via Chrome CDP (see also nettle.sniff_network for XHR).",
            stacklevel=2,
        )
    return doc


def fetch_bytes(
    url: str,
    *,
    timeout: Optional[float] = None,
    user_agent: Optional[str] = None,
    headers: Optional[dict] = None,
    spoof_browser: Optional[bool] = None,
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
