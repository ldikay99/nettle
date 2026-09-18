"""DNS resolution for scrape targets — which server am I actually hitting?

    from nettle import resolve_ip, server_ip

    resolve_ip("https://www.wikipedia.org/")   # "198.35.26.196"
    resolve_ip("www.wikipedia.org")            # same — scheme optional
    resolve_ip("wikipedia.org", all=True)      # every address, v4 first
    server_ip("https://ja.wikipedia.org/")     # alias

Pure stdlib (socket.getaddrinfo run in a worker thread so it can be timed
out — getaddrinfo has no native timeout). Failures raise FetchError with a
message naming the host, the cause, and what to do about it.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Union

from .exceptions import FetchError
from .registry import registry as _registry

__all__ = ["resolve_ip", "server_ip"]


def _host_from(url_or_host: str) -> str:
    """Accept 'https://host/path', 'host:port', '[v6]:port', or bare 'host'."""
    if not url_or_host or not isinstance(url_or_host, str):
        raise FetchError(
            f"resolve_ip() needs a URL or hostname string, got "
            f"{type(url_or_host).__name__}: {url_or_host!r}"
        )
    s = url_or_host.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    # path/query/fragment
    for sep in ("/", "?", "#"):
        s = s.split(sep, 1)[0]
    # userinfo
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    # [v6 literal]:port
    if s.startswith("["):
        end = s.find("]")
        if end == -1:
            raise FetchError(
                f"Malformed IPv6 literal in {url_or_host!r} (missing ']')"
            )
        return s[1:end]
    # host:port — only strip if the tail is all digits (and not a bare v6)
    if ":" in s:
        host, _, port = s.rpartition(":")
        if port.isdigit() and host:
            s = host
    return s.strip(".")


def resolve_ip(
    url_or_host: str,
    *,
    timeout: Optional[float] = None,
    all: bool = False,  # noqa: A002 — requests-style kwarg
    prefer_ipv4: bool = True,
) -> Union[str, List[str]]:
    """Resolve a URL or hostname to the server's IP address(es).

    Parameters
    ----------
    url_or_host:
        Full URL, 'host:port', or bare hostname ('example.com').
    timeout:
        Wall-clock seconds for the DNS lookup. None → registry.dns["timeout"]
        (default 8.0). getaddrinfo blocks with no native timeout, so the
        lookup runs in a worker thread and is abandoned on expiry.
    all:
        False (default) → first address as str (IPv4 preferred).
        True → every address as list[str], IPv4 first when prefer_ipv4.
    prefer_ipv4:
        Order IPv4 before IPv6 in the result (default True).

    Raises
    ------
    FetchError
        If the host is empty, DNS fails (NXDOMAIN / no answer), or the
        lookup exceeds *timeout* — each with a message naming the cause
        and the fix.
    """
    if timeout is None:
        timeout = float(_registry.dns["timeout"])
    host = _host_from(url_or_host)
    if not host:
        raise FetchError(
            f"Could not extract a hostname from {url_or_host!r}. "
            "Pass a full URL ('https://host/path') or a bare hostname."
        )
    if not timeout or timeout <= 0:
        raise FetchError(
            f"resolve_ip() timeout must be > 0, got {timeout!r}"
        )

    def _lookup() -> List[str]:
        seen: List[str] = []
        infos = socket.getaddrinfo(
            host, None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        for info in infos:
            sockaddr = info[4]
            if not sockaddr:
                continue
            ip = sockaddr[0]
            if ip not in seen:
                seen.append(ip)
        return seen

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_lookup)
            try:
                ips = future.result(timeout=timeout)
            except TimeoutError as e:  # py>=3.8 raises concurrent.futures.TimeoutError
                future.cancel()
                raise FetchError(
                    f"DNS lookup for {host!r} did not answer within "
                    f"{timeout}s. The resolver may be down or the host may "
                    "be slow — retry, raise timeout=, or check your network."
                ) from e
    except FetchError:
        raise
    except socket.gaierror as e:
        reason = str(e)
        if e.errno in (-2, 8, 11001, 11001) or "Name or service" in reason \
                or "not known" in reason:
            raise FetchError(
                f"Host {host!r} does not resolve (DNS name not found). "
                f"Check the spelling / scheme of {url_or_host!r}. "
                f"Underlying error: {reason}"
            ) from e
        raise FetchError(
            f"DNS resolution failed for {host!r}: {reason}. "
            "Check your network / DNS server / proxy settings."
        ) from e
    except OSError as e:
        raise FetchError(
            f"DNS resolution failed for {host!r}: {e}. "
            "Check your network connection."
        ) from e

    if not ips:
        raise FetchError(
            f"DNS returned no addresses for {host!r} "
            f"(lookup of {url_or_host!r}). The name exists but has no A/AAAA "
            "records — the site may be parked or misconfigured."
        )

    if prefer_ipv4:
        v4 = [ip for ip in ips if "." in ip]
        v6 = [ip for ip in ips if ":" in ip]
        ordered = v4 + v6
    else:
        ordered = ips

    if all:
        return ordered
    return ordered[0]


server_ip = resolve_ip  # friendly alias
