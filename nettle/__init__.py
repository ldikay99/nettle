"""Nettle — pure-Python HTML toolkit for clean scrape pipelines.

Stdlib only. Parse, CSS-select, clean text, declarative extract, tables,
URL discovery, embedded-JSON sniffing, and direct HTTP to any endpoint.

    from nettle import parse, fetch, request, call_endpoint

    # scrape HTML
    doc = parse(html)
    data = doc.extract({...})

    # you already have an endpoint — just call it (any method, any path)
    request("POST", "https://shop.example/catalog/load", json={"q": "shoes"})
    call_endpoint("https://shop.example/items/42", "DELETE")
"""

from .nodes import Comment, Document, Element, Node, Text
from .parse import parse, detect_charset
from .soup import Nettle
from .text import (
    clean_text,
    collapse_ws,
    decode_entities,
    normalize_unicode,
    remove_invisible,
    strip_noise,
)
from .extract import fields, records, table, lists, links, meta, values
from .clean import CleanPipeline, clean_tree
from .format import to_json, to_csv, to_tsv, to_dicts, pretty, write_json, write_csv
from .query import extract, ExtractQuery
from .http import fetch, fetch_response, fetch_html, Session, Response, request, call
from .urls import find_urls, classify_url, filter_urls, absolutize
from .resolve import resolve_ip, server_ip
from .network import sniff_embedded_json, sniff_api_candidates, probe_apis, har_from_cdp, call_endpoint
from .brotli_dec import BrotliError, BrotliLargeWindowError, decompress
from .cdp import (
    sniff_network,
    CDPSession,
    list_targets,
    ensure_debugging_chrome,
    shutdown_chrome,
    chrome_processes_alive,
    find_debugging_port,
    render_page,
    browser_cookies,
    export_browser_cookies,
    to_har,
    write_netscape_cookies,
)
from .brotli_dec import decompress as brotli_decompress, BrotliError
from .discover import discover_endpoints
from .registry import registry
from .serialize import html as serialize_html, prettify
from .exceptions import (
    NettleError,
    ParseError,
    SelectorError,
    ExtractError,
    FetchError,
    FormatError,
    JsonBodyError,
)

__all__ = [
    # core
    "parse",
    "detect_charset",
    "Nettle",
    "Node",
    "Element",
    "Text",
    "Comment",
    "Document",
    # text
    "clean_text",
    "collapse_ws",
    "decode_entities",
    "normalize_unicode",
    "remove_invisible",
    "strip_noise",
    # extract
    "fields",
    "records",
    "table",
    "lists",
    "links",
    "meta",
    "values",
    "extract",
    "ExtractQuery",
    # clean / format
    "CleanPipeline",
    "clean_tree",
    "to_json",
    "to_csv",
    "to_tsv",
    "to_dicts",
    "pretty",
    "write_json",
    "write_csv",
    # http / urls / network
    "fetch",
    "fetch_response",
    "fetch_html",
    "request",
    "call",
    "Session",
    "Response",
    "find_urls",
    "classify_url",
    "filter_urls",
    "absolutize",
    "resolve_ip",
    "server_ip",
    "sniff_embedded_json",
    "sniff_api_candidates",
    "probe_apis",
    "call_endpoint",
    "har_from_cdp",
    "discover_endpoints",
    "registry",
    "sniff_network",
    "render_page",
    "browser_cookies",
    "export_browser_cookies",
    "to_har",
    "write_netscape_cookies",
    "brotli_decompress",
    "BrotliError",
    "ensure_debugging_chrome",
    "find_debugging_port",
    "BrotliError",
    "BrotliLargeWindowError",
    "decompress",
    "shutdown_chrome",
    "chrome_processes_alive",
    "CDPSession",
    "list_targets",
    # serialize
    "serialize_html",
    "prettify",
    # errors
    "NettleError",
    "ParseError",
    "SelectorError",
    "ExtractError",
    "FetchError",
    "FormatError",
    "JsonBodyError",
]

__version__ = "0.9.0"
