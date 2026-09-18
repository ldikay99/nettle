"""Nettle exceptions."""

from __future__ import annotations


class NettleError(Exception):
    """Base exception for Nettle."""


class ParseError(NettleError, TypeError):
    """Raised when HTML cannot be parsed (bad input type, or on_error='raise').

    Also inherits TypeError so code written against BeautifulSoup's
    `except TypeError` for invalid markup keeps working.
    """


class SelectorError(NettleError):
    """Invalid CSS selector."""


class ExtractError(NettleError):
    """Schema / extract mapping error."""


class FetchError(NettleError):
    """HTTP fetch failed."""


class FormatError(NettleError):
    """Serialization / format conversion failed."""


class JsonBodyError(FormatError, ValueError):
    """Response body is not valid JSON (Response.json()).

    Inherits both FormatError (NettleError hierarchy) and ValueError, so
    callers catching either — including json.JSONDecodeError-style
    `except ValueError` — keep working.
    """
