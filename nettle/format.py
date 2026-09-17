"""Format scraped data to JSON / CSV / TSV / dicts — stable UTF-8."""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Union

from .exceptions import FormatError


def to_dicts(data: Any) -> List[dict]:
    """Normalize common scrape shapes into list[dict].

    Accepts:
      - list[dict]
      - dict with one list-valued key (unwrap that list if all dicts)
      - single dict → [dict]
    """
    if data is None:
        return []
    if isinstance(data, list):
        if not data:
            return []
        if all(isinstance(x, dict) for x in data):
            return list(data)
        raise FormatError("to_dicts expects list[dict]")
    if isinstance(data, dict):
        # unwrap {"items": [...]} if exactly one list-of-dicts value
        list_keys = [k for k, v in data.items() if isinstance(v, list)]
        if len(list_keys) == 1:
            inner = data[list_keys[0]]
            if inner and all(isinstance(x, dict) for x in inner):
                return list(inner)
            if not inner:
                return []
        return [data]
    raise FormatError(f"cannot convert {type(data).__name__} to list[dict]")


def _json_default(obj: Any) -> Any:
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def to_json(
    data: Any,
    *,
    indent: Optional[int] = 2,
    ensure_ascii: bool = False,
    sort_keys: bool = False,
) -> str:
    """Serialize to JSON string (UTF-8-safe; no ASCII escape by default)."""
    return json.dumps(
        data,
        indent=indent,
        ensure_ascii=ensure_ascii,
        sort_keys=sort_keys,
        default=_json_default,
    )


def to_csv(
    data: Any,
    *,
    fieldnames: Optional[Sequence[str]] = None,
    delimiter: str = ",",
    lineterminator: str = "\n",
) -> str:
    """Serialize list[dict] (or unwrap) to CSV string (UTF-8)."""
    rows = to_dicts(data)
    if not rows and not fieldnames:
        return ""
    if fieldnames is None:
        # stable: union of keys in first-seen order
        seen = []
        seen_set = set()
        for row in rows:
            for k in row.keys():
                if k not in seen_set:
                    seen_set.add(k)
                    seen.append(k)
        fieldnames = seen
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=list(fieldnames),
        delimiter=delimiter,
        lineterminator=lineterminator,
        extrasaction="ignore",
        quoting=csv.QUOTE_MINIMAL,
    )
    writer.writeheader()
    for row in rows:
        flat = {k: _cell(row.get(k)) for k in fieldnames}
        writer.writerow(flat)
    return buf.getvalue()


def to_tsv(data: Any, *, fieldnames: Optional[Sequence[str]] = None) -> str:
    """TSV variant of to_csv."""
    return to_csv(data, fieldnames=fieldnames, delimiter="\t")


def pretty(data: Any, *, indent: int = 2) -> str:
    """Pretty-print JSON for humans (alias of to_json with indent)."""
    return to_json(data, indent=indent, ensure_ascii=False)


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return "|".join(_cell(v) for v in value)
    if isinstance(value, dict):
        return to_json(value, indent=None)
    return str(value)


def write_json(path: str, data: Any, **kwargs: Any) -> None:
    """Write JSON file as UTF-8."""
    text = to_json(data, **kwargs)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        if not text.endswith("\n"):
            f.write("\n")


def write_csv(path: str, data: Any, **kwargs: Any) -> None:
    """Write CSV file as UTF-8."""
    text = to_csv(data, **kwargs)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
