"""HTML tables → list[dict] with header inference and basic colspan/rowspan."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .nodes import Element
from .text import clean_text


def parse_table(
    table: Element,
    *,
    header: Optional[Sequence[str]] = None,
    clean: str = "plain",
    header_row: int = 0,
) -> List[Dict[str, str]]:
    """Convert an HTML ``<table>`` element to list[dict].

    - Infers headers from first ``<th>`` row (or ``header_row``).
    - Handles basic ``colspan`` by repeating / expanding cells.
    - Basic ``rowspan``: carries value down into subsequent rows.
    """
    if table.tag != "table":
        # allow calling on a wrapper — find first table
        found = table.select_one("table")
        if found is None:
            return []
        table = found

    grid = _build_grid(table)
    if not grid:
        return []

    if header is not None:
        headers = [clean_text(h, mode=clean) for h in header]
        data_rows = grid
    else:
        # find header row: prefer row made of th
        hr = header_row
        if hr < 0 or hr >= len(grid):
            hr = 0
        headers = [clean_text(c, mode=clean) or f"col_{i}" for i, c in enumerate(grid[hr])]
        headers = _unique_headers(headers)
        data_rows = grid[hr + 1:]

    records: List[Dict[str, str]] = []
    for row in data_rows:
        rec: Dict[str, str] = {}
        for i, h in enumerate(headers):
            val = row[i] if i < len(row) else ""
            rec[h] = clean_text(val, mode=clean)
        # skip completely empty rows
        if any(v.strip() for v in rec.values()):
            records.append(rec)
    return records


def _unique_headers(headers: List[str]) -> List[str]:
    seen: Dict[str, int] = {}
    out: List[str] = []
    for h in headers:
        key = h or "col"
        if key not in seen:
            seen[key] = 0
            out.append(key)
        else:
            seen[key] += 1
            out.append(f"{key}_{seen[key]}")
    return out


def _own_rows(table: Element) -> List[Element]:
    """<tr> elements whose NEAREST table ancestor is *table* (excludes nested)."""
    rows: List[Element] = []
    for tr in table.select("tr"):
        p = tr.parent
        while p is not None and p.tag != "table":
            p = p.parent
        if p is table:
            rows.append(tr)
    return rows


def _build_grid(table: Element) -> List[List[str]]:
    """Expand table into a rectangular grid of cell text, honoring span attrs."""
    rows_el = _own_rows(table)
    if not rows_el:
        return []

    # occupancy map for rowspan: (r, c) -> text
    # We'll build row by row
    pending_rowspan: Dict[int, Tuple[str, int]] = {}  # col -> (text, remaining)

    grid: List[List[str]] = []

    for tr in rows_el:
        cells = [c for c in tr.child_elements if c.tag in ("td", "th")]
        row: List[str] = []
        col = 0

        def place(text: str) -> None:
            nonlocal col
            while col in pending_rowspan:
                t, left = pending_rowspan[col]
                row.append(t)
                left -= 1
                if left <= 0:
                    del pending_rowspan[col]
                else:
                    pending_rowspan[col] = (t, left)
                col += 1
            row.append(text)
            col += 1

        for cell in cells:
            # skip cols taken by rowspan from above
            while col in pending_rowspan:
                t, left = pending_rowspan[col]
                row.append(t)
                left -= 1
                if left <= 0:
                    del pending_rowspan[col]
                else:
                    pending_rowspan[col] = (t, left)
                col += 1

            text = cell.get_text(strip=True, sep=" ")
            try:
                colspan = int(cell.get("colspan") or 1)
            except ValueError:
                colspan = 1
            try:
                rowspan = int(cell.get("rowspan") or 1)
            except ValueError:
                rowspan = 1
            colspan = max(1, colspan)
            rowspan = max(1, rowspan)

            for _ in range(colspan):
                row.append(text)
                if rowspan > 1:
                    pending_rowspan[col] = (text, rowspan - 1)
                col += 1

        # flush remaining pending into this row
        while pending_rowspan and col <= max(pending_rowspan.keys(), default=-1):
            if col in pending_rowspan:
                t, left = pending_rowspan[col]
                row.append(t)
                left -= 1
                if left <= 0:
                    del pending_rowspan[col]
                else:
                    pending_rowspan[col] = (t, left)
            else:
                row.append("")
            col += 1

        grid.append(row)

    # normalize widths
    width = max((len(r) for r in grid), default=0)
    for r in grid:
        while len(r) < width:
            r.append("")
    return grid
