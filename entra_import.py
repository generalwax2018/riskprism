"""Entra ID users export (Users -> Download users, CSV) -> org units.

Only the department column is used. People are not stored. Each distinct
department string is resolved through risk_store.map_departments(): known strings
keep their unit, unknown ones get a new unit flagged for review. A missing or odd
department never stops the import; the row is counted and skipped.
"""
from __future__ import annotations

import csv
from io import StringIO

import risk_store

MAX_ROWS = 50000
DEPT_COLUMNS = ("department", "dept")


def read_departments(text: str) -> tuple[list[str], dict]:
    """Distinct department strings in first-seen order, plus row counts."""
    counts = {"rows": 0, "no_department": 0}
    sample = (text or "").lstrip("﻿").lstrip()
    if not sample:
        return [], counts
    reader = csv.DictReader(StringIO(sample))
    headers = {(h or "").strip().lower(): h for h in reader.fieldnames or []}
    col = next((headers[c] for c in DEPT_COLUMNS if c in headers), None)
    if col is None:
        counts["no_column"] = 1
        return [], counts
    seen, out = set(), []
    for raw in reader:
        if counts["rows"] >= MAX_ROWS:
            break
        counts["rows"] += 1
        dept = " ".join(str(raw.get(col) or "").split())
        if not dept:
            counts["no_department"] += 1
            continue
        key = risk_store.alias_key(dept)
        if key not in seen:
            seen.add(key)
            out.append(dept)
    return out, counts


def import_users(text: str, by: str = "") -> dict:
    depts, counts = read_departments(text)
    stats = risk_store.map_departments(depts, by) if depts else {"seen": 0, "known": 0, "matched": 0, "created": 0, "created_names": []}
    return {**counts, **stats}
