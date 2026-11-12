"""Analyst notes on vendors (SQLite, append-only).

Lives in the same DATA_DIR/riskprism.db as org units and acceptances, in its own
table. Writes take records.LOCK like every other store.

A note is evidence of what an analyst knew and when, so notes are never edited or
deleted. Triggers refuse both. A mistake is fixed by adding a correction that points
at the note it corrects; the page shows the original struck through, with the fix.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

import config
from records import LOCK, valid_slug

PATH = config.RISK_DB_PATH
BODY_MAX = 8000

# (code, label). Order is the order in the form.
KINDS = (
    ("general", "Note"),
    ("finding", "Finding"),
    ("follow_up", "Follow-up"),
    ("call", "Call or meeting"),
    ("doc_review", "Document review"),
)
LABELS = dict(KINDS)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vendor_notes (
  id          INTEGER PRIMARY KEY,
  vendor_slug TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('general', 'finding', 'follow_up', 'call', 'doc_review')),
  body        TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 8000),
  doc_id      TEXT NOT NULL DEFAULT '',
  corrects    INTEGER REFERENCES vendor_notes(id),
  author      TEXT NOT NULL,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS vendor_notes_slug ON vendor_notes(vendor_slug, id);

CREATE TRIGGER IF NOT EXISTS vendor_notes_no_update
BEFORE UPDATE ON vendor_notes
BEGIN SELECT RAISE(ABORT, 'notes cannot be changed; add a correction'); END;

CREATE TRIGGER IF NOT EXISTS vendor_notes_no_delete
BEFORE DELETE ON vendor_notes
BEGIN SELECT RAISE(ABORT, 'notes cannot be deleted'); END;
"""

_ready: set[str] = set()


class NoteError(ValueError):
    """A note that cannot be saved: empty, too long, or pointing at the wrong record."""


@contextmanager
def _db(write: bool = False):
    PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(PATH), timeout=10)
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA foreign_keys = ON")
        if str(PATH) not in _ready:
            with LOCK:
                con.executescript(_SCHEMA)
                _ready.add(str(PATH))
        if write:
            with LOCK, con:
                yield con
        else:
            yield con
    finally:
        con.close()


def add(slug: str, kind: str, body: str, author: str, *, doc_id: str = "", corrects: int | None = None) -> int:
    if not valid_slug(slug):
        raise NoteError("That record id is not valid.")
    body = (body or "").replace("\r\n", "\n").strip()
    if not body:
        raise NoteError("Write something before adding the note.")
    if len(body) > BODY_MAX:
        raise NoteError("Notes are limited to %d characters. Split it into two notes." % BODY_MAX)
    if kind not in LABELS:
        kind = "general"
    if not author:
        raise NoteError("A note needs a signed-in author.")
    with _db(write=True) as con:
        if corrects is not None:
            row = con.execute("SELECT vendor_slug FROM vendor_notes WHERE id = ?", (corrects,)).fetchone()
            if not row or row["vendor_slug"] != slug:
                raise NoteError("The note you are correcting is not on this vendor.")
        cur = con.execute(
            "INSERT INTO vendor_notes (vendor_slug, kind, body, doc_id, corrects, author, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (slug, kind, body, (doc_id or "")[:40], corrects, author[:200],
             datetime.now(timezone.utc).isoformat(timespec="seconds")))
        return int(cur.lastrowid)


def for_vendor(slug: str) -> list[dict]:
    """Newest first. Each note carries `corrected_by` (the id of its newest correction, or None)."""
    with _db() as con:
        rows = [dict(r) for r in con.execute("SELECT * FROM vendor_notes WHERE vendor_slug = ? ORDER BY id DESC", (slug,))]
    fixed = {}
    for r in rows:  # newest first, so the first correction seen is the latest
        if r["corrects"] is not None and r["corrects"] not in fixed:
            fixed[r["corrects"]] = r["id"]
    for r in rows:
        r["corrected_by"] = fixed.get(r["id"])
    return rows


def for_doc(slug: str, doc_id: str) -> list[dict]:
    return [n for n in for_vendor(slug) if n["doc_id"] == doc_id]


def counts() -> dict[str, int]:
    """Notes per vendor slug, for list pages."""
    with _db() as con:
        return {r[0]: r[1] for r in con.execute("SELECT vendor_slug, COUNT(*) FROM vendor_notes GROUP BY vendor_slug")}
