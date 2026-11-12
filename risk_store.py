"""Org units, department aliases, approvers and signed risk acceptances (SQLite).

One file, DATA_DIR/riskprism.db, through the standard library's sqlite3, so there
is still no new dependency. Writes take records.LOCK like every other store, so
the one process serialises them. Only this module opens the database.

Signed acceptances are append-only. Triggers refuse any change to a signed row
except moving its status off 'active', and refuse deletes. Nothing is permanent:
expires_on is required, and a row only counts while expires_on >= today, so an
expired acceptance stops covering its detection even before sweep_expired()
stamps it.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timezone

import config
from records import LOCK

PATH = config.RISK_DB_PATH
LEVELS = ("director", "vp", "ciso")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS org_units (
  id                INTEGER PRIMARY KEY,
  name              TEXT NOT NULL,
  parent_id         INTEGER REFERENCES org_units(id),
  accountable_owner TEXT NOT NULL DEFAULT '',
  needs_review      INTEGER NOT NULL DEFAULT 0,
  merged_into       INTEGER REFERENCES org_units(id),
  created_at        TEXT NOT NULL,
  created_by        TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS org_units_live_name ON org_units(name COLLATE NOCASE) WHERE merged_into IS NULL;

CREATE TABLE IF NOT EXISTS org_aliases (
  alias_key   TEXT PRIMARY KEY,
  raw         TEXT NOT NULL,
  org_unit_id INTEGER NOT NULL REFERENCES org_units(id),
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvers (
  principal TEXT PRIMARY KEY,
  level     TEXT NOT NULL CHECK (level IN ('director', 'vp', 'ciso')),
  set_by    TEXT NOT NULL,
  set_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS acceptances (
  id                    INTEGER PRIMARY KEY,
  vendor_slug           TEXT NOT NULL,
  vendor_name           TEXT NOT NULL,
  detection_code        TEXT NOT NULL,
  detection_text        TEXT NOT NULL,
  org_unit_id           INTEGER NOT NULL REFERENCES org_units(id),
  accepter              TEXT NOT NULL,
  accepter_level        TEXT NOT NULL CHECK (accepter_level IN ('director', 'vp', 'ciso', 'legacy')),
  risk_tier             TEXT NOT NULL CHECK (risk_tier IN ('low', 'medium', 'high', 'critical', 'unrated')),
  justification         TEXT NOT NULL,
  compensating_controls TEXT NOT NULL,
  expires_on            TEXT NOT NULL CHECK (expires_on GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]'),
  risk_snapshot         TEXT NOT NULL,
  signed_at             TEXT NOT NULL,
  recorded_by           TEXT NOT NULL,
  status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'superseded')),
  status_at             TEXT,
  legacy_ref            TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS acceptances_lookup ON acceptances(vendor_slug, detection_code, status);

CREATE TRIGGER IF NOT EXISTS acceptances_frozen
BEFORE UPDATE OF vendor_slug, vendor_name, detection_code, detection_text, org_unit_id, accepter, accepter_level,
                 risk_tier, justification, compensating_controls, expires_on, risk_snapshot, signed_at, recorded_by, legacy_ref
ON acceptances
BEGIN SELECT RAISE(ABORT, 'signed acceptances cannot be changed'); END;

CREATE TRIGGER IF NOT EXISTS acceptances_one_way
BEFORE UPDATE OF status ON acceptances
WHEN OLD.status <> 'active' OR NEW.status = 'active'
BEGIN SELECT RAISE(ABORT, 'a closed acceptance cannot be reopened'); END;

CREATE TRIGGER IF NOT EXISTS acceptances_no_delete
BEFORE DELETE ON acceptances
BEGIN SELECT RAISE(ABORT, 'signed acceptances cannot be deleted'); END;
"""

_ready: set[str] = set()


class OrgError(ValueError):
    """A change to org units, aliases or approvers that would break the tree or a rule."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def alias_key(raw: str) -> str:
    """'  Finance  Ops' and 'finance ops' are the same Entra department."""
    return " ".join((raw or "").split()).casefold()


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


def _dicts(cur) -> list[dict]:
    return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------- org units

def units(include_merged: bool = False) -> list[dict]:
    with _db() as con:
        sql = "SELECT * FROM org_units" + ("" if include_merged else " WHERE merged_into IS NULL") + " ORDER BY name COLLATE NOCASE"
        return _dicts(con.execute(sql))


def unit(uid) -> dict | None:
    with _db() as con:
        row = con.execute("SELECT * FROM org_units WHERE id = ?", (uid,)).fetchone()
        return dict(row) if row else None


def live_unit_id(con, uid):
    """Follow merged_into to the unit that now stands for uid."""
    seen = set()
    while uid is not None and uid not in seen:
        seen.add(uid)
        row = con.execute("SELECT merged_into FROM org_units WHERE id = ?", (uid,)).fetchone()
        if not row or row["merged_into"] is None:
            return uid if row else None
        uid = row["merged_into"]
    return uid


def _check_parent(con, uid, parent_id):
    if parent_id is None:
        return
    row = con.execute("SELECT id, merged_into FROM org_units WHERE id = ?", (parent_id,)).fetchone()
    if not row or row["merged_into"] is not None:
        raise OrgError("That parent unit does not exist.")
    cur, hops = parent_id, 0
    while cur is not None and hops < 1000:
        if cur == uid:
            raise OrgError("A unit cannot sit under itself or one of its own children.")
        r = con.execute("SELECT parent_id FROM org_units WHERE id = ?", (cur,)).fetchone()
        cur, hops = (r["parent_id"] if r else None), hops + 1


def _clean_name(name: str) -> str:
    name = " ".join((name or "").split())[:120]
    if not name:
        raise OrgError("A unit needs a name.")
    return name


def create_unit(name: str, *, parent_id=None, owner: str = "", needs_review: bool = False, by: str = "") -> int:
    name = _clean_name(name)
    with _db(write=True) as con:
        _check_parent(con, None, parent_id)
        try:
            cur = con.execute(
                "INSERT INTO org_units (name, parent_id, accountable_owner, needs_review, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)",
                (name, parent_id, (owner or "").strip()[:200], 1 if needs_review else 0, _now(), by[:200]))
        except sqlite3.IntegrityError:
            raise OrgError("A unit called %s already exists." % name)
        return cur.lastrowid


def save_unit(uid: int, *, name: str, parent_id, owner: str) -> None:
    """Admin edit. Saving a unit is the review, so it clears needs_review."""
    name = _clean_name(name)
    with _db(write=True) as con:
        row = con.execute("SELECT merged_into FROM org_units WHERE id = ?", (uid,)).fetchone()
        if not row or row["merged_into"] is not None:
            raise OrgError("That unit does not exist.")
        _check_parent(con, uid, parent_id)
        try:
            con.execute("UPDATE org_units SET name = ?, parent_id = ?, accountable_owner = ?, needs_review = 0 WHERE id = ?",
                        (name, parent_id, (owner or "").strip()[:200], uid))
        except sqlite3.IntegrityError:
            raise OrgError("A unit called %s already exists." % name)


def merge_units(from_id: int, into_id: int) -> None:
    """Fold one unit into another. Aliases and children move; signed acceptances keep
    pointing at the unit they were signed against and are read through merged_into."""
    if from_id == into_id:
        raise OrgError("Pick two different units to merge.")
    with _db(write=True) as con:
        src = con.execute("SELECT * FROM org_units WHERE id = ? AND merged_into IS NULL", (from_id,)).fetchone()
        dst = con.execute("SELECT * FROM org_units WHERE id = ? AND merged_into IS NULL", (into_id,)).fetchone()
        if not src or not dst:
            raise OrgError("Both units must exist and not already be merged.")
        # If the target sat under the unit being folded away, lift it to that unit's parent first.
        con.execute("UPDATE org_units SET parent_id = ? WHERE id = ? AND parent_id = ?", (src["parent_id"], into_id, from_id))
        con.execute("UPDATE org_units SET parent_id = ? WHERE parent_id = ? AND id <> ?", (into_id, from_id, into_id))
        con.execute("UPDATE org_aliases SET org_unit_id = ? WHERE org_unit_id = ?", (into_id, from_id))
        con.execute("UPDATE org_units SET merged_into = ?, needs_review = 0, parent_id = NULL WHERE id = ?", (into_id, from_id))
        if not dst["accountable_owner"] and src["accountable_owner"]:
            con.execute("UPDATE org_units SET accountable_owner = ? WHERE id = ?", (src["accountable_owner"], into_id))


def subtree_ids(root_id: int, all_units: list[dict] | None = None) -> set[int]:
    all_units = all_units if all_units is not None else units()
    kids: dict = {}
    for u in all_units:
        kids.setdefault(u["parent_id"], []).append(u["id"])
    out, todo = set(), [root_id]
    while todo:
        cur = todo.pop()
        if cur in out:
            continue
        out.add(cur)
        todo.extend(kids.get(cur, []))
    return out


# ---------------------------------------------------------------- aliases

def aliases() -> list[dict]:
    with _db() as con:
        return _dicts(con.execute("SELECT * FROM org_aliases ORDER BY raw COLLATE NOCASE"))


def move_alias(key: str, unit_id: int) -> None:
    with _db(write=True) as con:
        if not con.execute("SELECT 1 FROM org_units WHERE id = ? AND merged_into IS NULL", (unit_id,)).fetchone():
            raise OrgError("That unit does not exist.")
        if con.execute("UPDATE org_aliases SET org_unit_id = ? WHERE alias_key = ?", (unit_id, key)).rowcount == 0:
            raise OrgError("That department string is not on file.")


def map_departments(raw_values, by: str = "") -> dict:
    """Resolve Entra department strings to org units in one transaction.

    Known strings keep their unit. An unknown string maps to a live unit with the
    same name if there is one; otherwise a unit is created and flagged for review.
    Nothing here raises for a bad value, so an import is never blocked by it.
    """
    stats = {"seen": 0, "known": 0, "matched": 0, "created": 0, "created_names": []}
    now = _now()
    with _db(write=True) as con:
        for raw in raw_values:
            raw = " ".join((raw or "").split())[:120]
            key = alias_key(raw)
            if not key:
                continue
            stats["seen"] += 1
            if con.execute("UPDATE org_aliases SET last_seen = ? WHERE alias_key = ?", (now, key)).rowcount:
                stats["known"] += 1
                continue
            row = con.execute("SELECT id FROM org_units WHERE name = ? COLLATE NOCASE AND merged_into IS NULL", (raw,)).fetchone()
            if row:
                uid = row["id"]
                stats["matched"] += 1
            else:
                uid = con.execute(
                    "INSERT INTO org_units (name, needs_review, created_at, created_by) VALUES (?, 1, ?, ?)",
                    (raw, now, ("entra import by " + by)[:200])).lastrowid
                stats["created"] += 1
                stats["created_names"].append(raw)
            con.execute("INSERT INTO org_aliases (alias_key, raw, org_unit_id, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                        (key, raw, uid, now, now))
    return stats


# ---------------------------------------------------------------- approvers

def approvers() -> list[dict]:
    with _db() as con:
        return _dicts(con.execute("SELECT * FROM approvers ORDER BY principal"))


def approver_level(principal: str) -> str:
    with _db() as con:
        row = con.execute("SELECT level FROM approvers WHERE principal = ?", ((principal or "").strip().lower(),)).fetchone()
        return row["level"] if row else ""


def set_approver(principal: str, level: str, by: str) -> None:
    principal = (principal or "").strip().lower()[:200]
    if not principal:
        raise OrgError("Enter the approver's sign-in name.")
    with _db(write=True) as con:
        if level == "remove":
            con.execute("DELETE FROM approvers WHERE principal = ?", (principal,))
            return
        if level not in LEVELS:
            raise OrgError("Pick director, VP or CISO.")
        con.execute("INSERT INTO approvers (principal, level, set_by, set_at) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(principal) DO UPDATE SET level = excluded.level, set_by = excluded.set_by, set_at = excluded.set_at",
                    (principal, level, by[:200], _now()))


# ---------------------------------------------------------------- acceptances

_ACTIVE = "a.status = 'active' AND a.expires_on >= ?"
_SELECT = ("SELECT a.*, u.name AS unit_name FROM acceptances a JOIN org_units u ON u.id = a.org_unit_id")


def add_acceptance(entry: dict) -> tuple[int, list[int]]:
    """Insert a signed acceptance. Any active one for the same vendor and detection is
    superseded. Returns (new id, superseded ids)."""
    cols = ("vendor_slug", "vendor_name", "detection_code", "detection_text", "org_unit_id", "accepter", "accepter_level",
            "risk_tier", "justification", "compensating_controls", "expires_on", "risk_snapshot", "signed_at", "recorded_by")
    now = _now()
    with _db(write=True) as con:
        old = [r["id"] for r in con.execute(
            "SELECT id FROM acceptances WHERE vendor_slug = ? AND detection_code = ? AND status = 'active'",
            (entry["vendor_slug"], entry["detection_code"]))]
        if old:
            con.execute("UPDATE acceptances SET status = 'superseded', status_at = ? WHERE id IN (%s)" % ",".join("?" * len(old)), (now, *old))
        cur = con.execute("INSERT INTO acceptances (%s) VALUES (%s)" % (", ".join(cols), ", ".join("?" * len(cols))),
                          tuple(entry[c] for c in cols))
        return cur.lastrowid, old


def add_legacy(entry: dict, legacy_ref: str, status: str) -> bool:
    """Carry an acceptance from the old vendor-JSON shape. Idempotent on legacy_ref."""
    cols = ("vendor_slug", "vendor_name", "detection_code", "detection_text", "org_unit_id", "accepter", "accepter_level",
            "risk_tier", "justification", "compensating_controls", "expires_on", "risk_snapshot", "signed_at", "recorded_by")
    with _db(write=True) as con:
        cur = con.execute("INSERT OR IGNORE INTO acceptances (%s, status, status_at, legacy_ref) VALUES (%s, ?, ?, ?)"
                          % (", ".join(cols), ", ".join("?" * len(cols))),
                          (*(entry[c] for c in cols), status, _now() if status != "active" else None, legacy_ref))
        return cur.rowcount == 1


def acceptances(*, slug: str | None = None, unit_ids=None, since: str | None = None) -> list[dict]:
    """Rows newest first. unit_ids filters on the unit a row now rolls up to (after merges).
    since keeps active rows plus rows closed on or after that date."""
    sql, args = _SELECT + " WHERE 1 = 1", []
    if slug is not None:
        sql += " AND a.vendor_slug = ?"
        args.append(slug)
    if since is not None:
        sql += " AND (a.status = 'active' OR a.expires_on >= ? OR a.status_at >= ?)"
        args += [since, since]
    sql += " ORDER BY a.signed_at DESC, a.id DESC"
    with _db() as con:
        rows = _dicts(con.execute(sql, args))
        for r in rows:
            r["live_unit_id"] = live_unit_id(con, r["org_unit_id"])
    if unit_ids is not None:
        rows = [r for r in rows if r["live_unit_id"] in unit_ids]
    return rows


def is_active(row: dict, today: date | None = None) -> bool:
    return row.get("status") == "active" and row.get("expires_on", "") >= (today or date.today()).isoformat()


def active_by_vendor(today: date | None = None) -> dict:
    """{slug: {detection_code: row}} for acceptances that currently cover a detection."""
    out: dict = {}
    with _db() as con:
        for r in con.execute(_SELECT + " WHERE " + _ACTIVE, ((today or date.today()).isoformat(),)):
            out.setdefault(r["vendor_slug"], {})[r["detection_code"]] = dict(r)
    return out


def sweep_expired(today: date | None = None) -> list[dict]:
    """Stamp active rows whose date has passed as expired and return them for the audit log.
    Reads never depend on this having run; it only records when the reversion was seen."""
    day = (today or date.today()).isoformat()
    with _db(write=True) as con:
        rows = _dicts(con.execute("SELECT * FROM acceptances WHERE status = 'active' AND expires_on < ?", (day,)))
        if rows:
            con.execute("UPDATE acceptances SET status = 'expired', status_at = ? WHERE status = 'active' AND expires_on < ?", (_now(), day))
        return rows
