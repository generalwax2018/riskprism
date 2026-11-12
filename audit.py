"""Tamper-evident audit trail: who did what to which record, and when.

Entries live in the `audit` table of DATA_DIR/riskprism.db. Each entry is sealed with an HMAC over its
own fields and the seal of the entry before it, keyed from the server secret. Changing, removing or
reordering any entry breaks every seal after it, and `verify()` reports the first break. Database
triggers refuse UPDATE and DELETE on the table.

What this does and does not prove:
  - An edit or a deletion in the middle of the log is detected.
  - Someone holding both the database and the server secret could rebuild the whole chain. Keep
    ENTROPY_SECRET (or secret.key) away from the database backups, and record the head seal shown on
    the Data and audit page somewhere outside the server (the board pack prints it) so a rebuilt or
    shortened log can be told from the original.
  - Changing the server secret makes older entries fail verification. Do not rotate it casually.

Older installs kept the trail in DATA_DIR/audit.log. On first use those lines are imported in order,
sealed, and the file is renamed to audit.log.imported.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from io import StringIO

import config
from records import LOCK

PATH = config.AUDIT_PATH  # the legacy text log, imported once
GENESIS = "0" * 64
FIELDS = ("at", "actor", "action", "slug", "detail", "ip")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
  id      INTEGER PRIMARY KEY,
  at      TEXT NOT NULL,
  actor   TEXT NOT NULL DEFAULT '',
  action  TEXT NOT NULL DEFAULT '',
  slug    TEXT NOT NULL DEFAULT '',
  detail  TEXT NOT NULL DEFAULT '',
  ip      TEXT NOT NULL DEFAULT '',
  prev    TEXT NOT NULL,
  seal    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_by_slug ON audit(slug, id);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit entries cannot be changed'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit entries cannot be deleted'); END;
"""

_ready: set[str] = set()


def _key() -> bytes:
    return hmac.new(config.SECRET, b"riskprism audit seal v1", hashlib.sha256).digest()


def _seal(prev: str, entry: dict) -> str:
    body = json.dumps([entry.get(f, "") or "" for f in FIELDS], ensure_ascii=False, separators=(",", ":"))
    return hmac.new(_key(), (prev + "\n" + body).encode("utf-8"), hashlib.sha256).hexdigest()


@contextmanager
def _db():
    path = config.RISK_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path), timeout=30, isolation_level=None)  # transactions are explicit (_writing)
    con.row_factory = sqlite3.Row
    try:
        if str(path) not in _ready:
            with LOCK:
                con.executescript(_SCHEMA)
                try:  # one entry per predecessor: a fork in the chain fails loudly instead of silently
                    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS audit_one_successor ON audit(prev)")
                except sqlite3.IntegrityError:
                    pass  # an older database already forked; verify() reports where
                _import_legacy(con)
                _ready.add(str(path))
        yield con
    finally:
        con.close()


@contextmanager
def _writing(con):
    """One write transaction, taken before reading the previous seal. BEGIN IMMEDIATE holds SQLite's write
    lock across processes too (the server and a command-line tool), so two writers can never both
    chain onto the same entry."""
    con.execute("BEGIN IMMEDIATE")
    try:
        yield con
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise


def _append(con, entry: dict) -> None:
    """Call inside _writing(con)."""
    row = con.execute("SELECT seal FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = row[0] if row else GENESIS
    con.execute("INSERT INTO audit (at, actor, action, slug, detail, ip, prev, seal) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (*[entry.get(f, "") or "" for f in FIELDS], prev, _seal(prev, entry)))


def _import_legacy(con) -> int:
    """Bring an older audit.log into the sealed table, once, keeping its order."""
    if not PATH.is_file() or con.execute("SELECT 1 FROM audit LIMIT 1").fetchone():
        return 0
    n = 0
    with _writing(con):
        with PATH.open(encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(e, dict) or not e.get("at"):
                    continue
                _append(con, {k: str(e.get(k, "") or "") for k in FIELDS})
                n += 1
        _append(con, {"at": _now(), "actor": "system", "action": "audit_log_imported", "slug": "",
                      "detail": "%d earlier entries imported from audit.log and sealed" % n, "ip": ""})
    try:
        PATH.replace(PATH.with_name(PATH.name + ".imported"))
    except OSError:
        pass
    return n


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(actor: str, action: str, slug: str = "", detail: str = "", ip: str = "") -> None:
    entry = {"at": _now(), "actor": actor or "", "action": action or "", "slug": slug or "",
             "detail": (detail or "")[:300], "ip": ip or ""}
    with LOCK, _db() as con, _writing(con):
        _append(con, entry)


def _rows(sql: str, args: tuple = ()) -> list[dict]:
    with _db() as con:
        return [{k: r[k] for k in ("id", *FIELDS)} for r in con.execute(sql, args)]


def for_slug(slug: str, limit: int = 100) -> list[dict]:
    """Newest first, for one vendor. Uses the index, so the cost does not grow with the whole log."""
    return _rows("SELECT * FROM audit WHERE slug = ? ORDER BY id DESC LIMIT ?", (slug, int(limit)))


def recent(limit: int = 50) -> list[dict]:
    return _rows("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (int(limit),))


def count() -> int:
    with _db() as con:
        return con.execute("SELECT COUNT(*) FROM audit").fetchone()[0]


def head() -> str:
    """The newest seal. Record it outside the server to detect a rebuilt or shortened log later."""
    with _db() as con:
        row = con.execute("SELECT seal FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    return row[0] if row else GENESIS


def verify() -> dict:
    """Walk the whole chain. {'ok', 'count', 'head', 'first_bad', 'reason'}."""
    prev, n, last_id = GENESIS, 0, 0
    with _db() as con:
        for r in con.execute("SELECT * FROM audit ORDER BY id"):
            n += 1
            entry = {f: r[f] for f in FIELDS}
            if r["prev"] != prev:
                return {"ok": False, "count": n, "head": prev, "first_bad": r["id"],
                        "reason": "Entry %d does not follow entry %d: something before it was removed or reordered." % (r["id"], last_id)}
            if not hmac.compare_digest(r["seal"], _seal(prev, entry)):
                return {"ok": False, "count": n, "head": prev, "first_bad": r["id"],
                        "reason": "Entry %d was changed after it was written, or the server secret has changed since." % r["id"]}
            prev, last_id = r["seal"], r["id"]
    return {"ok": True, "count": n, "head": prev, "first_bad": None, "reason": ""}


def _cell(v) -> str:
    v = str(v if v is not None else "")
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def csv_text(limit: int = 100000) -> str:
    buf = StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "at", "actor", "action", "vendor", "detail", "ip", "seal"])
    with _db() as con:
        for r in con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (int(limit),)):
            w.writerow([r["id"]] + [_cell(r[f]) for f in FIELDS] + [r["seal"]])
    return buf.getvalue()


def wipe(actor: str, ip: str = "") -> None:
    """Delete every entry (only for 'delete all data'), then start a new chain that records the wipe."""
    with LOCK, _db() as con:
        n = con.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        con.executescript("DROP TABLE IF EXISTS audit;" + _SCHEMA)
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS audit_one_successor ON audit(prev)")
        with _writing(con):
            _append(con, {"at": _now(), "actor": actor, "action": "audit_log_wiped", "slug": "",
                          "detail": "%d entries removed by 'delete all data'" % n, "ip": ip})
