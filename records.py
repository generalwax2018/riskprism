"""Vendor records on disk (one JSON file per vendor).

Every path that touches disk goes through _path(), which only accepts a strict
slug and checks that the resolved file stays inside its folder. A slug can
therefore never walk out of data/ (../, absolute paths, drive letters, ...).
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from datetime import datetime
from pathlib import Path

import config
import memo

LOCK = threading.RLock()
VDIR = config.VDIR
QDIR = config.DATA_DIR / "questionnaires"
ADIR = config.DATA_DIR / "answers"

_SLUG_OK = re.compile(r"^[\w][\w.\-]{0,99}$", re.UNICODE)


class BadSlug(ValueError):
    pass


def slugify(name: str) -> str:
    s = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (name or "").strip())
    s = s.lstrip(".") or "unknown"
    return s[:100]


def valid_slug(slug: str) -> bool:
    return bool(slug) and bool(_SLUG_OK.match(slug)) and ".." not in slug


def _path(folder: Path, slug: str, ext: str = ".json") -> Path:
    if not valid_slug(slug):
        raise BadSlug("invalid record id")
    path = (folder / (slug + ext)).resolve()
    if path.parent != folder.resolve():
        raise BadSlug("invalid record id")
    return path


def atomic_write(path: Path, text: str) -> None:
    """Write via a temp file and rename so a crash never leaves half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
        memo.bump()
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def exists(slug: str) -> bool:
    try:
        return _path(VDIR, slug).is_file()
    except BadSlug:
        return False


def save_vendor(fields: dict, *, replace: bool = True) -> Path:
    """Save a record. Callers decide whether an existing record may be replaced."""
    name = str(fields.get("vendor") or "unknown").strip()[:200] or "unknown"
    slug = fields.get("slug") or slugify(name)
    path = _path(VDIR, slug)
    rec = dict(fields)
    rec["slug"] = slug
    rec["vendor"] = name
    rec["updated_at"] = datetime.now().isoformat(timespec="seconds")
    with LOCK:
        if not replace and path.is_file():
            raise FileExistsError(slug)
        atomic_write(path, json.dumps(rec, indent=2))
    return path


def load_vendor(slug: str):
    try:
        path = _path(VDIR, slug)
    except BadSlug:
        return None
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
    return None


def update_vendor(slug: str, fn) -> dict | None:
    """Read-modify-write under one lock so two requests cannot lose each other's edits."""
    with LOCK:
        rec = load_vendor(slug)
        if rec is None:
            return None
        out = fn(rec)
        rec = out if isinstance(out, dict) else rec
        save_vendor(rec)
        return rec


def list_vendors():
    """Every vendor record. Within one request the parsed records are reused (see memo.py): read-only."""
    return list(memo.cached("list_vendors", _read_all_vendors))


def _read_all_vendors() -> list:
    if not VDIR.is_dir():
        return []
    out = []
    for p in sorted(VDIR.glob("*.json")):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return out


def delete_vendor(slug: str) -> bool:
    found = False
    with LOCK:
        for folder in (VDIR, QDIR, ADIR):
            for ext in (".json", ".md"):
                try:
                    p = _path(folder, slug, ext)
                except BadSlug:
                    return False
                if p.is_file():
                    p.unlink()
                    found = True
    memo.bump()
    import tokens
    tokens.revoke_slug(slug)
    return found
