"""Vendor magic links.

Only a SHA-256 hash of each token is stored, so data/tokens.json cannot be used
to open a vendor form. Tokens expire, and issuing a new link for the same vendor
and kind revokes the previous one, so an old renewal link stops working.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

import config
from records import LOCK, atomic_write

PATH = config.TOKENS_PATH


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _hash(token: str) -> str:
    return "h:" + hashlib.sha256(token.encode()).hexdigest()


def _load() -> dict:
    if PATH.is_file():
        try:
            data = json.loads(PATH.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}
    return {}


def _save(data: dict) -> None:
    atomic_write(PATH, json.dumps(data, indent=2))


def issue(vendor: str, slug: str, kind: str = "onboard", days: int | None = None, by: str = "") -> str:
    token = secrets.token_urlsafe(24)
    days = days or config.TOKEN_DAYS
    with LOCK:
        data = _load()
        now = _iso(_now())
        for rec in data.values():
            if rec.get("slug") == slug and rec.get("kind") == kind and not rec.get("revoked_at"):
                rec["revoked_at"] = now
        data[_hash(token)] = {
            "vendor": vendor, "slug": slug, "kind": kind,
            "created_at": now, "expires_at": _iso(_now() + timedelta(days=days)),
            "revoked_at": None, "uses": 0, "by": (by or "")[:200],
        }
        _save(data)
    return token


def lookup(token: str):
    """Return the token record if it is valid right now, else None."""
    if not token or len(token) > 100:
        return None
    rec = _load().get(_hash(token))
    if not rec or rec.get("revoked_at"):
        return None
    try:
        if datetime.fromisoformat(rec["expires_at"]) < _now():
            return None
    except (KeyError, ValueError):
        return None
    return rec


def touch(token: str) -> None:
    with LOCK:
        data = _load()
        rec = data.get(_hash(token))
        if rec:
            rec["uses"] = int(rec.get("uses", 0)) + 1
            rec["last_used_at"] = _iso(_now())
            _save(data)


def revoke_slug(slug: str) -> None:
    with LOCK:
        data = _load()
        keep = {k: v for k, v in data.items() if v.get("slug") != slug}
        if len(keep) != len(data):
            _save(keep)
