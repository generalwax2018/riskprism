"""Live third-party access rows stored on the vendor JSON.

v1 is hand-seeded or pasted. Connectors write the same shape later.
Unknown keys are dropped. This module does not call update_vendor;
callers persist via records.update_vendor.
"""
from __future__ import annotations

from datetime import datetime, timezone

SOURCES = ("demo", "manual", "entra", "okta", "google", "saas_audit")
KINDS = ("oauth_app", "enterprise_app", "service_principal", "role", "token")

_KEEP = (
    "id", "kind", "source", "display_name", "app_id", "scopes", "last_seen",
    "first_seen", "owner", "status", "notes",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_row(raw: dict) -> dict | None:
    if not isinstance(raw, dict):
        return None
    name = str(raw.get("display_name") or raw.get("name") or "").strip()[:200]
    if not name:
        return None
    kind = raw.get("kind") if raw.get("kind") in KINDS else "oauth_app"
    source = raw.get("source") if raw.get("source") in SOURCES else "manual"
    status = raw.get("status") if raw.get("status") in ("active", "stale", "revoked") else "active"
    scopes = raw.get("scopes") or []
    if isinstance(scopes, str):
        scopes = [s.strip() for s in scopes.split() if s.strip()]
    scopes = [str(s)[:120] for s in scopes][:40]
    rid = str(raw.get("id") or raw.get("app_id") or name).strip()[:120]
    return {
        "id": rid,
        "kind": kind,
        "source": source,
        "display_name": name,
        "app_id": str(raw.get("app_id") or "")[:120],
        "scopes": scopes,
        "last_seen": str(raw.get("last_seen") or _now())[:40],
        "first_seen": str(raw.get("first_seen") or raw.get("last_seen") or _now())[:40],
        "owner": str(raw.get("owner") or "")[:200],
        "status": status,
        "notes": str(raw.get("notes") or "")[:400],
    }


def rows(rec: dict) -> list:
    out = []
    for raw in rec.get("live_access") or []:
        row = normalize_row(raw)
        if row:
            out.append(row)
    return out


def replace_rows(rec: dict, incoming: list) -> dict:
    cleaned = []
    seen = set()
    for raw in incoming or []:
        row = normalize_row(raw)
        if not row or row["id"] in seen:
            continue
        seen.add(row["id"])
        cleaned.append(row)
    rec["live_access"] = cleaned
    rec["live_access_synced_at"] = _now()
    return rec
