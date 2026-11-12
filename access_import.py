"""Import an app export into a vendor's live_access[] (queue item 4).

Input: a CSV or JSON export of connected apps from Entra ID, Okta, Google Workspace,
or a SaaS audit. Output: normalized rows through access_store.normalize_row().

No API calls. Columns are matched by name, ignoring case, spaces, underscores and
punctuation, so "Application ID", "app_id" and "AppId" all work. The result says
which columns were recognised and which rows were skipped, so a wrong export shows
up as an error instead of an empty list.

Replacing is deliberate: an import is the vendor's full list as of that export, and
rows that are no longer in the file disappear. Keep the export for the audit trail.
"""
from __future__ import annotations

import csv
import json
import re
from io import StringIO

import access_store

MAX_ROWS = 1000
MAX_BYTES = 2 * 1024 * 1024
SOURCES_IMPORTABLE = ("entra", "okta", "google", "saas_audit", "manual")

# Canonical field -> header spellings after normalising (lowercase, letters and digits only).
ALIASES = {
    "display_name": ("displayname", "applicationname", "appname", "application", "app", "name", "label",
                     "clientname", "appdisplayname", "integrationname", "title"),
    "app_id": ("appid", "applicationid", "clientid", "oauthclientid", "client", "id"),
    "scopes": ("scopes", "scope", "permissions", "grantedscopes", "oauthscopes", "grantedpermissions", "permission"),
    "last_seen": ("lastsignin", "lastsignedin", "lastsigninat", "lastused", "lastactivity", "lastaccessed",
                  "lastseen", "lastsignintime", "lastauthenticated"),
    "first_seen": ("firstseen", "firstsignin", "created", "createdat", "granted", "grantedat", "authorizedat",
                   "firstauthorized", "createdon"),
    "owner": ("owner", "owneremail", "userprincipalname", "grantedby", "createdby", "user", "email"),
    "kind": ("kind", "type", "apptype", "category"),
    "status": ("status", "state"),
}
KIND_WORDS = {
    "oauth": "oauth_app", "oauthapp": "oauth_app", "webapp": "oauth_app", "application": "oauth_app",
    "enterprise": "enterprise_app", "enterpriseapp": "enterprise_app", "saml": "enterprise_app",
    "serviceprincipal": "service_principal", "service": "service_principal", "role": "role", "token": "token",
    "apitoken": "token", "pat": "token",
}
STATUS_WORDS = {"active": "active", "enabled": "active", "stale": "stale", "inactive": "stale",
                "revoked": "revoked", "disabled": "revoked", "removed": "revoked", "deleted": "revoked"}


class ImportError_(ValueError):
    """The file cannot be used. The text is shown to the analyst as is."""


def _key(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _map_headers(headers: list[str]) -> dict[str, str]:
    """Canonical field -> the original header that matches it (first match wins)."""
    found = {}
    by_key = {}
    for h in headers:
        by_key.setdefault(_key(h), h)
    for field, names in ALIASES.items():
        for n in names:
            if n in by_key and by_key[n] not in found.values():
                found[field] = by_key[n]
                break
    return found


def _split_scopes(value) -> list[str]:
    if isinstance(value, list):
        parts = [str(p) for p in value]
    else:
        parts = re.split(r"[\s,;|]+", str(value or ""))
    return [p.strip() for p in parts if p.strip()]


def _from_mapping(raw: dict, colmap: dict) -> dict:
    def get(field):
        col = colmap.get(field)
        return raw.get(col) if col is not None else None

    status = str(get("status") or "").strip().lower()
    kind = str(get("kind") or "").strip().lower().replace("_", "").replace(" ", "").replace("-", "")
    return {
        "display_name": str(get("display_name") or "").strip(),
        "app_id": str(get("app_id") or "").strip(),
        "scopes": _split_scopes(get("scopes")),
        "last_seen": str(get("last_seen") or "").strip(),
        "first_seen": str(get("first_seen") or "").strip(),
        "owner": str(get("owner") or "").strip(),
        "kind": KIND_WORDS.get(kind, "oauth_app"),
        "status": STATUS_WORDS.get(status, "active"),
    }


def _rows_from_csv(text: str) -> tuple[list[dict], dict, list[str]]:
    reader = csv.DictReader(StringIO(text))
    headers = [h for h in (reader.fieldnames or []) if h]
    colmap = _map_headers(headers)
    return list(reader), colmap, headers


def _rows_from_json(text: str) -> tuple[list[dict], dict, list[str]]:
    try:
        data = json.loads(text)
    except ValueError:
        raise ImportError_("That is not valid JSON.")
    if isinstance(data, dict):
        for key in ("value", "items", "apps", "data", "rows"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
    if not isinstance(data, list) or not all(isinstance(x, dict) for x in data):
        raise ImportError_("JSON must be a list of app objects, or an object with a list under value, items, apps or data.")
    headers = []
    for obj in data[:50]:
        for k in obj:
            if k not in headers:
                headers.append(k)
    return data, _map_headers(headers), headers


def parse(text: str, filename: str = "", source: str = "entra") -> dict:
    """Return {"rows": [normalized...], "read", "skipped", "reasons", "columns", "missing"}.

    Raises ImportError_ when the file cannot be read or has no usable app-name column.
    """
    if source not in SOURCES_IMPORTABLE:
        raise ImportError_("Choose where the export came from.")
    text = (text or "").lstrip("﻿")
    if not text.strip():
        raise ImportError_("The file is empty.")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ImportError_("That file is larger than 2 MB. Export only the apps for this vendor.")

    is_json = filename.lower().endswith(".json") or text.lstrip().startswith(("[", "{"))
    raw_rows, colmap, headers = _rows_from_json(text) if is_json else _rows_from_csv(text)
    if "display_name" not in colmap:
        shown = ", ".join(headers[:12]) or "none"
        raise ImportError_("No app name column found. Expected one of: Application name, Display name, App name, Name. "
                           "Columns in this file: %s." % shown)
    if len(raw_rows) > MAX_ROWS:
        raise ImportError_("%d rows is more than the %d-row limit. Filter the export to this vendor's apps." % (len(raw_rows), MAX_ROWS))

    out, skipped, reasons, seen = [], 0, {}, set()
    for raw in raw_rows:
        row = _from_mapping(raw, colmap)
        if not row["display_name"]:
            skipped += 1
            reasons["no app name"] = reasons.get("no app name", 0) + 1
            continue
        normalized = access_store.normalize_row({
            **row,
            "source": source,
            "id": row["app_id"] or row["display_name"],
            "last_seen": _iso_or_now(row["last_seen"]),
            "first_seen": _iso_or_now(row["first_seen"]) if row["first_seen"] else "",
        })
        if not normalized:
            skipped += 1
            reasons["unusable row"] = reasons.get("unusable row", 0) + 1
            continue
        if normalized["id"] in seen:
            skipped += 1
            reasons["duplicate app"] = reasons.get("duplicate app", 0) + 1
            continue
        seen.add(normalized["id"])
        out.append(normalized)

    if not out:
        raise ImportError_("No apps could be read from this file. Check that rows have an app name.")
    optional = ("app_id", "scopes", "last_seen", "owner")
    return {
        "rows": out,
        "read": len(raw_rows),
        "skipped": skipped,
        "reasons": reasons,
        "columns": sorted(colmap),
        "missing": [f for f in optional if f not in colmap],
    }


def _iso_or_now(value: str) -> str:
    """Keep dates that look like dates; otherwise stamp the import time. Never guess a date."""
    v = (value or "").strip()
    if re.match(r"^\d{4}-\d{2}-\d{2}", v):
        return v[:40]
    if not v:
        return access_store._now()
    return v[:40]


def summary(result: dict, previous: int) -> str:
    text = "Read %d app%s; kept %d." % (result["read"], "" if result["read"] == 1 else "s", len(result["rows"]))
    if result["skipped"]:
        why = ", ".join("%d %s" % (n, k) for k, n in sorted(result["reasons"].items()))
        text += " Skipped %d (%s)." % (result["skipped"], why)
    text += " Replaces the %d row%s on file." % (previous, "" if previous == 1 else "s")
    if result["missing"]:
        text += " Not in this file: %s. Scope and last-seen checks are weaker without them." % ", ".join(
            {"app_id": "app ID", "scopes": "scopes", "last_seen": "last sign-in", "owner": "owner"}[m] for m in result["missing"])
    return text
