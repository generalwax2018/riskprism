"""Shadow IT: connected apps and SaaS in use that nobody approved or recorded.

Two inputs you already have:
  apps      an organization-wide connected-app export from Entra ID, Okta or Google (the same file
            format live access imports read)
  domains   a proxy, firewall or secure web gateway export of domains people use (domain, users, hits)

Each app and domain is matched to your tracked vendors and the product catalog, then placed in one of:
  unknown_app       an app holds access to your tenant and matches no tracked vendor
  not_authorized    it belongs to a tracked vendor that is not authorized
  unrecorded        the vendor is authorized, but this connection is not recorded as an integration
  shadow_saas       people use a known SaaS product (by domain) that is not tracked at all

Matching is by name, app ID and catalog domains. Fixed rules; no model.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import threading
from datetime import datetime, timezone
from io import StringIO

import catalog
import config
import integrations as ig
import records

PATH = config.DATA_DIR / "shadow.json"
LOCK = threading.RLock()
STATE_LABEL = {"unknown_app": "Unknown app", "not_authorized": "Vendor not authorized", "unrecorded": "Approved vendor, connection not recorded",
               "shadow_saas": "Shadow SaaS (seen in web traffic)"}
SENSITIVE_READS = ("mail.", "files.", "sites.", "chat", "calendars.", "notes.", "drive", "gmail", "contacts")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load() -> dict:
    if not PATH.exists():
        return {"apps": [], "domains": [], "decisions": {}, "apps_source": "", "domains_source": ""}
    try:
        data = json.loads(PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    return {"apps": data.get("apps") or [], "domains": data.get("domains") or [], "decisions": data.get("decisions") or {},
            "apps_source": data.get("apps_source", ""), "domains_source": data.get("domains_source", "")}


def _save(data: dict) -> None:
    PATH.parent.mkdir(parents=True, exist_ok=True)
    records.atomic_write(PATH, json.dumps(data, indent=2, sort_keys=True))


def import_apps(text: str, filename: str, source: str, by: str) -> int:
    import access_import
    result = access_import.parse(text, filename, source)
    with LOCK:
        data = _load()
        data["apps"] = result["rows"]
        data["apps_source"] = "%s, %s, %d apps, %s" % (source, filename or "upload", len(result["rows"]), _now()[:10])
        _save(data)
    return len(result["rows"])


_DOMAIN_COLS = ("domain", "host", "hostname", "url", "site", "destination", "fqdn")
_USER_COLS = ("users", "uniqueusers", "usercount", "user")
_HIT_COLS = ("hits", "requests", "count", "transactions", "events")


def import_domains(text: str, filename: str, by: str) -> int:
    text = (text or "").lstrip("﻿")
    if not text.strip():
        raise ValueError("The file is empty.")
    reader = csv.DictReader(StringIO(text))
    keys = {re.sub(r"[^a-z]", "", (h or "").lower()): h for h in reader.fieldnames or []}
    col = next((keys[c] for c in _DOMAIN_COLS if c in keys), None)
    if not col:
        raise ValueError("No domain column found. Columns in this file: %s." % ", ".join(list(keys.values())[:12]))
    ucol = next((keys[c] for c in _USER_COLS if c in keys), None)
    hcol = next((keys[c] for c in _HIT_COLS if c in keys), None)
    agg: dict[str, dict] = {}
    for i, row in enumerate(reader):
        if i >= 50000:
            break
        host = re.sub(r"^https?://", "", str(row.get(col) or "").strip().lower()).split("/")[0].split(":")[0]
        if not host or "." not in host:
            continue
        a = agg.setdefault(host, {"domain": host, "users": 0, "hits": 0})
        for c, f in ((ucol, "users"), (hcol, "hits")):
            try:
                a[f] += int(float(row.get(c) or 0)) if c else 0
            except ValueError:
                pass
    with LOCK:
        data = _load()
        data["domains"] = list(agg.values())
        data["domains_source"] = "%s, %d domains, %s" % (filename or "upload", len(agg), _now()[:10])
        _save(data)
    return len(agg)


def _item_id(kind: str, key: str) -> str:
    return "sh-" + hashlib.sha1(("%s|%s" % (kind, key.lower())).encode()).hexdigest()[:10]


def _vendor_match(name: str, vendors: list[dict]) -> dict | None:
    n = (name or "").lower()
    key = catalog.match_app(name)
    for v in vendors:
        vn = (v.get("vendor") or "").lower()
        if vn and (vn == n or vn in n or n in vn):
            return v
        if key and catalog.key_for(v.get("vendor") or "") == key:
            return v
    return None


def _severity(scopes: list[str]) -> str:
    classes = [ig.scope_class(s, "delegated") for s in scopes]
    if any(c in ("admin", "write") for c in classes):
        return "high"
    if any(any(w in s.lower() for w in SENSITIVE_READS) for s in scopes):
        return "medium"
    return "low"


def queue(include_decided: bool = False) -> dict:
    data = _load()
    vendors = [r for r in records.list_vendors() if r.get("slug")]
    recorded = ig.all_rows(include_retired=False)
    rec_ids = {r["app_id"] for r in recorded if r["app_id"]}
    rec_names = {r["name"].lower() for r in recorded}
    items = []
    for app in data["apps"]:
        if app.get("status") != "active":
            continue
        v = _vendor_match(app["display_name"], vendors)
        key = catalog.match_app(app["display_name"])
        product = catalog.BUILTIN.get(key, {}).get("product", "")
        sev = _severity(app.get("scopes") or [])
        base = {"name": app["display_name"], "app_id": app.get("app_id", ""), "scopes": app.get("scopes") or [],
                "evidence": "Seen %s; owner %s" % ((app.get("last_seen") or "")[:10] or "recently", app.get("owner") or "unknown"),
                "product": product, "users": "", "category": catalog.BUILTIN.get(key, {}).get("category", "")}
        if not v:
            items.append({**base, "kind": "unknown_app", "severity": sev, "vendor": "",
                          "id": _item_id("app", app.get("app_id") or app["display_name"])})
        elif v.get("authorization") != "authorized" or v.get("stage") == "offboarded":
            items.append({**base, "kind": "not_authorized", "severity": "high" if sev != "low" else "medium", "vendor": v["slug"],
                          "id": _item_id("app", app.get("app_id") or app["display_name"])})
        elif (app.get("app_id") and app["app_id"] in rec_ids) or any(app["display_name"].lower() in n for n in rec_names) \
                or ig.for_party(v["slug"]):
            continue
        else:
            items.append({**base, "kind": "unrecorded", "severity": "medium" if sev != "low" else "low", "vendor": v["slug"],
                          "id": _item_id("app", app.get("app_id") or app["display_name"])})
    tracked_keys = {catalog.key_for(v.get("vendor") or "") for v in vendors}
    by_product: dict[str, dict] = {}
    unmatched = 0
    for d in data["domains"]:
        k = catalog.match_domain(d["domain"])
        if not k:
            unmatched += 1
            continue
        if k in tracked_keys:
            continue
        p = by_product.setdefault(k, {"domains": [], "users": 0, "hits": 0})
        p["domains"].append(d["domain"])
        p["users"] += d.get("users") or 0
        p["hits"] += d.get("hits") or 0
    app_keys = {}
    for it in items:
        k = catalog.match_app(it["name"])
        if k:
            app_keys[k] = it
    for k, p in by_product.items():
        b = catalog.BUILTIN[k]
        if k in app_keys:  # the same product is already in the queue as an app: add the traffic as evidence
            app_keys[k]["evidence"] += "; web traffic: %d user%s, %d requests" % (p["users"], "" if p["users"] == 1 else "s", p["hits"])
            app_keys[k]["users"] = p["users"]
            continue
        items.append({"id": _item_id("saas", k), "kind": "shadow_saas", "name": b["product"], "product": b["product"], "vendor": "",
                      "category": b["category"], "scopes": [], "app_id": "",
                      "severity": "medium" if b["category"] in ("ai_assistant", "meeting_notes", "file_sharing") else "low",
                      "users": p["users"], "evidence": "%d user%s, %d requests to %s" % (
                          p["users"], "" if p["users"] == 1 else "s", p["hits"], ", ".join(sorted(p["domains"])[:3]))})
    decided = data["decisions"]
    for it in items:
        it["decision"] = decided.get(it["id"])
    open_items = [it for it in items if include_decided or not it["decision"]]
    open_items.sort(key=lambda it: (-ig.SEVERITY_RANK[it["severity"]], it["kind"], it["name"].lower()))
    return {"items": open_items, "all": items, "apps_source": data["apps_source"], "domains_source": data["domains_source"],
            "unmatched_domains": unmatched, "decided": len([i for i in items if i["decision"]])}


def decide(item_id: str, state: str, note: str, by: str) -> None:
    if state not in ("known", "ignored", "tracked"):
        raise ValueError("Pick known, ignored or tracked.")
    with LOCK:
        data = _load()
        data["decisions"][item_id] = {"state": state, "note": (note or "").strip()[:400], "by": by, "at": _now()}
        _save(data)


def track(item_id: str, by: str) -> str:
    """Start tracking the vendor behind a shadow item: a not-authorized vendor record, with the app as live access."""
    import access_store
    q = queue(include_decided=True)
    it = next((i for i in q["all"] if i["id"] == item_id), None)
    if not it:
        raise ValueError("That item is no longer in the queue.")
    if it["vendor"]:
        slug = it["vendor"]
    else:
        name = it["product"] or it["name"]
        slug = records.slugify(name)
        if not records.load_vendor(slug):
            records.save_vendor({"vendor": name, "slug": slug, "authorization": "not_authorized", "stage": "inquiry",
                                 "mode": "saas", "category": it.get("category", ""), "connects": "yes" if it["kind"] != "shadow_saas" else "unknown",
                                 "source": "shadow_it", "created_by": by,
                                 "notes": "Found by the shadow IT queue: %s." % it["evidence"]}, replace=False)
    if it["kind"] in ("unknown_app", "not_authorized", "unrecorded"):
        rec = records.load_vendor(slug)
        rows = [r for r in access_store.rows(rec) if r.get("app_id") != it["app_id"] or not it["app_id"]]
        new = access_store.normalize_row({"display_name": it["name"], "app_id": it["app_id"], "scopes": it["scopes"],
                                          "source": "entra", "status": "active"})
        if new:
            rows.append(new)
        access_store.replace_rows(rec, rows)
        records.save_vendor(rec)
    decide(item_id, "tracked", "Now tracked as %s" % slug, by)
    return slug
