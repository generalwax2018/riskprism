"""Your environment: the internal systems of the company using RiskPrism, and how vendors reach them.

A system is something you run or rent: your identity provider, each SaaS tenant (your Microsoft 365
tenant, your ServiceNow instance), cloud accounts, on-premises sites, endpoint fleets, security tools
and the data stores that hold sensitive data. A system can point at the tracked vendor that hosts it
(your Microsoft 365 tenant is hosted by Microsoft), which is how the map knows that an integration
recorded against "Microsoft 365" lands in that tenant.

Systems come from three places:
  setup     a short guided setup (which identity provider, collaboration suite, ITSM, HR system, clouds...)
  import    a CSV or JSON export from a CMDB or asset list (columns matched loosely, like live access)
  manual    added by hand

Systems are integration parties: an integration can run from a vendor to "sys-aws-prod".
Stored in data/environment.json. No model calls.
"""
from __future__ import annotations

import csv
import json
import re
import threading
from datetime import datetime, timezone
from io import StringIO

import config
import records

PATH = config.DATA_DIR / "environment.json"
LOCK = threading.RLock()

KINDS = {
    "identity_provider": "Identity provider",
    "saas_tenant": "SaaS tenant or instance",
    "cloud_account": "Cloud account or subscription",
    "on_prem": "On-premises site or network",
    "data_store": "Data store",
    "endpoints": "Endpoint fleet",
    "network_edge": "Network edge (proxy, firewall, SSE)",
    "security_tool": "Security tool",
    "application": "Internal application",
}
KIND_ORDER = list(KINDS)
CRITICALITY = ("high", "medium", "low")
MAX_IMPORT = 2000

# Guided setup. Each answer becomes one or more systems. "vendor" names the tracked vendor (by a word in
# its name) that hosts the system, so integrations recorded against that vendor land on the system.
SETUP = [
    ("idp", "Identity provider", "identity_provider", ["Microsoft Entra ID", "Okta", "Google Cloud Identity", "Ping Identity", "JumpCloud"]),
    ("collab", "Email and collaboration", "saas_tenant", ["Microsoft 365", "Google Workspace"]),
    ("itsm", "IT service management", "saas_tenant", ["ServiceNow", "Jira Service Management", "Zendesk", "Freshservice"]),
    ("hris", "HR system", "saas_tenant", ["Workday", "ADP", "BambooHR", "SAP SuccessFactors"]),
    ("crm", "CRM", "saas_tenant", ["Salesforce", "HubSpot", "Microsoft Dynamics 365"]),
    ("mdm", "Endpoint management", "endpoints", ["Microsoft Intune", "Jamf", "Kandji", "Workspace ONE"]),
    ("siem", "Security monitoring (SIEM)", "security_tool", ["Microsoft Sentinel", "Splunk", "Google SecOps", "Elastic Security"]),
    ("edge", "Internet edge", "network_edge", ["Zscaler", "Netskope", "Palo Alto Prisma Access", "On-premises proxy"]),
    ("secrets", "Secrets store", "security_tool", ["Azure Key Vault", "AWS Secrets Manager", "HashiCorp Vault", "CyberArk"]),
]
CLOUDS = [("aws", "AWS"), ("azure", "Azure"), ("gcp", "Google Cloud"), ("onprem", "On-premises data center")]
VENDOR_WORDS = {
    "Microsoft Entra ID": "microsoft", "Microsoft 365": "microsoft", "Microsoft Intune": "microsoft",
    "Microsoft Sentinel": "microsoft", "Microsoft Dynamics 365": "microsoft", "Azure Key Vault": "microsoft", "Azure": "microsoft",
    "Google Workspace": "google", "Google Cloud Identity": "google", "Google Cloud": "google", "Google SecOps": "google",
    "AWS": "aws", "AWS Secrets Manager": "aws",
}
PLATFORM = {  # how a system's product is named for permission catalogs in anticipate.py
    "Microsoft Entra ID": "microsoft", "Microsoft 365": "microsoft", "Google Workspace": "google",
    "Google Cloud Identity": "google", "Okta": "okta", "AWS": "aws", "Azure": "azure", "Google Cloud": "gcp",
}


class EnvironmentError_(ValueError):
    """Something a person must fix. Shown as is."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sid(text: str) -> str:
    return "sys-" + (re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:48] or "system")


# ------------------------------------------------------------------ store
_CACHE: dict = {"key": None, "data": None}


def _load() -> dict:
    """Read the store, cached on the file's modification time (pages ask for it many times)."""
    try:
        st = PATH.stat()
        key = (st.st_mtime_ns, st.st_size)
    except OSError:
        return {"systems": [], "profile": {}}
    if _CACHE["key"] == key:
        return json.loads(json.dumps(_CACHE["data"]))
    try:
        data = json.loads(PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    out = {"systems": [normalize(s) for s in data.get("systems") or [] if isinstance(s, dict)],
           "profile": data.get("profile") or {}}
    _CACHE["key"], _CACHE["data"] = key, out
    return json.loads(json.dumps(out))


def _save(data: dict) -> None:
    PATH.parent.mkdir(parents=True, exist_ok=True)
    records.atomic_write(PATH, json.dumps(data, indent=2, sort_keys=True))


def systems() -> list[dict]:
    return sorted(_load()["systems"], key=lambda s: (KIND_ORDER.index(s["kind"]), s["name"].lower()))


def profile() -> dict:
    return _load()["profile"]


def get(sid: str) -> dict | None:
    return next((s for s in _load()["systems"] if s["id"] == sid), None)


def normalize(raw: dict) -> dict:
    def s(v, n=200):
        return str(v or "").strip()[:n]
    data = raw.get("data_classes") or []
    if isinstance(data, str):
        data = [d.strip() for d in re.split(r"[;,\n]+", data) if d.strip()]
    kind = raw.get("kind") if raw.get("kind") in KINDS else "application"
    return {
        "id": s(raw.get("id"), 60) or _sid(raw.get("name")),
        "name": s(raw.get("name")),
        "kind": kind,
        "product": s(raw.get("product"), 120),
        "vendor": s(raw.get("vendor"), 80),
        "data_classes": [s(d, 80) for d in data][:12],
        "criticality": raw.get("criticality") if raw.get("criticality") in CRITICALITY else "medium",
        "owner": s(raw.get("owner"), 120),
        "environment": "nonprod" if str(raw.get("environment") or "").lower() in ("nonprod", "dev", "test", "staging") else "prod",
        "location": s(raw.get("location"), 120),
        "notes": s(raw.get("notes"), 600),
        "source": raw.get("source") if raw.get("source") in ("setup", "import", "manual") else "manual",
        "updated_at": s(raw.get("updated_at"), 40),
    }


def upsert(raw: dict, source: str = "manual") -> dict:
    row = normalize({**raw, "source": source, "updated_at": _now()})
    if not row["name"]:
        raise EnvironmentError_("Give the system a name.")
    with LOCK:
        data = _load()
        data["systems"] = [s for s in data["systems"] if s["id"] != row["id"]] + [row]
        _save(data)
    return row


def remove(sid: str) -> None:
    with LOCK:
        data = _load()
        data["systems"] = [s for s in data["systems"] if s["id"] != sid]
        _save(data)


def replace_all(rows: list[dict], prof: dict | None = None) -> None:
    with LOCK:
        _save({"systems": [normalize(r) for r in rows], "profile": prof or {}})


# ------------------------------------------------------------------ vendors and parties
def _vendor_for(product: str) -> str:
    """The tracked vendor that hosts a product, matched on a word in the vendor's name."""
    word = VENDOR_WORDS.get(product, product.split()[0].lower() if product else "")
    if not word:
        return ""
    for rec in records.list_vendors():
        if word in (rec.get("vendor") or "").lower():
            return rec.get("slug", "")
    return ""


def tenant_of(vendor_slug: str) -> dict | None:
    """Your system hosted by this vendor, if there is one (your tenant there)."""
    hits = [s for s in _load()["systems"] if s["vendor"] == vendor_slug]
    if not hits:
        return None
    return sorted(hits, key=lambda s: (s["kind"] != "saas_tenant", s["kind"] != "identity_provider"))[0]


def party_names() -> dict:
    return {s["id"]: s["name"] for s in _load()["systems"]}


# ------------------------------------------------------------------ the customer's own settings
DEFAULT_ROTATION_DAYS = 365


def org_name() -> str:
    return profile().get("org_name") or "Your organisation"


def sensitive_terms() -> list[str]:
    """The customer's own classification labels and data names that count as sensitive
    (for example "Restricted", "Confidential", "claims data"). Added to the built-in list."""
    return [t.lower() for t in profile().get("sensitive_terms") or [] if t]


def rotation_days() -> int:
    try:
        return max(1, int(profile().get("rotation_days") or DEFAULT_ROTATION_DAYS))
    except (TypeError, ValueError):
        return DEFAULT_ROTATION_DAYS


DEFAULT_FINDING_DAYS = {"high": 30, "medium": 90, "low": 180}


def finding_days() -> dict:
    """How long a finding of each severity may stay open before it is overdue. The customer's own rule."""
    saved = profile().get("finding_days") or {}
    out = {}
    for sev, default in DEFAULT_FINDING_DAYS.items():
        try:
            out[sev] = max(1, min(3650, int(saved.get(sev) or default)))
        except (TypeError, ValueError):
            out[sev] = default
    return out


def security_contact() -> str:
    """The address vendors are told to write to with questions. Empty when not set."""
    return profile().get("security_contact") or ""


def org_is_named() -> bool:
    return bool(profile().get("org_name"))


# ------------------------------------------------------------------ guided setup
def setup_systems(fields: dict) -> tuple[dict, list[dict]]:
    """(profile choices, systems) the setup answers describe. Nothing is saved."""
    prof, made = {}, []
    for key, label, kind, _choices in SETUP:
        product = (fields.get(key) or "").strip()[:120]
        if fields.get(key + "_other"):
            product = fields[key + "_other"].strip()[:120]
        if not product or product.lower() == "none":
            continue
        prof[key] = product
        name = product if kind != "saas_tenant" else "%s (your tenant)" % product
        made.append({"id": _sid(key + "-" + product), "name": name, "kind": kind, "product": product,
                     "vendor": _vendor_for(product), "criticality": "high" if key in ("idp", "collab", "hris") else "medium",
                     "data_classes": {"idp": ["identity", "credentials"], "collab": ["email content", "files", "chat messages"],
                                      "itsm": ["ticket content", "identity"], "hris": ["hr data", "personal data"],
                                      "crm": ["customer data", "personal data"]}.get(key, [])})
    for key, label in CLOUDS:
        if fields.get("cloud_" + key) == "on":
            prof.setdefault("clouds", []).append(label)
            kind = "on_prem" if key == "onprem" else "cloud_account"
            made.append({"id": _sid("cloud-" + key), "name": label if key == "onprem" else "%s (production)" % label,
                         "kind": kind, "product": label, "vendor": _vendor_for(label) if key != "onprem" else "",
                         "criticality": "high"})
    for line in (fields.get("stores") or "").splitlines():
        parts = [p.strip() for p in line.split("|")]
        if parts and parts[0]:
            made.append({"id": _sid("store-" + parts[0]), "name": parts[0], "kind": "data_store",
                         "data_classes": parts[1] if len(parts) > 1 else "", "location": parts[2] if len(parts) > 2 else "",
                         "criticality": "high"})
    return prof, made


def apply_setup(fields: dict, by: str) -> int:
    """Turn the setup answers into systems. Re-running updates them; it never deletes."""
    prof, made = setup_systems(fields)
    with LOCK:
        data = _load()
        ids = {m["id"] for m in made}
        data["systems"] = [s for s in data["systems"] if s["id"] not in ids] + [
            normalize({**m, "source": "setup", "owner": fields.get("owner", ""), "updated_at": _now()}) for m in made]
        terms = [t.strip()[:60] for t in re.split(r"[\n;,]+", fields.get("sensitive_terms") or "") if t.strip()][:40]
        try:
            rot = max(1, min(3650, int(fields.get("rotation_days") or DEFAULT_ROTATION_DAYS)))
        except ValueError:
            rot = DEFAULT_ROTATION_DAYS
        days = {}
        for sev, default in DEFAULT_FINDING_DAYS.items():
            try:
                days[sev] = max(1, min(3650, int(fields.get("due_" + sev) or default)))
            except ValueError:
                days[sev] = default
        contact = (fields.get("security_contact") or "").strip()[:200]
        import mailer
        if contact and not mailer.valid_address(contact):
            raise EnvironmentError_("The security contact must be an email address, for example security@yourco.com.")
        data["profile"] = {**prof, "org_name": (fields.get("org_name") or "").strip()[:120], "sensitive_terms": terms,
                           "rotation_days": rot, "finding_days": days, "security_contact": contact,
                           "updated_by": by, "updated_at": _now()}
        _save(data)
    return len(made)


def remove_systems(ids: set[str]) -> int:
    with LOCK:
        data = _load()
        keep = [s for s in data["systems"] if s["id"] not in ids]
        n = len(data["systems"]) - len(keep)
        data["systems"] = keep
        _save(data)
    return n


def reset_profile() -> None:
    with LOCK:
        data = _load()
        data["profile"] = {}
        _save(data)


# ------------------------------------------------------------------ import (CMDB or asset list)
ALIASES = {
    "name": ("name", "displayname", "ciname", "system", "asset", "assetname", "application", "service", "hostname"),
    "kind": ("kind", "type", "class", "sysclassname", "category", "citype", "assettype"),
    "owner": ("owner", "ownedby", "managedby", "supportgroup", "assignedto", "businessowner"),
    "criticality": ("criticality", "businesscriticality", "tier", "priority", "importance"),
    "data_classes": ("data", "dataclasses", "dataclassification", "classification", "sensitivity"),
    "environment": ("environment", "env", "usedfor", "lifecycle"),
    "location": ("location", "region", "site", "datacenter"),
    "product": ("product", "vendor", "manufacturer", "platform"),
}
KIND_WORDS = [
    ("identity", "identity_provider"), ("idp", "identity_provider"), ("directory", "identity_provider"),
    ("tenant", "saas_tenant"), ("saas", "saas_tenant"), ("cloudserviceaccount", "cloud_account"),
    ("cloud", "cloud_account"), ("subscription", "cloud_account"), ("awsaccount", "cloud_account"),
    ("database", "data_store"), ("db", "data_store"), ("storage", "data_store"), ("bucket", "data_store"),
    ("fileshare", "data_store"), ("datacenter", "on_prem"), ("network", "on_prem"), ("site", "on_prem"),
    ("firewall", "network_edge"), ("proxy", "network_edge"), ("endpoint", "endpoints"), ("computer", "endpoints"),
    ("siem", "security_tool"), ("security", "security_tool"), ("appl", "application"), ("application", "application"),
]
CRIT_WORDS = {"1": "high", "1 - most critical": "high", "critical": "high", "high": "high", "2": "medium",
              "medium": "medium", "3": "low", "4": "low", "low": "low"}


def _key(t: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (t or "").lower())


def parse_import(text: str, filename: str = "") -> list[dict]:
    text = (text or "").lstrip("﻿")
    if not text.strip():
        raise EnvironmentError_("The file is empty.")
    if filename.lower().endswith(".json") or text.lstrip().startswith(("[", "{")):
        try:
            data = json.loads(text)
        except ValueError:
            raise EnvironmentError_("That is not valid JSON.")
        if isinstance(data, dict):
            data = next((data[k] for k in ("result", "records", "items", "value", "systems") if isinstance(data.get(k), list)), [])
        rows = [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
        headers = list(dict.fromkeys(k for r in rows[:50] for k in r))
    else:
        reader = csv.DictReader(StringIO(text))
        rows, headers = list(reader), [h for h in (reader.fieldnames or []) if h]
    by_key = {_key(h): h for h in headers}
    colmap = {}
    for field, names in ALIASES.items():
        col = next((by_key[n] for n in names if n in by_key and by_key[n] not in colmap.values()), None)
        if col:
            colmap[field] = col
    if "name" not in colmap:
        raise EnvironmentError_("No name column found. Columns in this file: %s." % (", ".join(headers[:12]) or "none"))
    if len(rows) > MAX_IMPORT:
        raise EnvironmentError_("%d rows is more than the %d-row limit." % (len(rows), MAX_IMPORT))
    out = []
    for r in rows:
        get = lambda f: str(r.get(colmap[f]) or "").strip() if f in colmap else ""
        if not get("name"):
            continue
        kind_raw = _key(get("kind"))
        kind = next((k for w, k in KIND_WORDS if w in kind_raw), "application")
        out.append({"name": get("name"), "kind": kind, "owner": get("owner"),
                    "criticality": CRIT_WORDS.get(get("criticality").lower(), "medium"),
                    "data_classes": get("data_classes"), "environment": get("environment"), "location": get("location"),
                    "product": get("product"), "vendor": _vendor_for(get("product")) if get("product") else ""})
    if not out:
        raise EnvironmentError_("No systems could be read from this file.")
    return out


def import_rows(rows: list[dict]) -> int:
    with LOCK:
        data = _load()
        incoming = [normalize({**r, "source": "import", "updated_at": _now()}) for r in rows]
        ids = {r["id"] for r in incoming}
        data["systems"] = [s for s in data["systems"] if s["id"] not in ids] + incoming
        _save(data)
    return len(incoming)


# ------------------------------------------------------------------ exposure
def exposure() -> list[dict]:
    """For each of your systems: which vendors reach it, with what, and the worst finding."""
    import integrations as ig
    ov = ig.overview()
    vendors = {r["slug"]: r for r in records.list_vendors() if r.get("slug")}
    out = []
    primary = {}
    for s in systems():
        if s["vendor"] and s["vendor"] not in primary:
            t = tenant_of(s["vendor"])
            primary[s["vendor"]] = t["id"] if t else ""
    for s in systems():
        touching = []
        # An integration recorded against a vendor lands on your main tenant there, not on every system it hosts.
        via_vendor = s["vendor"] if s["vendor"] and primary.get(s["vendor"]) == s["id"] else ""
        for r in ov["live"]:
            ends = {r["source"], r["target"]}
            if s["id"] in ends or (via_vendor and via_vendor in ends):
                other = (ends - {s["id"], s["vendor"]}) or ends
                touching.append({"integration": r, "other": sorted(other)})
        grants = [sc for t in touching for sc in t["integration"]["scopes"]
                  if t["integration"]["target"] in (s["id"], s["vendor"])]
        strong = [sc for sc in grants if ig.scope_class(sc["name"], sc["grant"]) in ("admin", "write")]
        reach = sorted({o for t in touching for o in t["other"] if o not in (s["id"], s["vendor"])})
        worst = max((t["integration"]["worst"] for t in touching), key=lambda w: ig.SEVERITY_RANK.get(w, 0), default="")
        unapproved = [o for o in reach if o in vendors and vendors[o].get("authorization") != "authorized"]
        out.append({"system": s, "integrations": [t["integration"] for t in touching], "reach": reach,
                    "grants": grants, "strong": strong, "worst": worst, "unapproved": unapproved})
    return out
