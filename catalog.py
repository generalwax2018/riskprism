"""Product catalog: what RiskPrism knows about a product's APIs, integrations and footprint, and what your
own confirmed work has taught it.

Three layers, merged per product:
  built-in   shipped profiles for common products: the APIs they expose, typical integration types,
             the domains they use and how they appear in an identity provider's app list
  learned    built from your confirmed integrations (active and reviewed): the mechanisms, permissions,
             authentication and data actually seen, with counts
  imported   learned profiles exported from another RiskPrism instance, with customer details removed

Anticipated connections and the shadow IT queue both read this. Nothing here is a finding on its own.
"""
from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone

import config
import records

PATH = config.DATA_DIR / "catalog.json"
LOCK = threading.RLock()

BUILTIN = {
    "microsoft_365": {"product": "Microsoft 365", "words": ["microsoft 365", "office 365", "microsoft"], "category": "collaboration",
                      "apis": ["Microsoft Graph", "Exchange Online (IMAP, POP, SMTP with OAuth)", "SharePoint REST"],
                      "integration_types": ["sso", "scim", "oauth_app", "oauth_delegated", "email"],
                      "domains": ["microsoft.com", "office.com", "office365.com", "microsoftonline.com", "sharepoint.com", "outlook.com"],
                      "app_names": ["Microsoft 365", "Office 365"]},
    "servicenow": {"product": "ServiceNow", "words": ["servicenow"], "category": "itsm",
                   "apis": ["REST Table API", "IntegrationHub spokes", "SCIM", "MID Server (on-premises agent)"],
                   "integration_types": ["sso", "scim", "connector", "oauth_app", "agent", "email"],
                   "domains": ["service-now.com", "servicenow.com"], "app_names": ["ServiceNow"]},
    "workday": {"product": "Workday", "words": ["workday"], "category": "hris",
                "apis": ["Workday Web Services (SOAP)", "Workday REST API", "Report-as-a-Service (RaaS)"],
                "integration_types": ["sso", "connector", "file"], "domains": ["workday.com", "myworkday.com"], "app_names": ["Workday"]},
    "slack": {"product": "Slack", "words": ["slack"], "category": "collaboration",
              "apis": ["Slack Web API", "Events API", "SCIM API"], "integration_types": ["sso", "scim", "oauth_app", "webhook_out"],
              "domains": ["slack.com", "slack-edge.com"], "app_names": ["Slack"]},
    "zoom": {"product": "Zoom", "words": ["zoom"], "category": "collaboration", "apis": ["Zoom API", "Zoom webhooks"],
             "integration_types": ["sso", "scim", "oauth_app", "webhook_out"], "domains": ["zoom.us"], "app_names": ["Zoom"]},
    "salesforce": {"product": "Salesforce", "words": ["salesforce"], "category": "crm",
                   "apis": ["REST API", "Bulk API", "Platform Events"], "integration_types": ["sso", "scim", "oauth_app", "oauth_delegated"],
                   "domains": ["salesforce.com", "force.com"], "app_names": ["Salesforce"]},
    "google_workspace": {"product": "Google Workspace", "words": ["google workspace", "g suite"], "category": "collaboration",
                         "apis": ["Admin SDK", "Gmail API", "Drive API", "Calendar API"],
                         "integration_types": ["sso", "oauth_app", "oauth_delegated"], "domains": ["googleapis.com", "google.com"],
                         "app_names": ["Google Workspace"]},
    "okta": {"product": "Okta", "words": ["okta"], "category": "idp_iam", "apis": ["Okta Management API", "System Log API"],
             "integration_types": ["sso", "scim", "api_key"], "domains": ["okta.com", "oktapreview.com"], "app_names": ["Okta"]},
    "atlassian": {"product": "Atlassian (Jira, Confluence)", "words": ["atlassian", "jira", "confluence"], "category": "dev_tools",
                  "apis": ["Jira REST API", "Confluence REST API", "Webhooks"], "integration_types": ["sso", "scim", "oauth_app", "webhook_out"],
                  "domains": ["atlassian.net", "atlassian.com"], "app_names": ["Jira", "Confluence", "Atlassian"]},
    "github": {"product": "GitHub", "words": ["github"], "category": "dev_tools", "apis": ["REST API", "GraphQL API", "Webhooks"],
               "integration_types": ["sso", "scim", "oauth_app", "webhook_out"], "domains": ["github.com", "githubusercontent.com"],
               "app_names": ["GitHub"]},
    "docusign": {"product": "DocuSign", "words": ["docusign"], "category": "file_sharing", "apis": ["eSignature REST API", "Connect webhooks"],
                 "integration_types": ["sso", "oauth_app", "webhook_out"], "domains": ["docusign.net", "docusign.com"], "app_names": ["DocuSign"]},
    "dropbox": {"product": "Dropbox", "words": ["dropbox"], "category": "file_sharing", "apis": ["Dropbox API"],
                "integration_types": ["sso", "oauth_delegated"], "domains": ["dropbox.com", "dropboxapi.com"], "app_names": ["Dropbox"]},
    "box": {"product": "Box", "words": ["box.com", "box inc"], "category": "file_sharing", "apis": ["Box API"],
            "integration_types": ["sso", "oauth_delegated"], "domains": ["box.com", "boxcloud.com"], "app_names": ["Box"]},
    "otter": {"product": "Otter.ai", "words": ["otter"], "category": "meeting_notes", "apis": ["Calendar connection (OAuth)"],
              "integration_types": ["oauth_delegated"], "domains": ["otter.ai"], "app_names": ["Otter.ai", "Otter"]},
    "openai": {"product": "ChatGPT (OpenAI)", "words": ["openai", "chatgpt"], "category": "ai_assistant",
               "apis": ["OpenAI API", "Connectors (OAuth)"], "integration_types": ["oauth_delegated", "api_key"],
               "domains": ["openai.com", "chatgpt.com"], "app_names": ["ChatGPT", "OpenAI"]},
    "grammarly": {"product": "Grammarly", "words": ["grammarly"], "category": "ai_assistant", "apis": ["Browser extension", "OAuth sign-in"],
                  "integration_types": ["oauth_delegated"], "domains": ["grammarly.com"], "app_names": ["Grammarly"]},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load() -> dict:
    if not PATH.exists():
        return {"imported": {}}
    try:
        return {"imported": json.loads(PATH.read_text(encoding="utf-8")).get("imported") or {}}
    except (OSError, ValueError):
        return {"imported": {}}


def key_for(name: str) -> str:
    n = (name or "").lower()
    for k, p in BUILTIN.items():
        if any(w in n for w in p["words"]):
            return k
    return "learned:" + re.sub(r"[^a-z0-9]+", "-", n).strip("-")


def match_app(display_name: str) -> str:
    """Catalog key for an app as it appears in an identity provider's list, or ''."""
    n = (display_name or "").lower()
    for k, p in BUILTIN.items():
        if any(a.lower() == n or n.startswith(a.lower() + " ") for a in p["app_names"]):
            return k
    for k, p in BUILTIN.items():
        if any(w in n for w in p["words"]):
            return k
    return ""


def match_domain(host: str) -> str:
    h = (host or "").lower().strip().strip(".")
    h = re.sub(r"^https?://", "", h).split("/")[0].split(":")[0]
    for k, p in BUILTIN.items():
        if any(h == d or h.endswith("." + d) for d in p["domains"]):
            return k
    return ""


def _generalize(host: str, key: str) -> str:
    """yourco.service-now.com -> *.service-now.com, so a tenant name never leaves in an export."""
    h = host.lower().split("/")[0]
    for d in BUILTIN.get(key, {}).get("domains", []):
        if h.endswith("." + d):
            return "*." + d
    return h if "yourco" not in h else re.sub(r"^[^.]+", "*", h)


# ------------------------------------------------------------------ learned from your confirmed work
def learned() -> dict:
    """Per product: what your confirmed integrations (active and reviewed) actually used."""
    import integrations as ig
    vendors = {r["slug"]: r for r in records.list_vendors() if r.get("slug")}
    out: dict[str, dict] = {}
    for r in ig.all_rows(include_retired=False):
        if r["status"] != "active" or not r["reviewed"]:
            continue
        for party in (r["source"], r["target"]):
            if party not in vendors:
                continue
            name = vendors[party].get("vendor") or party
            k = key_for(name)
            e = out.setdefault(k, {"product": BUILTIN.get(k, {}).get("product", name), "integrations": 0, "mechanisms": {},
                                   "scopes": {}, "auth": {}, "domains": {}, "data": {}})
            e["integrations"] += 1
            e["mechanisms"][r["mechanism"]] = e["mechanisms"].get(r["mechanism"], 0) + 1
            if r["auth"]["method"] != "none":
                e["auth"][r["auth"]["method"]] = e["auth"].get(r["auth"]["method"], 0) + 1
            if party == r["source"]:  # what this product asked for in the other system
                for sc in r["scopes"]:
                    key = "%s|%s" % (sc["name"], sc["grant"])
                    e["scopes"][key] = e["scopes"].get(key, 0) + 1
            for host in r["network"]["egress"] + [f["endpoint"] for f in r["flows"] if f["endpoint"]]:
                g = _generalize(host, k)
                if g:
                    e["domains"][g] = e["domains"].get(g, 0) + 1
            for f in r["flows"]:
                for d in f["data"]:
                    e["data"][d] = e["data"].get(d, 0) + 1
    return out


def export_json() -> str:
    """Learned profiles without customer details: no owners, identities, tenant names, purposes or dates."""
    return json.dumps({"riskprism_catalog": 1, "exported_at": _now(), "products": learned()}, indent=2, sort_keys=True)


def import_json(text: str, by: str) -> int:
    try:
        data = json.loads(text)
    except ValueError:
        raise ValueError("That is not a RiskPrism catalog export.")
    products = data.get("products") if isinstance(data, dict) and data.get("riskprism_catalog") == 1 else None
    if not isinstance(products, dict):
        raise ValueError("That is not a RiskPrism catalog export.")
    clean = {}
    for k, e in list(products.items())[:500]:
        if not isinstance(e, dict):
            continue
        clean[str(k)[:80]] = {"product": str(e.get("product") or k)[:120], "integrations": int(e.get("integrations") or 0),
                              **{f: {str(a)[:160]: int(b) for a, b in (e.get(f) or {}).items() if isinstance(b, int)}
                                 for f in ("mechanisms", "scopes", "auth", "domains", "data")}}
    with LOCK:
        cur = _load()
        for k, e in clean.items():
            prev = cur["imported"].get(k)
            if prev:
                for f in ("mechanisms", "scopes", "auth", "domains", "data"):
                    for a, b in e[f].items():
                        prev[f][a] = prev[f].get(a, 0) + b
                prev["integrations"] += e["integrations"]
            else:
                cur["imported"][k] = e
        PATH.parent.mkdir(parents=True, exist_ok=True)
        records.atomic_write(PATH, json.dumps({"imported": cur["imported"], "updated_by": by, "updated_at": _now()}, indent=2))
    return len(clean)


def profile_for(name: str) -> dict:
    """Everything known about one product, layer by layer."""
    k = key_for(name)
    return {"key": k, "builtin": BUILTIN.get(k), "learned": learned().get(k), "imported": _load()["imported"].get(k)}
