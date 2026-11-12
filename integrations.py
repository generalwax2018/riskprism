"""Integration data layer: how your SaaS tenants, your vendors and your own systems connect.

One record per integration (a connection between two parties). A party is a tracked vendor
(its slug, meaning *your* tenant or instance at that vendor) or "you" (your own network,
people and on-premises systems).

Each integration records:
  mechanism   how it connects (SSO, SCIM, app-only OAuth, delegated OAuth, API key, webhook,
              vendor connector, on-prem agent, email, file transfer)
  auth        the identity it acts as, its roles, the credential, where it is stored, rotation
  scopes      what it was granted, and whether as the app itself (application) or for a user
              (delegated), or as a role in the target
  flows       each movement of data: from, to, what data, when, over which endpoint
  network     outbound domains, inbound endpoints, IP allow-listing, how inbound calls are verified

Everything here is rule-based: scope classes and findings come from fixed rules, with no
model calls. Stored centrally in data/integrations.json (atomic writes), because one
integration touches two vendors and the dashboard needs the whole graph.
"""
from __future__ import annotations

import json
import re
import secrets
import threading
from datetime import date, datetime, timezone

import config
import memo
import records

PATH = config.DATA_DIR / "integrations.json"
LOCK = threading.RLock()
YOU = "you"
YOU_LABEL = "Your organisation"

MECHANISMS = {
    "sso": "Single sign-on (SAML / OIDC)",
    "scim": "User provisioning (SCIM)",
    "oauth_app": "App-only OAuth (application permissions)",
    "oauth_delegated": "Delegated OAuth (acts as a user)",
    "connector": "Vendor-built connector or spoke",
    "api_key": "API key or token",
    "webhook_out": "Outbound webhook (events pushed out)",
    "webhook_in": "Inbound webhook (events received)",
    "agent": "On-premises agent",
    "email": "Email ingestion or relay",
    "file": "File transfer (SFTP, export)",
}
AUTH_METHODS = {
    "saml": "SAML assertion", "oidc": "OpenID Connect", "oauth_client_credentials": "OAuth client credentials",
    "oauth_auth_code": "OAuth authorization code (user consent)", "basic": "Username and password",
    "api_key": "API key", "certificate": "Certificate", "mtls": "Mutual TLS", "none": "None",
}
STATIC_SECRETS = {"basic", "api_key"}
STATUSES = ("active", "planned", "retired")
SENSITIVE_WORDS = ("credential", "password", "secret", "email content", "chat", "hr data", "personal", "phi", "health",
                   "pci", "card", "financial", "source code", "customer data", "ticket content", "attachment")
ADMIN_ROLES = {"admin", "security_admin", "global administrator", "privileged role administrator"}
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


class IntegrationError(ValueError):
    """Something a person must fix. The text is shown as is."""


# ------------------------------------------------------------------ store
def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def all_rows(include_retired: bool = True) -> list[dict]:
    if not PATH.exists():
        return []
    try:
        data = json.loads(PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    rows = [normalize(r) for r in data.get("integrations") or [] if isinstance(r, dict)]
    return [r for r in rows if include_retired or r["status"] != "retired"]


def _save(rows: list[dict]) -> None:
    PATH.parent.mkdir(parents=True, exist_ok=True)
    records.atomic_write(PATH, json.dumps({"integrations": rows}, indent=2, sort_keys=True))


def get(iid: str) -> dict | None:
    return next((r for r in all_rows() if r["id"] == iid), None)


def add(raw: dict, by: str) -> dict:
    row = normalize(raw)
    problem = validate(row)
    if problem:
        raise IntegrationError(problem)
    with LOCK:
        rows = all_rows()
        row["id"] = "int-" + secrets.token_hex(4)
        row["created_by"], row["created_at"] = by, _now()
        rows.append(row)
        _save(rows)
    return row


def replace_all(rows: list[dict]) -> None:
    """Used by the sample data loader."""
    with LOCK:
        _save([normalize(r) for r in rows])


def set_status(iid: str, status: str, by: str) -> dict:
    if status not in STATUSES:
        raise IntegrationError("Unknown status.")
    with LOCK:
        rows = all_rows()
        row = next((r for r in rows if r["id"] == iid), None)
        if not row:
            raise IntegrationError("That integration does not exist.")
        row["status"] = status
        row["updated_by"], row["updated_at"] = by, _now()
        _save(rows)
    return row


def for_party(slug: str, include_retired: bool = False) -> list[dict]:
    return [r for r in all_rows(include_retired) if slug in (r["source"], r["target"])]


# ------------------------------------------------------------------ normalize and validate
def _s(v, n=200) -> str:
    return str(v or "").strip()[:n]


def _list(v) -> list[str]:
    if isinstance(v, list):
        return [_s(x) for x in v if _s(x)]
    return [p.strip() for p in re.split(r"[\n;,]+", str(v or "")) if p.strip()]


def normalize(raw: dict) -> dict:
    auth = raw.get("auth") or {}
    net = raw.get("network") or {}
    scopes = []
    for sc in raw.get("scopes") or []:
        if isinstance(sc, str):
            sc = {"name": sc}
        name = _s(sc.get("name"), 120)
        if name:
            grant = sc.get("grant") if sc.get("grant") in ("application", "delegated", "role") else "delegated"
            scopes.append({"name": name, "grant": grant, "consent": _s(sc.get("consent"), 20)})
    flows = []
    for f in raw.get("flows") or []:
        if f.get("from") and f.get("to"):
            flows.append({"from": _s(f["from"], 80), "to": _s(f["to"], 80), "data": _list(f.get("data")),
                          "trigger": _s(f.get("trigger"), 80), "endpoint": _s(f.get("endpoint"), 200)})
    return {
        "id": _s(raw.get("id"), 40),
        "name": _s(raw.get("name")),
        "source": _s(raw.get("source"), 80),
        "target": _s(raw.get("target"), 80),
        "mechanism": raw.get("mechanism") if raw.get("mechanism") in MECHANISMS else "connector",
        "built_by": _s(raw.get("built_by"), 80),
        "purpose": _s(raw.get("purpose"), 400),
        "app_id": _s(raw.get("app_id"), 120),
        "auth": {
            "method": auth.get("method") if auth.get("method") in AUTH_METHODS else "none",
            "identity": _s(auth.get("identity")),
            "roles": _list(auth.get("roles")),
            "credential": _s(auth.get("credential"), 80),
            "stored_in": _s(auth.get("stored_in")),
            "rotated": _s(auth.get("rotated"), 10),
            "rotation_days": int(auth.get("rotation_days") or 0),
        },
        "scopes": scopes,
        "flows": flows,
        "network": {
            "egress": _list(net.get("egress")),
            "ingress": _list(net.get("ingress")),
            "ip_allowlist": net.get("ip_allowlist") if net.get("ip_allowlist") in ("yes", "no") else "unknown",
            "inbound_auth": _s(net.get("inbound_auth"), 60) or "unknown",
        },
        "owner": _s(raw.get("owner"), 120),
        "status": raw.get("status") if raw.get("status") in STATUSES else "active",
        "reviewed": _s(raw.get("reviewed"), 10),
        "created_by": _s(raw.get("created_by"), 200), "created_at": _s(raw.get("created_at"), 40),
        "updated_by": _s(raw.get("updated_by"), 200), "updated_at": _s(raw.get("updated_at"), 40),
    }


def _date_ok(v: str) -> bool:
    try:
        date.fromisoformat(v)
        return True
    except ValueError:
        return False


def validate(row: dict) -> str:
    parties = set(party_names())
    if not row["name"]:
        return "Give the integration a name."
    if row["source"] not in parties or row["target"] not in parties:
        return "Pick both ends of the integration from your tracked vendors or Your organisation."
    if row["source"] == row["target"]:
        return "The two ends must be different."
    for f in row["flows"]:
        if f["from"] not in (row["source"], row["target"]) or f["to"] not in (row["source"], row["target"]):
            return "Each data flow must run between the two ends of the integration."
    for d in (row["auth"]["rotated"], row["reviewed"]):
        if d and not _date_ok(d):
            return "Dates must be YYYY-MM-DD."
    return ""


# ------------------------------------------------------------------ parties
def party_names() -> dict:
    """id -> display name: Your organisation, your own systems (sys-...), and every tracked vendor."""
    return dict(memo.cached("ig.party_names", _party_names))


def _party_names() -> dict:
    import environment
    names = {YOU: environment.org_name()}
    names.update(environment.party_names())
    for rec in records.list_vendors():
        if rec.get("slug"):
            names[rec["slug"]] = rec.get("vendor") or rec["slug"]
    return names


def _vendors() -> dict:
    return {r["slug"]: r for r in records.list_vendors() if r.get("slug")}


# ------------------------------------------------------------------ rules
def scope_class(name: str, grant: str) -> str:
    """admin | write | read | identity | session | other. Fixed rules on the permission name."""
    n = name.lower()
    if grant == "role":
        if n in ADMIN_ROLES:
            return "admin"
        if n.endswith("_admin") or n.endswith("admin") or n in ("itil",) or n.endswith("_manager"):
            return "write"
        return "read"
    if any(k in n for k in ("directory.readwrite", "rolemanagement.readwrite", "approleassignment.readwrite",
                            "application.readwrite", "policy.readwrite", "full_access", "privilegedaccess")):
        return "admin"
    if n in ("openid", "profile", "email"):
        return "identity"
    if n == "offline_access":
        return "session"
    parts = n.split(".")
    if ("readwrite" in n or "write" in parts or "send" in parts or "accessasuser" in n or "accessasapp" in n
            or any(p in ("create", "delete", "manage", "manageall") for p in parts)):
        return "write"
    if "read" in parts or "read" in n:
        return "read"
    return "other"


def tenant_wide(name: str, grant: str) -> bool:
    """App-only permissions reach every user unless limited to what the app owns (*.OwnedBy)."""
    if name.endswith(".OwnedBy"):
        return False
    return grant == "application" or name.endswith(".All")


def sensitive(data: str) -> bool:
    """Built-in sensitive words plus the customer's own classification labels (set in Your environment)."""
    import environment
    d = data.lower()
    return any(w in d for w in SENSITIVE_WORDS + tuple(environment.sensitive_terms()))


def _age_days(iso: str) -> int | None:
    try:
        return (date.today() - date.fromisoformat(iso)).days
    except ValueError:
        return None


def observed_index(vendors: dict) -> dict[str, set[str]]:
    """app ID -> scopes seen for it in active imported live access, across every vendor record.
    Built once per pass, so checking N integrations costs one walk over the vendors, not N."""
    import access_store
    index: dict[str, set[str]] = {}
    for rec in vendors.values():
        for row in access_store.rows(rec):
            if row.get("app_id") and row.get("status") == "active":
                index.setdefault(row["app_id"], set()).update(row.get("scopes") or [])
    return index


def _observed_scopes(app_id: str, vendors: dict, index: dict | None = None) -> set[str] | None:
    """Scopes seen in imported live access for this app, from any vendor record. None if never seen."""
    if not app_id:
        return None
    index = index if index is not None else observed_index(vendors)
    seen = index.get(app_id)
    return set(seen) if seen is not None else None


def findings(row: dict, vendors: dict | None = None, names: dict | None = None,
             observed: dict | None = None) -> list[tuple[str, str, str]]:
    """(code, text, severity) for one integration, worst first. Pass `observed` (observed_index) when
    checking many integrations in one pass."""
    vendors = vendors if vendors is not None else _vendors()
    names = names or party_names()
    if observed is None and row["app_id"]:
        observed = observed_index(vendors)
    out: list[tuple[str, str, str]] = []
    if row["status"] == "retired":
        seen = _observed_scopes(row["app_id"], vendors, observed)
        if seen is not None:
            out.append(("retired_still_live", "Marked retired, but the app still shows in live access.", "high"))
        return out

    for sc in row["scopes"]:
        cls = scope_class(sc["name"], sc["grant"])
        if cls == "admin":
            out.append(("admin_scope", "%s lets it administer the tenant (%s)." % (sc["name"], sc["grant"]), "high"))
        elif cls == "write" and sc["grant"] == "application" and tenant_wide(sc["name"], sc["grant"]):
            if "readwrite" in sc["name"].lower():
                out.append(("app_write_all", "%s can change data across the whole tenant, with no user involved."
                            % sc["name"], "high"))
            else:
                out.append(("app_send_all", "%s can act toward every user in the tenant (app-only)." % sc["name"], "medium"))
        elif cls == "write" and sc["grant"] == "role":
            out.append(("elevated_role", "The integration identity holds the %s role." % sc["name"], "medium"))
        elif cls == "session" and sc["grant"] == "delegated":
            out.append(("refresh_tokens", "offline_access: refresh tokens keep working after the user signs out.", "low"))
    for role in row["auth"]["roles"]:
        if role.lower() in ADMIN_ROLES:
            out.append(("admin_identity", "It signs in as an identity with the %s role." % role, "high"))
        elif scope_class(role, "role") == "write":
            out.append(("elevated_role", "The integration identity holds the %s role." % role, "medium"))

    method = row["auth"]["method"]
    if method in STATIC_SECRETS or row["auth"]["credential"].lower() in ("password", "api key", "client secret"):
        age = _age_days(row["auth"]["rotated"]) if row["auth"]["rotated"] else None
        if age is None:
            out.append(("rotation_unknown", "The %s has no recorded rotation date." % (row["auth"]["credential"] or "secret"), "medium"))
        else:
            import environment
            policy = row["auth"]["rotation_days"] or environment.rotation_days()
            if age > policy:
                out.append(("stale_secret", "The %s was last rotated %d days ago (policy %d)." % (
                    row["auth"]["credential"] or "secret", age, policy), "medium"))
    if method in STATIC_SECRETS:
        out.append(("static_secret", "Uses a static %s. Prefer a certificate or OAuth." % AUTH_METHODS[method].lower(), "low"))

    if row["network"]["ingress"] or row["mechanism"] == "webhook_in":
        if row["network"]["inbound_auth"].lower() in ("none", "unknown", ""):
            out.append(("inbound_unverified", "Inbound calls are not verified (no signature or token on record).", "medium"))
        if row["network"]["ip_allowlist"] != "yes":
            out.append(("no_allowlist", "Inbound endpoint is not limited to known IP ranges.", "low"))

    for f in row["flows"]:
        dest = vendors.get(f["to"])
        risky = [d for d in f["data"] if sensitive(d)]
        if dest and risky:
            if dest.get("stage") == "offboarded":
                out.append(("data_to_offboarded", "%s goes to %s, which is offboarded." % (", ".join(risky), names.get(f["to"], f["to"])), "high"))
            elif dest.get("authorization") != "authorized":
                out.append(("data_to_unapproved", "%s goes to %s, which is not authorized." % (
                    ", ".join(risky), names.get(f["to"], f["to"])), "high"))

    declared = {s["name"] for s in row["scopes"]}
    seen = _observed_scopes(row["app_id"], vendors, observed)
    if seen:
        extra = sorted(seen - declared)
        if extra:
            out.append(("scope_drift", "Live access shows scopes nobody declared: %s." % ", ".join(extra), "high"))

    if not row["owner"]:
        out.append(("no_owner", "No named owner.", "medium"))
    age = _age_days(row["reviewed"]) if row["reviewed"] else None
    if age is None or age > 365:
        out.append(("not_reviewed", "Not reviewed in the last 12 months.", "low"))

    seen_codes, uniq = set(), []
    for f in sorted(out, key=lambda x: -SEVERITY_RANK[x[2]]):
        key = (f[0], f[1])
        if key not in seen_codes:
            seen_codes.add(key)
            uniq.append(f)
    return uniq


def worst(fs: list[tuple]) -> str:
    return max((f[2] for f in fs), key=lambda s: SEVERITY_RANK[s], default="")


# ------------------------------------------------------------------ roll-ups
def overview(slug: str | None = None) -> dict:
    """Everything the dashboard (or one vendor's tab) needs, computed in one pass.
    Reused within a request (memo.py), so callers must not modify what it returns."""
    return memo.cached(("ig.overview", slug), lambda: _overview(slug))


def _overview(slug: str | None) -> dict:
    vendors = _vendors()
    names = party_names()
    observed = observed_index(vendors)
    rows = all_rows(include_retired=True)
    if slug:
        rows = [r for r in rows if slug in (r["source"], r["target"])]
    enriched = []
    for r in rows:
        fs = findings(r, vendors, names, observed)
        enriched.append({**r, "findings": fs, "worst": worst(fs),
                         "source_name": names.get(r["source"], r["source"]), "target_name": names.get(r["target"], r["target"])})
    live = [r for r in enriched if r["status"] != "retired"]

    scope_rows: dict[tuple, dict] = {}
    for r in live:
        for sc in r["scopes"]:
            key = (r["target"], sc["name"], sc["grant"])
            s = scope_rows.setdefault(key, {"platform": names.get(r["target"], r["target"]), "name": sc["name"],
                                            "grant": sc["grant"], "class": scope_class(sc["name"], sc["grant"]),
                                            "tenant_wide": tenant_wide(sc["name"], sc["grant"]), "used_by": []})
            s["used_by"].append(r["name"])
        for role in r["auth"]["roles"]:
            key = (r["target"], role, "role")
            s = scope_rows.setdefault(key, {"platform": names.get(r["target"], r["target"]), "name": role, "grant": "role",
                                            "class": scope_class(role, "role"), "tenant_wide": False, "used_by": []})
            if r["name"] not in s["used_by"]:
                s["used_by"].append(r["name"])
    class_rank = {"admin": 0, "write": 1, "session": 2, "read": 3, "identity": 4, "other": 5}
    scopes = sorted(scope_rows.values(), key=lambda s: (class_rank[s["class"]], s["platform"], s["name"]))

    flows = []
    for r in live:
        for f in r["flows"]:
            flows.append({**f, "integration": r["name"], "from_name": names.get(f["from"], f["from"]),
                          "to_name": names.get(f["to"], f["to"]), "sensitive": [d for d in f["data"] if sensitive(d)]})

    def count(code_set):
        return sum(1 for r in live if any(f[0] in code_set for f in r["findings"]))

    metrics = {
        "integrations": len(live),
        "parties": len({p for r in live for p in (r["source"], r["target"])}),
        "admin": sum(1 for s in scopes if s["class"] == "admin"),
        "app_write": sum(1 for s in scopes if s["class"] in ("admin", "write") and s["grant"] == "application"),
        "secrets": count({"stale_secret", "rotation_unknown"}),
        "no_owner": count({"no_owner"}),
        "sensitive_flows": sum(1 for f in flows if f["sensitive"]),
        "high": sum(1 for r in live if r["worst"] == "high"),
        "drift": count({"scope_drift", "retired_still_live"}),
    }
    return {"rows": enriched, "live": live, "scopes": scopes, "flows": flows, "metrics": metrics,
            "names": names, "paths": onward_paths(flows, names)}


def onward_paths(flows: list[dict], names: dict, max_hops: int = 3) -> list[dict]:
    """Where sensitive data can travel next. For each flow that carries sensitive data, follow
    any further flow out of the destination, up to max_hops. This over-approximates on purpose:
    it shows what is reachable, not what is proven to move."""
    out_edges: dict[str, list[dict]] = {}
    for f in flows:
        out_edges.setdefault(f["from"], []).append(f)
    paths = []
    for f in flows:
        if not f["sensitive"]:
            continue
        chain = [f["from"], f["to"]]
        frontier = [(f["to"], chain)]
        longest = chain
        while frontier:
            node, ch = frontier.pop()
            if len(ch) - 1 >= max_hops:
                continue
            for nxt in out_edges.get(node, []):
                if nxt["to"] in ch:
                    continue
                new = ch + [nxt["to"]]
                if len(new) > len(longest):
                    longest = new
                frontier.append((nxt["to"], new))
        if len(longest) > 2:
            paths.append({"data": ", ".join(f["sensitive"]), "via": f["integration"],
                          "path": [names.get(p, p) for p in longest]})
    seen, uniq = set(), []
    for p in sorted(paths, key=lambda p: -len(p["path"])):
        key = (p["data"], tuple(p["path"]))
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq


# ------------------------------------------------------------------ coverage and questions
OWNER_QUESTIONS = [
    ("owner", "Who owns this integration and answers for it?"),
    ("flows", "What data moves, in which direction, how often, and through which endpoint?"),
    ("identity", "Which identity does it act as: an app registration, a service account, or each signed-in user?"),
    ("scopes", "Which permissions, scopes or roles were granted? Export them from the admin console."),
    ("rotation", "When was the credential last rotated, and where is it stored?"),
    ("inbound", "How are calls to the inbound endpoint verified (signature, token, mutual TLS), and from which IP ranges?"),
    ("reviewed", "When was this integration last reviewed?"),
]
OAUTHISH = {"oauth_app", "oauth_delegated", "connector", "api_key", "scim"}


def drift(slug: str) -> dict:
    """Declared versus observed, for one vendor: each recorded integration's declared scopes against what
    imported live access shows for the same app ID, plus live apps on the vendor that no integration records."""
    import access_store
    vendors = _vendors()
    rec = vendors.get(slug) or {}
    rows = [r for r in all_rows(include_retired=True) if slug in (r["source"], r["target"])]
    observed = observed_index(vendors)
    pairs = []
    for r in rows:
        if not r["app_id"]:
            continue
        seen = _observed_scopes(r["app_id"], vendors, observed)
        declared = {s["name"] for s in r["scopes"]}
        if seen is None and r["status"] == "retired":
            continue
        pairs.append({"id": r["id"], "name": r["name"], "status": r["status"], "app_id": r["app_id"],
                      "observed_known": seen is not None,
                      "both": sorted(declared & (seen or set())),
                      "declared_only": sorted(declared - (seen or set())) if seen is not None else sorted(declared),
                      "observed_only": sorted((seen or set()) - declared)})
    recorded = {r["app_id"] for r in rows if r["app_id"]}
    unrecorded = [{"name": a["display_name"], "app_id": a.get("app_id", ""), "scopes": a.get("scopes") or [],
                   "source": a.get("source", ""), "last_seen": (a.get("last_seen") or "")[:10]}
                  for a in access_store.rows(rec) if a.get("status") == "active" and a.get("app_id") not in recorded]
    no_app_id = [r["name"] for r in rows if not r["app_id"] and r["status"] != "retired"]
    return {"pairs": pairs, "unrecorded": unrecorded, "no_app_id": no_app_id,
            "drifting": sum(1 for p in pairs if p["observed_only"]) + len(unrecorded)}


def owner_questions(row: dict) -> list[str]:
    """What the internal owner still needs to answer for this integration. Empty when complete."""
    missing = set()
    if not row["owner"]:
        missing.add("owner")
    if not row["flows"]:
        missing.add("flows")
    if not row["auth"]["identity"]:
        missing.add("identity")
    if row["mechanism"] in OAUTHISH and not row["scopes"] and not row["auth"]["roles"]:
        missing.add("scopes")
    if (row["auth"]["method"] in STATIC_SECRETS or row["auth"]["credential"].lower() in ("password", "api key", "client secret")) \
            and (not row["auth"]["rotated"] or not row["auth"]["stored_in"]):
        missing.add("rotation")
    if (row["network"]["ingress"] or row["mechanism"] == "webhook_in") and row["network"]["inbound_auth"].lower() in ("", "unknown"):
        missing.add("inbound")
    if not row["reviewed"]:
        missing.add("reviewed")
    return [q for key, q in OWNER_QUESTIONS if key in missing]


def vendor_says(rec: dict) -> dict:
    """What the vendor and the intake said about connections, from any questionnaire."""
    a = {}
    for k in ("answers", "renewal_answers", "followup_answers"):
        a.update(rec.get(k) or {})
    keys = ("int_connect", "int_list", "int_permissions", "int_admin", "int_narrower", "int_credentials", "int_data",
            "int_inbound", "int_egress", "int_onward", "int_change", "integrations")
    out = {k: str(a[k]).strip() for k in keys if str(a.get(k) or "").strip()}
    if rec.get("connects") in ("yes", "no"):
        out["intake_connects"] = rec["connects"]
    if rec.get("connects_to"):
        out["intake_connects_to"] = rec["connects_to"]
    return out


_NONE = re.compile(r"^\s*(none|no|n/a|not applicable|nothing|no connections?)\b", re.I)


def connects(rec: dict) -> str:
    """yes | no | unknown: does this vendor connect to your systems, by any source we hold."""
    import access_store
    said = vendor_says(rec)
    if any(r.get("status") == "active" for r in access_store.rows(rec)):
        return "yes"
    if said.get("int_connect") == "yes" or said.get("intake_connects") == "yes":
        return "yes"
    listing = said.get("int_list") or said.get("integrations") or ""
    if listing and not _NONE.match(listing):
        return "yes"
    if said.get("int_connect") == "no" or said.get("intake_connects") == "no" or (listing and _NONE.match(listing)):
        return "no"
    return "unknown"


def coverage() -> list[dict]:
    """Tracked vendors whose integrations are not recorded yet, or not asked about yet."""
    rows = all_rows(include_retired=False)
    out = []
    for rec in records.list_vendors():
        slug = rec.get("slug")
        if not slug or rec.get("stage") == "offboarded":
            continue
        has = any(slug in (r["source"], r["target"]) for r in rows)
        c = connects(rec)
        if c == "yes" and not has:
            out.append({"slug": slug, "name": rec.get("vendor") or slug, "state": "unrecorded",
                        "text": "Connects to your systems, but no integration is recorded."})
        elif c == "unknown" and not has:
            out.append({"slug": slug, "name": rec.get("vendor") or slug, "state": "unasked",
                        "text": "Not yet asked whether it connects to your systems."})
    return out


_SCOPE = re.compile(r"\b[A-Z][A-Za-z]+(?:\.[A-Za-z]+){1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,12}\b")
_MECH_WORDS = [("scim", "scim"), ("webhook", "webhook_in"), ("api key", "api_key"), ("agent", "agent"), ("sftp", "file"),
               ("oauth", "oauth_app"), ("saml", "sso"), ("single sign-on", "sso"), ("email", "email")]


def _auth_from(text: str) -> dict:
    t = text.lower()
    for word, method, cred in (("certificate", "certificate", "certificate"), ("client secret", "oauth_client_credentials", "client secret"),
                               ("api key", "api_key", "API key"), ("password", "basic", "password"), ("token", "oauth_auth_code", "user token")):
        if word in t:
            return {"method": method, "credential": cred, "identity": "", "stored_in": ""}
    return {"method": "none", "credential": "", "identity": ""}


def draft_from_answers(rec: dict) -> dict:
    """A planned integration built from the vendor's answers, for a person to confirm and complete.
    Scope names and domains are copied as written; nothing is inferred beyond the words used."""
    said = vendor_says(rec)
    text = " ".join(said.values())
    names = party_names()
    slug = rec.get("slug", "")
    target = YOU
    for s_, n in names.items():
        if s_ not in (YOU, slug) and n.lower() in text.lower():
            target = s_
            break
    mech = next((m for w, m in _MECH_WORDS if w in text.lower()), "connector")
    perms = said.get("int_permissions") or said.get("integrations") or ""
    scopes = []
    for name in dict.fromkeys(_SCOPE.findall(perms)):
        line = next((l for l in perms.splitlines() if name in l), perms).lower()
        grant = "delegated" if ("delegated" in line or "on behalf" in line or "user" in line and "app" not in line) else "application"
        scopes.append({"name": name, "grant": grant})
    domains = list(dict.fromkeys(_DOMAIN.findall(" ".join([said.get("int_egress", ""), said.get("int_data", "")]))))[:8]
    data = [d.strip() for d in re.split(r"[;,\n]+", said.get("int_data", "")) if d.strip()][:6]
    flows = [{"from": target, "to": slug, "data": data or ["not stated"], "trigger": "", "endpoint": ""}] if data else []
    return {"name": "%s connection (from questionnaire)" % (rec.get("vendor") or slug), "source": slug, "target": target,
            "mechanism": mech, "status": "planned", "built_by": rec.get("vendor") or "",
            "purpose": (said.get("int_list") or said.get("integrations") or "")[:400],
            "auth": _auth_from(said.get("int_credentials", "")), "scopes": scopes, "flows": flows,
            "network": {"egress": domains}, "owner": "", "reviewed": ""}
