"""Anticipated connections: what a vendor of this kind usually needs from *your* environment.

Rule-based, no model. The vendor's category (set at intake) is crossed with your environment
(identity provider, collaboration suite, clouds, data stores from Your environment) to predict:

  connections   the integrations a vendor like this normally asks for in your stack, with the
                permissions named the way your platform names them, a narrower option where one
                exists, the data that would move, and the question to confirm it
  their stack   the components a vendor like this normally runs on (hosting, email delivery,
                model provider...), marked declared or not declared from what the vendor told us

Every item is a prediction, labelled "anticipated", until someone confirms it. One click turns an
anticipated connection into a planned integration. Nothing here is a finding by itself.
"""
from __future__ import annotations

import environment
import integrations as ig

CATEGORIES = [
    ("", "Not set"), ("itsm", "IT service management"), ("hris", "HR and payroll"), ("crm", "CRM and sales"),
    ("collaboration", "Collaboration and chat"), ("file_sharing", "File sharing and e-signature"),
    ("ai_assistant", "AI assistant or copilot"), ("meeting_notes", "AI meeting notes and transcription"),
    ("finance", "Finance, billing and payments"), ("security_tool", "Security tool"), ("dev_tools", "Developer tools and CI/CD"),
    ("marketing", "Marketing and email"), ("analytics", "Data and analytics"), ("idp_iam", "Identity and access"),
    ("other", "Other"),
]
CATEGORY_LABEL = dict(CATEGORIES)
USES_ACCOUNTS = {"itsm", "hris", "crm", "collaboration", "file_sharing", "ai_assistant", "meeting_notes", "finance",
                 "security_tool", "dev_tools", "marketing", "analytics", "other"}

# Permission names as each platform spells them. (name, grant)
CATALOG = {
    ("meeting_notes", "microsoft"): {
        "scopes": [("Calendars.Read", "delegated"), ("OnlineMeetings.Read", "delegated"), ("OnlineMeetingTranscript.Read.All", "application")],
        "narrower": "Keep it delegated per user; if app-only meeting access is needed, limit it to named users with a Teams application access policy.",
        "data": ["meeting audio and transcripts", "calendar entries", "personal data (attendees)"]},
    ("meeting_notes", "google"): {
        "scopes": [("calendar.readonly", "delegated"), ("drive.file", "delegated")],
        "narrower": "Use drive.file (only files the app creates) rather than full drive access.",
        "data": ["meeting recordings and transcripts", "calendar entries", "personal data (attendees)"]},
    ("ai_assistant", "microsoft"): {
        "scopes": [("Files.Read.All", "delegated"), ("Mail.Read", "delegated"), ("Chat.Read", "delegated"), ("Sites.Read.All", "delegated")],
        "narrower": "Sites.Selected limits access to named SharePoint sites; avoid application-wide Files or Mail permissions.",
        "data": ["files", "email content", "chat messages"]},
    ("ai_assistant", "google"): {
        "scopes": [("drive.readonly", "delegated"), ("gmail.readonly", "delegated")],
        "narrower": "Use drive.file and restrict to shared drives the assistant needs.",
        "data": ["files", "email content"]},
    ("file_sharing", "microsoft"): {
        "scopes": [("Files.ReadWrite.All", "delegated"), ("Sites.ReadWrite.All", "application")],
        "narrower": "Sites.Selected with write granted only on the sites in scope.",
        "data": ["files", "personal data"]},
    ("file_sharing", "google"): {
        "scopes": [("drive", "delegated")], "narrower": "drive.file instead of full drive access.", "data": ["files"]},
    ("itsm", "microsoft"): {
        "scopes": [("User.Read.All", "application"), ("Group.Read.All", "application"), ("IMAP.AccessAsUser.All", "delegated"),
                   ("TeamsActivity.Send", "application")],
        "narrower": "Read-only directory access; a dedicated service-desk mailbox for email ingestion; no ReadWrite unless the "
                    "service desk must create users.",
        "data": ["identity (users, groups)", "email content", "ticket content"]},
    ("itsm", "google"): {
        "scopes": [("admin.directory.user.readonly", "application"), ("gmail.modify", "delegated")],
        "narrower": "Directory read-only; a dedicated mailbox.", "data": ["identity (users, groups)", "email content"]},
    ("crm", "microsoft"): {
        "scopes": [("Mail.ReadWrite", "delegated"), ("Mail.Send", "delegated"), ("Calendars.ReadWrite", "delegated")],
        "narrower": "Sync only sales users' mailboxes; Exchange application access policy if any app-only access is used.",
        "data": ["email content", "calendar entries", "customer data"]},
    ("crm", "google"): {
        "scopes": [("gmail.modify", "delegated"), ("calendar", "delegated")], "narrower": "Sales users only.",
        "data": ["email content", "calendar entries", "customer data"]},
    ("finance", "microsoft"): {
        "scopes": [("Mail.Send", "application")],
        "narrower": "An Exchange application access policy limits Mail.Send to the finance mailbox.",
        "data": ["invoices", "financial data", "personal data (approvers)"]},
    ("security_tool", "microsoft"): {
        "scopes": [("AuditLog.Read.All", "application"), ("Directory.Read.All", "application"), ("SecurityEvents.Read.All", "application")],
        "narrower": "Read-only; no ReadWrite or remediation permissions unless automated response is in scope.",
        "data": ["audit logs", "identity (users, groups)", "security alerts"]},
    ("security_tool", "okta"): {
        "scopes": [("okta.logs.read", "application"), ("okta.users.read", "application")], "narrower": "Read-only scopes.",
        "data": ["audit logs", "identity (users, groups)"]},
    ("security_tool", "google"): {
        "scopes": [("admin.reports.audit.readonly", "application")], "narrower": "Read-only.", "data": ["audit logs"]},
    ("marketing", "microsoft"): {
        "scopes": [("Mail.Send", "delegated")], "narrower": "Send from a dedicated marketing mailbox.", "data": ["customer data", "email content"]},
}
CLOUD_ROLES = {
    ("security_tool", "aws"): ([("SecurityAudit (AWS managed policy)", "role")], "Read-only; cross-account role with an external ID."),
    ("security_tool", "azure"): ([("Security Reader", "role"), ("Reader", "role")], "Read-only at management-group scope."),
    ("security_tool", "gcp"): ([("roles/iam.securityReviewer", "role"), ("roles/viewer", "role")], "Read-only at organization scope."),
    ("dev_tools", "aws"): ([("Deployment role (write)", "role")], "OIDC federation with short-lived credentials, scoped to named accounts."),
    ("dev_tools", "azure"): ([("Contributor", "role")], "Workload identity federation scoped to one resource group."),
    ("dev_tools", "gcp"): ([("roles/editor", "role")], "Workload identity federation, project-scoped custom role."),
    ("analytics", "aws"): ([("s3:GetObject on named buckets", "role")], "Read-only, named buckets or a curated export."),
    ("analytics", "azure"): ([("Storage Blob Data Reader", "role")], "Read-only on one storage account."),
    ("analytics", "gcp"): ([("roles/bigquery.dataViewer", "role")], "Dataset-scoped viewer."),
}
THEIR_STACK = {
    "*": [("Hosting provider and region", "hosting")],
    "ai_assistant": [("Model provider", "model_provider"), ("Sub-processors on the AI path", "subprocessors")],
    "meeting_notes": [("Model provider (transcription and summaries)", "model_provider"), ("Recording storage location", "hosting")],
    "finance": [("Payment processor", "subprocessors"), ("Email delivery service", "subprocessors")],
    "marketing": [("Email delivery service", "subprocessors")],
    "crm": [("Email and calendar sync service", "subprocessors")],
    "itsm": [("Email ingestion path", "subprocessors")],
}


def _platform(system: dict | None) -> str:
    if not system:
        return ""
    return environment.PLATFORM.get(system["product"], "")


def _find(kind: str, key_prefix: str = "") -> dict | None:
    for s in environment.systems():
        if s["kind"] == kind and (not key_prefix or s["id"].startswith(key_prefix)):
            return s
    return None


def _party(system: dict | None) -> str:
    """Use your system id; an integration against its hosting vendor lands on the same node."""
    return system["id"] if system else ig.YOU


def connections(rec: dict) -> list[dict]:
    cat = rec.get("category") or ""
    slug = rec.get("slug", "")
    vendor = rec.get("vendor") or slug
    cat_rules = cat
    idp = _find("identity_provider")
    collab = _find("saas_tenant", "sys-collab")
    clouds = [s for s in environment.systems() if s["kind"] == "cloud_account"]
    stores = [s for s in environment.systems() if s["kind"] == "data_store"]
    out = []

    if idp and cat_rules in USES_ACCOUNTS:
        out.append({"key": "sso", "title": "Single sign-on through %s" % idp["name"], "mechanism": "sso",
                    "source": idp["id"], "target": slug, "scopes": [], "narrower": "",
                    "data": ["identity (name, email, groups)"],
                    "why": "Your people sign in with %s; most SaaS vendors are connected for single sign-on." % idp["product"],
                    "question": "Does %s support SAML or OIDC single sign-on with %s, and can local passwords be turned off?" % (vendor, idp["product"])})
        out.append({"key": "scim", "title": "User provisioning from %s" % idp["name"], "mechanism": "scim",
                    "source": idp["id"], "target": slug, "scopes": [], "narrower": "Provision only the groups that use the service.",
                    "data": ["identity (name, email, department)", "group membership"],
                    "why": "Accounts should be created and removed from %s, not by hand." % idp["product"],
                    "question": "Does %s support SCIM provisioning from %s, and does deprovisioning remove access immediately?" % (vendor, idp["product"])})

    for host in [s for s in (collab, idp) if s]:
        plat = _platform(host)
        entry = CATALOG.get((cat_rules, plat))
        if entry and not any(o["key"] == "workspace" for o in out):
            names = ", ".join(n for n, _g in entry["scopes"])
            out.append({"key": "workspace", "title": "%s access to %s" % (CATEGORY_LABEL.get(cat_rules, cat_rules), host["name"]),
                        "mechanism": "oauth_delegated" if all(g == "delegated" for _n, g in entry["scopes"]) else "oauth_app",
                        "source": slug, "target": host["id"], "scopes": entry["scopes"], "narrower": entry["narrower"],
                        "data": entry["data"],
                        "why": "A %s vendor in a %s environment usually asks for these permissions." % (
                            CATEGORY_LABEL.get(cat_rules, cat_rules).lower(), host["product"]),
                        "question": "Which of these does %s need in our %s: %s? Granted to the app or per user, and can it use the "
                                    "narrower option (%s)?" % (vendor, host["product"], names, entry["narrower"])})
    for c in clouds:
        plat = _platform(c) or {"AWS": "aws", "Azure": "azure", "Google Cloud": "gcp"}.get(c["product"], "")
        role = CLOUD_ROLES.get((cat_rules, plat))
        if role:
            out.append({"key": "cloud-" + c["id"], "title": "Role in %s" % c["name"], "mechanism": "oauth_app",
                        "source": slug, "target": c["id"], "scopes": role[0], "narrower": role[1],
                        "data": ["cloud configuration and logs"] if cat_rules == "security_tool" else ["deployments"] if cat_rules == "dev_tools" else ["analytics data"],
                        "why": "A %s vendor usually needs a role in your %s." % (CATEGORY_LABEL[cat_rules].lower(), c["product"]),
                        "question": "Which role does %s need in %s, at what scope, and does it use short-lived federated credentials?" % (vendor, c["name"])})
    if cat_rules == "analytics":
        for st in stores[:3]:
            out.append({"key": "store-" + st["id"], "title": "Read access to %s" % st["name"], "mechanism": "api_key",
                        "source": slug, "target": st["id"], "scopes": [("read on named tables or exports", "role")],
                        "narrower": "A curated export or view instead of the source store.", "data": st["data_classes"] or ["analytics data"],
                        "why": "Analytics vendors usually read from your data stores.",
                        "question": "Does %s need direct access to %s, or can it work from a curated export?" % (vendor, st["name"])})
    if cat_rules == "hris" and idp:
        out.append({"key": "hr_driven", "title": "HR-driven provisioning into %s" % idp["name"], "mechanism": "connector",
                    "source": idp["id"], "target": slug, "scopes": [("integration system user (read workers)", "role")],
                    "narrower": "A dedicated integration user limited to the worker fields provisioning needs.",
                    "data": ["hr data (name, title, manager, hire and termination dates)"],
                    "why": "HR systems usually drive account creation and removal.",
                    "question": "Which worker fields does provisioning read from %s, and through which integration user?" % vendor})

    recorded = [r for r in ig.all_rows(include_retired=False) if slug in (r["source"], r["target"])]
    oauthish = {"oauth_app", "oauth_delegated", "connector", "email"}
    for o in out:
        ends = {_tenant_vendor(o["source"]), _tenant_vendor(o["target"])}
        o["recorded"] = any({_tenant_vendor(r["source"]), _tenant_vendor(r["target"])} == ends and
                            (r["mechanism"] == o["mechanism"] or {r["mechanism"], o["mechanism"]} <= oauthish)
                            for r in recorded)
    return out


def _tenant_vendor(party: str) -> str:
    s = environment.get(party) if party.startswith("sys-") else None
    return (s or {}).get("vendor") or party


def their_stack(rec: dict) -> list[dict]:
    import threat_model
    inp = threat_model.inputs(rec)
    cat = rec.get("category") or ""
    items = THEIR_STACK["*"] + THEIR_STACK.get(cat, [])
    if inp["ai_used"] == "yes" and cat not in ("ai_assistant", "meeting_notes"):
        items = items + [("Model provider", "model_provider")]
    out, seen = [], set()
    for label, field in items:
        if label in seen:
            continue
        seen.add(label)
        value = inp.get(field) or ""
        out.append({"component": label, "declared": bool(value), "value": value})
    return out


def to_integration(rec: dict, item: dict) -> dict:
    """A planned integration from an anticipated connection, for a person to confirm."""
    return {"name": "%s: %s" % (rec.get("vendor") or rec.get("slug"), item["title"]), "source": item["source"],
            "target": item["target"], "mechanism": item["mechanism"], "status": "planned",
            "purpose": "Anticipated: %s" % item["why"], "built_by": rec.get("vendor") or "",
            "scopes": [{"name": n, "grant": g} for n, g in item["scopes"]],
            "flows": [{"from": item["target"] if item["source"] == rec.get("slug") else item["source"],
                       "to": rec.get("slug") if item["source"] == rec.get("slug") else item["target"],
                       "data": item["data"], "trigger": "", "endpoint": ""}] if item["data"] else [],
            "auth": {"method": "none"}, "owner": "", "reviewed": ""}
