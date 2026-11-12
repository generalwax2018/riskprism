"""Sample integration data for demos: Microsoft 365, ServiceNow, Workday and a fictional AI note-taker.

The configurations are typical of how these products are commonly connected, written as an
example of one company's setup. They are not statements about any vendor's security.
Instance names use "yourco" placeholders. Loaded only by the sample-data button or a test.
"""
from __future__ import annotations

import access_store
import integrations
from records import load_vendor, save_vendor

M365, SNOW, WD, FN = "Microsoft_365", "ServiceNow", "Workday", "Fieldnote_AI"
YOU = integrations.YOU

VENDORS = [
    {"vendor": "Microsoft 365", "slug": M365, "business": "Email, files, Teams and identity (Entra ID)",
     "authorization": "authorized", "stage": "active", "mode": "saas", "website": "https://www.microsoft.com"},
    {"vendor": "ServiceNow", "slug": SNOW, "business": "IT service management, CMDB and HR service delivery",
     "authorization": "authorized", "stage": "active", "mode": "saas", "website": "https://www.servicenow.com"},
    {"vendor": "Workday", "slug": WD, "business": "HR system of record",
     "authorization": "authorized", "stage": "active", "mode": "saas", "website": "https://www.workday.com"},
    {"vendor": "Fieldnote AI", "slug": FN, "business": "AI meeting notes (fictional; found through an OAuth grant)",
     "authorization": "not_authorized", "stage": "inquiry", "mode": "saas"},
    {"vendor": "Ledgerline Billing", "slug": "Ledgerline_Billing", "business": "Invoicing (fictional; answered the questionnaire)",
     "authorization": "authorized", "stage": "onboarding", "mode": "saas", "connects": "yes", "connects_to": "Microsoft 365",
     "answers": {
         "int_connect": "yes",
         "int_list": "Microsoft 365: OAuth app that emails invoices from your finance mailbox and reads the staff directory for approvers.",
         "int_permissions": "Mail.Send (application) to send invoices\nUser.Read.All (application) to look up approvers",
         "int_admin": "no",
         "int_credentials": "Client secret stored in our vault; can be rotated by you at any time.",
         "int_data": "invoice PDFs, approver names and emails",
         "int_inbound": "None",
         "int_egress": "api.ledgerline.example, mail relay at graph.microsoft.com",
         "int_onward": "None"}},
]

SNOW_HOST = "yourco.service-now.com"


def _int(name, source, target, mechanism, **kw):
    return {"name": name, "source": source, "target": target, "mechanism": mechanism, "status": "active", **kw}


INTEGRATIONS = [
    _int("Entra ID single sign-on to ServiceNow", M365, SNOW, "sso", built_by="Microsoft and ServiceNow (standard)",
         purpose="Staff sign in to ServiceNow with their Microsoft account.",
         auth={"method": "saml", "identity": "Enterprise app: ServiceNow", "credential": "signing certificate",
               "rotated": "2025-11-02", "rotation_days": 730},
         flows=[{"from": M365, "to": SNOW, "data": ["identity (name, email, groups)"], "trigger": "at each sign-in",
                 "endpoint": SNOW_HOST + "/navpage.do"}],
         owner="IAM team", reviewed="2026-06-01"),
    _int("Entra ID provisioning (SCIM) to ServiceNow", M365, SNOW, "scim", built_by="Microsoft (gallery app)",
         purpose="Creates and disables ServiceNow users from Entra ID.",
         auth={"method": "basic", "identity": "svc_entra_provisioning (ServiceNow user)", "roles": ["user_admin"],
               "credential": "password", "stored_in": "Entra provisioning settings", "rotated": "2024-08-15", "rotation_days": 365},
         flows=[{"from": M365, "to": SNOW, "data": ["identity (name, email, department, manager)", "group membership"],
                 "trigger": "every 40 minutes", "endpoint": SNOW_HOST + "/api/now/table/sys_user"}],
         network={"ingress": [SNOW_HOST + "/api/now/table/sys_user"], "ip_allowlist": "no", "inbound_auth": "basic auth"},
         owner="IAM team", reviewed="2026-06-01"),
    _int("ServiceNow Entra ID spoke (IntegrationHub)", SNOW, M365, "oauth_app", built_by="ServiceNow",
         purpose="Catalog requests create users, reset passwords and change group membership in Entra ID.",
         app_id="5f1c0b8e-snow-entra-spoke",
         auth={"method": "oauth_client_credentials", "identity": "App registration: snow-entra-spoke",
               "credential": "client secret", "stored_in": "ServiceNow credential record", "rotated": "2025-01-10",
               "rotation_days": 180},
         scopes=[{"name": "User.ReadWrite.All", "grant": "application", "consent": "admin"},
                 {"name": "Group.ReadWrite.All", "grant": "application", "consent": "admin"},
                 {"name": "Directory.ReadWrite.All", "grant": "application", "consent": "admin"}],
         flows=[{"from": SNOW, "to": M365, "data": ["identity changes (create user, password reset, group change)"],
                 "trigger": "on catalog request", "endpoint": "graph.microsoft.com"},
                {"from": M365, "to": SNOW, "data": ["identity (users, groups)"], "trigger": "on lookup",
                 "endpoint": "graph.microsoft.com"}],
         network={"egress": ["login.microsoftonline.com", "graph.microsoft.com"]},
         owner="ITSM platform team", reviewed="2025-09-12"),
    _int("ServiceNow notifications in Microsoft Teams", SNOW, M365, "oauth_app", built_by="ServiceNow (Teams spoke)",
         purpose="Sends approvals and incident updates to people in Teams.",
         app_id="a2d7-snow-teams",
         auth={"method": "certificate", "identity": "App registration: snow-teams-notify", "credential": "certificate",
               "stored_in": "ServiceNow key store", "rotated": "2026-02-01", "rotation_days": 365},
         scopes=[{"name": "TeamsActivity.Send", "grant": "application", "consent": "admin"},
                 {"name": "User.Read.All", "grant": "application", "consent": "admin"}],
         flows=[{"from": SNOW, "to": M365, "data": ["ticket summaries", "approval requests"], "trigger": "on ticket change",
                 "endpoint": "graph.microsoft.com"}],
         owner="ITSM platform team", reviewed="2026-03-20"),
    _int("ServiceNow Virtual Agent in Teams", M365, SNOW, "connector", built_by="ServiceNow",
         purpose="Staff ask the service desk bot questions from Teams.",
         auth={"method": "oauth_auth_code", "identity": "Each signed-in user (delegated)", "credential": "user tokens"},
         scopes=[{"name": "openid", "grant": "delegated"}, {"name": "profile", "grant": "delegated"},
                 {"name": "User.Read", "grant": "delegated"}, {"name": "offline_access", "grant": "delegated"}],
         flows=[{"from": M365, "to": SNOW, "data": ["chat messages", "identity (name, email)"], "trigger": "real time",
                 "endpoint": SNOW_HOST + "/api/sn_va_as_service/bot/integration"},
                {"from": SNOW, "to": M365, "data": ["ticket content", "knowledge answers"], "trigger": "real time",
                 "endpoint": "smba.trafficmanager.net"}],
         network={"ingress": [SNOW_HOST + "/api/sn_va_as_service/bot/integration"], "ip_allowlist": "no",
                  "inbound_auth": "signed bot token"},
         owner="Service desk", reviewed="2026-04-11"),
    _int("Inbound email from Exchange Online", SNOW, M365, "email", built_by="ServiceNow (email OAuth)",
         purpose="ServiceNow reads the servicedesk@ mailbox and sends notifications through it.",
         auth={"method": "oauth_auth_code", "identity": "servicedesk@yourco.com mailbox", "credential": "refresh token",
               "stored_in": "ServiceNow OAuth profile", "rotated": "", "rotation_days": 90},
         scopes=[{"name": "IMAP.AccessAsUser.All", "grant": "delegated"}, {"name": "SMTP.Send", "grant": "delegated"},
                 {"name": "offline_access", "grant": "delegated"}],
         flows=[{"from": M365, "to": SNOW, "data": ["email content", "attachments"], "trigger": "every 2 minutes",
                 "endpoint": "outlook.office365.com:993"},
                {"from": SNOW, "to": M365, "data": ["outbound notifications"], "trigger": "on ticket change",
                 "endpoint": "smtp.office365.com:587"}],
         owner="Service desk", reviewed="2025-02-03"),
    _int("Microsoft Search connector for ServiceNow", M365, SNOW, "connector", built_by="Microsoft (Graph connector)",
         purpose="Indexes ServiceNow knowledge and tickets into Microsoft Search and Copilot.",
         auth={"method": "basic", "identity": "svc_graph_connector (ServiceNow user)", "roles": ["itil", "knowledge"],
               "credential": "password", "stored_in": "Microsoft 365 admin center", "rotated": ""},
         scopes=[{"name": "ExternalConnection.ReadWrite.OwnedBy", "grant": "application", "consent": "admin"},
                 {"name": "ExternalItem.ReadWrite.OwnedBy", "grant": "application", "consent": "admin"}],
         flows=[{"from": SNOW, "to": M365, "data": ["knowledge articles", "ticket content"], "trigger": "full crawl daily, incremental every 15 minutes",
                 "endpoint": SNOW_HOST + "/api/now/table/kb_knowledge"}],
         network={"ingress": [SNOW_HOST + "/api/now/table"], "ip_allowlist": "no", "inbound_auth": "basic auth"},
         owner="", reviewed=""),
    _int("Service Graph connector for Microsoft Intune", SNOW, M365, "oauth_app", built_by="ServiceNow",
         purpose="Loads managed devices and installed apps into the CMDB.",
         app_id="c9e2-snow-intune",
         auth={"method": "certificate", "identity": "App registration: snow-sg-intune", "credential": "certificate",
               "stored_in": "ServiceNow key store", "rotated": "2026-02-01", "rotation_days": 365},
         scopes=[{"name": "DeviceManagementManagedDevices.Read.All", "grant": "application", "consent": "admin"},
                 {"name": "DeviceManagementApps.Read.All", "grant": "application", "consent": "admin"}],
         flows=[{"from": M365, "to": SNOW, "data": ["device inventory", "installed software"], "trigger": "daily 02:00 UTC",
                 "endpoint": "graph.microsoft.com"}],
         owner="CMDB team", reviewed="2026-05-30"),
    _int("ServiceNow MID Server (on-premises)", YOU, SNOW, "agent", built_by="ServiceNow",
         purpose="Discovery and orchestration inside your network.",
         auth={"method": "basic", "identity": "mid_server_user", "roles": ["mid_server"], "credential": "password",
               "stored_in": "MID Server config.xml", "rotated": "2025-05-01", "rotation_days": 365},
         flows=[{"from": YOU, "to": SNOW, "data": ["discovery data (hosts, software, open ports)"], "trigger": "continuous",
                 "endpoint": SNOW_HOST + ":443"},
                {"from": SNOW, "to": YOU, "data": ["orchestration commands"], "trigger": "on workflow", "endpoint": "outbound polling"}],
         network={"egress": [SNOW_HOST + ":443 (from the MID host)"], "ip_allowlist": "yes"},
         owner="Infrastructure", reviewed="2026-01-15"),
    _int("Workday inbound provisioning to Entra ID", M365, WD, "connector", built_by="Microsoft (provisioning app)",
         purpose="Hires, moves and leavers in Workday create and disable accounts in Entra ID.",
         auth={"method": "basic", "identity": "ISU_Entra_Provisioning (Workday integration system user)",
               "roles": ["Get_Workers (domain security)"], "credential": "password", "stored_in": "Entra provisioning settings",
               "rotated": "2025-12-01", "rotation_days": 365},
         flows=[{"from": WD, "to": M365, "data": ["hr data (name, title, manager, hire and termination dates)"],
                 "trigger": "every 40 minutes", "endpoint": "services1.myworkday.com/ccx/service/yourco"}],
         owner="IAM team", reviewed="2026-02-20"),
    _int("Workday to ServiceNow HR profile sync", SNOW, WD, "connector", built_by="ServiceNow (Workday spoke)",
         purpose="Keeps HR profiles in ServiceNow HR Service Delivery current.",
         auth={"method": "basic", "identity": "ISU_ServiceNow_HR", "credential": "password",
               "stored_in": "ServiceNow credential record", "rotated": ""},
         flows=[{"from": WD, "to": SNOW, "data": ["hr data (job, location, manager)", "personal data (home address, phone)"],
                 "trigger": "nightly", "endpoint": "services1.myworkday.com/ccx/service/yourco"}],
         owner="HR technology", reviewed="2025-11-05"),
    _int("Fieldnote AI calendar and mail grant", FN, M365, "oauth_delegated", built_by="Fieldnote AI",
         purpose="An employee connected an AI note-taker to their Microsoft account.",
         app_id="fn-0a77-notes",
         auth={"method": "oauth_auth_code", "identity": "One employee (user consent)", "credential": "refresh token"},
         scopes=[{"name": "Calendars.Read", "grant": "delegated", "consent": "user"},
                 {"name": "Mail.Read", "grant": "delegated", "consent": "user"},
                 {"name": "offline_access", "grant": "delegated", "consent": "user"}],
         flows=[{"from": M365, "to": FN, "data": ["email content", "meeting invites", "personal data (attendees)"],
                 "trigger": "continuous", "endpoint": "api.fieldnote.example"}],
         owner="", reviewed=""),
]


ENTRA, INTUNE, ONPREM = "sys-idp-microsoft-entra-id", "sys-mdm-microsoft-intune", "sys-cloud-onprem"

ENVIRONMENT = {
    "org_name": "Northwind Health (demo)", "rotation_days": "365", "owner": "Security engineering",
    "sensitive_terms": "Restricted\nPHI\nclaims data",
    "idp": "Microsoft Entra ID", "collab": "Microsoft 365", "itsm": "ServiceNow", "hris": "Workday", "mdm": "Microsoft Intune",
    "siem": "Microsoft Sentinel", "edge": "Zscaler", "secrets": "Azure Key Vault",
    "cloud_azure": "on", "cloud_aws": "on", "cloud_onprem": "on",
    "stores": "Claims database | claims data, PHI | Azure East US\nHR file share | hr data, personal data | On-premises",
}
VENDOR_DETAILS = {
    M365: {"category": "collaboration", "soc2_expires": "2027-03-31", "pentest_expires": "2027-01-31", "next_review": "2027-02-01",
           "factsheet": {"sso": "Native sign-in through Entra ID with MFA enforced", "hosting": "US and EU regions",
                         "subprocessors": "Published sub-processor list", "ai_used": "yes", "trains_on_customer_content": "no",
                         "model_provider": "Microsoft (Azure OpenAI)", "gaps": []}},
    SNOW: {"category": "itsm", "soc2_expires": "2026-12-31", "pentest_expires": "2026-08-30", "next_review": "2026-11-15",
           "factsheet": {"sso": "SAML SSO through Entra ID with MFA", "hosting": "US data centers",
                         "subprocessors": "Listed in the vendor's trust portal", "gaps": []}},
    WD: {"category": "hris", "soc2_expires": "2027-01-15", "next_review": "2026-09-30",
         "factsheet": {"sso": "SAML SSO", "hosting": "US", "gaps": []}},
    FN: {"category": "meeting_notes"},
    "Ledgerline_Billing": {"category": "finance"},
}
# Where each sample integration really lands in the demo environment.
REMAP = {
    "Entra ID single sign-on to ServiceNow": (M365, ENTRA),
    "Entra ID provisioning (SCIM) to ServiceNow": (M365, ENTRA),
    "ServiceNow Entra ID spoke (IntegrationHub)": (M365, ENTRA),
    "Service Graph connector for Microsoft Intune": (M365, INTUNE),
    "ServiceNow MID Server (on-premises)": (YOU, ONPREM),
    "Workday inbound provisioning to Entra ID": (M365, ENTRA),
}
SHADOW_APPS = """Display name,Application ID,Permissions,Last sign-in,Owner
ServiceNow Entra spoke,5f1c0b8e-snow-entra-spoke,User.ReadWrite.All Group.ReadWrite.All Directory.ReadWrite.All,2026-10-09,itsm@northwind.example
Fieldnote AI,fn-0a77-notes,Calendars.Read Mail.Read offline_access Files.Read.All,2026-10-09,j.doe@northwind.example
Otter.ai,ot-551,Calendars.Read OnlineMeetings.Read offline_access,2026-10-08,
PDF Converter Pro,pdfc-9910,Files.ReadWrite.All offline_access,2026-10-07,a.lee@northwind.example
Zoom,zm-1201,User.Read openid profile,2026-10-06,
Ledgerline Billing,ll-3302,Mail.Send User.Read.All,2026-10-05,finance@northwind.example
"""
SHADOW_DOMAINS = """domain,users,hits
chatgpt.com,140,51230
otter.ai,12,880
dropbox.com,35,4120
slack.com,22,9300
yourco.service-now.com,410,120000
weather.example.org,90,1500
"""


def _remap(row: dict) -> dict:
    old, new = REMAP.get(row["name"], (None, None))
    if not old:
        return row
    row = dict(row)
    row["source"] = new if row["source"] == old else row["source"]
    row["target"] = new if row["target"] == old else row["target"]
    row["flows"] = [{**f, "from": new if f["from"] == old else f["from"], "to": new if f["to"] == old else f["to"]}
                    for f in row.get("flows") or []]
    return row


def run() -> int:
    """Create the demo company: its environment, vendors, integrations and shadow IT exports.
    Existing vendor records are left as they are; the integration list is replaced."""
    import environment
    import shadow
    for v in VENDORS:
        if not load_vendor(v["slug"]):
            save_vendor({**v, **{k: d for k, d in VENDOR_DETAILS.get(v["slug"], {}).items()}, "source": "demo"}, replace=False)
    if not environment.systems() and not environment.profile():  # never overwrite a customer's own setup
        environment.apply_setup(ENVIRONMENT, "sample data")
    # Observed in an Entra export: the note-taker also holds a scope nobody declared.
    rec = load_vendor(FN)
    access_store.replace_rows(rec, [access_store.normalize_row({
        "id": "fn-0a77-notes", "app_id": "fn-0a77-notes", "display_name": "Fieldnote AI", "kind": "oauth_app",
        "status": "active", "source": "entra", "scopes": ["Calendars.Read", "Mail.Read", "offline_access", "Files.Read.All"],
        "last_seen": "2026-10-09", "owner": ""})])
    save_vendor(rec)
    # ServiceNow's apps as granted in the tenant: the spoke matches its record; the Intune connector was
    # declared with a scope the tenant never consented.
    rec = load_vendor("ServiceNow")
    access_store.replace_rows(rec, [access_store.normalize_row(r) for r in (
        {"id": "5f1c0b8e-snow-entra-spoke", "app_id": "5f1c0b8e-snow-entra-spoke", "display_name": "ServiceNow Entra ID spoke",
         "kind": "oauth_app", "status": "active", "source": "entra", "last_seen": "2026-10-09", "owner": "IT service management",
         "scopes": ["User.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All"]},
        {"id": "c9e2-snow-intune", "app_id": "c9e2-snow-intune", "display_name": "ServiceNow Service Graph connector for Intune",
         "kind": "oauth_app", "status": "active", "source": "entra", "last_seen": "2026-10-09", "owner": "Endpoint team",
         "scopes": ["DeviceManagementManagedDevices.Read.All"]})])
    save_vendor(rec)
    integrations.replace_all([{**_remap(r), "id": "int-demo-%02d" % i} for i, r in enumerate(INTEGRATIONS, 1)])
    shadow.import_apps(SHADOW_APPS, "entra-enterprise-apps.csv", "entra", "sample data")
    shadow.import_domains(SHADOW_DOMAINS, "proxy-top-domains.csv", "sample data")
    return len(INTEGRATIONS)
