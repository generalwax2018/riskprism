#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import sys
from datetime import date

STANDARD = [
    ("data", "What customer or company data will this engagement store or process?"),
    ("data_class", "How does the customer classify that data for this use? standard / sensitive / critical"),
    ("hosting", "Cloud provider and region for our tenant / our data?"),
    ("subprocessors", "List subprocessors on the data path (hosting, support, AI/inference, analytics)."),
    ("soc2", "How do we obtain your current SOC 2 Type II or ISO 27001 report? Period covered?"),
    ("encryption", "Encryption in transit and at rest? Who holds keys?"),
    ("sso", "SSO / MFA options for our tenant?"),
    ("incident", "How do you notify customers of an incident, and in what window?"),
    ("deletion", "How do we request deletion at trial end and at contract end?"),
]
HYBRID = [
    ("hybrid_split", "What runs in our network vs yours (agents, collectors, on-prem connectors)?"),
    ("hybrid_privs", "What privileges does the on-prem component need?"),
    ("hybrid_updates", "How are updates shipped to the on-prem piece?"),
    ("hybrid_phonehome", "Does the on-prem component phone home? What data leaves our network?"),
]
ONPREM = [
    ("onprem_os", "Supported OS / hypervisor and required ports?"),
    ("onprem_cloud", "Does anything still call your cloud (license, telemetry, support)?"),
    ("onprem_patch", "How are security patches delivered?"),
]
AI_SCREEN = [
    ("ai_used", "Does any feature use a model (yours or a third party) on our content, tickets, files, or recordings?"),
    ("ai_models", "If yes: list every model by vendor and name (example: OpenAI GPT-4o, Anthropic Claude 3.5, Google Gemini). No marketing names only."),
    ("ai_train", "If yes: default training on customer content — on or off? How do we disable it?"),
    ("ai_provider", "If yes: who runs inference, and in which country/region?"),
    ("ai_region", "If our data is critical: exact inference and storage regions. Can we pin the EU / US / other?"),
]
ARCHITECTURE = [
    ("dataflow", "Describe or attach a one-page data-flow: user -> your app -> storage -> subprocessors."),
    ("tenancy", "How is tenant A isolated from tenant B?"),
    ("admin", "Support / admin access into our tenant: SSO, logging, off-hours?"),
    ("sec_contact", "Security contact name, email, and notification window."),
]
INTEGRATIONS = [
    ("int_connect", "Does your product connect to any of our systems or SaaS tenants (for example Microsoft 365, Google Workspace, Salesforce, ServiceNow, Slack, our network)?"),
    ("int_list", "For each connection: which system, how it connects (single sign-on, SCIM provisioning, OAuth app, API key, webhook, on-prem agent, file transfer, email) and what it is used for."),
    ("int_permissions", "List every permission, scope or role your product needs in each system, exactly as that system names it (for example User.Read.All or itil). For each: granted to your app itself or on behalf of a user, and why it is needed."),
    ("int_admin", "Does any connection need administrator rights or tenant-wide write access?"),
    ("int_narrower", "Can any permission be narrowed (for example to selected sites, mailboxes, channels or records)? How do we set that up?"),
    ("int_credentials", "How does each connection authenticate (certificate, client secret, API key, password, user token)? Where do you store those credentials, and can we rotate them or set them to expire?"),
    ("int_data", "What data moves in each direction for each connection, how often, and through which endpoints or domains?"),
    ("int_inbound", "Do we need to expose any endpoint to you (webhook or callback)? How are your calls to it signed or authenticated, and from which IP ranges?"),
    ("int_egress", "Which domains or IP ranges does your service connect from or to, so we can allow-list them?"),
    ("int_onward", "Does data from these connections go on to any other party (sub-processor, model provider, analytics)? Which, and what data?"),
]
RENEWAL = [
    ("soc2_current", "Attach or link the current SOC 2 Type II or ISO 27001 report. Period start and end dates?"),
    ("soc2_exceptions", "Any new exceptions, qualified opinions, or bridge letters since last review?"),
    ("pentest_current", "Date and firm of the latest application / AI pentest or red team. How do we receive the report?"),
    ("pentest_open", "Open high/critical findings still unremediated?"),
    ("material_change", "Material changes in the last 12 months: hosting region, ownership, subprocessors, product scope?"),
    ("breach", "Security incidents affecting customers since last review? Dates and what changed afterward."),
    ("ai_change", "New or changed models (full vendor + model name), training default, or inference region?"),
    ("int_change", "New or changed connections to our systems since the last review: permissions or scopes, service accounts, endpoints, or credentials?"),
    ("data_class", "Has the data classification for this use changed (standard / sensitive / critical)?"),
    ("subprocessors_delta", "Subprocessors added or removed on the data path?"),
    ("cert_expiry", "Upcoming expiry dates for SOC 2, ISO, PCI, FedRAMP, or pentest."),
    ("sec_contact", "Current security contact and incident notification window."),
]


def questions(mode: str, kind: str = "onboard"):
    if kind == "renewal":
        return [("Annual security review", RENEWAL)]
    mode = (mode or "saas").lower()
    items = [("A. Standard", STANDARD)]
    if mode.startswith("hybrid"):
        items.append(("B. Hybrid delivery", HYBRID))
    elif mode.startswith("on"):
        items.append(("B. On-prem delivery", ONPREM))
    items.append(("C. AI screen", AI_SCREEN))
    items.append(("D. Architecture", ARCHITECTURE))
    items.append(("E. Integrations and permissions", INTEGRATIONS))
    return items


def render(name: str, desc: str = "", mode: str = "saas", url: str = "", contact: str = "", kind: str = "onboard") -> str:
    title = "Security review (renewal)" if kind == "renewal" else "Security questionnaire"
    lines = [title + " - " + name, "Generated " + date.today().isoformat() + " | RiskPrism", ""]
    n = 1
    for section, qs in questions(mode, kind):
        lines.append(section)
        for _id, text in qs:
            lines += [str(n) + ". " + text, "   Answer:", ""]
            n += 1
    return "\n".join(lines)


# Questions whose answer decides a risk flag are multiple choice, so a vendor's
# wording can never be misread by the parser. Everything else is free text.
CHOICES = {
    "ai_used": [("yes", "Yes"), ("no", "No"), ("unsure", "Not sure")],
    "ai_train": [("off", "Off by default"), ("on", "On by default"), ("unsure", "Not sure")],
    "data_class": [("standard", "Standard"), ("sensitive", "Sensitive"), ("critical", "Critical")],
    "int_connect": [("yes", "Yes"), ("no", "No"), ("unsure", "Not sure")],
    "int_admin": [("yes", "Yes"), ("no", "No"), ("unsure", "Not sure")],
}
SHORT = {"hosting", "ai_provider", "ai_region", "sec_contact", "sso", "int_egress"}
EXTRA_FIELDS = {"ai_train_how"}


def allowed_ids(mode: str, kind: str = "onboard") -> set:
    ids = set(EXTRA_FIELDS)
    for _title, qs in questions(mode, kind):
        ids.update(qid for qid, _t in qs)
    return ids


def render_fields_html(mode: str, kind: str = "onboard") -> str:
    """HTML for the vendor form. Static question text only; safe to insert as-is."""
    chunks = []
    n = 1
    for title, qs in questions(mode, kind):
        chunks.append("<h2>" + html.escape(title) + "</h2>")
        for qid, text in qs:
            label_id = "ql-" + qid
            head = '<div class="q" data-qid="%s"><p id="%s" class="qtext">%d. %s</p>' % (qid, label_id, n, html.escape(text))
            if qid in CHOICES:
                opts = "".join(
                    '<label class="seg"><input type="radio" name="%s" value="%s"><span>%s</span></label>' % (qid, v, html.escape(lab))
                    for v, lab in CHOICES[qid]
                )
                body = '<div class="seg-group" role="radiogroup" aria-labelledby="%s">%s</div>' % (label_id, opts)
                if qid == "ai_train":
                    body += ('<input class="text" type="text" name="ai_train_how" maxlength="500" '
                             'aria-label="How to turn training off" placeholder="If it is on, how does a customer turn it off?">')
            elif qid in SHORT:
                body = '<input class="text" type="text" name="%s" maxlength="500" aria-labelledby="%s" placeholder="Your answer">' % (qid, label_id)
            else:
                body = '<textarea name="%s" maxlength="4000" aria-labelledby="%s" placeholder="Your answer"></textarea>' % (qid, label_id)
            chunks.append(head + body + "</div>")
            n += 1
    return "".join(chunks)


def ai_allowed_ids(qs: list) -> set:
    ids = {q["id"] for q in qs}
    ids.update(q["id"] + "__none" for q in qs if q.get("kind") == "document")
    if any(q.get("feeds") == "ai_train" for q in qs):
        ids.add("ai_train_how")
    return ids


def render_ai_html(qs: list, area_labels: dict, docs: dict | None = None, accept: str = "") -> str:
    """Vendor form for an approved AI questionnaire, grouped by security area.
    Question text came from a model or an analyst, so everything is escaped.
    A question that feeds a multiple-choice rule field is multiple choice here too.
    A document request takes a file, a "we don't have this" box and a note."""
    chunks, n, current = [], 1, None
    docs = docs or {}
    for q in qs:
        if q["area"] != current:
            current = q["area"]
            chunks.append("<h2>" + html.escape(area_labels.get(current, current)) + "</h2>")
        qid, label_id = html.escape(q["id"]), "ql-" + html.escape(q["id"])
        head = '<div class="q" data-qid="%s"><p id="%s" class="qtext">%d. %s</p>' % (qid, label_id, n, html.escape(q["text"]))
        feeds = q.get("feeds", "")
        if q.get("kind") == "document":
            have = (docs.get(q["id"]) or {}).get("files") or []
            got = ('<p class="muted small">Already received: %d file%s. Upload again only to add or replace.</p>'
                   % (len(have), "" if len(have) == 1 else "s")) if have else ""
            body = ('<p class="muted small">Document requested: %s</p>%s'
                    '<input type="file" name="file_%s" accept="%s" aria-labelledby="%s">'
                    '<label class="checkline"><input type="checkbox" name="%s__none" value="yes"> We do not have this document</label>'
                    '<textarea name="%s" maxlength="2000" aria-label="Notes or link" placeholder="Notes, or a link to where we can get it (optional)"></textarea>'
                    % (html.escape(q.get("doc_type") or "see question"), got, qid, html.escape(accept), label_id, qid, qid))
        elif feeds in CHOICES:
            opts = "".join('<label class="seg"><input type="radio" name="%s" value="%s"><span>%s</span></label>' % (qid, v, html.escape(lab))
                           for v, lab in CHOICES[feeds])
            body = '<div class="seg-group" role="radiogroup" aria-labelledby="%s">%s</div>' % (label_id, opts)
            if feeds == "ai_train":
                body += ('<input class="text" type="text" name="ai_train_how" maxlength="500" '
                         'aria-label="How to turn training off" placeholder="If it is on, how does a customer turn it off?">')
        else:
            body = '<textarea name="%s" maxlength="4000" aria-labelledby="%s" placeholder="Your answer"></textarea>' % (qid, label_id)
        chunks.append(head + body + "</div>")
        n += 1
    return "".join(chunks)


def render_followup_html(qs: list) -> str:
    if not qs:
        return "<p>No open follow-ups.</p>"
    chunks = ["<h2>Follow-up from security review</h2>"]
    for qid, text in qs:
        chunks.append(
            '<div class="q"><p id="ql-%s" class="qtext">%s</p><textarea name="%s" maxlength="4000" aria-labelledby="ql-%s"></textarea></div>'
            % (html.escape(qid), html.escape(text), html.escape(qid), html.escape(qid))
        )
    return "".join(chunks)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    p = argparse.ArgumentParser()
    p.add_argument("--name", required=True)
    p.add_argument("--kind", default="onboard", choices=("onboard", "renewal"))
    p.add_argument("--mode", default="saas")
    args = p.parse_args()
    print(render(args.name, kind=args.kind, mode=args.mode))


if __name__ == "__main__":
    main()
