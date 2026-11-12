"""Builds page HTML. Every value that came from a person goes through tpl.esc()."""
from __future__ import annotations

import json
import time
from datetime import date, datetime, timedelta

import access_flags
import access_store
import ai_questionnaire
import alerts
import audit
import config
import documents
import evidence_store
import llm
import notes_store
import policy_store
import portfolio
import risk_rules
import records
import risk_store
import tpl
from questionnaire import questions
from records import list_vendors, slugify
from tpl import esc

TIER_NAMES = {"T1": "T1 Critical", "T2": "T2 High", "T3": "T3 Moderate", "T4": "T4 Low"}
FACTOR_LABELS = [
    ("data_sensitivity", "Data sensitivity", "20%"), ("data_volume", "Data volume", "10%"),
    ("access_level", "Access level", "18%"), ("criticality", "Business criticality", "15%"),
    ("ai_involvement", "AI / model involvement", "15%"), ("blast_radius", "Connectivity / blast radius", "10%"),
    ("substitutability", "Substitutability", "7%"), ("regulatory", "Regulatory overlay", "5%"),
]
MODES = [("saas", "SaaS"), ("hybrid", "Hybrid"), ("onprem", "On-prem"), ("unknown", "Unknown")]
AUTHS = [("not_authorized", "Not authorized"), ("trial_only", "Trial only"), ("authorized", "Authorized"), ("blocked", "Blocked")]
STAGES = [("inquiry", "Inquiry"), ("trial_30", "Trial"), ("contracted", "In use"), ("renewal_due", "Review due"), ("offboarded", "Offboarded")]
AI_USED = [("unknown", "Unknown"), ("yes", "Yes"), ("no", "No")]
AI_TRAIN = [("unknown", "Unknown"), ("off", "Default off"), ("on", "Default on")]
FOUND_VIA = [("employee", "Someone on the team uses it"), ("sso", "Showed up in SSO"), ("saas", "SaaS / finance export"), ("other", "Other")]
AUTH_LABEL = dict(AUTHS)
STAGE_LABEL = dict(STAGES)


def _all_question_labels() -> dict:
    labels = {}
    for mode in ("saas", "hybrid", "onprem"):
        for kind in ("onboard", "renewal"):
            for _title, qs in questions(mode, kind):
                for qid, text in qs:
                    labels.setdefault(qid, text)
    labels["ai_train_how"] = "How does a customer turn training off?"
    return labels


def tier_chip(code: str, provisional: bool = False) -> str:
    code = code if code in TIER_NAMES else "T?"
    label = TIER_NAMES.get(code, "Unscored") + (" (draft)" if provisional else "")
    return '<span class="tier %s"><i class="dot"></i>%s</span>' % (esc(code.lower()), esc(label))


def select(name: str, options, current: str = "") -> str:
    opts = "".join(
        '<option value="%s"%s>%s</option>' % (esc(v), " selected" if v == current else "", esc(lab)) for v, lab in options
    )
    return '<select name="%s">%s</select>' % (esc(name), opts)


def notice(kind: str, text: str) -> str:
    if not text:
        return ""
    return '<div class="notice %s" role="alert">%s</div>' % (esc(kind), esc(text))


def error_page(title: str, text: str, back: str = "/") -> str:
    return tpl.render("error.html", title=title, text=text, back=back)


def _when(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%b %d, %H:%M")
    except (ValueError, TypeError):
        return iso or ""


# ---------------------------------------------------------------- risk acceptance helpers

RISK_TIER_CLASS = {"critical": "t1", "high": "t2", "medium": "t3", "low": "t4"}


def risk_tier_chip(tier: str) -> str:
    return '<span class="tier %s"><i class="dot"></i>%s</span>' % (
        esc(RISK_TIER_CLASS.get(tier, "t?")), esc(risk_rules.TIER_LABEL.get(tier, tier)))


def _expiry_cell(row: dict) -> dict:
    if row.get("status") == "superseded":
        return {"tone": "grey", "top": "Superseded", "bottom": row.get("expires_on", "")}
    if not risk_store.is_active(row):
        return {"tone": "red", "top": "Expired, open again", "bottom": row.get("expires_on", "")}
    try:
        days = (date.fromisoformat(row["expires_on"]) - date.today()).days
    except (KeyError, ValueError):
        return {"tone": "grey", "top": "No date", "bottom": ""}
    top = "Today" if days == 0 else "In %d day%s" % (days, "" if days == 1 else "s")
    # Blue, not green: an acceptance is an exception with an owner, never a pass.
    return {"tone": "amber" if days <= 30 else "blue", "top": top, "bottom": row["expires_on"]}


def unit_tree(units: list[dict]) -> list[tuple[dict, int]]:
    """Units in tree order with their depth. Orphans (parent merged or missing) sit at the top level."""
    ids = {u["id"] for u in units}
    kids: dict = {}
    for u in units:
        kids.setdefault(u["parent_id"] if u["parent_id"] in ids else None, []).append(u)
    out, seen = [], set()

    def walk(parent, depth):
        for u in kids.get(parent, []):
            if u["id"] in seen:
                continue
            seen.add(u["id"])
            out.append((u, depth))
            walk(u["id"], depth + 1)
    walk(None, 0)
    return out


def _unit_options(units: list[dict], current=None, blank: str = "") -> str:
    opts = [('<option value="">%s</option>' % esc(blank))] if blank else []
    for u, depth in unit_tree(units):
        opts.append('<option value="%d"%s>%s%s</option>' % (u["id"], " selected" if u["id"] == current else "",
                                                          "— " * depth, esc(u["name"])))
    return "".join(opts)


def _acceptance_block(a: dict) -> str:
    cell = _expiry_cell(a)
    controls = a.get("compensating_controls") or "None recorded"
    return (
        '<div class="issue acc"><div class="acc-top">%s<span class="strong">%s</span>%s</div>'
        '<div class="muted small">Signed by %s (%s) for %s on %s</div>'
        '<div class="small pre-line"><span class="muted">Why:</span> %s</div>'
        '<div class="small pre-line"><span class="muted">Compensating controls:</span> %s</div></div>'
        % (risk_tier_chip(a["risk_tier"]), esc(a["detection_text"]), _cell(cell), esc(a["accepter"]),
           esc(risk_rules.LEVEL_LABEL.get(a["accepter_level"], a["accepter_level"])), esc(a["unit_name"]),
           esc(_when(a["signed_at"])), esc(a["justification"]), esc(controls)))


def _expiry_choices(rec: dict, draft: dict, tier: str) -> str:
    """Clickable suggestions under 'Accepted until'. They fill the date field (app.js) and
    nothing else; the signer can type any other allowed date."""
    chips = []
    for o in risk_rules.expiry_options(rec):
        on = o["tier"] and o["tier"] == tier
        chips.append('<button class="chipbtn expiry-opt%s" type="button" data-date="%s" data-tier="%s">%s <span class="mono">%s</span></button>'
                     % (" suggested" if on else "", esc(o["date"]), esc(o["tier"]), esc(o["label"]), esc(o["date"])))
    ai = draft.get("ai") or {}
    if ai.get("date"):
        chips.append('<button class="chipbtn expiry-opt ai" type="button" data-date="%s" data-tier="">AI <span class="mono">%s</span></button>'
                     % (esc(ai["date"]), esc(ai["date"])))
    out = ['<div class="expiry-opts">%s</div>' % "".join(chips)]
    out.append('<p class="muted small">Suggested by tier: Critical %d days, High %d, Medium %d, Low %d. You choose the date.</p>'
               % tuple(risk_rules.SUGGEST_DAYS[t] for t in ("critical", "high", "medium", "low")))
    if ai.get("date"):
        out.append('<p class="small ai-reason"><span class="muted">AI draft:</span> %s</p>' % esc(ai.get("reason", "")))
    if draft.get("ai_error"):
        out.append('<p class="muted small">%s</p>' % esc(draft["ai_error"]))
    return "".join(out)


def _acceptance_html(rec: dict, who: str, tracked: bool, draft: dict | None = None) -> str:
    """Risk acceptance card on the vendor record: what is accepted now, what lapsed, and the signing form.
    draft holds what the signer already typed when the form comes back (an error or an AI suggestion)."""
    draft = draft or {}
    if not tracked:
        return '<p class="muted">Start tracking this vendor to record a decision.</p>'
    slug = rec.get("slug", "")
    rows = risk_store.acceptances(slug=slug)
    live = [a for a in rows if risk_store.is_active(a)]
    past = [a for a in rows if not risk_store.is_active(a)]
    out = ["".join(_acceptance_block(a) for a in live) or '<p class="muted small">No acceptance in force.</p>']
    if past:
        out.append('<details class="pad-b"><summary class="muted small">%d expired or superseded</summary>%s</details>' % (len(past), "".join(
            '<div class="row srow"><span class="mono small">%s</span><span class="small">%s · %s</span><span class="tone %s">%s</span></div>'
            % (esc(a["expires_on"]), esc(a["detection_text"]), esc(a["accepter"]), esc(_expiry_cell(a)["tone"]), esc(_expiry_cell(a)["top"]))
            for a in past)))

    if config.AUTH_MODE == "password":
        out.append('<p class="muted small">Signing needs per-person sign-in. The shared analyst password cannot say who accepted a risk, so switch this server to ENTROPY_AUTH=accounts.</p>')
        return "".join(out)
    level = risk_store.approver_level(who)
    if not level:
        out.append('<p class="muted small">You are signed in as %s, who is not a registered approver. An admin adds approvers on the Org units page.</p>' % esc(who))
        return "".join(out)
    units = risk_store.units()
    if not units:
        out.append('<p class="muted small">Add an org unit first (Org units page, or import Entra users). Every acceptance belongs to one.</p>')
        return "".join(out)
    dets = risk_rules.detections(rec)
    det_opts = "".join('<option value="%s"%s>%s (at least %s)</option>' % (
        esc(d["code"]), " selected" if d["code"] == draft.get("detection") else "", esc(d["text"]), esc(risk_rules.TIER_LABEL[d["floor"]]))
        for d in dets)
    tier = draft.get("risk_tier") if draft.get("risk_tier") in risk_rules.TIER_RANK else "medium"
    last = (date.today() + timedelta(days=config.ACCEPT_MAX_DAYS)).isoformat()
    ask_ai = ('<button class="btn ghost small-btn" type="submit" formaction="/accept/suggest" formnovalidate>Ask AI for a date</button>'
              if llm.configured() else "")
    out.append(
        '<form method="post" action="/accept" class="form accept-form"><input type="hidden" name="slug" value="%s">'
        '<p class="muted small">Signing as <b>%s</b> (%s). Low and Medium need a director or above; High and Critical need a VP or the CISO. '
        'Accepting does not clear the flag: it shows blue until the date you set, at most %d days out, then opens again.</p>'
        '<label>What is being accepted</label><select name="detection">%s</select>'
        '<div class="row2"><div><label>Org unit that owns the risk</label><select name="org_unit_id" required>%s</select></div>'
        '<div><label>Risk tier</label>%s</div></div>'
        '<label>Accepted until</label><div class="row-inline"><input name="until" type="date" required min="%s" max="%s" value="%s">%s</div>%s'
        '<label>Justification</label><textarea name="justification" required maxlength="4000">%s</textarea>'
        '<label>Compensating controls</label><textarea name="controls" required maxlength="4000">%s</textarea>'
        '<p><button class="btn primary" type="submit">Accept the risk</button></p></form>'
        % (esc(slug), esc(who), esc(risk_rules.LEVEL_LABEL[level]), config.ACCEPT_MAX_DAYS, det_opts,
           _unit_options(units, current=_int(draft.get("org_unit_id")), blank="Choose a unit"), select("risk_tier", risk_rules.TIERS, tier),
           date.today().isoformat(), last, esc(draft.get("until", "")), ask_ai, _expiry_choices(rec, draft, tier),
           esc(draft.get("justification", "")), esc(draft.get("controls", ""))))
    return "".join(out)


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------- portfolio

def portfolio_page() -> str:
    rows = portfolio.rows()
    rows.sort(key=lambda r: (-r["score"], r["name"]))
    total = len(rows)
    counts = {"inh": {}, "res": {}}
    for r in rows:
        counts["inh"][r["inh"]] = counts["inh"].get(r["inh"], 0) + 1
        counts["res"][r["res"]] = counts["res"].get(r["res"], 0) + 1

    def bar(which):
        segs = []
        for t in ("T1", "T2", "T3", "T4"):
            n = counts[which].get(t, 0)
            if n:
                segs.append('<div class="seg-bar %s" style="flex:%d 1 0" title="%s: %d">%d</div>' % (t.lower(), n, esc(TIER_NAMES[t]), n, n))
        return "".join(segs) or '<div class="seg-bar empty">No vendors yet</div>'

    body = []
    for r in rows:
        prov = ' <span class="muted-tag">draft</span>' if r["provisional"] else ""
        status = ' <span class="muted-tag">%s</span>' % esc(r["status"]) if r["status"] else ""
        body.append(
            '<a class="row prow" href="/vendor/%s" data-name="%s" data-ai="%d" data-human="%d" data-res="%s">'
            '<div class="cell-main"><div class="strong">%s%s</div><div class="muted small">%s</div></div>'
            '<div class="cell-inh"><span class="mono score">%d</span>'
            '<meter class="scorebar %s" min="0" max="100" value="%d"></meter>%s</div>'
            '<div>%s%s</div><div class="muted">%s</div><div><span class="gate %s">%s</span></div>'
            '<svg class="chev" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="9 6 15 12 9 18"></polyline></svg></a>'
            % (esc(r["slug"]), esc((r["name"] + " " + r["product"]).lower()), 1 if r["ai"] else 0, 1 if r["human"] else 0, esc(r["res"]),
               esc(r["name"]), status, esc(r["product"]), r["score"], esc(r["inh"].lower()), r["score"], tier_chip(r["inh"]),
               tier_chip(r["res"], r["provisional"]), prov, "Yes" if r["ai"] else "No",
               "human" if r["human"] else "auto", "Human gate" if r["human"] else "Auto-close")
        )
    att = portfolio.attention()
    if att:
        att_html = "".join(
            '<a class="att" href="/vendor/%s"><i class="dot t1"></i><div><div class="strong">%s</div><div class="muted small">%s</div></div></a>'
            % (esc(a["slug"]), esc(a["vendor"]), esc(a["text"])) for a in att)
    else:
        att_html = '<p class="muted pad">Nothing is flagged. Add SOC 2, pentest and review dates on a vendor to start its clocks.</p>'
    return tpl.render(
        "ui.html",
        kpi_total=total, kpi_human=sum(1 for r in rows if r["human"]), kpi_ai=sum(1 for r in rows if r["ai"]),
        kpi_t1=counts["res"].get("T1", 0), inh_bar=bar("inh"), res_bar=bar("res"), attention=att_html,
        rows=("".join(body) or '<p class="muted pad">No vendors yet. Add one, report a tool, or import a CSV.</p>'),
        n_all=total, n_t1=counts["res"].get("T1", 0), n_ai=sum(1 for r in rows if r["ai"]),
        n_human=sum(1 for r in rows if r["human"]), n_auto=sum(1 for r in rows if not r["human"]),
    )


# ---------------------------------------------------------------- alerts / renewals

def _cell(c: dict) -> str:
    bottom = '<div class="mono small muted">%s</div>' % esc(c.get("bottom", "")) if c.get("bottom") else ""
    return '<div><span class="tone %s">%s</span>%s</div>' % (esc(c["tone"]), esc(c["top"]), bottom)


def alerts_page(seed_button: bool) -> str:
    counts, rows, clocks = alerts.dashboard()
    clock_html = []
    for v in clocks:
        c = v["cells"]
        clock_html.append(
            '<div class="row crow"><div><a class="strong" href="/vendor/%s">%s</a><div class="muted small">%s</div></div>%s%s%s%s'
            '<div class="right"><form method="post" action="/renewal"><input type="hidden" name="slug" value="%s">'
            '<button class="btn ghost small-btn" type="submit">%s</button></form></div></div>'
            % (esc(v["slug"]), esc(v["vendor"]), esc(v["sub"]), _cell(c["soc"]), _cell(c["pen"]), _cell(c["rev"]), _cell(c["mod"]),
               esc(v["slug"]), esc(v["action"])))
    flag_html = []
    for r in rows:
        if r["severity"] == "accepted":
            flag_html.append(
                '<div class="row frow" data-sev="accepted"><span class="sev accepted">Accepted</span>'
                '<a class="strong gold" href="/vendor/%s">%s</a><div class="muted">%s</div>'
                '<div class="right"><a class="btn ghost small-btn" href="/vendor/%s#risk-acceptance">View</a></div></div>'
                % (esc(r["slug"]), esc(r["vendor"]), esc(r["text"]), esc(r["slug"])))
            continue
        label = "Send renewal" if r["action"] == "/renewal" else "Follow up"
        flag_html.append(
            '<div class="row frow" data-sev="%s"><span class="sev %s">%s</span>'
            '<a class="strong gold" href="/vendor/%s">%s</a><div>%s</div>'
            '<div class="right"><form method="post" action="%s"><input type="hidden" name="slug" value="%s">'
            '<button class="btn ghost small-btn" type="submit">%s</button></form></div></div>'
            % (esc(r["severity"]), esc(r["severity"]), esc(r["severity"].title()), esc(r["slug"]), esc(r["vendor"]), esc(r["text"]),
               esc(r["action"]), esc(r["slug"]), label))
    seed = ('<form method="post" action="/seed" class="inline"><button class="btn ghost" type="submit">Load sample clocks</button></form>'
            if seed_button else "")
    return tpl.render(
        "alerts.html", high=counts.get("high", 0), med=counts.get("medium", 0), flagged=counts.get("vendors_flagged", 0),
        waiting=counts.get("waiting", 0), clock_rows=("".join(clock_html) or '<p class="muted pad">No dates on file yet. Open a vendor and add SOC 2, pentest and review dates.</p>'),
        flag_rows=("".join(flag_html) or '<p class="muted pad">No clocks or follow-ups.</p>'), seed_button=seed,
        n_flags=len(rows), n_high=counts.get("high", 0), n_med=counts.get("medium", 0), n_accepted=counts.get("accepted", 0),
    )


def high_count() -> int:
    try:
        return alerts.dashboard()[0].get("high", 0)
    except Exception:
        return 0


# ---------------------------------------------------------------- forms

def _categories():
    import anticipate  # imported here: anticipate imports integrations, which reads records
    return anticipate.CATEGORIES


def intake_page(values: dict, *, edit: bool, error: str = "", slug: str = "") -> str:
    v = values or {}
    hidden = '<input type="hidden" name="slug" value="%s">' % esc(slug) if edit else ""
    return tpl.render(
        "intake.html",
        title="Edit vendor" if edit else "Onboard a vendor",
        lede=("Change the vendor's details. Answers, evidence and history stay as they are." if edit else
              "Name, delivery model, website, contact. Architecture comes from research and the questionnaire."),
        action="/edit" if edit else "/intake", hidden=hidden, error=notice("error", error),
        button="Save changes" if edit else "Save and generate questionnaire",
        v_vendor=v.get("vendor", ""), v_website=v.get("website", ""), v_contact=v.get("contact", ""),
        v_business=v.get("business", ""), v_owner=v.get("owner", ""), v_notes=v.get("notes", ""),
        sel_mode=select("mode", MODES, v.get("mode", "saas")),
        sel_auth=select("authorization", AUTHS, v.get("authorization", "not_authorized")),
        sel_stage=select("stage", STAGES[:4], v.get("stage", "inquiry")),
        sel_ai_used=select("ai_used", AI_USED, v.get("ai_used", "unknown")),
        sel_ai_train=select("ai_train", AI_TRAIN, v.get("ai_train", "unknown")),
        sel_connects=select("connects", AI_USED, v.get("connects", "unknown")), v_connects_to=v.get("connects_to", ""),
        sel_category=select("category", _categories(), v.get("category", "")),
    )


def report_page(values: dict | None = None, error: str = "") -> str:
    v = values or {}
    return tpl.render("report.html", error=notice("error", error), v_vendor=v.get("vendor", ""), v_website=v.get("website", ""),
                      v_owner=v.get("owner", ""), v_business=v.get("business", ""), v_notes=v.get("notes", ""),
                      sel_found=select("found_via", FOUND_VIA, v.get("found_via", "employee")))


def import_page(error: str = "", ok: str = "", access_error: str = "", access_ok: str = "",
                access_vendor: str = "", access_source: str = "") -> str:
    return tpl.render("import.html", error=notice("error", error), ok=notice("ok", ok),
                      access_form=_access_import_form(access_error, access_ok, access_vendor, access_source))


def _access_import_form(error: str, ok: str, vendor: str, source: str) -> str:
    tracked = sorted((r for r in records.list_vendors() if r.get("slug")), key=lambda r: (r.get("vendor") or "").lower())
    if not tracked:
        return ('<section class="card"><h2>Import live access</h2><p class="muted">Start tracking a vendor first. '
                'An export attaches to a tracked vendor.</p></section>')
    opts = "".join('<option value="%s"%s>%s</option>' % (esc(r["slug"]), " selected" if r["slug"] == vendor else "", esc(r.get("vendor") or r["slug"]))
                   for r in tracked)
    labels = {"entra": "Microsoft Entra ID", "okta": "Okta", "google": "Google Workspace", "saas_audit": "SaaS audit or finance export", "manual": "Hand-made list"}
    src = "".join('<option value="%s"%s>%s</option>' % (k, " selected" if k == source else "", esc(v)) for k, v in labels.items())
    return ('<header class="page-head"><div><h2>Import live access</h2>'
            '<p class="lede">Upload a list of apps connected to a vendor. CSV or JSON. The export replaces that vendor\'s current live access list, '
            'so upload the full list each time. Use the app name, app ID, scopes and last sign-in columns when your export has them.</p></div></header>'
            '<section class="card">' + notice("error", error) + notice("ok", ok) +
            '<form method="post" action="/import/access" enctype="multipart/form-data" class="form narrow">'
            '<label for="ia-vendor">Vendor</label><select id="ia-vendor" name="vendor">%s</select>'
            '<label for="ia-source">Export came from</label><select id="ia-source" name="source">%s</select>'
            '<label for="ia-file">Export file</label><input id="ia-file" type="file" name="file" accept=".csv,.json,text/csv,application/json" required>'
            '<p><button class="btn primary" type="submit">Import apps</button></p>'
            '<p class="muted small">Entra: Enterprise applications, then Download, or the app list from the Graph API as JSON. '
            'Okta: Applications, then Export. Google: Admin console, Security, API controls, App access control. Column names are matched loosely; '
            'a file with no app-name column is rejected with the columns it does have.</p></form></section>'
            % (opts, src))


def entra_result(stats: dict) -> str:
    text = "Read %d users and %d departments: %d already mapped, %d matched an existing unit by name, %d new units flagged for review." % (
        stats.get("rows", 0), stats.get("seen", 0), stats.get("known", 0), stats.get("matched", 0), stats.get("created", 0))
    if stats.get("no_department"):
        text += " %d users had no department and were skipped." % stats["no_department"]
    return text


AI_TONE = {"covered": "green", "partial": "amber", "missing": "red"}
SEVERITY_OPTS = [("high", "High"), ("medium", "Medium"), ("low", "Low")]
DOC_STATUS = {"provided": "Provided", "not_available": "Vendor does not have it", "missing": "Not provided"}


def _ai_area_options(current: str) -> str:
    return "".join('<option value="%s"%s>%s</option>' % (esc(k), " selected" if k == current else "", esc(lab))
                   for k, lab in ai_questionnaire.AREAS)


def ai_page(rec: dict, error: str = "", ok: str = "") -> str:
    """Research, profile and question review for one vendor."""
    slug = rec.get("slug", "")
    s = ai_questionnaire.state(rec)
    status = s.get("status", "")
    configured = llm.configured()

    if status == "running":
        status_html = ('<div class="notice" data-ai-running="1" role="status">Reading the vendor\'s pages and drafting questions. '
                       'This usually takes one to three minutes; the page refreshes itself.</div>')
    elif status == "error":
        status_html = notice("error", "The last run failed: " + (s.get("error") or "unknown error"))
    elif s.get("approved_at"):
        status_html = notice("ok", "Approved by %s on %s with %d questions. Approving again replaces the vendor link." % (
            s.get("approved_by", ""), (s.get("approved_at") or "")[:10], len(s.get("approved") or [])))
    else:
        status_html = ""
    if not configured:
        error = error or "No model is configured on this server. Set LLM_BASE_URL, LLM_API_KEY and LLM_MODEL (or XAI_API_KEY)."

    # Pages read
    r = s.get("research") or {}
    pages_html = ""
    if r:
        rows = "".join('<div class="row srow"><a class="small gold" href="%s" target="_blank" rel="noopener noreferrer">%s</a>'
                       '<span class="small">%s</span><span class="mono small muted">%s chars</span></div>'
                       % (esc(p["url"]), esc(p["url"]), esc(p.get("title", "")[:80]), esc(p.get("chars", 0))) for p in r.get("pages") or [])
        docs = "".join('<li><a class="gold" href="%s" target="_blank" rel="noopener noreferrer">%s</a></li>' % (esc(d), esc(d))
                       for d in r.get("documents") or [])
        errs = "".join("<li>%s: %s</li>" % (esc(e.get("url", "")), esc(e.get("error", ""))) for e in r.get("errors") or [])
        pages_html = ('<details class="pad-b"><summary class="muted small">Read %d page%s from the vendor\'s site</summary>%s%s%s</details>'
                      % (len(r.get("pages") or []), "" if len(r.get("pages") or []) == 1 else "s",
                         rows or '<p class="muted small">No readable pages. The questions assume nothing is published.</p>',
                         ('<p class="muted small">Documents linked from those pages (not read yet):</p><ul class="small">%s</ul>' % docs) if docs else "",
                         ('<p class="muted small">Could not read:</p><ul class="small muted">%s</ul>' % errs) if errs else ""))

    # Profile
    p = s.get("profile") or {}
    profile_html = ""
    if p:
        area_rows = []
        for key, label in ai_questionnaire.AREAS:
            a = (p.get("areas") or {}).get(key) or {}
            st = a.get("status", "missing")
            srcs = " ".join('<a class="gold small" href="%s" target="_blank" rel="noopener noreferrer">source</a>' % esc(u) for u in a.get("sources") or [])
            area_rows.append('<div class="row parow"><div class="strong small">%s</div><div><span class="tone %s">%s</span></div>'
                             '<div class="small">%s %s</div></div>' % (esc(label), AI_TONE.get(st, "grey"), esc(st.title()), esc(a.get("notes", "")), srcs))
        notes = "".join("<li>%s</li>" % esc(n) for n in p.get("product_notes") or [])
        profile_html = (
            '<section class="card"><div class="card-head"><h2>2. What the vendor publishes</h2><span class="pill">Published material: %s</span></div>'
            '%s<p class="pre-line">%s</p><h3 class="label pad-t">Data flow and access</h3><p class="pre-line">%s</p>%s'
            '<p class="muted small">These are the vendor\'s own claims, not verified evidence.</p></section>'
            '<section class="card flush"><div class="card-head padded"><h2>Coverage by area</h2></div>%s</section>'
            % (esc(p.get("published_material", "")),
               ('<p class="strong">%s</p>' % esc(p["engagement"])) if p.get("engagement") else "", esc(p.get("summary", "")), esc(p.get("data_flow", "") or "Not described."),
               ('<h3 class="label pad-t">Specific to this product</h3><ul>%s</ul>' % notes) if notes else "", "".join(area_rows)))

    # Questions
    draft = ai_questionnaire.ordered(s.get("draft") or [])
    questions_html = ""
    if draft:
        rows = []
        for i, q in enumerate(draft):
            tag = ' <span class="muted-tag">also checked by rules</span>' if q.get("feeds") else ""
            src = ' <span class="muted-tag">added by analyst</span>' if q.get("source") == "analyst" else ""
            doc = ""
            if q.get("kind") == "document":
                doc = ('<div class="docline"><span class="muted-tag">document: %s</span><label class="inline-sel">If not provided, flag as %s</label></div>'
                       % (esc(q.get("doc_type") or "see question"), select("q%d_if_missing" % i, SEVERITY_OPTS, q.get("if_missing") or "medium")))
            rows.append(
                '<div class="row qrow"><input type="checkbox" name="q%d_keep" checked aria-label="Keep question %d">'
                '<input type="hidden" name="q%d_id" value="%s"><select name="q%d_area" aria-label="Area">%s</select>'
                '<div><textarea name="q%d_text" rows="2" maxlength="600" aria-label="Question %d">%s</textarea>'
                '<div class="muted small">%s%s%s</div>%s</div><span class="pill">%s</span></div>'
                % (i, i + 1, i, esc(q["id"]), i, _ai_area_options(q["area"]), i, i + 1, esc(q["text"]), esc(q.get("why", "")), tag, src,
                   doc, esc(q.get("priority", "medium"))))
        adds = "".join('<div class="row qrow"><span></span><select name="new%d_area" aria-label="Area for new question">%s</select>'
                       '<div><textarea name="new%d_text" rows="2" maxlength="600" placeholder="Add your own question or document request" aria-label="New question"></textarea>'
                       '<div class="docline"><label class="inline-sel">Type %s</label><label class="inline-sel">If a document is not provided, flag as %s</label></div></div>'
                       '<span></span></div>'
                       % (j, _ai_area_options("governance"), j, select("new%d_kind" % j, [("answer", "Question"), ("document", "Document request")], "answer"),
                          select("new%d_if_missing" % j, SEVERITY_OPTS, "medium")) for j in range(3))
        questions_html = (
            '<section class="card flush"><div class="card-head padded"><h2>3. Questions for the vendor</h2>'
            '<span class="muted small">%d drafted. Untick to drop, edit the wording, or add your own.</span></div>'
            '<form method="post" action="/ai/questions"><input type="hidden" name="slug" value="%s"><input type="hidden" name="n" value="%d">'
            '<div class="row head qrow"><div>Keep</div><div>Area</div><div>Question and why it is asked</div><div>Priority</div></div>%s%s'
            '<div class="pad qactions"><button class="btn ghost" type="submit" name="do" value="save">Save changes</button>'
            '<button class="btn primary" type="submit" name="do" value="approve">Approve and create vendor link</button></div></form></section>'
            % (len(draft), esc(slug), len(draft), "".join(rows), adds))

    busy = status == "running" or not configured
    return tpl.render(
        "ai.html", vendor=rec.get("vendor", ""), slug=slug, model=llm.describe(), error=notice("error", error), ok=notice("ok", ok),
        status=status_html, source_url=s.get("source_url") or rec.get("website", ""), context=s.get("context", ""),
        research_when=("Last run " + _when(r.get("fetched_at", ""))) if r else "",
        draft_label="Research again and redraft" if draft else "Research and draft questions",
        draft_disabled="disabled" if busy else "", pages=pages_html, profile=profile_html, questions=questions_html,
    )


def risk_page(org_id=None) -> str:
    """Per-org dashboard: acceptances rolled up the org tree, with the owner of each unit."""
    today = date.today()
    soon = (today + timedelta(days=30)).isoformat()
    units = risk_store.units()
    by_id = {u["id"]: u for u in units}
    rows = risk_store.acceptances(since=(today - timedelta(days=90)).isoformat())

    def tally(ids):
        mine = [r for r in rows if r["live_unit_id"] in ids]
        live = [r for r in mine if risk_store.is_active(r, today)]
        return {"active": len(live), "high": sum(1 for r in live if r["risk_tier"] in ("high", "critical")),
                "soon": sum(1 for r in live if r["expires_on"] <= soon),
                "reopened": sum(1 for r in mine if r["status"] != "superseded" and not risk_store.is_active(r, today))}

    notice_html, scope = "", None
    if org_id is not None:
        if org_id in by_id:
            scope = risk_store.subtree_ids(org_id, units)
        else:
            notice_html = notice("error", "That unit does not exist or was merged. Showing every unit.")
    shown = [r for r in rows if scope is None or r["live_unit_id"] in scope]
    total = tally(scope if scope is not None else {r["live_unit_id"] for r in rows})

    unit_rows = []
    for u, depth in unit_tree(units):
        t = tally(risk_store.subtree_ids(u["id"], units))
        owner = esc(u["accountable_owner"]) if u["accountable_owner"] else '<span class="tone amber">No owner</span>'
        review = ' <span class="muted-tag">review</span>' if u["needs_review"] else ""
        unit_rows.append(
            '<a class="row orow%s" href="/risk?org=%d"><div style="padding-left:%dpx"><span class="strong">%s</span>%s</div>'
            '<div class="small">%s</div><div class="mono">%d</div><div class="mono%s">%d</div><div class="mono%s">%d</div><div class="mono">%d</div></a>'
            % (" on" if u["id"] == org_id else "", u["id"], 18 * depth, esc(u["name"]), review, owner, t["active"],
               " danger-text" if t["high"] else "", t["high"], " warn-text" if t["soon"] else "", t["soon"], t["reopened"]))

    def order(r):
        return (0 if risk_store.is_active(r, today) else 1, r["expires_on"])
    acc_rows = "".join(
        '<div class="row rrow"><div><a class="strong gold" href="/vendor/%s#risk-acceptance">%s</a><div class="muted small">%s</div></div>'
        '<div>%s</div><div><div class="small">%s</div><div class="muted small">%s</div></div><div class="small">%s</div>%s</div>'
        % (esc(r["vendor_slug"]), esc(r["vendor_name"]), esc(r["detection_text"]), risk_tier_chip(r["risk_tier"]), esc(r["accepter"]),
           esc(risk_rules.LEVEL_LABEL.get(r["accepter_level"], r["accepter_level"])),
           esc(by_id.get(r["live_unit_id"], {}).get("name") or r["unit_name"]), _cell(_expiry_cell(r)))
        for r in sorted(shown, key=order))

    if scope is not None:
        u = by_id[org_id]
        heading = u["name"]
        lede = "Accountable owner: %s. Includes every unit under %s." % (u["accountable_owner"] or "not set", u["name"])
        head_actions = '<a class="btn ghost" href="/risk">All units</a>'
    else:
        heading = "Risk acceptance"
        lede = "Every accepted risk, by the org unit that owns it. Nothing is permanent: when an acceptance expires, its detection opens again."
        head_actions = ""
    return tpl.render(
        "risk.html", heading=heading, lede=lede, head_actions=head_actions, notice=notice_html,
        n_active=total["active"], n_high=total["high"], n_soon=total["soon"], n_reopened=total["reopened"],
        unit_rows="".join(unit_rows) or '<p class="muted pad">No org units yet. Import Entra users or add units on the Org units page.</p>',
        acc_rows=acc_rows or '<p class="muted pad">No acceptances here.</p>',
    )


def orgs_page(who: str, error: str = "", ok: str = "") -> str:
    units = risk_store.units()
    names = {u["id"]: u["name"] for u in units}
    alias_n: dict = {}
    als = risk_store.aliases()
    for a in als:
        alias_n[a["org_unit_id"]] = alias_n.get(a["org_unit_id"], 0) + 1
    rows = []
    for u, depth in unit_tree(units):
        if u["needs_review"]:
            status = '<span class="tone amber">Needs review</span>'
        elif not u["accountable_owner"]:
            status = '<span class="tone grey">No owner</span>'
        else:
            status = '<span class="tone green">Reviewed</span>'
        rows.append(
            '<form method="post" action="/admin/unit" class="row urow"><input type="hidden" name="unit_id" value="%d">'
            '<div style="padding-left:%dpx"><input name="name" value="%s" required maxlength="120" aria-label="Unit name">'
            '<div class="muted small">%d department string%s</div></div>'
            '<select name="parent_id" aria-label="Parent">%s</select>'
            '<input name="owner" value="%s" maxlength="200" placeholder="name@example.com" aria-label="Accountable owner">'
            '<div>%s</div><button class="btn ghost small-btn" type="submit">Save</button></form>'
            % (u["id"], 18 * depth, esc(u["name"]), alias_n.get(u["id"], 0), "" if alias_n.get(u["id"], 0) == 1 else "s",
               _unit_options([x for x in units if x["id"] != u["id"]], u["parent_id"], blank="No parent"),
               esc(u["accountable_owner"]), status))
    alias_rows = "".join(
        '<form method="post" action="/admin/alias" class="row alrow"><input type="hidden" name="alias_key" value="%s">'
        '<div><div class="strong">%s</div><div class="muted small">last seen %s</div></div>'
        '<select name="org_unit_id" aria-label="Unit">%s</select><button class="btn ghost small-btn" type="submit">Move</button></form>'
        % (esc(a["alias_key"]), esc(a["raw"]), esc(_when(a["last_seen"])), _unit_options(units, a["org_unit_id"]))
        for a in als if a["org_unit_id"] in names)
    apps = risk_store.approvers()
    approver_rows = "".join(
        '<form method="post" action="/admin/approver" class="row aprow"><input type="hidden" name="principal" value="%s">'
        '<input type="hidden" name="level" value="remove"><div class="strong">%s</div><div>%s</div>'
        '<div class="muted small">%s · %s</div><button class="btn ghost small-btn" type="submit">Remove</button></form>'
        % (esc(a["principal"]), esc(a["principal"]), esc(risk_rules.LEVEL_LABEL.get(a["level"], a["level"])),
           esc(a["set_by"]), esc(_when(a["set_at"])))
        for a in apps)
    return tpl.render(
        "orgs.html", error=notice("error", error), ok=notice("ok", ok),
        n_units=len(units), n_review=sum(1 for u in units if u["needs_review"]),
        n_no_owner=sum(1 for u in units if not u["accountable_owner"]), n_approvers=len(apps),
        unit_rows="".join(rows) or '<p class="muted pad">No units yet. Import Entra users or add one below.</p>',
        parent_options=_unit_options(units, blank="No parent"), merge_options=_unit_options(units, blank="Choose a unit"),
        alias_rows=alias_rows or '<p class="muted pad">No department strings yet. They arrive with an Entra users import.</p>',
        approver_rows=approver_rows or '<p class="muted pad">No approvers yet. Nobody can sign an acceptance until one is added.</p>',
        level_select=select("level", risk_rules.LEVELS, "director"),
        self_note="" if config.AUTH_MODE == "none" else "You cannot change your own level.",
    )


def policy_page(saved: bool = False) -> str:
    p = policy_store.load()
    yes = p.get("required_region_if_critical", True)
    return tpl.render(
        "policy.html", models="\n".join(p.get("restricted_models") or []), regions="\n".join(p.get("restricted_regions") or []),
        sel_required=select("required_region_if_critical", [("yes", "Yes"), ("no", "No")], "yes" if yes else "no"),
        ok=notice("ok", "Policy saved.") if saved else "",
    )


# ---------------------------------------------------------------- documents

def _doc_link(slug: str, f: dict) -> str:
    stored = f.get("stored_as") or ""
    name = esc(f.get("filename", "") or "file")
    return '<a class="strong gold" href="/evidence/%s/file/%s">%s</a>' % (esc(slug), esc(stored), name) if stored else name


def _doc_period(f: dict) -> str:
    bits = []
    if f.get("period_end"):
        bits.append("period ends " + f["period_end"])
    until = documents.good_until(f)
    if until:
        bits.append(("valid until " if f.get("valid_until") else "stale after ") + until.isoformat())
    return " · ".join(bits) or "no dates"


def _doc_status(f: dict) -> str:
    _code, text, tone = documents.status(f)
    return '<span class="tone %s">%s</span>' % (esc(tone), esc(text))


def _doc_who(f: dict) -> str:
    up = f.get("uploaded_by") or ""
    up = "the vendor" if up.startswith("vendor:") else up or "unknown"
    out = "Added %s by %s" % (_when(f.get("uploaded_at", "")), up)
    if f.get("reviewed_by"):
        out += ". Reviewed %s by %s" % (_when(f.get("reviewed_at", "")), f["reviewed_by"])
    return out


def _review_form(slug: str, f: dict, back: str) -> str:
    verb = "Review again" if f.get("reviewed_by") else "Mark reviewed"
    return (
        '<details class="inline-details"><summary class="gold small">%s</summary>'
        '<form method="post" action="/document/review" class="form">'
        '<input type="hidden" name="slug" value="%s"><input type="hidden" name="doc_id" value="%s"><input type="hidden" name="back" value="%s">'
        '<label>What you checked (optional, saved as a note): scope, period, exceptions, CUECs, bridge letter</label>'
        '<textarea name="note" maxlength="%d"></textarea>'
        '<p><button class="btn primary small-btn" type="submit">Record my review</button></p></form></details>'
        % (esc(verb), esc(slug), esc(f.get("id", "")), esc(back), documents.REVIEW_NOTE_MAX))


def _upload_form(slug: str, back: str) -> str:
    return (
        '<form method="post" action="/evidence" enctype="multipart/form-data" class="form">'
        '<input type="hidden" name="slug" value="%s"><input type="hidden" name="back" value="%s">'
        '<div class="row2"><div><label>Type</label>%s</div><div><label>File (up to %d MB)</label><input type="file" name="file" required></div></div>'
        '<div class="row2"><div><label>Report period ends / test date</label><input type="date" name="period_end"></div>'
        '<div><label>Valid until (moves the matching clock)</label><input type="date" name="valid_until"></div></div>'
        '<label>Description (optional)</label><input name="description" maxlength="%d" placeholder="e.g. FY25 SOC 2 Type II, AWS us-east-1 scope">'
        '<p><button class="btn primary small-btn" type="submit">Upload document</button></p></form>'
        % (esc(slug), esc(back), select("kind", documents.TYPES, "soc2_type2"),
           evidence_store.config.MAX_UPLOAD_BYTES // (1024 * 1024), documents.DESC_MAX))


def _doc_row_compact(slug: str, f: dict) -> str:
    """Narrower row for the vendor page card: file and dates on the left, status and review on the right."""
    desc = (' · %s' % esc(f["description"])) if f.get("description") else ""
    return (
        '<div class="row dcrow"><div>%s<div class="small">%s%s</div><div class="muted small">%s. %s</div></div>'
        '<div class="right">%s%s</div></div>'
        % (_doc_link(slug, f), esc(documents.label(f.get("kind", ""))), desc, esc(_doc_period(f)).capitalize(), esc(_doc_who(f)),
           _doc_status(f), _review_form(slug, f, "vendor")))


def _doc_row(slug: str, f: dict, back: str, vendor: str = "") -> str:
    desc = ('<div class="small">%s</div>' % esc(f["description"])) if f.get("description") else ""
    who = '<a class="muted small" href="/vendor/%s#documents">%s</a> · ' % (esc(slug), esc(vendor)) if vendor else ""
    return (
        '<div class="row drow"><div>%s%s<div class="muted small">%s%s</div></div>'
        '<div><div class="small">%s</div><div class="muted small">%s</div></div>'
        '<div>%s</div><div>%s</div></div>'
        % (_doc_link(slug, f), desc, who, esc(_doc_who(f)), esc(documents.label(f.get("kind", ""))), esc(_doc_period(f)),
           _doc_status(f), _review_form(slug, f, back)))


def _documents_card(rec: dict, slug: str) -> str:
    files = list(reversed(rec.get("evidence_files") or []))
    rows = "".join(_doc_row_compact(slug, f) for f in files[:8])
    more = ('<p class="small pad-t"><a class="gold" href="/evidence/%s">All %d documents</a></p>' % (esc(slug), len(files))) if len(files) > 8 else ""
    waiting = sum(1 for f in files if documents.status(f)[0] == "unreviewed")
    head = ('<p class="muted small">%d document%s waiting for someone to read %s.</p>' % (waiting, "" if waiting == 1 else "s", "it" if waiting == 1 else "them")) if waiting else ""
    return (head + (rows or '<p class="muted">No documents yet. SOC reports, pentests, certificates and contracts go here.</p>') + more
            + '<details class="inline-details pad-t"><summary class="btn ghost small-btn">Upload a document</summary>%s</details>' % _upload_form(slug, "vendor"))


def evidence_page(rec: dict, error: str = "") -> str:
    slug = rec.get("slug") or slugify(rec.get("vendor", ""))
    files = list(reversed(rec.get("evidence_files") or []))
    return tpl.render(
        "evidence.html", vendor=rec.get("vendor", ""), slug=slug, azure=evidence_store.azure_status(),
        error=notice("error", error), upload=_upload_form(slug, "evidence"),
        exts=", ".join(sorted(e.lstrip(".") for e in evidence_store.config.ALLOWED_UPLOAD_EXT)),
        files=("".join(_doc_row(slug, f, "evidence") for f in files) or '<p class="muted pad">Nothing stored yet.</p>'),
    )


DOC_STATUS_FILTER = (("", "Any status"), ("unreviewed", "Not reviewed"), ("expired", "Expired"), ("expiring", "Expiring in 30 days"), ("reviewed", "Reviewed"))


def documents_page(pick: dict) -> str:
    """Every document on every tracked vendor in this workspace, with filters."""
    want_type, want_status, needle = pick.get("type", ""), pick.get("status", ""), (pick.get("q") or "").strip().lower()
    all_rows, tally = [], {"total": 0, "unreviewed": 0, "expired": 0, "expiring": 0}
    for rec in list_vendors():
        slug = rec.get("slug") or slugify(rec.get("vendor", ""))
        for f in rec.get("evidence_files") or []:
            code = documents.status(f)[0]
            tally["total"] += 1
            if code in tally:
                tally[code] += 1
            if want_type and f.get("kind") != want_type:
                continue
            if want_status and code != want_status:
                continue
            hay = " ".join((rec.get("vendor", ""), f.get("filename", ""), f.get("description", ""))).lower()
            if needle and needle not in hay:
                continue
            all_rows.append((f.get("uploaded_at", ""), slug, rec.get("vendor", ""), f))
    all_rows.sort(key=lambda r: r[0], reverse=True)
    rows = "".join(_doc_row(slug, f, "library", vendor) for _at, slug, vendor, f in all_rows[:500])
    return tpl.render(
        "documents.html", n_total=tally["total"], n_unreviewed=tally["unreviewed"], n_expired=tally["expired"], n_expiring=tally["expiring"],
        sel_type=select("type", (("", "Any type"),) + documents.TYPES, want_type),
        sel_status=select("status", DOC_STATUS_FILTER, want_status), q=pick.get("q", ""),
        shown=len(all_rows), rows=rows or '<p class="muted pad">No documents match.</p>',
    )


# ---------------------------------------------------------------- analyst notes

def _notes_card(rec: dict, slug: str) -> str:
    notes = notes_store.for_vendor(slug)
    form = (
        '<form method="post" action="/note" class="form"><input type="hidden" name="slug" value="%s">'
        '<div class="row-inline"><label class="sr-only" for="n-kind">Kind</label>%s</div>'
        '<label class="sr-only" for="n-body">Note</label><textarea id="n-body" name="body" maxlength="%d" required '
        'placeholder="What did you learn, decide or ask? Notes are permanent and signed with your name."></textarea>'
        '<p><button class="btn primary small-btn" type="submit">Add note</button></p></form>'
        % (esc(slug), select("kind", notes_store.KINDS, "general").replace("<select ", '<select id="n-kind" ', 1), notes_store.BODY_MAX))
    items = []
    for n in notes:
        fixed = n["corrected_by"]
        tag = ""
        if n["corrects"]:
            tag = ' <span class="muted-tag">corrects #%d</span>' % n["corrects"]
        if fixed:
            tag += ' <span class="muted-tag">corrected by #%d</span>' % fixed
        doc = ""
        if n["doc_id"]:
            f = documents.find(rec, n["doc_id"])
            doc = (' · on <a class="gold" href="/evidence/%s/file/%s">%s</a>' % (esc(slug), esc(f.get("stored_as", "")), esc(f.get("filename", "")))) if f else ""
        correct = "" if fixed else (
            '<details class="inline-details"><summary class="muted small">Correct this note</summary>'
            '<form method="post" action="/note" class="form"><input type="hidden" name="slug" value="%s"><input type="hidden" name="corrects" value="%d">'
            '<input type="hidden" name="kind" value="%s"><textarea name="body" maxlength="%d" required>%s</textarea>'
            '<p><button class="btn ghost small-btn" type="submit">Save correction</button></p></form></details>'
            % (esc(slug), n["id"], esc(n["kind"]), notes_store.BODY_MAX, esc(n["body"])))
        items.append(
            '<div class="note%s"><div class="note-head"><span class="label">%s</span><span class="mono small muted">#%d</span>%s</div>'
            '<p class="pre-line">%s</p><div class="muted small">%s · %s%s</div>%s</div>'
            % (" struck" if fixed else "", esc(notes_store.LABELS.get(n["kind"], "Note")), n["id"], tag, esc(n["body"]),
               esc(n["author"]), esc(_when(n["created_at"])), doc, correct))
    legacy = rec.get("notes") or ""
    if legacy:
        items.append('<div class="note"><div class="note-head"><span class="label">Intake notes</span></div><p class="pre-line">%s</p>'
                     '<div class="muted small">From intake or a tool report. Change these on the Edit page.</div></div>' % esc(legacy))
    return form + ("".join(items) or '<p class="muted">No notes yet.</p>')


# ---------------------------------------------------------------- vendor record

def _factor_html(factors: dict, unconfirmed=()) -> str:
    out = []
    for key, label, weight in FACTOR_LABELS:
        try:
            n = max(0, min(5, int(factors.get(key, 0))))
        except (TypeError, ValueError):
            n = 0
        pips = "".join('<i class="pip%s"></i>' % (" on" if n >= i else "") for i in range(1, 6))
        note = ' <span class="muted-tag">to confirm</span>' if key in unconfirmed else ""
        out.append('<div class="factor"><div>%s%s</div><div class="pips" aria-label="%d of 5">%s</div><div class="mono small muted right">%s</div></div>'
                   % (esc(label), note, n, pips, esc(weight)))
    return "".join(out)


def _controls_html(controls: dict) -> str:
    auto = {"AI-01", "AI-08", "AI-10"}
    tally = {}
    for v in controls.values():
        tally[v] = tally.get(v, 0) + 1
    head = "".join('<span class="verdict %s">%s <b class="mono">%d</b></span>' % (esc(k.lower().replace("/", "")), esc(k), tally[k])
                   for k in ("Pass", "Partial", "Unknown", "Fail", "n/a") if k in tally)
    cards = "".join(
        '<div class="ctl"><div class="ctl-top"><span class="mono strong">%s</span><span class="small muted">%s</span></div><span class="verdict %s">%s</span></div>'
        % (esc(cid), "Auto-high" if cid in auto else "", esc(v.lower().replace("/", "")), esc(v))
        for cid, v in controls.items())
    return '<div class="verdicts">%s<span class="muted small">Unknown counts as fail under Methodology v0.1.</span></div><div class="ctl-grid">%s</div>' % (head, cards)


def _access_html(rec: dict) -> str:
    """Live access card: rows on live_access[] plus the rule flags they raise. Read-only in v1."""
    rows = access_store.rows(rec)
    flags = access_flags.findings(rec)
    out = []
    for _code, text, sev in flags:
        out.append('<div class="issue %s"><div class="label">%s</div><div class="strong">%s</div></div>' % (esc(sev), esc(sev), esc(text)))
    for r in rows:
        scopes = ", ".join(r.get("scopes") or []) or "no scopes on file"
        out.append(
            '<div class="row lrow"><div><div class="strong">%s</div><div class="muted small">%s · %s · %s</div>'
            '<div class="mono small muted">%s</div></div><span class="pill">%s</span></div>'
            % (esc(r["display_name"]), esc(r["kind"].replace("_", " ")), esc(r["source"]),
               esc("last seen " + _when(r.get("last_seen", ""))), esc(scopes), esc(r["status"])))
    if not rows:
        out.append('<p class="muted">No live access on file. Connectors or an import will fill this; until then the vendor is a blind spot.</p>')
    return "".join(out)


def record_page(rec: dict, *, tracked: bool, demo=None, error: str = "", ok: str = "", who: str = "", accept_draft: dict | None = None,
                threat_error: str = "", threat_draft: dict | None = None, tab: str = "overview", controls_error: str = "") -> str:
    slug = rec.get("slug") or slugify(rec.get("vendor", ""))
    name = rec.get("vendor", "")
    row = next((r for r in portfolio.rows() if r["slug"] == slug), None)
    factors = (demo.factors if demo else None) or rec.get("draft_factors") or {}
    unconfirmed = () if demo else (rec.get("draft_factors") or {}).get("unconfirmed", ())
    provisional = bool(row and row["provisional"])
    chips = []
    if row:
        chips.append("Inherent " + tier_chip(row["inh"]))
        chips.append("Residual " + tier_chip(row["res"], provisional))
    chips.append('<span class="pill">%s</span>' % esc(AUTH_LABEL.get(rec.get("authorization", ""), "Not tracked yet")))
    if row and row["ai"]:
        chips.append('<span class="pill">AI in scope</span>')

    # Banner
    banner = ""
    vendor_acc = risk_store.active_by_vendor().get(slug, {}).get(risk_rules.VENDOR_CODE) if tracked else None
    if row and row["human"] and not vendor_acc:
        why = "Only a signer can accept this risk, and the record keeps who signed and until when."
        if demo and demo.issues:
            why = demo.issues[0] + ". " + why
        banner = ('<section class="banner"><div><div class="strong">A named human must decide this one</div><div>%s</div></div>%s</section>'
                  % (esc(why), '<a class="btn ghost" href="#risk-acceptance">Record risk acceptance</a>' if tracked else ""))
    if vendor_acc:
        chips.append('<span class="pill accepted">Accepted until %s</span>' % esc(vendor_acc["expires_on"]))

    # Actions
    if tracked:
        actions = (
            '<form method="post" action="/followup" class="inline"><input type="hidden" name="slug" value="%s"><button class="btn ghost" type="submit">Send follow-up questions</button></form>'
            '<form method="post" action="/link" class="inline"><input type="hidden" name="slug" value="%s"><input type="hidden" name="kind" value="onboard"><button class="btn ghost" type="submit">New vendor form link</button></form>'
            '<form method="post" action="/renewal" class="inline"><input type="hidden" name="slug" value="%s"><button class="btn ghost" type="submit">Send renewal</button></form>'
            '%s'
            '<a class="btn primary" href="/edit/%s">Edit</a>' % (esc(slug), esc(slug), esc(slug),
                ('<a class="btn ghost" href="/ai/%s">AI questionnaire</a>' % esc(slug)) if llm.enabled() else "", esc(slug)))
    else:
        actions = ('<form method="post" action="/track" class="inline"><input type="hidden" name="slug" value="%s"><button class="btn primary" type="submit">Start tracking this vendor</button></form>' % esc(slug))

    # Clocks
    if tracked:
        cells = alerts.clock_cells(rec)
        tiles = "".join('<div class="clock"><div class="label">%s</div>%s</div>' % (esc(lab), _cell(cells[k]))
                        for k, lab in (("soc", "SOC 2 / ISO"), ("pen", "Pentest"), ("rev", "Next review"), ("mod", "Model list")))
        clocks = (
            '<div class="clocks">%s</div>'
            '<form method="post" action="/clock" class="form"><input type="hidden" name="slug" value="%s">'
            '<div class="row3"><div><label>SOC 2 / ISO expires</label><input name="soc2_expires" type="date" value="%s"></div>'
            '<div><label>Pentest expires</label><input name="pentest_expires" type="date" value="%s"></div>'
            '<div><label>Next security review</label><input name="next_review" type="date" value="%s"></div></div>'
            '<label>Contract ends</label><input name="contract_end" type="date" value="%s">'
            '<label>SOC 2 / ISO link</label><input name="soc2_url" maxlength="500" value="%s">'
            '<label>Pentest report link (full findings, not the executive page)</label><input name="pentest_url" maxlength="500" value="%s">'
            '<p><button class="btn primary" type="submit">Save dates</button> <a class="btn ghost" href="#documents">Documents</a></p></form>'
            % (tiles, esc(slug), esc(rec.get("soc2_expires", "")), esc(rec.get("pentest_expires", "")),
               esc(rec.get("next_review") or rec.get("renewal_date") or ""), esc(rec.get("contract_end", "")), esc(rec.get("soc2_url", "")), esc(rec.get("pentest_url", ""))))
    else:
        clocks = '<p class="muted">Start tracking this vendor to add SOC 2, pentest and review dates.</p>'

    # Live access
    access = _access_html(rec) if tracked else '<p class="muted">Start tracking this vendor to see live access.</p>'
    synced = rec.get("live_access_synced_at")
    access_synced = ("Updated " + _when(synced)) if synced else ""

    # Factors + controls
    if factors:
        risk = '<div class="muted small pad-b">Each factor is scored 0 to 5 and weighted.%s</div>%s' % (
            " These are drafted from the questionnaire, so an analyst must confirm them." if provisional else "", _factor_html(factors, unconfirmed))
    else:
        risk = '<p class="muted">Not scored yet. The questionnaire drafts factor scores once the vendor answers.</p>'
    controls = _controls_html(demo.controls) if demo and demo.controls else ""

    # Follow-ups
    fu = []
    for f in rec.get("followups") or []:
        if f.get("status") != "open":
            continue
        fu.append(
            '<div class="issue %s"><div class="label">%s</div><div class="strong">%s</div><div class="muted small">%s</div>'
            '<form method="post" action="/resolve" class="inline"><input type="hidden" name="slug" value="%s"><input type="hidden" name="fid" value="%s">'
            '<button class="btn ghost small-btn" type="submit">Mark resolved</button></form></div>'
            % (esc(f.get("severity", "medium")), esc(f.get("severity", "medium")), esc(f.get("title", "")), esc(f.get("detail", "")),
               esc(slug), esc(f.get("id", ""))))
    if demo and demo.issues:
        for i in demo.issues:
            fu.append('<div class="issue medium"><div class="label">Scoring</div><div class="strong">%s</div></div>' % esc(i))
    issues = "".join(fu) or '<p class="muted">None open.</p>'

    # Risk acceptance
    accept = _acceptance_html(rec, who, tracked, accept_draft)
    if tracked:
        danger = (
            '<section class="card danger-zone"><h2>Danger zone</h2><p class="muted small">Offboarding keeps the record for audit and cancels vendor links. '
            'Purging deletes it for good, so type the vendor name to confirm.</p>'
            '<form method="post" action="/offboard" class="inline"><input type="hidden" name="slug" value="%s"><button class="btn ghost" type="submit">Mark offboarded</button></form>'
            '<form method="post" action="/purge" class="purge"><input type="hidden" name="slug" value="%s">'
            '<label>Type <b>%s</b> to purge</label><input name="confirm" autocomplete="off" required>'
            '<p><button class="btn danger" type="submit">Purge record</button></p></form></section>' % (esc(slug), esc(slug), esc(name)))
    else:
        danger = ""

    # Factsheet
    facts = rec.get("factsheet") or {}
    gaps = facts.get("gaps") or []
    fact_txt = json.dumps(facts, indent=2) if facts else "No factsheet yet."
    if gaps:
        fact_txt = "Gaps:\n- " + "\n- ".join(gaps) + "\n\n" + fact_txt

    # Questionnaire tab
    labels = _all_question_labels()
    ans = {}
    for k in ("answers", "renewal_answers", "followup_answers"):
        ans.update(rec.get(k) or {})
    # AI questionnaire answers are shown under their own question text. The copies made
    # into rule fields (ai_mapped_keys) are not shown twice.
    for k in rec.get("ai_mapped_keys") or []:
        ans.pop(k, None)
    for q in ((rec.get("ai_q") or {}).get("approved") or []):
        labels[q["id"]] = q["text"]
    ans.update(rec.get("ai_answers") or {})
    names = {f.get("stored_as"): f.get("filename", "") for f in rec.get("evidence_files") or []}
    for qid, d in (rec.get("ai_docs") or {}).items():
        files = ", ".join(names.get(s, s) for s in d.get("files") or [])
        ans[qid] = DOC_STATUS.get(d.get("status"), "Not provided") + (": " + files if files else "") + (". " + d["note"] if d.get("note") else "")
    dl = "".join('<div class="qa"><div class="muted small">%s</div><div>%s</div></div>' % (esc(labels.get(k, k)), esc(v) or '<span class="muted">No answer</span>')
                 for k, v in ans.items()) or '<p class="muted">The vendor has not submitted answers yet.</p>'
    subs = "".join('<div class="row srow"><span class="mono small">%s</span><span>%s</span><span class="muted small">%d answers</span></div>'
                   % (esc(_when(s.get("at", ""))), esc(s.get("kind", "")), len(s.get("answers") or {})) for s in reversed(rec.get("submissions") or []))

    # Activity tab
    act = "".join('<div class="row arow"><div class="mono small muted">%s</div><div><div class="strong">%s</div><div class="muted small">%s%s</div></div></div>'
                  % (esc(_when(e.get("at", ""))), esc(e.get("action", "").replace("_", " ")), esc(e.get("actor", "")),
                     (" · " + esc(e.get("detail"))) if e.get("detail") else "")
                  for e in audit.for_slug(slug)) or '<p class="muted pad">No activity recorded yet.</p>'

    # Threat model tab: computed from the record, rendered by threat_views (imported here: it imports this module).
    import threat_views
    threat_html = (threat_views.panel(rec, who=who, error=threat_error, draft=threat_draft) if tracked
                   else '<p class="muted">Start tracking this vendor to build its threat model.</p>')
    tab_keys = {}
    import integrations_views
    integrations_html = (integrations_views.vendor_panel(rec) if tracked
                         else '<p class="muted">Start tracking this vendor to record its integrations.</p>')
    import controls_views
    controls_html = (controls_views.vendor_panel(rec, controls_error) if tracked
                     else '<p class="muted">Start tracking this vendor to check it against your control objectives.</p>')
    for k in ("overview", "questionnaire", "integrations", "controls", "threat", "activity"):
        tab_keys["on_" + k] = " on" if k == tab else ""
        tab_keys["sel_" + k] = "true" if k == tab else "false"
        tab_keys["hide_" + k] = "" if k == tab else " hidden"
    sub = rec.get("business") or rec.get("website") or rec.get("source") or ""
    return tpl.render(
        "record.html", vendor=name, slug=slug, sub=sub, chips="  ".join(chips), banner=banner, actions=actions,
        error=notice("error", error), ok=notice("ok", ok), clocks=clocks, access=access, access_synced=access_synced, risk=risk, controls=controls,
        controls_class="" if controls else "hidden", issues=issues, accept=accept,
        notes=_notes_card(rec, slug) if tracked else '<p class="pre-line">%s</p><p class="muted small">Start tracking this vendor to add notes.</p>' % esc(rec.get("notes") or "No notes."),
        docs=_documents_card(rec, slug) if tracked else '<p class="muted">Start tracking this vendor to store documents.</p>',
        danger=danger, facts=fact_txt, answers=dl, submissions=subs or '<p class="muted small">No submissions yet.</p>',
        activity=act, inh_score=(row or {}).get("score", "–"), threat=threat_html, integrations=integrations_html, ctl_tab=controls_html, **tab_keys,
    )


# ------------------------------------------------------------------ people (ENTROPY_AUTH=accounts)
def people_page(me: dict, error: str = "", ok: str = "", link: str = "", link_for: str = "") -> str:
    import accounts
    users = accounts.list_users()
    tones = {"active": ("green", "Active"), "invited": ("amber", "Invited"), "disabled": ("grey", "Disabled")}
    rows = []
    for u in users:
        tone, label = tones.get(u["status"], ("grey", u["status"]))
        if u["status"] == "active" and u["locked_until"] and u["locked_until"] > time.time():
            tone, label = "red", "Locked"
        acts = []

        def btn(action, text, cls="ghost"):
            return ('<form method="post" action="/people" class="inline"><input type="hidden" name="action" value="%s">'
                    '<input type="hidden" name="uid" value="%d"><button class="btn %s small-btn" type="submit">%s</button></form>'
                    % (esc(action), u["id"], cls, esc(text)))
        if u["id"] != me["id"]:
            acts.append(btn("reset", "Reset sign-in" if u["status"] != "invited" else "New invite link"))
            if u["status"] == "disabled":
                acts.append(btn("enable", "Enable"))
            elif u["status"] == "active":
                acts.append(btn("disable", "Disable", "danger"))
            if u.get("view_only"):
                acts.append(btn("unviewer", "Allow changes"))
            else:
                acts.append(btn("unadmin", "Remove admin") if u["is_admin"] else btn("admin", "Make admin"))
                if not u["is_admin"]:
                    acts.append(btn("viewer", "Make view-only"))
        else:
            acts.append('<span class="muted small">This is you. <a class="gold" href="/account">Change password</a></span>')
        who_html = '<div class="strong">%s%s</div><div class="muted small">%s</div>' % (
            esc(u["name"] or u["email"]), ' <span class="pill">Admin</span>' if u["is_admin"] else ' <span class="pill">View only</span>' if u.get("view_only") else "", esc(u["email"]))
        last = _when(u["last_login"]) if u["last_login"] else ("Invite expires " + _when(u["invite_expires"]) if u["status"] == "invited" else "Never")
        rows.append('<div class="row peoprow"><div>%s</div><div><span class="tone %s">%s</span></div><div class="muted small">%s</div><div class="acts">%s</div></div>'
                    % (who_html, tone, esc(label), esc(last), "".join(acts)))
    link_html = ""
    if link:
        link_html = ('<section class="card"><div class="label">One-time setup link for %s</div>'
                     '<div class="linkbox"><code id="setup-link">%s</code><button class="btn ghost" type="button" data-copy="#setup-link">Copy</button></div>'
                     '<p class="muted small">Send it to that person only. It works once, expires in %d hours, and is shown here only now. '
                     'They choose a password and scan a code with an authenticator app.</p></section>'
                     % (esc(link_for), esc(link), accounts.INVITE_HOURS))
    n = {s: sum(1 for u in users if u["status"] == s) for s in ("active", "invited", "disabled")}
    import mailer
    if mailer.configured():
        mail_option = ('<label class="check"><input type="checkbox" name="email_link" value="1" checked> Email the one-time link to them</label>'
                       '<p><button class="btn primary" type="submit">Create invite</button></p>'
                       '<p class="muted small">The link is also shown here once. It expires in %d hours.</p>' % accounts.INVITE_HOURS)
    else:
        mail_option = ('<p><button class="btn primary" type="submit">Create invite link</button></p>'
                       '<p class="muted small">Email is not set up on this server, so you get a one-time link to send the person yourself. '
                       'It expires in %d hours.</p>' % accounts.INVITE_HOURS)
    return tpl.render("people.html", error=notice("error", error), ok=notice("ok", ok), link=link_html, mail_option=mail_option, rows="".join(rows) or '<p class="muted pad">No accounts yet.</p>',
                      n_active=n["active"], n_invited=n["invited"], n_disabled=n["disabled"], hours=accounts.INVITE_HOURS)


def account_page(me: dict, error: str = "", ok: str = "") -> str:
    return tpl.render("account.html", email=me["email"], admin=" · admin" if me["is_admin"] else " · view-only" if me.get("view_only") else "",
                      error=notice("error", error), ok=notice("ok", ok))
