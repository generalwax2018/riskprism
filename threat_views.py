"""HTML for the Threat model tab on the vendor record. Computed live from the record.

Forms only, no scripts, so the strict CSP holds. The tab is one panel of the vendor
page: it does not render its own page chrome, and it posts back to the vendor page.
"""
from __future__ import annotations

import risk_rules
import risk_store
import threat_diagram
import threat_model as tm
from tpl import esc
from views import notice


def _opt(value, label, current) -> str:
    sel = " selected" if str(current if current is not None else "") == str(value) else ""
    return '<option value="%s"%s>%s</option>' % (esc(value), sel, esc(label))


def _rating_chip(t: dict) -> str:
    if not t.get("rating"):
        return '<span class="pill">Unrated</span>'
    return '<span class="pill">%s (%sx%s)</span>' % (esc(tm.rating_label(t["rating"])), t.get("likelihood"), t.get("impact"))


def _decision_chip(t: dict) -> str:
    if t.get("expired"):
        return '<span class="pill accepted">Acceptance expired</span>'
    if not t.get("decided"):
        return '<span class="pill">Needs decision</span>'
    return '<span class="pill">%s</span>' % esc(tm.DISPOSITIONS_LABEL.get(t.get("disposition"), "Open"))


def _state_pill(info: dict) -> str:
    labels = {"draft": "Draft", "current": "Reviewed", "needs_review": "Needs review"}
    tone = "accepted" if info["state"] in ("current", "needs_review") else ""
    return '<span class="pill %s">%s</span>' % (tone, esc(labels.get(info["state"], info["state"])))


def _threat_form(slug: str, t: dict, draft: dict | None) -> str:
    d = draft if draft is not None else None

    def val(key, default=""):
        return d.get(key, default) if d is not None else default

    scale = [("", "Not rated")] + [(str(n), str(n)) for n in tm.SCALE]
    lik = "".join(_opt(v, lbl, val("likelihood", "" if t.get("likelihood") is None else t["likelihood"])) for v, lbl in scale)
    imp = "".join(_opt(v, lbl, val("impact", "" if t.get("impact") is None else t["impact"])) for v, lbl in scale)
    disp = "".join(_opt(k, tm.DISPOSITIONS_LABEL[k], val("disposition", t.get("disposition") or "open")) for k in tm.DISPOSITIONS)
    mit = val("mitigations", "\n".join(t.get("mitigations") or []))
    return (
        '<form method="post" action="/threat/%s/threat" class="tm-form">'
        '<input type="hidden" name="tid" value="%s">'
        '<label>Scenario: how this could happen here</label>'
        '<textarea name="scenario" rows="3" maxlength="1000">%s</textarea>'
        '<div class="row-inline"><div><label>Likelihood (1 rare to 5 expected)</label><select name="likelihood">%s</select></div>'
        '<div><label>Impact (1 minor to 5 severe)</label><select name="impact">%s</select></div></div>'
        '<label>Disposition</label><select name="disposition">%s</select>'
        '<label>Mitigations, one per line (needed to mitigate)</label>'
        '<textarea name="mitigations" rows="3">%s</textarea>'
        '<label>Why this rating</label><input name="rating_basis" maxlength="500" value="%s">'
        '<label>Accepted until (only when accepting)</label><input type="date" name="accepted_until" value="%s">'
        '<p class="muted small">Accepting needs an approver for this rating and an expiry date. Rating is likelihood times impact: '
        '20 or more is Critical, 12 to 19 High, 6 to 11 Medium, 5 or less Low.</p>'
        '<p><button class="btn primary small-btn" type="submit">Save threat</button></p>'
        '</form>'
        % (esc(slug), esc(t["id"]), esc(val("scenario", t.get("scenario") or "")), lik, imp, disp, esc(mit),
           esc(val("rating_basis", t.get("rating_basis") or "")), esc(val("accepted_until", t.get("accepted_until") or ""))))


def _threat_block(slug: str, t: dict, draft: dict | None, boundary_name: str) -> str:
    stride = ", ".join(tm.stride_label(c) for c in t.get("stride") or "") or "n/a"
    if t.get("lens") == "privacy":
        stride += " (privacy lens)"
    mine = draft if draft is not None and draft.get("tid") == t["id"] else None
    open_it = " open" if mine is not None else ""
    return (
        '<details class="tm-threat"%s id="%s"><summary><span class="strong">%s</span> %s '
        '<span class="muted small">%s</span> %s %s</summary>'
        '<p class="small muted">%s</p>%s</details>'
        % (open_it, esc(t["id"]), esc(t["id"]), esc(boundary_name), esc(stride), _rating_chip(t), _decision_chip(t),
           esc(t.get("scenario") or t.get("text", "")), _threat_form(slug, t, mine)))


def _retired_block(t: dict, boundary_name: str) -> str:
    return ('<div class="tm-threat muted"><span class="strong">%s</span> %s <span class="muted small">no longer applies to this vendor. '
            'Decision kept: %s, %s.</span></div>'
            % (esc(t["id"]), esc(boundary_name), esc(tm.DISPOSITIONS_LABEL.get(t.get("disposition"), "Open")),
               esc(tm.rating_label(t.get("rating")))))


def _question_block(slug: str, q: dict) -> str:
    return (
        '<details class="tm-threat"><summary><span class="strong">%s</span> %s '
        '<span class="pill">%s</span></summary>'
        '<form method="post" action="/threat/%s/question" class="tm-form">'
        '<input type="hidden" name="qid" value="%s">'
        '<label>Answer</label><textarea name="answer" rows="2" maxlength="1000">%s</textarea>'
        '<label>Owner</label><input name="owner" maxlength="80" value="%s">'
        '<p><button class="btn ghost small-btn" type="submit">Save answer</button></p></form></details>'
        % (esc(q["id"]), esc(q["text"]), esc("Answered" if q.get("status") == "answered" else "Open"),
           esc(slug), esc(q["id"]), esc(q.get("answer") or ""), esc(q.get("owner") or "")))


def panel(rec: dict, who: str = "", error: str = "", draft: dict | None = None) -> str:
    """The tab body. draft is the form the analyst just submitted, so a rejected entry is not lost."""
    slug = rec.get("slug", "")
    model = tm.build(rec)
    info = model["status"]
    level = risk_store.approver_level(who) if who else ""
    if level == "director":
        approver_line = "You are registered as %s, so you can accept Low and Medium threats." % risk_rules.LEVEL_LABEL[level]
    elif level:
        approver_line = "You are registered as %s, so you can accept threats in any tier." % risk_rules.LEVEL_LABEL[level]
    else:
        approver_line = "You are not a registered approver. You can rate threats, but an approver must accept them."

    parts = [notice("error", error)]
    if info["state"] == "needs_review":
        parts.append(notice("error", "Needs review: %s. Review again to make this version current." % "; ".join(info["changes"])))
    last = ("Version %d, reviewed %s by %s" % (model["version"], tm.when(model["reviewed_at"]), model["reviewed_by"] or "?")
            if model["reviewed_at"] else "Not reviewed yet")
    parts.append(
        '<div class="card"><div class="card-head"><div><h2>Threat model</h2>'
        '<p class="muted small">Built live from this vendor\'s record: systems, data flows, trust boundaries and fixed STRIDE and '
        'privacy prompts. Only the analyst\'s decisions are stored. %s</p></div><div class="right">%s</div></div>'
        '<div class="tm-actions"><a class="btn ghost small-btn" href="/threat/%s/export.docx">Export Word</a>'
        '<a class="btn ghost small-btn" href="/threat/%s/export.pdf">Export PDF</a></div>'
        '<p class="muted small">%s</p></div>'
        % (esc(approver_line), _state_pill(info), esc(slug), esc(slug), esc(last)))

    if info["undecided"]:
        parts.append('<div class="card"><h2>Review</h2><p class="muted">%d threat%s still need a decision: open, unrated, or past '
                     'acceptance expiry. Decide each one before review.</p></div>'
                     % (info["undecided"], "" if info["undecided"] == 1 else "s"))
    else:
        parts.append('<div class="card"><h2>Review</h2>'
                     '<form method="post" action="/threat/%s/review" class="tm-form">'
                     '<label>What changed, or why this version is ready (optional)</label>'
                     '<textarea name="note" rows="2" maxlength="300"></textarea>'
                     '<p><button class="btn primary small-btn" type="submit">Mark this version reviewed</button></p></form></div>'
                     % esc(slug))

    # 1. Document control
    history = model["history"]
    hist_rows = "".join(
        '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d threats, %d accepted, %d open questions</td></tr>'
        % (esc(h["version"]), esc(tm.when(h["reviewed_at"])), esc(h["reviewed_by"]), esc(h.get("note") or ""),
           h["summary"]["threats"], h["summary"]["accepted"], h["summary"]["open_questions"])
        for h in reversed(history))
    parts.append('<div class="card"><h2>1. Document control</h2>%s</div>' % (
        ('<table class="tm-table"><thead><tr><th>Version</th><th>Reviewed</th><th>By</th><th>Note</th><th>Summary</th></tr></thead>'
         '<tbody>%s</tbody></table>' % hist_rows) if hist_rows else '<p class="muted small">No reviewed versions yet.</p>'))

    # 2. Scope summary
    snap = model["inputs"]
    facts = [("Business", rec.get("business")), ("Authorization", rec.get("authorization")), ("Stage", rec.get("stage")),
             ("Delivery", tm.mode_label(rec.get("mode"))), ("Data classes", snap.get("data_classes")),
             ("Hosting regions", snap.get("hosting")), ("Tenancy", snap.get("tenancy")),
             ("Single sign-on and MFA", snap.get("sso")), ("AI used on our data", snap.get("ai_used")),
             ("Model provider", snap.get("model_provider")), ("Models", snap.get("models"))]
    fact_rows = "".join('<tr><td>%s</td><td>%s</td></tr>' % (esc(k), esc(v or "Not recorded")) for k, v in facts)
    parts.append('<div class="card"><h2>2. Scope summary</h2><table class="tm-table"><tbody>%s</tbody></table></div>' % fact_rows)

    # 3. Target design (the one free-text section the analyst writes)
    parts.append('<div class="card"><h2>3. Proposed target design</h2>'
                 '<form method="post" action="/threat/%s/design" class="tm-form">'
                 '<label>Describe how the service is built and used for us</label>'
                 '<textarea name="design" rows="4" maxlength="3000">%s</textarea>'
                 '<p><button class="btn ghost small-btn" type="submit">Save design</button></p></form></div>'
                 % (esc(slug), esc(model["design_statement"])))

    # 4-6. Systems, flows and boundaries
    sys_rows = "".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
        esc(s["id"]), esc(s["name"]), esc(s.get("owner")), esc(s.get("does")), esc(s.get("auth")), esc(s.get("status")))
        for s in model["systems"])
    parts.append('<div class="card"><h2>4. System inventory</h2><table class="tm-table"><thead><tr><th>ID</th><th>System</th>'
                 '<th>Owner</th><th>What it does</th><th>Authentication</th><th>Status</th></tr></thead><tbody>%s</tbody></table></div>' % sys_rows)
    name_by_id = {tm.TB_ID[k]: b["name"] for k, b in tm.BOUNDARY_BY_KEY.items()}
    flow_rows = "".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
        esc(f["id"]), esc(f["from"]), esc(f["to"]), esc(f["data"]), esc(name_by_id.get(f["boundary"], f["boundary"])))
        for f in model["flows"])
    diagram = threat_diagram.layout(rec, model)
    parts.append('<div class="card"><div class="card-head"><h2>5. Data flow and trust boundaries</h2>'
                 '<a class="gold small" href="/threat/%s/diagram.svg">Download diagram (SVG)</a></div>'
                 '<figure class="tm-figure">%s<figcaption class="muted small">%s Red dashed flows cross a boundary the record '
                 'has not confirmed; answering the open questions turns them solid.</figcaption></figure>'
                 '<table class="tm-table"><thead><tr><th>ID</th><th>From</th><th>To</th>'
                 '<th>Data</th><th>Crosses</th></tr></thead><tbody>%s</tbody></table></div>'
                 % (esc(slug), threat_diagram.svg(diagram), esc(diagram["caption"]), flow_rows))
    bnd_rows = "".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
        esc(b["id"]), esc(b["name"]), esc(b["crosses"]), esc(b["status"])) for b in model["boundaries"])
    parts.append('<div class="card"><h2>6. Trust boundaries</h2><table class="tm-table"><thead><tr><th>ID</th><th>Boundary</th>'
                 '<th>What crosses it</th><th>Status</th></tr></thead><tbody>%s</tbody></table></div>' % bnd_rows)

    # 7. Threats
    blocks = "".join(_threat_block(slug, t, draft, name_by_id.get(t["boundary"], t["boundary"])) for t in model["threats"])
    retired = "".join(_retired_block(t, name_by_id.get(t["boundary"], t["boundary"])) for t in model["retired"])
    parts.append('<div class="card"><h2>7. Threat table</h2><p class="muted small">Each threat stays a draft prompt until someone '
                 'writes the scenario, rates it and chooses a disposition.</p>%s%s</div>'
                 % (blocks or '<p class="muted small">No threats apply to this vendor.</p>', retired))

    # 8. Open questions
    q_html = "".join(_question_block(slug, q) for q in model["questions"]) or '<p class="muted small">No open questions.</p>'
    parts.append('<div class="card"><h2>8. Open questions</h2>%s</div>' % q_html)

    # 9. Sign-off
    accepted = [t for t in model["threats"] if t["disposition"] == "accept" and t["decided"]]
    acc_rows = "".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
        esc(t["id"]), esc(t.get("scenario") or ""), esc(tm.rating_label(t.get("rating"))), esc(t.get("accepted_by")),
        esc(t.get("accepted_until"))) for t in accepted)
    acc_html = ('<table class="tm-table"><thead><tr><th>ID</th><th>Scenario</th><th>Rating</th><th>Accepted by</th>'
                '<th>Until</th></tr></thead><tbody>%s</tbody></table>' % acc_rows) if acc_rows else '<p class="muted small">No threats are accepted.</p>'
    parts.append('<div class="card"><h2>9. Sign-off</h2>%s</div>' % acc_html)
    return '<div class="threat-panel">%s</div>' % "".join(parts)
