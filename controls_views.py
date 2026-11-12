"""HTML for control objectives: the cross-vendor matrix, the objective library and the vendor tab."""
from __future__ import annotations

from urllib.parse import quote

import control_objectives as co
from tpl import esc

STATUS_TONE = {"met": "green", "partial": "amber", "not_met": "red", "unknown": "grey", "na": "na"}
STATUS_MARK = {"met": "✓", "partial": "◐", "not_met": "✕", "unknown": "?", "na": "–"}


def chip(status: str) -> str:
    return '<span class="co-chip %s">%s</span>' % (esc(status), esc(co.STATUS_LABEL[status]))


def _cell(slug: str, r: dict) -> str:
    title = "%s: %s. %s%s" % (r["objective"]["id"], co.STATUS_LABEL[r["status"]], " ".join(r["evidence"]),
                              (" Attested by %s." % r["attested"]["by"]) if r["attested"] else "")
    return ('<td class="co-td"><a class="co-cell %s%s" href="/vendor/%s#controls" title="%s" aria-label="%s">%s</a></td>'
            % (r["status"], " att" if r["attested"] else "", esc(quote(slug)), esc(title), esc(title), STATUS_MARK[r["status"]]))


def _refs(o: dict, fw: str = "") -> str:
    if fw:
        return esc(o["refs"].get(fw, ""))
    return "; ".join("%s %s" % (lab, o["refs"][k]) for k, lab in co.FRAMEWORKS if o["refs"].get(k))


def dashboard(fw: str = "nist", error: str = "", ok: str = "") -> str:
    from views import notice
    m = co.matrix()
    fw = fw if fw in dict(co.FRAMEWORKS) else "nist"
    fopts = "".join('<option value="%s"%s>%s</option>' % (k, " selected" if k == fw else "", esc(lab)) for k, lab in co.FRAMEWORKS)
    t = m["totals"]
    tiles = [("Objectives in force", len(m["objectives"]), ""), ("Vendors assessed", len(m["rows"]), ""),
             ("Met across vendors", ("%d%%" % m["pct"]) if m["pct"] is not None else "–", ""),
             ("Not met", t.get("not_met", 0), "danger-text" if t.get("not_met") else ""),
             ("Unknown", t.get("unknown", 0), "warn-text" if t.get("unknown") else ""),
             ("Partly met", t.get("partial", 0), "")]
    kpis = '<section class="kpis ig-kpis">%s</section>' % "".join(
        '<div class="kpi"><div class="label">%s</div><div class="num %s">%s</div></div>' % (esc(a), c, esc(b)) for a, b, c in tiles)

    head_cells = "".join('<th class="co-th" title="%s"><span>%s</span></th>' % (esc(o["title"]), esc(o["id"])) for o in m["objectives"])
    body = []
    for r in m["rows"]:
        body.append('<tr><td class="co-vendor"><a class="gold" href="/vendor/%s#controls">%s</a><div class="muted small">%s</div></td>%s'
                    '<td class="co-pct">%s</td></tr>' % (
                        esc(quote(r["slug"])), esc(r["rec"].get("vendor") or r["slug"]), esc(r["tier"] or "Unscored"),
                        "".join(_cell(r["slug"], x) for x in r["results"]),
                        ("%d%%" % r["pct"]) if r["pct"] is not None else "–"))
    legend = " ".join('<span class="co-cell %s">%s</span> %s' % (s, STATUS_MARK[s], esc(co.STATUS_LABEL[s])) for s in co.STATUSES)
    matrix = ('<div class="co-scroll"><table class="co-matrix"><thead><tr><th>Vendor</th>%s<th>Met</th></tr></thead>'
              '<tbody>%s</tbody></table></div><p class="muted small co-legend">%s · outlined = attested by an analyst. '
              'Hover or tap a cell for the evidence.</p>' % (head_cells, "".join(body), legend))

    obj_rows = "".join(
        '<tr><td class="mono small">%s</td><td><div class="strong">%s</div><div class="muted small">%s</div></td><td class="small">%s</td>'
        '<td class="small">%s</td><td class="small">%s</td><td>%d / %d / %d / %d</td><td>%s</td></tr>' % (
            esc(p["objective"]["id"]), esc(p["objective"]["title"]), esc(p["objective"]["domain"]),
            esc(", ".join(p["objective"]["tiers"])), _refs(p["objective"], fw) or '<span class="muted">—</span>',
            esc(p["objective"].get("owner") or ""), p["met"], p["partial"], p["not_met"], p["unknown"],
            ("%d%%" % p["pct"]) if p["pct"] is not None else "–") for p in m["per_objective"])
    summary = ('<table class="tm-table"><thead><tr><th>ID</th><th>Objective</th><th>Applies to</th><th>%s</th><th>Owner</th>'
               '<th>Met / partly / not / unknown</th><th>Met</th></tr></thead><tbody>%s</tbody></table>' % (
                   esc(dict(co.FRAMEWORKS)[fw]), obj_rows))

    return ('<header class="page-head"><div><h1 class="big">Control objectives</h1>'
            '<p class="lede">What every vendor relationship must achieve, checked against the evidence, answers, live access, '
            'integrations and threat models RiskPrism already holds. Fixed rules, no model.</p></div>'
            '<div class="head-actions wrap"><form method="get" action="/controls" class="inline row-inline">'
            '<select name="fw" aria-label="Framework">%s</select><button class="btn ghost small-btn" type="submit">Show references</button>'
            '</form><a class="btn ghost small-btn" href="#library">Manage objectives</a></div></header>' % fopts
            + notice("error", error) + notice("ok", ok) + kpis
            + '<section class="card"><div class="card-head"><h2>Vendors against objectives</h2></div>%s</section>' % matrix
            + '<section class="card"><div class="card-head"><h2>By objective</h2><span class="muted small">References are a '
              'starting map; confirm them against the version you are audited to.</span></div>%s</section>' % summary
            + library_html())


def library_html() -> str:
    tiers_box = lambda chosen, prefix="": "".join(
        '<label class="checkline inline"><input type="checkbox" name="%stier_%s" value="on"%s> %s</label>' % (
            prefix, t, " checked" if t in chosen else "", t) for t in co.TIERS)
    items = []
    for o in co.library():
        checks = "; ".join(co.CHECKS[c][0] for c in o["checks"] if c in co.CHECKS) or "Manual attestation only"
        items.append(
            '<details class="card ig-card"><summary><span class="mono small">%s</span> <span class="strong">%s</span> '
            '<span class="muted small">%s</span> %s</summary><p class="small">%s</p><p class="muted small">Checked by: %s<br>%s</p>'
            '<form method="post" action="/controls/objective" class="tm-form"><input type="hidden" name="oid" value="%s">'
            '<label class="checkline"><input type="checkbox" name="enabled" value="on"%s> In force</label>'
            '<label>Applies to tiers</label><div class="row-inline">%s</div>'
            '<label>Owner</label><input name="owner" maxlength="120" value="%s">'
            '<p><button class="btn ghost small-btn" type="submit">Save</button></p></form></details>' % (
                esc(o["id"]), esc(o["title"]), esc(o["domain"]),
                "" if o["enabled"] else '<span class="tone grey">Off</span>',
                esc(o["statement"]), esc(checks), esc(_refs(o)), esc(o["id"]), " checked" if o["enabled"] else "",
                tiers_box(o["tiers"]), esc(o.get("owner") or "")))
    checks = "".join('<label class="checkline"><input type="checkbox" name="check_%s" value="on"> %s</label>' % (esc(k), esc(lab))
                     for k, (lab, _f) in co.CHECKS.items())
    domains = "".join('<option>%s</option>' % esc(d) for d in co.DOMAINS)
    refs = "".join('<div><label>%s</label><input name="ref_%s" maxlength="120"></div>' % (esc(lab), k) for k, lab in co.FRAMEWORKS)
    add = ('<details class="card ig-add"><summary class="strong">Add your own objective</summary>'
           '<form method="post" action="/controls/add" class="tm-form">'
           '<label>Title</label><input name="title" maxlength="160" required>'
           '<label>Statement: what must be true</label><textarea name="statement" rows="2" maxlength="600"></textarea>'
           '<div class="row-inline"><div><label>Domain</label><select name="domain">%s</select></div>'
           '<div><label>Owner</label><input name="owner" maxlength="120"></div></div>'
           '<label>Applies to tiers</label><div class="row-inline">%s</div>'
           '<label>Checked by (pick any; none means analysts attest it per vendor)</label><div class="co-checks">%s</div>'
           '<label>Framework references</label><div class="row-inline co-refs">%s</div>'
           '<p><button class="btn primary small-btn" type="submit">Add objective</button></p></form></details>' % (
               domains, tiers_box(co.TIERS), checks, refs))
    return ('<section id="library"><header class="page-head"><div><h2>Objective library</h2><p class="lede">Built-in objectives can be '
            'switched off, scoped to tiers and given an owner. Your own objectives apply to every vendor in the tiers you pick.</p>'
            '</div></header>%s%s</section>' % ("".join(items), add))


def vendor_panel(rec: dict, error: str = "") -> str:
    from views import notice
    res = co.evaluate(rec)
    slug = rec.get("slug", "")
    counts = {s: sum(1 for r in res if r["status"] == s) for s in co.STATUSES}
    scope = len(res) - counts["na"]
    head = ('<section class="card"><div class="card-head"><h2>Control objectives</h2><a class="gold small" href="/controls">All vendors</a></div>'
            '<p class="small">%s of %d objectives met. %d not met, %d unknown, %d partly met. Unknown is not a pass.</p></section>' % (
                counts["met"], scope, counts["not_met"], counts["unknown"], counts["partial"]))
    rows = []
    order = {s: i for i, s in enumerate(("not_met", "unknown", "partial", "met", "na"))}
    for r in sorted(res, key=lambda r: (order[r["status"]], r["objective"]["id"])):
        o = r["objective"]
        att = r["attested"]
        att_html = ('<div class="small">Attested <b>%s</b> by %s: %s <span class="muted">(automatic result: %s)</span></div>' % (
            esc(co.STATUS_LABEL[att["status"]]), esc(att["by"]), esc(att["note"]), esc(co.STATUS_LABEL[r["auto"]]))) if att else ""
        sel = "".join('<option value="%s">%s</option>' % (s, esc(co.STATUS_LABEL[s])) for s in co.STATUSES)
        form = ('<details class="co-attest"><summary class="small gold">Attest a result</summary>'
                '<form method="post" action="/controls/attest" class="tm-form"><input type="hidden" name="slug" value="%s">'
                '<input type="hidden" name="oid" value="%s"><div class="row-inline"><select name="status">%s'
                '<option value="clear">Remove attestation</option></select></div>'
                '<label>Why (for example the compensating control)</label><textarea name="note" rows="2" maxlength="600"></textarea>'
                '<p><button class="btn ghost small-btn" type="submit">Save</button></p></form></details>' % (esc(slug), esc(o["id"]), sel))
        rows.append('<tr><td class="mono small">%s</td><td><div class="strong">%s</div><div class="muted small">%s</div>%s</td>'
                    '<td>%s</td><td class="small">%s%s</td></tr>' % (
                        esc(o["id"]), esc(o["title"]), esc(_refs(o)), form, chip(r["status"]),
                        esc(" ".join(r["evidence"])), att_html))
    return notice("error", error) + head + ('<section class="card"><table class="tm-table co-vendor-table"><thead><tr><th>ID</th>'
                                            '<th>Objective</th><th>Result</th><th>Evidence</th></tr></thead><tbody>%s</tbody></table></section>'
                                            % "".join(rows))
