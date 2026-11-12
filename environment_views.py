"""HTML for Your environment: setup, import, the environment map and per-system drill-downs."""
from __future__ import annotations

from urllib.parse import quote

import environment as env
import integrations as ig
from tpl import esc

SEV_COLOR = {"high": "#c0392b", "medium": "#e07020", "low": "#24476b", "": "#7d8fa3"}
COL_X = (170, 510, 850)
NW, NH, ROW = 236, 48, 62


def _resolve(party: str, tenants: dict) -> str:
    if party.startswith("sys-") or party == ig.YOU:
        return party
    return tenants.get(party, party)


def map_svg(focus: str = "") -> str:
    systems = env.systems()
    tenants = {}
    for s in systems:
        if s["vendor"] and s["vendor"] not in tenants:
            tenants[s["vendor"]] = (env.tenant_of(s["vendor"]) or s)["id"]
    by_id = {s["id"]: s for s in systems}
    ov = ig.overview()
    names = ov["names"]
    vendors = ig._vendors()
    pairs: dict[tuple, dict] = {}
    used = set()
    for r in ov["live"]:
        a, b = _resolve(r["source"], tenants), _resolve(r["target"], tenants)
        if a == b:
            continue
        used.update((a, b))
        key = tuple(sorted((a, b)))
        e = pairs.setdefault(key, {"items": [], "worst": ""})
        e["items"].append(r["name"])
        if ig.SEVERITY_RANK.get(r["worst"], 0) > ig.SEVERITY_RANK.get(e["worst"], 0):
            e["worst"] = r["worst"]
    # Connected systems first, so lines run across rather than behind unconnected boxes.
    col_a = sorted([s["id"] for s in systems if s["kind"] != "saas_tenant"], key=lambda i: i not in used) + ([ig.YOU] if ig.YOU in used else [])
    col_b = sorted([s["id"] for s in systems if s["kind"] == "saas_tenant"], key=lambda i: i not in used)
    col_c = sorted([p for p in used if p not in by_id and p != ig.YOU], key=lambda p: names.get(p, p).lower())
    cols = [col_a, col_b, col_c]
    rows = max(len(c) for c in cols) or 1
    height = 90 + rows * ROW
    pos = {}
    for ci, col in enumerate(cols):
        top = 70
        for i, p in enumerate(col):
            pos[p] = (COL_X[ci], top + i * ROW + NH / 2)

    def clip(c, t):
        dx, dy = t[0] - c[0], t[1] - c[1]
        k = min((NW / 2 + 4) / abs(dx) if dx else 1e9, (NH / 2 + 4) / abs(dy) if dy else 1e9)
        return c[0] + dx * k, c[1] + dy * k

    out = ['<svg class="ig-map" viewBox="0 0 1020 %d" role="img" font-family="Helvetica, Arial, sans-serif" '
           'aria-label="Map of your systems, your SaaS tenants and the vendors connected to them">' % height,
           '<rect width="1020" height="%d" fill="#ffffff"/>' % height]
    for x, label in zip(COL_X, ("Your core environment", "Your SaaS tenants", "Vendors and outside services")):
        out.append('<text x="%d" y="32" font-size="13" font-weight="bold" fill="#24476b" text-anchor="middle">%s</text>' % (x, esc(label)))
    for (a, b), e in pairs.items():
        if a not in pos or b not in pos:
            continue
        pa, pb = pos[a], pos[b]
        color = SEV_COLOR[e["worst"]]
        dim = focus and focus not in (a, b)
        op = ' opacity="0.25"' if dim else ""
        out.append('<g%s><title>%s</title>' % (op, esc("; ".join(e["items"]))))
        if pa[0] == pb[0]:  # same column: bow out to the side
            side = -1 if pa[0] == COL_X[0] else 1
            s1, s2 = (pa[0] + side * NW / 2, pa[1]), (pb[0] + side * NW / 2, pb[1])
            cx = pa[0] + side * (NW / 2 + 40 + abs(pa[1] - pb[1]) / 8)
            out.append('<path d="M%.1f %.1f Q %.1f %.1f %.1f %.1f" fill="none" stroke="%s" stroke-width="%.1f"/>' % (
                s1[0], s1[1], cx, (pa[1] + pb[1]) / 2, s2[0], s2[1], color, 1.4 + min(len(e["items"]), 6) * 0.5))
        else:
            p1, p2 = clip(pa, pb), clip(pb, pa)
            out.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="%.1f"/>' % (
                p1[0], p1[1], p2[0], p2[1], color, 1.4 + min(len(e["items"]), 6) * 0.5))
        out.append("</g>")
    for p, (x, y) in pos.items():
        s = by_id.get(p)
        if s:
            href, name = "/environment/%s" % quote(p), s["name"]
            sub = env.KINDS[s["kind"]] + (" · critical" if s["criticality"] == "high" else "")
            fill, stroke, dash = "#eef3f9", "#24476b", ""
        elif p == ig.YOU:
            href, name, sub, fill, stroke, dash = "/environment", names.get(p, p), "General", "#eef3f9", "#24476b", ""
        else:
            rec = vendors.get(p) or {}
            ok = rec.get("authorization") == "authorized"
            href, name = "/vendor/%s#integrations" % quote(p), names.get(p, p)
            sub = "Vendor" + ("" if ok else " · not authorized")
            fill, stroke, dash = "#ffffff", "#24476b" if ok else "#c0392b", "" if ok else ' stroke-dasharray="6 4"'
        width = 2.6 if p == focus else 1.5
        short = name if len(name) <= 30 else name[:29] + "…"
        out.append('<a href="%s"><g><title>%s</title><rect x="%.1f" y="%.1f" width="%d" height="%d" rx="7" fill="%s" stroke="%s" '
                   'stroke-width="%s"%s/><text x="%.1f" y="%.1f" font-size="13" font-weight="bold" fill="#1f2937" text-anchor="middle">%s</text>'
                   '<text x="%.1f" y="%.1f" font-size="11" fill="%s" text-anchor="middle">%s</text></g></a>' % (
                       esc(href), esc(name), x - NW / 2, y - NH / 2, NW, NH, fill, "#e07020" if p == focus else stroke, width, dash,
                       x, y - 3, esc(short), x, y + 13, "#c0392b" if "not authorized" in sub else "#4b5563", esc(sub)))
    out.append('<text x="12" y="%d" font-size="11.5" fill="#4b5563">Lines are integrations, coloured by the worst finding. '
               'Click any box to drill in. Integrations recorded against a vendor that hosts one of your tenants are drawn to that tenant.</text>' % (height - 12))
    out.append("</svg>")
    return "".join(out)


def _setup_form() -> str:
    prof = env.profile()
    rows = []
    for key, label, _kind, choices in env.SETUP:
        cur = prof.get(key, "")
        opts = '<option value="">None or not sure</option>' + "".join(
            '<option%s>%s</option>' % (" selected" if c == cur else "", esc(c)) for c in choices)
        other = cur if cur and cur not in choices else ""
        rows.append('<div><label>%s</label><select name="%s">%s</select><input name="%s_other" maxlength="120" '
                    'placeholder="Other: type it" value="%s"></div>' % (esc(label), key, opts, key, esc(other)))
    clouds = "".join('<label class="checkline inline"><input type="checkbox" name="cloud_%s" value="on"%s> %s</label>' % (
        k, " checked" if lab in (prof.get("clouds") or []) else "", esc(lab)) for k, lab in env.CLOUDS)
    stores = "\n".join("%s | %s | %s" % (s["name"], ", ".join(s["data_classes"]), s["location"]) for s in env.systems() if s["kind"] == "data_store")
    return (
        '<details class="card ig-add"%s><summary class="strong">Guided setup: your stack and your rules</summary>'
        '<form method="post" action="/environment/setup" class="tm-form">'
        '<div class="row-inline"><div><label>Organisation name</label><input name="org_name" maxlength="120" value="%s"></div>'
        '<div><label>Default secret rotation (days)</label><input name="rotation_days" type="number" min="1" max="3650" value="%s"></div>'
        '<div><label>Default owner</label><input name="owner" maxlength="120"></div></div>'
        '<div class="row-inline"><div><label>Security contact shown to vendors (email)</label>'
        '<input name="security_contact" type="email" maxlength="200" placeholder="security@yourco.com" value="%s"></div>'
        '<div><label>Fix high findings within (days)</label><input name="due_high" type="number" min="1" max="3650" value="%d"></div>'
        '<div><label>Medium</label><input name="due_medium" type="number" min="1" max="3650" value="%d"></div>'
        '<div><label>Low</label><input name="due_low" type="number" min="1" max="3650" value="%d"></div></div>'
        '<label>Your own classification labels and data that count as sensitive (one per line)</label>'
        '<textarea name="sensitive_terms" rows="3" placeholder="Restricted&#10;Confidential&#10;claims data">%s</textarea>'
        '<div class="env-grid">%s</div><label>Clouds and sites</label><div class="row-inline">%s</div>'
        '<label>Where sensitive data lives, one per line: name | data | location</label>'
        '<textarea name="stores" rows="3" placeholder="Claims database | claims data, PHI | Azure East US">%s</textarea>'
        '<p><button class="btn primary small-btn" type="submit">Save my environment</button></p></form></details>' % (
            "" if env.systems() else " open", esc(prof.get("org_name", "")), esc(env.rotation_days()),
            esc(env.security_contact()), env.finding_days()["high"], env.finding_days()["medium"], env.finding_days()["low"],
            esc("\n".join(prof.get("sensitive_terms") or [])), "".join(rows), clouds, esc(stores)))


def _import_form() -> str:
    return ('<details class="card ig-add"><summary class="strong">Import systems from a CMDB or asset list</summary>'
            '<form method="post" action="/environment/import" enctype="multipart/form-data" class="tm-form">'
            '<input type="file" name="file" accept=".csv,.json,text/csv,application/json" required>'
            '<p class="muted small">CSV or JSON. Columns are matched loosely: name, class or type, owner, business criticality, '
            'data classification, environment, location, product or vendor. A ServiceNow CMDB export works as is. Rows with the same '
            'name replace the earlier import.</p><p><button class="btn ghost small-btn" type="submit">Import</button></p></form></details>')


def _add_system_form() -> str:
    kinds = "".join('<option value="%s">%s</option>' % (k, esc(v)) for k, v in env.KINDS.items())
    import records
    vend = '<option value="">Not hosted by a tracked vendor</option>' + "".join(
        '<option value="%s">%s</option>' % (esc(r["slug"]), esc(r.get("vendor"))) for r in sorted(
            records.list_vendors(), key=lambda r: (r.get("vendor") or "").lower()) if r.get("slug"))
    crit = "".join('<option value="%s"%s>%s</option>' % (c, " selected" if c == "medium" else "", c.capitalize()) for c in env.CRITICALITY)
    return ('<details class="card ig-add"><summary class="strong">Add a system by hand</summary>'
            '<form method="post" action="/environment/system" class="tm-form">'
            '<div class="row-inline"><div><label>Name</label><input name="name" maxlength="200" required></div>'
            '<div><label>Kind</label><select name="kind">%s</select></div><div><label>Criticality</label><select name="criticality">%s</select></div></div>'
            '<div class="row-inline"><div><label>Hosted by</label><select name="vendor">%s</select></div>'
            '<div><label>Owner</label><input name="owner" maxlength="120"></div><div><label>Location</label><input name="location" maxlength="120"></div></div>'
            '<label>Data it holds (comma separated)</label><input name="data_classes" maxlength="400">'
            '<p><button class="btn ghost small-btn" type="submit">Add system</button></p></form></details>' % (kinds, crit, vend))


def _exposure_table(rows: list[dict]) -> str:
    body = "".join(
        '<tr><td><a class="gold" href="/environment/%s">%s</a><div class="muted small">%s%s</div></td><td>%s</td><td class="small">%s</td>'
        '<td>%d</td><td>%d</td><td class="small">%s</td><td>%s</td></tr>' % (
            esc(quote(e["system"]["id"])), esc(e["system"]["name"]), esc(env.KINDS[e["system"]["kind"]]),
            (" · hosted by %s" % esc(e["system"]["vendor"].replace("_", " "))) if e["system"]["vendor"] else "",
            esc(e["system"]["criticality"].capitalize()), esc(", ".join(e["system"]["data_classes"][:4])),
            len(e["reach"]), len(e["strong"]), esc(e["system"]["owner"] or "No owner"),
            ('<span class="sev %s">%s</span>' % (e["worst"], e["worst"].capitalize())) if e["worst"] else '<span class="tone green">Clear</span>')
        for e in rows)
    return ('<table class="tm-table"><thead><tr><th>System</th><th>Criticality</th><th>Data</th><th>Vendors reaching it</th>'
            '<th>Write or admin grants</th><th>Owner</th><th>Worst</th></tr></thead><tbody>%s</tbody></table>' % body)


def page(error: str = "", ok: str = "") -> str:
    from views import notice
    rows = env.exposure()
    prof = env.profile()
    stack = ", ".join(v for k, v in prof.items() if k in {s[0] for s in env.SETUP}) or "not set up yet"
    return ('<header class="page-head"><div><h1 class="big">Your environment</h1><p class="lede">%s: the systems you run or rent, '
            'and every way a vendor reaches them. Your stack: %s.</p></div><div class="head-actions wrap">'
            '<a class="btn ghost small-btn" href="/executive">Executive summary</a></div></header>' % (esc(env.org_name()), esc(stack))
            + notice("error", error) + notice("ok", ok)
            + '<section class="card"><div class="card-head"><h2>Environment map</h2><span class="muted small">%d systems</span></div>'
              '<figure class="tm-figure">%s</figure></section>' % (len(rows), map_svg())
            + '<section class="card"><div class="card-head"><h2>Systems and who can reach them</h2></div>%s</section>' % (
                _exposure_table(rows) if rows else '<p class="muted">No systems yet. Start with the guided setup.</p>')
            + _setup_form() + _import_form() + _add_system_form())


def system_page(sid: str) -> str:
    import integrations_views as iv
    e = next((x for x in env.exposure() if x["system"]["id"] == sid), None)
    if not e:
        return '<p class="muted">That system does not exist.</p>'
    s = e["system"]
    facts = [("Kind", env.KINDS[s["kind"]]), ("Product", s["product"] or "—"),
             ("Hosted by", s["vendor"].replace("_", " ") if s["vendor"] else "You"), ("Criticality", s["criticality"].capitalize()),
             ("Data it holds", ", ".join(s["data_classes"]) or "Not recorded"), ("Owner", s["owner"] or "No owner"),
             ("Environment", s["environment"]), ("Location", s["location"] or "—"), ("Source", s["source"])]
    fact_rows = "".join('<tr><td class="muted">%s</td><td>%s</td></tr>' % (esc(k), esc(v)) for k, v in facts)
    names = ig.party_names()
    reach = "".join('<li>%s</li>' % esc(names.get(p, p)) for p in e["reach"]) or "<li>None recorded</li>"
    ov = ig.overview()
    rows = [r for r in ov["rows"] if r["id"] in {i["id"] for i in e["integrations"]}]
    grants = [{"platform": s["name"], "name": g["name"], "grant": g["grant"], "class": ig.scope_class(g["name"], g["grant"]),
               "tenant_wide": ig.tenant_wide(g["name"], g["grant"]),
               "used_by": [r["name"] for r in rows if g in r["scopes"]]} for g in e["grants"]]
    cards = "".join(iv._card(r, s["vendor"] or sid) for r in rows) or '<p class="muted">No integrations touch this system yet.</p>'
    return ('<nav class="crumbs"><a class="gold" href="/environment">Your environment</a><span aria-hidden="true">/</span><span>%s</span></nav>'
            '<header class="page-head"><div><h1 class="big">%s</h1><p class="lede">%d vendor%s reach this system; %d hold write or admin '
            'grants in it.%s</p></div></header>' % (
                esc(s["name"]), esc(s["name"]), len(e["reach"]), "" if len(e["reach"]) == 1 else "s", len(e["strong"]),
                (" Not authorized: %s." % esc(", ".join(names.get(u, u) for u in e["unapproved"]))) if e["unapproved"] else "")
            + '<section class="card"><figure class="tm-figure">%s</figure></section>' % map_svg(focus=sid)
            + '<div class="two-col"><section class="card"><h2>About this system</h2><table class="tm-table"><tbody>%s</tbody></table>'
              '<form method="post" action="/environment/%s/remove" class="inline"><button class="btn ghost small-btn" type="submit">'
              'Remove from environment</button></form></section>'
              '<section class="card"><h2>Who can reach it</h2><ul class="ig-qs">%s</ul></section></div>' % (fact_rows, esc(quote(sid)), reach)
            + '<section class="card"><div class="card-head"><h2>Grants in this system</h2></div>%s</section>' % iv._scope_table(grants)
            + '<h2 class="ig-section">Integrations</h2>' + cards)


def anticipated_card(rec: dict) -> str:
    import anticipate
    items = anticipate.connections(rec)
    stack = anticipate.their_stack(rec)
    cat = anticipate.CATEGORY_LABEL.get(rec.get("category") or "", "Not set")
    if not env.systems():
        hint = ('<p class="muted small">Set up <a class="gold" href="/environment">Your environment</a> so RiskPrism can predict '
                'what this vendor will need from your stack.</p>')
    elif not rec.get("category"):
        hint = '<p class="muted small">Set the vendor category (Edit) to predict the connections a vendor like this usually needs.</p>'
    else:
        hint = ""
    rows = []
    for i, it in enumerate(items):
        scopes = ", ".join("%s (%s)" % (n, g) for n, g in it["scopes"]) or "No permissions; configuration only"
        action = ('<span class="tone green">Recorded</span>' if it["recorded"] else
                  '<form method="post" action="/integrations/anticipate" class="inline"><input type="hidden" name="slug" value="%s">'
                  '<input type="hidden" name="key" value="%s"><button class="btn ghost small-btn" type="submit">Add as planned</button></form>'
                  % (esc(rec.get("slug")), esc(it["key"])))
        rows.append('<div class="ig-path"><div class="strong">%s %s</div><div class="small"><span class="muted">Expected permissions:</span> '
                    '<span class="mono">%s</span></div>%s<div class="small"><span class="muted">Data:</span> %s</div>'
                    '<div class="small"><span class="muted">Ask:</span> %s</div><div class="tm-actions">%s</div></div>' % (
                        esc(it["title"]), '<span class="tone blue">Anticipated</span>' if not it["recorded"] else "", esc(scopes),
                        ('<div class="small"><span class="muted">Narrower option:</span> %s</div>' % esc(it["narrower"])) if it["narrower"] else "",
                        esc(", ".join(it["data"])), esc(it["question"]), action))
    st = "".join('<tr><td>%s</td><td>%s</td></tr>' % (esc(c["component"]),
                                                    esc(c["value"]) if c["declared"] else '<span class="tone grey">Not declared</span>')
                 for c in stack)
    return ('<details class="card ig-card" open><summary class="strong">Anticipated from your stack <span class="muted small">'
            'category: %s</span></summary><p class="muted small">Predicted from the vendor category and Your environment. Each item stays '
            '"anticipated" until it is recorded and confirmed.</p>%s%s<h3 class="ig-h">Their stack: what a vendor like this runs on</h3>'
            '<table class="tm-table"><tbody>%s</tbody></table></details>' % (
                esc(cat), hint, "".join(rows) or '<p class="muted small">No connections predicted.</p>', st))
