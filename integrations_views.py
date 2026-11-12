"""HTML for the integration data layer: the central dashboard and the per-vendor tab.

Server-rendered, no scripts (strict CSP). The map is inline SVG drawn from the same roll-up
the tables use, so the picture and the numbers always agree.
"""
from __future__ import annotations

from urllib.parse import quote

import integrations as ig
from tpl import esc

SEV_COLOR = {"high": "#c0392b", "medium": "#e07020", "low": "#24476b", "": "#7d8fa3"}
CLASS_TONE = {"admin": "red", "write": "amber", "session": "blue", "read": "green", "identity": "grey", "other": "grey"}
CLASS_LABEL = {"admin": "Admin", "write": "Write / act", "session": "Session", "read": "Read", "identity": "Identity", "other": "Other"}


def _sev(s: str) -> str:
    return '<span class="sev %s">%s</span>' % (esc(s), esc(s.capitalize())) if s else '<span class="tone green">Clear</span>'


def _party_link(slug: str, name: str) -> str:
    if slug == ig.YOU:
        return esc(name)
    return '<a class="gold" href="/vendor/%s#integrations">%s</a>' % (esc(quote(slug)), esc(name))


# ------------------------------------------------------------------ map
NODE_W, NODE_H = 184, 58
HUBS = [(330, 250), (690, 250)]
TOP = [(150, 70), (510, 70), (870, 70)]
BOTTOM = [(150, 430), (510, 430), (870, 430)]
MAX_NODES = len(HUBS) + len(TOP) + len(BOTTOM)


def _edge_point(cx, cy, tx, ty):
    dx, dy = tx - cx, ty - cy
    if dx == 0 and dy == 0:
        return cx, cy
    t = min((NODE_W / 2 + 6) / abs(dx) if dx else 1e9, (NODE_H / 2 + 6) / abs(dy) if dy else 1e9)
    return cx + dx * t, cy + dy * t


def _arrow(x1, y1, x2, y2, color):
    dx, dy = x2 - x1, y2 - y1
    n = (dx * dx + dy * dy) ** 0.5 or 1
    ux, uy = dx / n, dy / n
    bx, by = x2 - ux * 10, y2 - uy * 10
    return '<polygon points="%.1f,%.1f %.1f,%.1f %.1f,%.1f" fill="%s"/>' % (
        x2, y2, bx - uy * 5, by + ux * 5, bx + uy * 5, by - ux * 5, color)


def map_svg(ov: dict, focus: str | None = None) -> str:
    live = ov["live"]
    if not live:
        return '<p class="muted">No integrations recorded yet.</p>'
    degree: dict[str, int] = {}
    for r in live:
        for p in (r["source"], r["target"]):
            degree[p] = degree.get(p, 0) + 1
    order = sorted(degree, key=lambda p: (p != focus, -degree[p], ov["names"].get(p, p)))
    shown, hidden = order[:MAX_NODES], order[MAX_NODES:]
    hubs, rest = shown[:2], shown[2:]
    # Put each other party nearest the hub it connects to most: left for the first hub, right for the second.
    links = {}
    for r in live:
        for a, b in ((r["source"], r["target"]), (r["target"], r["source"])):
            links[(a, b)] = links.get((a, b), 0) + 1

    def lean(p):
        return links.get((p, hubs[0]), 0) - (links.get((p, hubs[1]), 0) if len(hubs) > 1 else 0)
    rest.sort(key=lambda p: (-lean(p), ov["names"].get(p, p)))
    pos = {p: HUBS[i] for i, p in enumerate(hubs)}
    top, bottom = rest[:3], rest[3:]
    for row, slots in ((top, TOP), (bottom, BOTTOM)):
        if len(row) == 1:
            pos[row[0]] = slots[1]
        elif len(row) == 2:
            pos[row[0]], pos[row[1]] = slots[0], slots[2]
        else:
            for p, slot in zip(row, slots):
                pos[p] = slot
    height = 520 if bottom else 360
    if len(hubs) == 1:
        pos[hubs[0]] = (510, 250)

    pairs: dict[tuple, dict] = {}
    for r in live:
        a, b = sorted((r["source"], r["target"]))
        if a not in pos or b not in pos:
            continue
        e = pairs.setdefault((a, b), {"items": [], "worst": "", "dirs": set()})
        e["items"].append(r["name"])
        if ig.SEVERITY_RANK.get(r["worst"], 0) > ig.SEVERITY_RANK.get(e["worst"], 0):
            e["worst"] = r["worst"]
        for f in r["flows"]:
            e["dirs"].add((f["from"], f["to"]))

    vendors = {s: rec for s, rec in ig._vendors().items()}
    out = ['<svg class="ig-map" viewBox="0 0 1020 %d" role="img" font-family="Helvetica, Arial, sans-serif" '
           'aria-label="Map of integrations between your organisation and your vendors, coloured by the worst finding">' % height,
           '<rect width="1020" height="%d" fill="#ffffff"/>' % height]
    for (a, b), e in pairs.items():
        color = SEV_COLOR[e["worst"]]
        (ax, ay), (bx, by) = pos[a], pos[b]
        p1, p2 = _edge_point(ax, ay, bx, by), _edge_point(bx, by, ax, ay)
        out.append('<g><title>%s</title>' % esc("; ".join(e["items"])))
        out.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="%.1f"/>' % (
            p1[0], p1[1], p2[0], p2[1], color, 1.6 + min(len(e["items"]), 6) * 0.6))
        if (a, b) in e["dirs"]:
            out.append(_arrow(p1[0], p1[1], p2[0], p2[1], color))
        if (b, a) in e["dirs"]:
            out.append(_arrow(p2[0], p2[1], p1[0], p1[1], color))
        # Label near the outer party, so labels on crossing lines do not stack in the middle.
        t = 0.5
        if (a in hubs) != (b in hubs):
            t = 0.7 if a in hubs else 0.3
        mx, my = p1[0] + (p2[0] - p1[0]) * t, p1[1] + (p2[1] - p1[1]) * t
        label = "%d integration%s" % (len(e["items"]), "" if len(e["items"]) == 1 else "s")
        w = len(label) * 6.4 + 14
        out.append('<rect x="%.1f" y="%.1f" width="%.1f" height="20" rx="10" fill="#ffffff" stroke="%s"/>' % (mx - w / 2, my - 10, w, color))
        out.append('<text x="%.1f" y="%.1f" font-size="11.5" font-weight="bold" fill="%s" text-anchor="middle">%s</text></g>' % (
            mx, my + 4, color, esc(label)))
    for p in shown:
        x, y = pos[p]
        rec = vendors.get(p) or {}
        unapproved = p != ig.YOU and rec.get("authorization") != "authorized"
        fill = "#eef3f9" if p == ig.YOU else "#ffffff"
        stroke = "#c0392b" if unapproved else ("#24476b" if p != focus else "#e07020")
        name = ov["names"].get(p, p)
        out.append('<g><title>%s</title><rect x="%.1f" y="%.1f" width="%d" height="%d" rx="8" fill="%s" stroke="%s" stroke-width="%s"%s/>' % (
            esc(name), x - NODE_W / 2, y - NODE_H / 2, NODE_W, NODE_H, fill, stroke, 2.4 if p == focus else 1.6,
            ' stroke-dasharray="6 4"' if unapproved else ""))
        short = name if len(name) <= 24 else name[:23] + "…"
        out.append('<text x="%.1f" y="%.1f" font-size="14" font-weight="bold" fill="#1f2937" text-anchor="middle">%s</text>' % (x, y - 3, esc(short)))
        sub = "%d integration%s%s" % (degree[p], "" if degree[p] == 1 else "s", " · not authorized" if unapproved else "")
        out.append('<text x="%.1f" y="%.1f" font-size="11.5" fill="%s" text-anchor="middle">%s</text></g>' % (
            x, y + 15, "#c0392b" if unapproved else "#4b5563", esc(sub)))
    legend = ("Line colour = worst finding on that connection (red high, orange medium, blue low, grey clear). "
              "Arrows = direction data moves. Dashed red box = vendor not authorized.")
    out.append('<text x="12" y="%d" font-size="11.5" fill="#4b5563">%s</text>' % (height - 12, esc(legend)))
    if hidden:
        out.append('<text x="1008" y="%d" font-size="11.5" fill="#4b5563" text-anchor="end">+ %d more not drawn</text>' % (height - 12, len(hidden)))
    out.append("</svg>")
    return "".join(out)


# ------------------------------------------------------------------ shared blocks
def _kpis(m: dict) -> str:
    tiles = [
        ("Integrations", m["integrations"], "", "between %d parties" % m["parties"]),
        ("High findings", m["high"], "danger-text" if m["high"] else "", "integrations with a high finding"),
        ("Admin or tenant-wide write grants", m["app_write"], "warn-text" if m["app_write"] else "", "app-only, no user involved"),
        ("Secrets past rotation", m["secrets"], "warn-text" if m["secrets"] else "", "or with no rotation date"),
        ("Sensitive data flows", m["sensitive_flows"], "", "email, chat, HR, personal, tickets"),
        ("Declared vs observed drift", m["drift"], "danger-text" if m["drift"] else "", "live access differs from the record"),
        ("No named owner", m["no_owner"], "warn-text" if m["no_owner"] else "", "nobody answers for it"),
    ]
    return '<section class="kpis ig-kpis" aria-label="Summary">%s</section>' % "".join(
        '<div class="kpi"><div class="label">%s</div><div class="num %s">%d</div><div class="muted small">%s</div></div>'
        % (esc(label), cls, n, esc(note)) for label, n, cls, note in tiles)


def _findings_list(rows: list[dict], limit: int | None = None) -> str:
    items = []
    for r in sorted(rows, key=lambda r: -ig.SEVERITY_RANK.get(r["worst"], 0)):
        for code, text, sev in r["findings"]:
            items.append((ig.SEVERITY_RANK[sev], r, text, sev))
    items.sort(key=lambda x: -x[0])
    if limit:
        items = items[:limit]
    if not items:
        return '<p class="muted">No findings.</p>'
    return "".join('<div class="row ig-frow">%s<div><div class="strong">%s</div><div class="small">%s</div></div></div>'
                   % (_sev(sev), esc(r["name"]), esc(text)) for _rank, r, text, sev in items)


def _scope_table(scopes: list[dict]) -> str:
    if not scopes:
        return '<p class="muted small">No scopes or roles recorded.</p>'
    rows = "".join('<tr><td>%s</td><td class="mono small">%s</td><td>%s</td><td><span class="tone %s">%s</span></td><td>%s</td><td class="small">%s</td></tr>'
                   % (esc(s["platform"]), esc(s["name"]), esc(s["grant"]), CLASS_TONE[s["class"]], esc(CLASS_LABEL[s["class"]]),
                      "Yes" if s["tenant_wide"] else "", esc("; ".join(s["used_by"]))) for s in scopes)
    return ('<table class="tm-table"><thead><tr><th>Granted in</th><th>Permission or role</th><th>Grant</th><th>Class</th>'
            '<th>Tenant-wide</th><th>Used by</th></tr></thead><tbody>%s</tbody></table>' % rows)


def _flow_table(flows: list[dict]) -> str:
    if not flows:
        return '<p class="muted small">No data flows recorded.</p>'
    rows = "".join('<tr><td>%s → %s</td><td>%s</td><td class="small">%s</td><td class="mono small">%s</td><td class="small">%s</td></tr>'
                   % (esc(f["from_name"]), esc(f["to_name"]),
                      "; ".join(('<span class="tone amber">%s</span>' % esc(d)) if ig.sensitive(d) else esc(d) for d in f["data"]),
                      esc(f["trigger"]), esc(f["endpoint"]), esc(f["integration"])) for f in flows)
    return ('<table class="tm-table"><thead><tr><th>From → to</th><th>Data</th><th>When</th><th>Endpoint</th>'
            '<th>Integration</th></tr></thead><tbody>%s</tbody></table>' % rows)


def _paths(paths: list[dict]) -> str:
    if not paths:
        return '<p class="muted small">No onward paths for sensitive data.</p>'
    return "".join('<div class="ig-path"><div class="strong">%s</div><div class="small"><span class="tone amber">%s</span> '
                   '<span class="muted">starts with %s</span></div></div>'
                   % (esc(" → ".join(p["path"])), esc(p["data"]), esc(p["via"])) for p in paths)


def _integration_table(rows: list[dict]) -> str:
    body = []
    for r in sorted(rows, key=lambda r: (r["status"] == "retired", -ig.SEVERITY_RANK.get(r["worst"], 0), r["name"])):
        n_admin = sum(1 for s in r["scopes"] if ig.scope_class(s["name"], s["grant"]) in ("admin", "write"))
        body.append('<tr%s><td><div class="strong">%s</div><div class="muted small">%s</div></td><td>%s → %s</td><td class="small">%s</td>'
                    '<td class="small">%s</td><td>%d%s</td><td class="small">%s</td><td>%s</td></tr>' % (
                        ' class="muted"' if r["status"] == "retired" else "", esc(r["name"]), esc(r["built_by"]),
                        _party_link(r["source"], r["source_name"]), _party_link(r["target"], r["target_name"]),
                        esc(ig.MECHANISMS[r["mechanism"]]), esc(r["auth"]["identity"] or ig.AUTH_METHODS[r["auth"]["method"]]),
                        len(r["scopes"]) + len(r["auth"]["roles"]), (" (%d write/admin)" % n_admin) if n_admin else "",
                        esc(r["owner"] or "No owner"), _sev(r["worst"]) if r["status"] != "retired" else '<span class="tone grey">Retired</span>'))
    return ('<table class="tm-table"><thead><tr><th>Integration</th><th>From → to</th><th>Mechanism</th><th>Acts as</th>'
            '<th>Grants</th><th>Owner</th><th>Worst</th></tr></thead><tbody>%s</tbody></table>' % "".join(body))


def _add_form(names: dict, fixed: str = "") -> str:
    ordered = sorted(names.items(), key=lambda kv: (kv[0] != ig.YOU, kv[1].lower()))
    opts = "".join('<option value="%s"%s>%s</option>' % (esc(s), " selected" if s == fixed else "", esc(n)) for s, n in ordered)
    other = next((s for s, _n in ordered if s != fixed), "")
    opts_to = "".join('<option value="%s"%s>%s</option>' % (esc(s), " selected" if s == other else "", esc(n)) for s, n in ordered)
    mech = "".join('<option value="%s">%s</option>' % (esc(k), esc(v)) for k, v in ig.MECHANISMS.items())
    auth = "".join('<option value="%s">%s</option>' % (esc(k), esc(v)) for k, v in ig.AUTH_METHODS.items())
    return (
        '<details class="card ig-add"><summary class="strong">Add an integration</summary>'
        '<form method="post" action="/integrations/add" class="form tm-form">'
        '<input type="hidden" name="back" value="%s">'
        '<label>Name</label><input name="name" maxlength="200" required placeholder="e.g. ServiceNow Entra ID spoke">'
        '<div class="row-inline"><div><label>From (initiates)</label><select name="source">%s</select></div>'
        '<div><label>To (grants access)</label><select name="target">%s</select></div>'
        '<div><label>Mechanism</label><select name="mechanism">%s</select></div></div>'
        '<label>Purpose</label><input name="purpose" maxlength="400">'
        '<div class="row-inline"><div><label>Authentication</label><select name="auth_method">%s</select></div>'
        '<div><label>Acts as (identity)</label><input name="auth_identity" maxlength="200" placeholder="App registration, service user, or each user"></div></div>'
        '<div class="row-inline"><div><label>Credential</label><input name="auth_credential" maxlength="80" placeholder="client secret, certificate, password"></div>'
        '<div><label>Last rotated</label><input type="date" name="auth_rotated"></div>'
        '<div><label>App or client ID</label><input name="app_id" maxlength="120"></div></div>'
        '<label>Scopes, one per line: name | application or delegated</label>'
        '<textarea name="scopes" rows="3" placeholder="User.Read.All | application"></textarea>'
        '<label>Roles held by the identity, one per line</label><textarea name="roles" rows="2" placeholder="user_admin"></textarea>'
        '<label>Data flows, one per line: from or to | data, data | when | endpoint</label>'
        '<textarea name="flows" rows="3" placeholder="to | ticket content, attachments | real time | yourco.service-now.com"></textarea>'
        '<p class="muted small">"to" means data moves from the first party to the second; "from" means the reverse.</p>'
        '<div class="row-inline"><div><label>Owner</label><input name="owner" maxlength="120"></div>'
        '<div><label>Last reviewed</label><input type="date" name="reviewed"></div></div>'
        '<p><button class="btn primary small-btn" type="submit">Add integration</button></p></form></details>'
        % (esc(fixed), opts, opts_to, mech, auth))


def form_to_raw(fields: dict) -> dict:
    """The add form's text fields as an integration record."""
    src, tgt = fields.get("source", ""), fields.get("target", "")
    scopes = []
    for line in (fields.get("scopes") or "").splitlines():
        if line.strip():
            name, _, grant = line.partition("|")
            scopes.append({"name": name.strip(), "grant": (grant.strip().lower() or "delegated")})
    flows = []
    for line in (fields.get("flows") or "").splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 2 and parts[1]:
            back = parts[0].lower() == "from"
            flows.append({"from": tgt if back else src, "to": src if back else tgt, "data": parts[1],
                          "trigger": parts[2] if len(parts) > 2 else "", "endpoint": parts[3] if len(parts) > 3 else ""})
    return {"name": fields.get("name", ""), "source": src, "target": tgt, "mechanism": fields.get("mechanism", ""),
            "purpose": fields.get("purpose", ""), "app_id": fields.get("app_id", ""),
            "auth": {"method": fields.get("auth_method", ""), "identity": fields.get("auth_identity", ""),
                     "credential": fields.get("auth_credential", ""), "rotated": fields.get("auth_rotated", ""),
                     "roles": fields.get("roles", "")},
            "scopes": scopes, "flows": flows, "owner": fields.get("owner", ""), "reviewed": fields.get("reviewed", "")}


# ------------------------------------------------------------------ pages
def dashboard(vendor: str = "", error: str = "", ok: str = "", seed_button: bool = False) -> str:
    from views import notice
    ov = ig.overview(vendor or None)
    names = ig.party_names()
    filt = "".join('<option value="%s"%s>%s</option>' % (esc(s), " selected" if s == vendor else "", esc(n))
                   for s, n in sorted(names.items(), key=lambda kv: kv[1].lower()) if s != ig.YOU)
    seed = ('<form method="post" action="/integrations/seed" class="inline"><button class="btn ghost small-btn" type="submit">'
            'Load sample integrations</button></form>') if seed_button else ""
    head = (
        '<header class="page-head"><div><h1 class="big">Integrations</h1>'
        '<p class="lede">Every connection between your tenants, your vendors and your own systems: who it acts as, what it was '
        'granted, and what data moves. Findings come from fixed rules, not a model.</p></div>'
        '<div class="head-actions wrap"><form method="get" action="/integrations" class="inline row-inline">'
        '<select name="vendor" aria-label="Filter by vendor"><option value="">All vendors</option>%s</select>'
        '<button class="btn ghost small-btn" type="submit">Filter</button></form>%s</div></header>' % (filt, seed))
    return (head + notice("error", error) + notice("ok", ok) + _kpis(ov["metrics"]) +
            '<section class="card"><div class="card-head"><h2>Integration map</h2><span class="muted small">Hover a line to see '
            'its integrations</span></div><figure class="tm-figure">%s</figure></section>' % map_svg(ov, vendor or None) +
            '<div class="two-col wide-left"><section class="card"><div class="card-head"><h2>Findings</h2>'
            '<span class="muted small">Worst first</span></div>%s</section>' % _findings_list(ov["live"], 14) +
            '<section class="card"><div class="card-head"><h2>Where sensitive data can go next</h2></div>'
            '<p class="muted small">Follows each sensitive flow onward through other integrations. It shows what is reachable, '
            'not what is proven to move.</p>%s</section></div>' % _paths(ov["paths"]) +
            _coverage(vendor) +
            '<section class="card"><div class="card-head"><h2>All integrations</h2></div>%s</section>' % _integration_table(ov["rows"]) +
            '<section class="card"><div class="card-head"><h2>Scopes and roles granted</h2><span class="muted small">Most powerful first</span></div>%s</section>'
            % _scope_table(ov["scopes"]) +
            '<section class="card"><div class="card-head"><h2>Data movement</h2><span class="muted small">Sensitive data highlighted</span></div>%s</section>'
            % _flow_table(ov["flows"]) +
            _add_form(names, vendor) +
            '<details class="card ig-add"><summary class="strong">Product catalog: share what you learned</summary>'
            '<p class="small">Confirmed integrations (active and reviewed) teach RiskPrism what each product really needs. Export that '
            'knowledge without your owners, identities, tenant names or dates, or import another deployment\'s export.</p>'
            '<div class="tm-actions"><a class="btn ghost small-btn" href="/integrations/catalog.json">Export learned catalog</a></div>'
            '<form method="post" action="/integrations/catalog" enctype="multipart/form-data" class="tm-form">'
            '<input type="file" name="file" accept=".json" required><p><button class="btn ghost small-btn" type="submit">Import a catalog</button></p>'
            '</form></details>')


def _coverage(vendor: str = "") -> str:
    gaps = [g for g in ig.coverage() if not vendor or g["slug"] == vendor]
    if not gaps:
        return ""
    rows = "".join('<div class="row ig-frow"><span class="tone %s">%s</span><div><a class="strong gold" href="/vendor/%s#integrations">%s</a>'
                   '<div class="small muted">%s</div></div></div>' % (
                       "red" if g["state"] == "unrecorded" else "grey", "Not recorded" if g["state"] == "unrecorded" else "Not asked",
                       esc(quote(g["slug"])), esc(g["name"]), esc(g["text"])) for g in gaps)
    return ('<section class="card"><div class="card-head"><h2>Vendors not covered yet</h2><span class="muted small">%d vendor%s</span></div>'
            '<p class="muted small">Every tracked vendor should either have its integrations recorded or a clear answer that it does not '
            'connect. These do not yet.</p>%s</section>' % (len(gaps), "" if len(gaps) == 1 else "s", rows))


def _card(r: dict, slug: str) -> str:
    me = slug
    direction = []
    for f in r["flows"]:
        tag = "Into %s" % (r["target_name"] if f["to"] == r["target"] else r["source_name"])
        if me:
            tag = "Ingress" if f["to"] == me else "Egress"
        direction.append('<tr><td><span class="tone %s">%s</span></td><td>%s</td><td class="small">%s</td><td class="mono small">%s</td></tr>' % (
            "blue" if tag == "Ingress" else "amber", esc(tag),
            "; ".join(('<b>%s</b>' % esc(d)) if ig.sensitive(d) else esc(d) for d in f["data"]), esc(f["trigger"]), esc(f["endpoint"])))
    scopes = "".join('<tr><td class="mono small">%s</td><td>%s</td><td><span class="tone %s">%s</span></td><td>%s</td></tr>' % (
        esc(s["name"]), esc(s["grant"]), CLASS_TONE[ig.scope_class(s["name"], s["grant"])],
        esc(CLASS_LABEL[ig.scope_class(s["name"], s["grant"])]), "Yes" if ig.tenant_wide(s["name"], s["grant"]) else "")
        for s in r["scopes"])
    a = r["auth"]
    auth_rows = [("Mechanism", ig.MECHANISMS[r["mechanism"]]), ("Authentication", ig.AUTH_METHODS[a["method"]]),
                 ("Acts as", a["identity"] or "Not recorded"), ("Roles held", ", ".join(a["roles"]) or "None recorded"),
                 ("Credential", ("%s, stored in %s" % (a["credential"], a["stored_in"])) if a["stored_in"] else (a["credential"] or "Not recorded")),
                 ("Last rotated", a["rotated"] or "Not recorded"),
                 ("Outbound to", ", ".join(r["network"]["egress"]) or "Not recorded"),
                 ("Inbound endpoint", ", ".join(r["network"]["ingress"]) or "None"),
                 ("Owner", r["owner"] or "No owner"), ("Last reviewed", r["reviewed"] or "Never")]
    facts = "".join('<tr><td class="muted">%s</td><td>%s</td></tr>' % (esc(k), esc(v)) for k, v in auth_rows)
    fl = "".join('<div class="row ig-frow">%s<div class="small">%s</div></div>' % (_sev(sev), esc(text)) for _c, text, sev in r["findings"])
    oq = ig.owner_questions(r) if r["status"] != "retired" else []
    if oq:
        fl += ('<h3 class="ig-h">Questions for the owner</h3><ol class="ig-qs">%s</ol>'
               % "".join("<li>%s</li>" % esc(q) for q in oq))
    retire = ('<form method="post" action="/integrations/%s/retire" class="inline"><input type="hidden" name="back" value="%s">'
              '<button class="btn ghost small-btn" type="submit">Mark retired</button></form>' % (esc(r["id"]), esc(slug))
              if r["status"] != "retired" else '<span class="tone grey">Retired</span>')
    return (
        '<details class="card ig-card"%s><summary><span class="strong">%s</span> <span class="muted small">%s → %s · %s</span> %s</summary>'
        '<p class="small">%s</p><div class="two-col"><div><h3 class="ig-h">How it connects</h3><table class="tm-table"><tbody>%s</tbody></table></div>'
        '<div><h3 class="ig-h">Findings</h3>%s</div></div>'
        '<h3 class="ig-h">Scopes granted</h3>%s'
        '<h3 class="ig-h">Data flows</h3><table class="tm-table"><thead><tr><th>Direction</th><th>Data</th><th>When</th><th>Endpoint</th></tr></thead><tbody>%s</tbody></table>'
        '<div class="tm-actions">%s</div></details>' % (
            " open" if r["worst"] == "high" else "", esc(r["name"]), esc(r["source_name"]), esc(r["target_name"]),
            esc(ig.MECHANISMS[r["mechanism"]]), (_sev(r["worst"]) if r["status"] != "retired" else "")
            + (' <span class="tone blue">Planned</span>' if r["status"] == "planned" else ""), esc(r["purpose"]),
            facts, fl or '<p class="muted small">No findings.</p>',
            ('<table class="tm-table"><thead><tr><th>Permission</th><th>Grant</th><th>Class</th><th>Tenant-wide</th></tr></thead><tbody>%s</tbody></table>' % scopes)
            if scopes else '<p class="muted small">No scopes; see roles above.</p>',
            "".join(direction) or '<tr><td colspan="4" class="muted small">No flows recorded.</td></tr>', retire))


SAID_LABEL = {
    "intake_connects": "At intake: connects to our systems", "intake_connects_to": "At intake: which systems",
    "int_connect": "Connects to our systems", "int_list": "Connections", "int_permissions": "Permissions, scopes and roles",
    "int_admin": "Needs admin or tenant-wide write", "int_narrower": "Can permissions be narrowed", "int_credentials": "Credentials",
    "int_data": "Data each way", "int_inbound": "Inbound endpoints", "int_egress": "Domains and IP ranges",
    "int_onward": "Onward to other parties", "int_change": "Changes since last review", "integrations": "Connections (questionnaire)",
}


def _vendor_said(rec: dict) -> str:
    slug = rec.get("slug", "")
    said = ig.vendor_says(rec)
    state = ig.connects(rec)
    has = bool(ig.for_party(slug))
    banner = ""
    if state == "yes" and not has:
        banner = ('<div class="notice error">This vendor connects to your systems, but no integration is recorded. '
                  'Draft one from the answers below or add it by hand.</div>')
    elif state == "unknown" and not has:
        banner = ('<div class="notice">Not asked yet whether this vendor connects to your systems. The onboarding and AI '
                  'questionnaires both ask; send one, or record the answer at intake.</div>')
    if not said:
        return banner
    rows = "".join('<tr><td class="muted">%s</td><td class="pre-line small">%s</td></tr>' % (esc(SAID_LABEL.get(k, k)), esc(v[:1200]))
                   for k, v in said.items())
    draft = ('<form method="post" action="/integrations/draft" class="inline"><input type="hidden" name="slug" value="%s">'
             '<button class="btn ghost small-btn" type="submit">Draft an integration from these answers</button></form>' % esc(slug)
             if state == "yes" else "")
    return (banner + '<details class="card ig-card"%s><summary class="strong">What the vendor and intake told us</summary>'
            '<p class="muted small">Copied as written. A draft takes the scope names and domains exactly as stated and is marked '
            'Planned until someone confirms it.</p><table class="tm-table"><tbody>%s</tbody></table><div class="tm-actions">%s</div></details>'
            % ("" if has else " open", rows, draft))


def drift_card(slug: str) -> str:
    d = ig.drift(slug)
    if not (d["pairs"] or d["unrecorded"]):
        if d["no_app_id"]:
            return ('<section class="card"><div class="card-head"><h2>Declared vs observed</h2></div><p class="muted small">Add the app ID '
                    'to %s to compare what was declared with what your identity provider shows. Import live access on the Overview tab.</p></section>'
                    % esc(", ".join(d["no_app_id"][:4])))
        return ""

    def chips(names, cls):
        return "".join('<span class="dr-scope %s mono">%s</span>' % (cls, esc(n)) for n in names) or '<span class="muted small">none</span>'
    blocks = []
    for p in d["pairs"]:
        if not p["observed_known"]:
            right = '<p class="muted small">Not seen in imported live access yet. Import from Entra, Okta or Google on the Overview tab.</p>'
        else:
            right = ('<div class="small muted">Granted in your tenant</div><div class="dr-chips">%s%s</div>' % (
                chips(p["both"], "ok"), chips(p["observed_only"], "bad") if p["observed_only"] else ""))
        verdict = ('<span class="tone red">%d undeclared</span>' % len(p["observed_only"])) if p["observed_only"] else \
                  ('<span class="tone amber">declared, not granted: %d</span>' % len(p["declared_only"])) if p["observed_known"] and p["declared_only"] else \
                  ('<span class="tone green">matches</span>' if p["observed_known"] else '<span class="tone grey">not observed</span>')
        if p["status"] == "retired" and p["observed_known"]:
            verdict = '<span class="tone red">retired, still live</span>'
        blocks.append(
            '<div class="dr-pair"><div class="dr-head"><span class="strong">%s</span> <span class="mono small muted">%s</span> %s</div>'
            '<div class="dr-cols"><div><div class="small muted">Declared on the integration record</div><div class="dr-chips">%s%s</div></div>'
            '<div>%s</div></div></div>' % (
                esc(p["name"]), esc(p["app_id"]), verdict, chips(p["both"], "ok") if p["observed_known"] and p["both"] else "",
                chips(p["declared_only"], "warn" if p["observed_known"] else "") if p["declared_only"] or not p["both"] else "", right))
    for a in d["unrecorded"]:
        blocks.append(
            '<div class="dr-pair"><div class="dr-head"><span class="strong">%s</span> <span class="mono small muted">%s</span> '
            '<span class="tone red">not recorded</span></div><div class="dr-cols"><div><div class="small muted">Declared on the integration record'
            '</div><p class="muted small">No integration records this app.</p></div><div><div class="small muted">Granted in your tenant (%s, %s)'
            '</div><div class="dr-chips">%s</div></div></div></div>' % (
                esc(a["name"]), esc(a["app_id"]), esc(a["source"] or "import"), esc(a["last_seen"] or "recent"), chips(a["scopes"], "bad")))
    legend = ('<p class="muted small">Green: declared and granted. Red: granted but never declared (drift). Amber: declared but not '
              'granted, which can usually be removed from the record or was never consented.</p>')
    return ('<section class="card"><div class="card-head"><h2>Declared vs observed</h2><span class="muted small">%s</span></div>%s%s</section>' % (
        ("%d need attention" % d["drifting"]) if d["drifting"] else "No drift", legend, "".join(blocks)))


def vendor_panel(rec: dict) -> str:
    import environment_views
    import shadow_views
    slug = rec.get("slug", "")
    ov = ig.overview(slug)
    said = _vendor_said(rec) + environment_views.anticipated_card(rec) + shadow_views.catalog_card(rec)
    if not ov["rows"]:
        return (drift_card(slug) + said + '<section class="card"><h2>Integrations</h2><p class="muted">No integrations recorded for this vendor. Record how it '
                'connects to your tenants and other vendors: the identity it acts as, the scopes it holds and the data it moves.</p></section>'
                + _add_form(ig.party_names(), slug))
    m = ov["metrics"]
    ingress = sum(1 for f in ov["flows"] if f["to"] == slug)
    egress = sum(1 for f in ov["flows"] if f["from"] == slug)
    summary = ('<section class="card"><div class="card-head"><h2>Integrations</h2><a class="gold small" href="/integrations?vendor=%s">'
               'Open in the integrations dashboard</a></div>'
               '<p class="muted small">%d integration%s with this vendor: %d data flow%s in, %d out. %d grant%s that can change data or '
               'act for users. Your tenant here can also connect onward to other vendors.</p>'
               '<figure class="tm-figure">%s</figure></section>' % (
                   esc(quote(slug)), m["integrations"], "" if m["integrations"] == 1 else "s", ingress, "" if ingress == 1 else "s",
                   egress, m["app_write"], "" if m["app_write"] == 1 else "s", map_svg(ov, slug)))
    cards = "".join(_card(r, slug) for r in sorted(ov["rows"], key=lambda r: (r["status"] == "retired", -ig.SEVERITY_RANK.get(r["worst"], 0))))
    return summary + drift_card(slug) + said + cards + _add_form(ig.party_names(), slug)
