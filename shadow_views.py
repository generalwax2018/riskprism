"""HTML for the shadow IT queue and the product catalog card."""
from __future__ import annotations

from urllib.parse import quote

import catalog
import integrations as ig
import shadow
from tpl import esc


def page(error: str = "", ok: str = "") -> str:
    from views import notice
    q = shadow.queue()
    counts = {k: sum(1 for i in q["items"] if i["kind"] == k) for k in shadow.STATE_LABEL}
    tiles = [(shadow.STATE_LABEL[k], counts[k], "danger-text" if k in ("unknown_app", "not_authorized") and counts[k] else "")
             for k in shadow.STATE_LABEL] + [("Handled", q["decided"], "")]
    kpis = '<section class="kpis ig-kpis">%s</section>' % "".join(
        '<div class="kpi"><div class="label">%s</div><div class="num %s">%d</div></div>' % (esc(a), c, n) for a, n, c in tiles)
    rows = []
    for it in q["items"]:
        scopes = ", ".join(it["scopes"][:6]) + (" …" if len(it["scopes"]) > 6 else "")
        vend = ('<a class="gold" href="/vendor/%s">%s</a>' % (esc(quote(it["vendor"])), esc(it["vendor"].replace("_", " ")))) if it["vendor"] else ""
        rows.append(
            '<div class="row ig-frow"><span class="sev %s">%s</span><div><div class="strong">%s <span class="tone %s">%s</span></div>'
            '<div class="small">%s%s%s</div><div class="small muted">%s</div><div class="tm-actions">'
            '<form method="post" action="/shadow/track" class="inline"><input type="hidden" name="id" value="%s">'
            '<button class="btn ghost small-btn" type="submit">%s</button></form>'
            '<form method="post" action="/shadow/decide" class="inline row-inline"><input type="hidden" name="id" value="%s">'
            '<input type="hidden" name="state" value="known"><input name="note" maxlength="400" placeholder="Why it is fine (required)" required>'
            '<button class="btn ghost small-btn" type="submit">Mark as known</button></form></div></div></div>' % (
                it["severity"], it["severity"].capitalize(), esc(it["name"]),
                "red" if it["kind"] in ("unknown_app", "not_authorized") else "amber", esc(shadow.STATE_LABEL[it["kind"]]),
                ("Product: %s. " % esc(it["product"])) if it["product"] and it["product"] != it["name"] else "",
                ("Vendor: %s. " % vend) if vend else "",
                ('Permissions: <span class="mono">%s</span>' % esc(scopes)) if scopes else "",
                esc(it["evidence"]), esc(it["id"]),
                "Record the integration" if it["kind"] == "unrecorded" else "Start tracking" if not it["vendor"] else "Add to vendor's live access",
                esc(it["id"])))
    sources = ('<p class="muted small">Apps: %s. Web traffic: %s.%s</p>' % (
        esc(q["apps_source"] or "not imported"), esc(q["domains_source"] or "not imported"),
        (" %d domains matched no catalog product and are not shown." % q["unmatched_domains"]) if q["unmatched_domains"] else ""))
    sources_form = (
        '<div class="two-col"><details class="card ig-add"><summary class="strong">Import all connected apps</summary>'
        '<form method="post" action="/shadow/apps" enctype="multipart/form-data" class="tm-form">'
        '<label>Export came from</label><select name="source"><option value="entra">Microsoft Entra ID</option>'
        '<option value="okta">Okta</option><option value="google">Google Workspace</option><option value="saas_audit">SaaS audit</option></select>'
        '<input type="file" name="file" accept=".csv,.json" required><p class="muted small">The organization-wide list of enterprise '
        'applications and OAuth grants. Same columns as live access imports.</p>'
        '<p><button class="btn ghost small-btn" type="submit">Import apps</button></p></form></details>'
        '<details class="card ig-add"><summary class="strong">Import web traffic domains</summary>'
        '<form method="post" action="/shadow/domains" enctype="multipart/form-data" class="tm-form">'
        '<input type="file" name="file" accept=".csv" required><p class="muted small">A proxy, firewall or secure web gateway export '
        'with a domain or URL column, and users or hits if you have them. Only domains of known SaaS products are shown.</p>'
        '<p><button class="btn ghost small-btn" type="submit">Import domains</button></p></form></details></div>')
    return ('<header class="page-head"><div><h1 class="big">Shadow IT</h1><p class="lede">Connected apps and SaaS in use that nobody '
            'approved or recorded, from your own identity provider and web traffic exports.</p></div></header>'
            + notice("error", error) + notice("ok", ok) + kpis
            + '<section class="card"><div class="card-head"><h2>Queue</h2><span class="muted small">Worst first</span></div>%s%s</section>' % (
                sources, "".join(rows) or '<p class="muted">Nothing in the queue.</p>')
            + sources_form)


def catalog_card(rec: dict) -> str:
    prof = catalog.profile_for(rec.get("vendor") or "")
    b, l, i = prof["builtin"], prof["learned"], prof["imported"]
    if not (b or l or i):
        return ""
    parts = []
    if b:
        parts.append('<tr><td class="muted">APIs</td><td>%s</td></tr>' % esc(", ".join(b["apis"])))
        parts.append('<tr><td class="muted">Integration types</td><td>%s</td></tr>' % esc(
            ", ".join(ig.MECHANISMS.get(m, m) for m in b["integration_types"])))
        parts.append('<tr><td class="muted">Domains</td><td class="mono small">%s</td></tr>' % esc(", ".join(b["domains"])))

    def top(d, n=8):
        return ", ".join("%s (%d)" % (k.replace("|", " · "), v) for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:n])
    for label, layer in (("Confirmed by your team", l), ("Seen in other RiskPrism deployments", i)):
        if layer:
            parts.append('<tr><td class="muted">%s</td><td class="small">%d integration%s. Permissions: <span class="mono">%s</span>. '
                         'Authentication: %s. Domains: <span class="mono">%s</span>.</td></tr>' % (
                             esc(label), layer["integrations"], "" if layer["integrations"] == 1 else "s",
                             esc(top(layer["scopes"]) or "none"), esc(top(layer["auth"]) or "none"), esc(top(layer["domains"]) or "none")))
    return ('<details class="card ig-card"><summary class="strong">What RiskPrism knows about %s</summary>'
            '<p class="muted small">Built-in product profile, plus what confirmed integrations taught it. Learned profiles can be '
            'exported without your details from the Integrations dashboard.</p><table class="tm-table"><tbody>%s</tbody></table></details>' % (
                esc((b or l or i)["product"]), "".join(parts)))
