"""HTML for the findings worklist."""
from __future__ import annotations

from urllib.parse import quote

import findings
from tpl import esc


def page(source: str = "", show: str = "open", error: str = "", ok: str = "") -> str:
    from views import notice
    items = findings.collect()
    all_items = items
    s = findings.summary(items)
    if source in findings.SOURCES:
        items = [f for f in items if f["source"] == source]
    if show != "all":
        items = [f for f in items if not f["ticket"]]
    systems = findings.systems()

    tiles = [("Open, no ticket", s["open"], "danger-text" if s["by_severity"]["high"] else ""),
             ("High", s["by_severity"]["high"], "danger-text" if s["by_severity"]["high"] else ""),
             ("Overdue", s["overdue"], "danger-text" if s["overdue"] else ""), ("Ticketed", s["ticketed"], "")]
    kpis = '<section class="kpis">%s</section>' % "".join(
        '<div class="kpi"><div class="label">%s</div><div class="num %s">%d</div></div>' % (esc(a), c, n) for a, n, c in tiles)

    def chip(label, src, n):
        on = " on" if src == source else ""
        href = "/findings?%s" % "&".join(p for p in (("source=" + src) if src else "", "show=all" if show == "all" else "") if p)
        return '<a class="chipbtn%s" href="%s">%s <span class="mono">%d</span></a>' % (on, esc(href.rstrip("?")), esc(label), n)
    chips = ('<div class="chips fd-chips">%s%s<span class="grow"></span><a class="gold small" href="/findings?%s">%s</a></div>' % (
        chip("All", "", s["total"]), "".join(chip(findings.SOURCES[k], k, s["by_source"][k]) for k in findings.SOURCES),
        ("source=%s&" % source if source else "") + ("show=open" if show == "all" else "show=all"),
        "Hide ticketed" if show == "all" else "Show ticketed too"))

    rows = []
    for f in items:
        t = f["ticket"]
        if t:
            ref = ('<a class="gold" href="%s" rel="noopener noreferrer" target="_blank">%s</a>' % (esc(t["url"]), esc(t["ref"]))) if t.get("url") else esc(t["ref"])
            right = ('<div class="small">Ticket %s <span class="muted">(%s, %s)</span></div>'
                     '<form method="post" action="/findings/untrack" class="inline"><input type="hidden" name="key" value="%s">'
                     '<button class="linkbtn small" type="submit">Clear</button></form>' % (ref, esc(t["by"]), esc(t["at"][:10]), esc(f["key"])))
            box = '<span></span>'
        else:
            right = ('<details class="fd-manual"><summary class="small gold">Record a ticket</summary>'
                     '<form method="post" action="/findings/ticket" class="row-inline"><input type="hidden" name="key" value="%s">'
                     '<input name="ref" maxlength="60" placeholder="INC0012345 or SEC-42" required>'
                     '<input name="url" maxlength="300" placeholder="Link (optional)">'
                     '<button class="btn ghost small-btn" type="submit">Save</button></form></details>' % esc(f["key"]))
            box = ('<input type="checkbox" name="k_%s" form="fd-push" aria-label="Select %s">' % (esc(f["key"]), esc(f["title"][:60]))
                   if systems else '<span></span>')
        vend = ('<a class="gold" href="/vendor/%s">%s</a> · ' % (esc(quote(f["vendor"])), esc(f["vendor"].replace("_", " ")))) if f["vendor"] else ""
        if f["overdue_days"]:
            clock = '<span class="tone red">Overdue by %d day%s</span>' % (f["overdue_days"], "" if f["overdue_days"] == 1 else "s")
        else:
            clock = '<span class="muted">Due %s</span>' % esc(f["due"])
        clock = ' · open %d day%s · %s' % (f["age_days"], "" if f["age_days"] == 1 else "s", clock)
        rows.append(
            '<div class="row fd-row">%s<span class="sev %s">%s</span><div class="fd-main"><div class="strong">%s</div>'
            '<div class="small muted">%s%s · <span class="mono">%s</span>%s%s · <a class="gold" href="%s">Open</a></div>'
            '<div class="small">%s</div></div><div class="fd-ticket">%s</div></div>' % (
                box, f["severity"], f["severity"].capitalize(), esc(f["title"]), vend, esc(findings.SOURCES[f["source"]]),
                esc(f["key"]), (" · owner " + esc(f["owner"])) if f["owner"] else "", clock, esc(f["link"]), esc(f["detail"][:400]), right))

    if systems:
        opts = "".join('<option value="%s">%s</option>' % (esc(k), esc(v["label"])) for k, v in systems.items())
        push = ('<form method="post" action="/findings/push" id="fd-push" class="row-inline fd-push">'
                '<span class="small muted">Raise a ticket for each ticked finding in</span><select name="system">%s</select>'
                '<button class="btn primary small-btn" type="submit">Create tickets</button></form>' % opts)
    else:
        push = ('<p class="muted small">No ticketing system is connected. Set the ServiceNow or Jira variables (see the README) to raise '
                'tickets from here, or download the CSV and import it. Either way, record the ticket number on each finding.</p>')
    csv_href = "/findings.csv" + (("?source=" + source) if source else "")
    return ('<header class="page-head"><div><h1 class="big">Findings</h1><p class="lede">Everything that needs someone to act, from '
            'integrations, control objectives, shadow IT and vendor evidence, worst first. Each finding keeps its ticket.</p></div>'
            '<div class="actions"><a class="btn ghost" href="%s">Download CSV</a></div></header>' % esc(csv_href)
            + notice("error", error) + notice("ok", ok) + kpis
            + '<p class="muted small fd-trend">%s Deadlines come from your own rule in <a class="gold" href="/environment">Your environment</a>.</p>'
              % esc(findings.trend_sentence(findings.trend(all_items)))
            + '<section class="card"><div class="card-head"><h2>Worklist</h2></div>%s%s%s</section>' % (
                chips, push, "".join(rows) or '<p class="muted">Nothing here.</p>'))
