"""Executive summary: one page (and a board-pack PDF) for the security leader, with every line linking
to the engineer's detail. Built from the same rules as the rest of RiskPrism; nothing is summarized by a model."""
from __future__ import annotations

from datetime import date, timedelta
from urllib.parse import quote

import alerts
import control_objectives as co
import environment
import integrations as ig
import portfolio
import records
import risk_store
from tpl import esc

SEV_RANK = {"high": 3, "medium": 2, "low": 1}


def summary() -> dict:
    vendors = [r for r in records.list_vendors() if r.get("slug")]
    prow = {r["slug"]: r for r in portfolio.rows()}
    tiers = {t: 0 for t in co.TIERS}
    for v in vendors:
        t = (prow.get(v["slug"]) or {}).get("inh")
        if t in tiers:
            tiers[t] += 1
    m = co.matrix()
    ctl_by_slug = {r["slug"]: r for r in m["rows"]}
    ov = ig.overview()
    gaps = ig.coverage()
    exposure = environment.exposure()
    today = date.today()
    soon = (today + timedelta(days=30)).isoformat()
    expiring = [a for a in risk_store.acceptances() if risk_store.is_active(a, today) and a["expires_on"] <= soon]

    decisions = []
    for r in ov["live"]:
        highs = [f for f in r["findings"] if f[2] == "high"]
        if highs:
            decisions.append({"sev": "high", "what": "%s: %s" % (r["name"], highs[0][1]),
                              "who": r["owner"] or "No owner", "link": "/integrations?vendor=%s" % quote(r["target"] if r["source"] == ig.YOU else r["source"]),
                              "area": "Integration"})
    for e in exposure:
        s = e["system"]
        if s["criticality"] == "high" and e["unapproved"]:
            names = ", ".join(ov["names"].get(u, u) for u in e["unapproved"])
            decisions.append({"sev": "high", "what": "%s is reachable by a vendor that is not authorized (%s)." % (s["name"], names),
                              "who": s["owner"] or "No owner", "link": "/environment/%s" % quote(s["id"]), "area": "Environment"})
    for row in m["rows"]:
        if row["tier"] in ("T1", "T2"):
            nm = [x for x in row["results"] if x["status"] == "not_met"]
            if nm:
                decisions.append({"sev": "high" if row["tier"] == "T1" else "medium",
                                  "what": "%s (%s) misses %d control objective%s: %s." % (
                                      row["rec"].get("vendor"), row["tier"], len(nm), "" if len(nm) == 1 else "s",
                                      "; ".join(x["objective"]["title"] for x in nm[:3])),
                                  "who": row["rec"].get("owner") or "No owner", "link": "/vendor/%s#controls" % quote(row["slug"]),
                                  "area": "Controls"})
    for g in gaps:
        if g["state"] == "unrecorded":
            decisions.append({"sev": "medium", "what": "%s connects to your systems, but nobody has recorded how." % g["name"],
                              "who": "Vendor owner", "link": "/vendor/%s#integrations" % quote(g["slug"]), "area": "Coverage"})
    for a in expiring:
        decisions.append({"sev": "medium", "what": "Risk acceptance for %s (%s) expires on %s." % (a["vendor_name"], a["detection_text"][:80], a["expires_on"]),
                          "who": a["accepter"], "link": "/vendor/%s#risk-acceptance" % quote(a["vendor_slug"]), "area": "Risk acceptance"})
    import shadow
    sq = shadow.queue()
    for it in sq["items"]:
        if it["severity"] == "high" or it["kind"] == "not_authorized":
            decisions.append({"sev": "high", "what": "Shadow IT: %s (%s). %s" % (it["name"], shadow.STATE_LABEL[it["kind"]].lower(), it["evidence"]),
                              "who": "Security team", "link": "/shadow", "area": "Shadow IT"})
    decisions.sort(key=lambda d: -SEV_RANK[d["sev"]])

    high_flags = sum(1 for v in vendors for f in alerts.flags(v) if f[2] == "high")
    critical_systems = [e for e in exposure if e["system"]["criticality"] == "high"]
    exposed = [e for e in critical_systems if e["strong"] or e["unapproved"]]
    key_vendors = []
    for v in vendors:
        t = (prow.get(v["slug"]) or {}).get("inh") or ""
        c = ctl_by_slug.get(v["slug"])
        worst = max((r["worst"] for r in ov["live"] if v["slug"] in (r["source"], r["target"])), key=lambda w: SEV_RANK.get(w, 0), default="")
        key_vendors.append({"rec": v, "tier": t, "pct": c["pct"] if c else None,
                            "not_met": c["counts"]["not_met"] if c else 0, "worst": worst})
    import findings
    items = findings.collect()
    key_vendors.sort(key=lambda k: ({"T1": 0, "T2": 1, "T3": 2, "T4": 3}.get(k["tier"], 4), -(k["not_met"]), (k["rec"].get("vendor") or "")))
    return {"org": environment.org_name(), "date": today.isoformat(), "vendors": len(vendors), "tiers": tiers,
            "controls_pct": m["pct"], "controls": m["totals"], "ig": ov["metrics"], "gaps": gaps, "expiring": expiring,
            "decisions": decisions, "high_flags": high_flags, "critical_systems": critical_systems, "exposed": exposed,
            "key_vendors": key_vendors, "systems": len(exposure), "shadow": len(sq["items"]),
            "findings": findings.summary(items), "trend": findings.trend(items)}


def _headline(s: dict) -> str:
    parts = ["%d vendors, %d of them critical (T1)." % (s["vendors"], s["tiers"]["T1"])]
    if s["controls_pct"] is not None:
        parts.append("%d%% of control objectives are met." % s["controls_pct"])
    parts.append("%d integration%s with a high finding." % (s["ig"]["high"], "" if s["ig"]["high"] == 1 else "s"))
    unrec = sum(1 for g in s["gaps"] if g["state"] == "unrecorded")
    if unrec:
        parts.append("%d vendor%s to your systems with nothing recorded." % (unrec, " connects" if unrec == 1 else "s connect"))
    if s["shadow"]:
        parts.append("%d shadow IT item%s need a decision." % (s["shadow"], "" if s["shadow"] == 1 else "s"))
    if s["exposed"]:
        parts.append("%d of your %d critical systems can be changed by a vendor or reached by one that is not authorized." % (
            len(s["exposed"]), len(s["critical_systems"])))
    return " ".join(parts)


def _trend_line(s: dict) -> str:
    import findings
    return findings.trend_sentence(s["trend"])


def page() -> str:
    s = summary()
    tiles = [("Vendors", s["vendors"], "%d critical" % s["tiers"]["T1"], ""),
             ("Control objectives met", ("%d%%" % s["controls_pct"]) if s["controls_pct"] is not None else "–",
              "%d not met" % s["controls"].get("not_met", 0), ""),
             ("Integrations with high findings", s["ig"]["high"], "of %d recorded" % s["ig"]["integrations"], "danger-text" if s["ig"]["high"] else ""),
             ("Critical systems exposed", len(s["exposed"]), "of %d critical" % len(s["critical_systems"]), "danger-text" if s["exposed"] else ""),
             ("Vendors not covered", len(s["gaps"]), "integrations not recorded or not asked", "warn-text" if s["gaps"] else ""),
             ("Acceptances expiring", len(s["expiring"]), "in the next 30 days", "warn-text" if s["expiring"] else ""),
             ("Shadow IT open", s["shadow"], "apps and SaaS nobody approved", "danger-text" if s["shadow"] else ""),
             ("Findings overdue", s["findings"]["overdue"], "of %d open" % s["findings"]["total"], "danger-text" if s["findings"]["overdue"] else "")]
    kpis = '<section class="kpis ig-kpis">%s</section>' % "".join(
        '<div class="kpi"><div class="label">%s</div><div class="num %s">%s</div><div class="muted small">%s</div></div>' % (
            esc(a), c, esc(b), esc(n)) for a, b, n, c in tiles)
    dec = "".join('<div class="row ig-frow"><span class="sev %s">%s</span><div><div>%s</div><div class="muted small">%s · Owner: %s · '
                  '<a class="gold" href="%s">Engineer detail</a></div></div></div>' % (
                      d["sev"], d["sev"].capitalize(), esc(d["what"]), esc(d["area"]), esc(d["who"]), esc(d["link"]))
                  for d in s["decisions"][:10]) or '<p class="muted">Nothing needs a decision.</p>'
    sys_rows = "".join('<tr><td><a class="gold" href="/environment/%s">%s</a><div class="muted small">%s</div></td><td>%d</td><td>%d</td>'
                       '<td>%s</td><td>%s</td></tr>' % (
                           esc(quote(e["system"]["id"])), esc(e["system"]["name"]), esc(", ".join(e["system"]["data_classes"][:3])),
                           len(e["reach"]), len(e["strong"]),
                           esc(", ".join(e["unapproved"])) or "None",
                           ('<span class="sev %s">%s</span>' % (e["worst"], e["worst"].capitalize())) if e["worst"] else '<span class="tone green">Clear</span>')
                       for e in s["critical_systems"])
    ven_rows = "".join('<tr><td><a class="gold" href="/vendor/%s">%s</a></td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>' % (
        esc(quote(k["rec"]["slug"])), esc(k["rec"].get("vendor")), esc(k["tier"] or "Unscored"),
        ("%d%%" % k["pct"]) if k["pct"] is not None else "–", k["not_met"],
        ('<span class="sev %s">%s</span>' % (k["worst"], k["worst"].capitalize())) if k["worst"] else "—")
        for k in s["key_vendors"][:12])
    return (
        '<header class="page-head"><div><h1 class="big">Executive summary</h1><p class="lede">%s · %s</p></div>'
        '<div class="head-actions wrap"><a class="btn primary small-btn" href="/executive/board.pdf">Download board pack (PDF)</a>'
        '<a class="btn ghost small-btn" href="/environment">Engineer view: environment map</a></div></header>' % (esc(s["org"]), esc(s["date"]))
        + '<section class="card exec-headline"><p>%s</p><p class="muted small">%s <a class="gold" href="/findings">Findings</a></p></section>' % (
            esc(_headline(s)), esc(_trend_line(s))) + kpis
        + '<section class="card"><div class="card-head"><h2>What needs a decision</h2><span class="muted small">Worst first</span></div>%s</section>' % dec
        + '<div class="two-col"><section class="card"><div class="card-head"><h2>Your critical systems</h2></div>'
          '<table class="tm-table"><thead><tr><th>System</th><th>Vendors reaching it</th><th>Write or admin grants</th>'
          '<th>Not authorized</th><th>Worst</th></tr></thead><tbody>%s</tbody></table></section>' % (
              sys_rows or '<tr><td colspan="5" class="muted">Set up Your environment to see this.</td></tr>')
        + '<section class="card"><div class="card-head"><h2>Vendors by tier</h2><a class="gold small" href="/controls">Controls</a></div>'
          '<table class="tm-table"><thead><tr><th>Vendor</th><th>Tier</th><th>Controls met</th><th>Not met</th><th>Worst integration</th></tr>'
          '</thead><tbody>%s</tbody></table></section></div>' % ven_rows)


def board_pdf() -> bytes:
    import threat_export
    s = summary()
    blocks = [("title", "Third-party security: board summary"),
              ("meta", "%s, %s. Produced by RiskPrism from vendor records, questionnaires, live access, integrations and control "
                       "objectives. Fixed rules; no model." % (s["org"], s["date"])),
              ("h1", "Headline"), ("p", _headline(s)), ("p", _trend_line(s)),
              ("table", {"head": ["Measure", "Value"], "widths": [2, 1], "rows": [
                  ["Vendors (critical)", "%d (%d)" % (s["vendors"], s["tiers"]["T1"])],
                  ["Control objectives met", ("%d%%" % s["controls_pct"]) if s["controls_pct"] is not None else "n/a"],
                  ["Integrations with high findings", "%d of %d" % (s["ig"]["high"], s["ig"]["integrations"])],
                  ["Critical systems exposed", "%d of %d" % (len(s["exposed"]), len(s["critical_systems"]))],
                  ["Vendors not covered", str(len(s["gaps"]))],
                  ["Risk acceptances expiring in 30 days", str(len(s["expiring"]))],
                  ["Shadow IT items open", str(s["shadow"])],
                  ["Findings open (overdue)", "%d (%d)" % (s["findings"]["total"], s["findings"]["overdue"])]]}),
              ("h1", "What needs a decision"),
              ("table", {"head": ["Severity", "Area", "Issue", "Owner"], "widths": [0.8, 1, 4, 1.2], "rows": [
                  [d["sev"].capitalize(), d["area"], d["what"], d["who"]] for d in s["decisions"][:12]] or [["", "", "Nothing needs a decision.", ""]]}),
              ("h1", "Critical systems and who can reach them"),
              ("table", {"head": ["System", "Vendors reaching it", "Write or admin grants", "Not authorized", "Worst"],
                         "widths": [2, 1, 1, 1.6, 0.8], "rows": [
                  [e["system"]["name"], str(len(e["reach"])), str(len(e["strong"])), ", ".join(e["unapproved"]) or "None",
                   e["worst"].capitalize() or "Clear"] for e in s["critical_systems"]] or [["Not set up", "", "", "", ""]]}),
              ("h1", "Vendors by tier"),
              ("table", {"head": ["Vendor", "Tier", "Controls met", "Not met", "Worst integration"], "widths": [2.4, 0.7, 1, 0.8, 1.2],
                         "rows": [[k["rec"].get("vendor") or "", k["tier"] or "Unscored",
                                   ("%d%%" % k["pct"]) if k["pct"] is not None else "n/a", str(k["not_met"]),
                                   k["worst"].capitalize() or "None"] for k in s["key_vendors"][:20]]})]
    import audit
    blocks.append(("meta", "Audit log seal on %s: %s (%d entries). Keep this page: the seal lets you prove later that the "
                           "audit log was not rewritten or shortened." % (s["date"], audit.head(), audit.count())))
    return threat_export.pdf_bytes(blocks, title="Board summary: %s" % s["org"])
