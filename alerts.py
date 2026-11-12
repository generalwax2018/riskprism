from __future__ import annotations

from datetime import date, datetime

import access_flags
import risk_store
from models import due as models_due
from models import uses_ai
from records import list_vendors


def _parse(d):
    if not d:
        return None
    try:
        return datetime.strptime(str(d)[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def flags(rec: dict, today: date | None = None):
    today = today or date.today()
    out = list(access_flags.findings(rec))
    if rec.get("stage") == "offboarded" or rec.get("authorization") == "blocked":
        return out
    soc = _parse(rec.get("soc2_expires") or rec.get("soc2_expiry"))
    pen = _parse(rec.get("pentest_expires") or rec.get("pentest_expiry"))
    nxt = _parse(rec.get("next_review") or rec.get("renewal_date"))
    if soc and soc < today:
        out.append(("soc2_expired", "SOC 2 / ISO expired " + soc.isoformat(), "high"))
    elif soc and (soc - today).days <= 90:
        out.append(("soc2_soon", "SOC 2 / ISO expires " + soc.isoformat(), "medium"))
    if pen and pen < today:
        out.append(("pentest_expired", "Pentest older than marked expiry " + pen.isoformat(), "high"))
    elif pen and (pen - today).days <= 90:
        out.append(("pentest_soon", "Pentest expiry " + pen.isoformat(), "medium"))
    if nxt and nxt < today:
        out.append(("review_overdue", "Security review overdue since " + nxt.isoformat(), "high"))
    elif nxt and (nxt - today).days <= 90:
        out.append(("review_soon", "Security review due " + nxt.isoformat(), "medium"))
    target, overdue = models_due(rec, today)
    if target is not None and overdue is not None:
        if overdue > 0:
            out.append(("models_affirm", "Model list not affirmed since cadence (due " + target.isoformat() + ")", "high"))
        elif overdue == 0:
            out.append(("models_affirm", "Model list affirmation due today (" + target.isoformat() + ")", "medium"))
        elif overdue > -31:
            out.append(("models_affirm_soon", "Model list affirmation due " + target.isoformat(), "medium"))
    if rec.get("renewal_status") == "sent":
        out.append(("renewal_open", "Renewal questionnaire sent — waiting on vendor", "medium"))
    if rec.get("followup_status") == "sent":
        out.append(("followup_sent", "Follow-up questions sent — waiting on vendor", "medium"))
    if not nxt and not soc and rec.get("authorization") == "authorized":
        out.append(("no_clock", "Authorized but no review or SOC 2 expiry on file", "medium"))
    for f in rec.get("followups") or []:
        if f.get("status") == "open":
            out.append((f.get("id") or "followup", f.get("title") or "Follow-up needed", f.get("severity") or "medium"))
    return out


def action_for(code: str) -> str:
    """Which POST the row button should trigger."""
    if str(code).startswith(("pentest", "soc2", "ai_", "critical", "region", "access_", "doc_")):
        return "/followup"
    return "/renewal"


def _plural(n: int, word: str) -> str:
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def _date_cell(d, *, late_word: str):
    today = date.today()
    if not d:
        return None
    days = (d - today).days
    if days < 0:
        return {"tone": "red", "top": "%s %s" % (late_word, _plural(-days, "day")), "bottom": d.isoformat()}
    if days == 0:
        return {"tone": "amber", "top": "Today", "bottom": d.isoformat()}
    return {"tone": "amber" if days <= 90 else "green", "top": "In " + _plural(days, "day"), "bottom": d.isoformat()}


def clock_cells(rec: dict) -> dict:
    """Four grid cells for one vendor: soc, pen, rev, mod. Each is tone/top/bottom."""
    open_ids = {f.get("id") for f in rec.get("followups") or [] if f.get("status") == "open"}
    missing = {"tone": "grey", "top": "Not on file", "bottom": ""}
    soc = _date_cell(_parse(rec.get("soc2_expires") or rec.get("soc2_expiry")), late_word="Expired")
    if soc is None:
        soc = {"tone": "amber", "top": "Type I only", "bottom": "no expiry"} if "soc2_type1" in open_ids else dict(missing)
    pen = _date_cell(_parse(rec.get("pentest_expires") or rec.get("pentest_expiry")), late_word="Expired")
    if pen is None:
        pen = {"tone": "red", "top": "Executive summary only", "bottom": ""} if "pentest_exec_only" in open_ids else dict(missing)
    rev = _date_cell(_parse(rec.get("next_review") or rec.get("renewal_date")), late_word="Overdue")
    if rev is None:
        rev = {"tone": "grey", "top": "Not set", "bottom": ""}
    if not uses_ai(rec):
        mod = {"tone": "grey", "top": "No AI", "bottom": ""}
    else:
        target, overdue = models_due(rec, date.today())
        if not rec.get("models_affirmed_at"):
            mod = {"tone": "red" if overdue is not None and overdue > 0 else "amber",
                   "top": "Never affirmed", "bottom": ""}
        elif overdue is None:
            mod = {"tone": "green", "top": "Due " + target.isoformat(), "bottom": ""}
        elif overdue > 0:
            mod = {"tone": "red", "top": "Overdue " + _plural(overdue, "day"), "bottom": target.isoformat()}
        elif overdue == 0:
            mod = {"tone": "amber", "top": "Due today", "bottom": target.isoformat()}
        else:
            mod = {"tone": "amber", "top": "In " + _plural(-overdue, "day"), "bottom": target.isoformat()}
    return {"soc": soc, "pen": pen, "rev": rev, "mod": mod}


def dashboard():
    """Flag rows for every vendor. A flag covered by an active acceptance stays in the
    list as severity 'accepted' and is not counted; once the acceptance expires the
    flag counts again, because risk_store only returns acceptances still in date."""
    rows = []
    clocks = []
    counts = {"high": 0, "medium": 0, "low": 0, "vendors_flagged": 0, "waiting": 0, "accepted": 0}
    accepted = risk_store.active_by_vendor()
    for rec in list_vendors():
        fl = flags(rec)
        slug = rec.get("slug") or rec.get("vendor", "")
        if rec.get("stage") != "offboarded" and rec.get("authorization") != "blocked":
            has_clock = any(rec.get(k) for k in ("soc2_expires", "pentest_expires", "next_review", "renewal_date", "models_affirmed_at"))
            if fl or has_clock or uses_ai(rec) or rec.get("live_access"):
                clocks.append({
                    "vendor": rec.get("vendor", ""), "slug": slug,
                    "sub": rec.get("business") or rec.get("website") or "",
                    "cells": clock_cells(rec),
                    "action": "Resend link" if rec.get("renewal_status") == "sent" else "Send renewal",
                })
        if not fl:
            continue
        covered = accepted.get(slug, {})
        if any(code not in covered for code, _t, _s in fl):
            counts["vendors_flagged"] += 1
        for code, text, sev in fl:
            acc = covered.get(code)
            if acc:
                counts["accepted"] += 1
                rows.append({
                    "vendor": rec.get("vendor", ""), "slug": slug, "code": code,
                    "text": "%s (accepted until %s by %s)" % (text, acc["expires_on"], acc["accepter"]),
                    "severity": "accepted", "authorization": rec.get("authorization") or "",
                    "stage": rec.get("stage") or "", "action": "",
                })
                continue
            counts[sev] = counts.get(sev, 0) + 1
            if code in ("renewal_open", "followup_sent"):
                counts["waiting"] += 1
            rows.append({
                "vendor": rec.get("vendor", ""), "slug": slug, "code": code, "text": text,
                "severity": sev, "authorization": rec.get("authorization") or "",
                "stage": rec.get("stage") or "", "action": action_for(code),
            })
    order = {"high": 0, "medium": 1, "low": 2, "accepted": 3}
    rows.sort(key=lambda r: (order.get(r["severity"], 9), r["vendor"]))
    return counts, rows, clocks
