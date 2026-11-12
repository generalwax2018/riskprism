"""Who may accept which risk, what can be accepted, and the snapshot frozen at signing.

Deterministic. No model calls. risk_store holds the rows; this module decides.

Thresholds by tier:
  Low, Medium      a director, VP or the CISO
  High, Critical   a VP or the CISO

The signer picks the tier, but never below the detection's own severity (or the
vendor's residual tier for a whole-vendor acceptance), so a high flag cannot be
relabelled Medium to get round the VP rule.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone

import access_store
import alerts
import config
import portfolio
import risk_store
from records import list_vendors

TIERS = [("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")]
LEVELS = [("director", "Director"), ("vp", "VP"), ("ciso", "CISO")]
TIER_LABEL = {**dict(TIERS), "unrated": "Unrated"}
LEVEL_LABEL = {**dict(LEVELS), "legacy": "Legacy"}
TIER_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
LEVEL_RANK = {"director": 1, "vp": 2, "ciso": 3}
REQUIRED_LEVEL = {"low": "director", "medium": "director", "high": "vp", "critical": "vp"}
FLOOR_BY_SEVERITY = {"low": "low", "medium": "medium", "high": "high"}
FLOOR_BY_RESIDUAL = {"T1": "critical", "T2": "high", "T3": "medium", "T4": "low"}
# Suggested length of an acceptance by tier. Only a suggestion: the signer picks the date.
SUGGEST_DAYS = {"critical": 30, "high": 60, "medium": 90, "low": 180}
VENDOR_CODE = "vendor"
LEGACY_UNIT = "Unassigned (legacy acceptances)"


def _residual(slug: str) -> dict | None:
    return next((r for r in portfolio.rows() if r["slug"] == slug), None)


def detections(rec: dict) -> list[dict]:
    """What can be accepted on this vendor right now: the whole vendor's residual risk,
    plus each open flag (clocks, follow-ups, live access). One entry per code."""
    slug = rec.get("slug", "")
    row = _residual(slug)
    res = (row or {}).get("res", "")
    out = [{"code": VENDOR_CODE, "text": "Residual risk of the whole vendor (%s)" % (res or "unscored"),
            "severity": "", "floor": FLOOR_BY_RESIDUAL.get(res, "low")}]
    seen = {VENDOR_CODE}
    for code, text, sev in alerts.flags(rec):
        if code in seen:
            continue
        seen.add(code)
        out.append({"code": code, "text": text, "severity": sev, "floor": FLOOR_BY_SEVERITY.get(sev, "low")})
    return out


def signer_problem(level: str, tier: str, floor: str) -> str:
    """Empty when this signer may accept this tier; otherwise the reason they may not."""
    if tier not in TIER_RANK:
        return "Pick a risk tier."
    if TIER_RANK[tier] < TIER_RANK.get(floor, 1):
        return "This detection is at least %s. Record it at that tier or higher." % TIER_LABEL[floor]
    if level not in LEVEL_RANK:
        return "You are not a registered approver. An admin adds approvers on the Org units page."
    need = REQUIRED_LEVEL[tier]
    if LEVEL_RANK[level] < LEVEL_RANK[need]:
        return "%s risk needs a %s to sign it. You are registered as %s." % (
            TIER_LABEL[tier], "VP or the CISO" if need == "vp" else "director, VP or the CISO", LEVEL_LABEL[level])
    return ""


def expiry_problem(until: str, today: date | None = None) -> str:
    today = today or date.today()
    if not until:
        return "Every acceptance needs an expiry date. There are no permanent acceptances."
    if until < today.isoformat():
        return "The acceptance cannot expire in the past."
    last = today + timedelta(days=config.ACCEPT_MAX_DAYS)
    if until > last.isoformat():
        return "An acceptance can run for at most %d days (until %s)." % (config.ACCEPT_MAX_DAYS, last.isoformat())
    return ""


def expiry_options(rec: dict, today: date | None = None) -> list[dict]:
    """Dates the signer can click to fill 'Accepted until': 30 / 60 / 90 / 180 days, the
    next security review and the end of the contract, each only when it is a date the
    form would accept. 'tier' names the tier this option is the suggestion for, if any."""
    today = today or date.today()
    last = today + timedelta(days=config.ACCEPT_MAX_DAYS)
    by_days = {n: t for t, n in SUGGEST_DAYS.items()}
    out = []
    for n in sorted(by_days):
        d = today + timedelta(days=n)
        if d <= last:
            out.append({"label": "%d days" % n, "date": d.isoformat(), "tier": by_days[n]})
    for key, label in (("next_review", "Next security review"), ("contract_end", "End of contract")):
        raw = rec.get(key) or (rec.get("renewal_date") if key == "next_review" else "")
        try:
            d = date.fromisoformat(str(raw or "")[:10])
        except ValueError:
            continue
        if today <= d <= last:
            out.append({"label": label, "date": d.isoformat(), "tier": ""})
    return out


def snapshot(rec: dict, det: dict) -> dict:
    """What the risk looked like when it was signed. Stored as JSON and never updated."""
    row = _residual(rec.get("slug", "")) or {}
    return {
        "taken_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "detection": {k: det.get(k, "") for k in ("code", "text", "severity")},
        "vendor": {k: rec.get(k, "") for k in ("vendor", "slug", "business", "authorization", "stage", "mode", "data_class")},
        "tier": {"inherent": row.get("inh", ""), "residual": row.get("res", ""), "score": row.get("score", ""),
                 "provisional": bool(row.get("provisional"))},
        "clocks": {k: rec.get(k, "") for k in ("soc2_expires", "pentest_expires", "next_review", "contract_end")},
        "flags": [{"code": c, "text": t, "severity": s} for c, t, s in alerts.flags(rec)],
        "open_followups": [f.get("title", "") for f in rec.get("followups") or [] if f.get("status") == "open"],
        "live_access": [{"name": r["display_name"], "kind": r["kind"], "status": r["status"], "scopes": r["scopes"]}
                        for r in access_store.rows(rec)],
    }


def build_entry(rec: dict, det: dict, *, unit_id: int, accepter: str, level: str, tier: str,
                justification: str, controls: str, until: str, recorded_by: str) -> dict:
    return {
        "vendor_slug": rec.get("slug", ""), "vendor_name": rec.get("vendor", ""),
        "detection_code": det["code"], "detection_text": det["text"][:400], "org_unit_id": unit_id,
        "accepter": accepter, "accepter_level": level, "risk_tier": tier,
        "justification": justification, "compensating_controls": controls, "expires_on": until,
        "risk_snapshot": json.dumps(snapshot(rec, det), sort_keys=True),
        "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "recorded_by": recorded_by,
    }


def migrate_legacy(today: date | None = None) -> int:
    """Copy acceptances from the old vendor JSON (exception / exceptions[]) into the store.

    They land as whole-vendor acceptances on a review-flagged unit, tier 'unrated',
    level 'legacy'. The vendor JSON is left as it was. Safe to run on every start.
    """
    today = today or date.today()
    todo = []
    for rec in list_vendors():
        entries = list(rec.get("exceptions") or [])
        if rec.get("exception") and rec["exception"] not in entries:
            entries.append(rec["exception"])
        for ex in entries:
            if isinstance(ex, dict) and ex.get("until") and ex.get("signed_by"):
                todo.append((rec, ex))
    if not todo:
        return 0
    unit_id = next((u["id"] for u in risk_store.units() if u["name"].lower() == LEGACY_UNIT.lower()), None)
    if unit_id is None:
        unit_id = risk_store.create_unit(LEGACY_UNIT, needs_review=True, by="migration")
    n = 0
    for rec, ex in todo:
        until = str(ex.get("until"))[:10]
        try:
            datetime.strptime(until, "%Y-%m-%d")
        except ValueError:
            continue
        slug = rec.get("slug", "")
        ref = "|".join((slug, str(ex.get("at", "")), str(ex.get("signed_by", "")), until))
        entry = {
            "vendor_slug": slug, "vendor_name": rec.get("vendor", ""),
            "detection_code": VENDOR_CODE, "detection_text": "Whole vendor (recorded before per-detection acceptances)",
            "org_unit_id": unit_id, "accepter": str(ex.get("signed_by", ""))[:200], "accepter_level": "legacy",
            "risk_tier": "unrated", "justification": str(ex.get("why", ""))[:4000], "compensating_controls": "",
            "expires_on": until, "risk_snapshot": json.dumps({"legacy": ex}, sort_keys=True),
            "signed_at": str(ex.get("at", "")) or until, "recorded_by": str(ex.get("recorded_by", "")) or "migration",
        }
        if risk_store.add_legacy(entry, ref, "active" if until >= today.isoformat() else "expired"):
            n += 1
    return n
