"""One list of vendors for the portfolio screen.

Two sources feed it: the scored sample portfolio (vendors.demo.csv + controls.demo.csv)
and vendor records created in the app. Onboarded vendors are scored from the factors
drafted out of their questionnaire, so they get a tier like everyone else. Those tiers
are marked provisional until a human confirms the factors.
"""
from __future__ import annotations

from pathlib import Path

import alerts
import config
from records import list_vendors, slugify
from score import load_csv, score_vendor

BASE = config.BASE
FACTOR_KEYS = ("data_sensitivity", "data_volume", "access_level", "criticality",
               "ai_involvement", "blast_radius", "substitutability", "regulatory")
STATUS_LABELS = {"not_authorized": "Not authorized", "trial_only": "Trial only", "blocked": "Blocked"}


def load_results():
    path = BASE / "vendors.demo.csv"
    if not path.is_file():
        return []
    controls = {}
    cpath = BASE / "controls.demo.csv"
    if cpath.is_file():
        for row in load_csv(cpath):
            controls[(row.get("vendor") or "").strip()] = row
    scored = [score_vendor(row, controls.get((row.get("vendor") or "").strip())) for row in load_csv(path)]
    scored.sort(key=lambda r: (-r.inherent_score, r.vendor))
    return scored


def match_demo(slug: str):
    for r in load_results():
        if slugify(r.vendor) == slug:
            return r
    return None


def _tier(label: str) -> str:
    return (label or "T?")[:2]


def rows() -> list[dict]:
    out = []
    demo_names = set()
    records = {r.get("vendor"): r for r in list_vendors()}
    for r in load_results():
        demo_names.add(r.vendor)
        rec = records.get(r.vendor) or {}
        out.append({
            "name": r.vendor, "slug": slugify(r.vendor), "product": r.product,
            "score": r.inherent_score, "inh": _tier(r.inherent_tier), "res": _tier(r.residual_tier),
            "ai": bool(r.ai_in_scope), "human": bool(r.human_required), "provisional": False,
            "status": STATUS_LABELS.get(rec.get("authorization", ""), ""), "tracked": bool(rec),
        })
    for rec in records.values():
        name = rec.get("vendor", "")
        if not name or name in demo_names:
            continue
        if rec.get("stage") == "offboarded":
            continue
        factors = rec.get("draft_factors") or {}
        row = {"vendor": name, "product": rec.get("business") or "", "website": rec.get("website") or "", "notes": ""}
        for k in FACTOR_KEYS:
            row[k] = factors.get(k, 5)  # nothing answered yet: score as unknown-is-worst
        res = score_vendor(row, None)
        out.append({
            "name": name, "slug": rec.get("slug") or slugify(name),
            "product": rec.get("business") or rec.get("source") or "vendor",
            "score": res.inherent_score, "inh": _tier(res.inherent_tier), "res": _tier(res.residual_tier),
            "ai": bool(res.ai_in_scope), "human": True, "provisional": True,
            "status": STATUS_LABELS.get(rec.get("authorization", ""), ""), "tracked": True,
        })
    return out


def attention(limit: int = 4) -> list[dict]:
    """Vendors with the most serious open flags, for the 'needs you now' panel."""
    _counts, flag_rows, _clocks = alerts.dashboard()
    by: dict[str, dict] = {}
    for r in flag_rows:
        if r["severity"] == "accepted":
            continue
        d = by.setdefault(r["slug"], {"vendor": r["vendor"], "slug": r["slug"], "high": 0, "texts": []})
        if r["severity"] == "high":
            d["high"] += 1
        d["texts"].append(r["text"])
    ranked = sorted(by.values(), key=lambda d: (-d["high"], -len(d["texts"]), d["vendor"]))[:limit]
    out = []
    for d in ranked:
        extra = len(d["texts"]) - 2
        text = "; ".join(d["texts"][:2]) + (" (+%d more)" % extra if extra > 0 else "")
        out.append({"vendor": d["vendor"], "slug": d["slug"], "text": text, "high": d["high"]})
    return out
