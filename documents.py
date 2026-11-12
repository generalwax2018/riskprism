"""Vendor document repository: types, metadata and status.

Files are still stored by evidence_store.py and listed on the vendor record as
evidence_files[]. This module only knows what a document *is*: its type, the
period it covers, how long it is good for, and whether a person has read it.

"Received" and "reviewed" are different states on purpose. A SOC 2 that nobody
opened is not evidence of anything, so an unreviewed document is never shown green.
"""
from __future__ import annotations

import re
from datetime import date, timedelta

# (code, label). Order is the order in the upload menu.
TYPES = (
    ("soc2_type2", "SOC 2 Type II"),
    ("soc2_type1", "SOC 2 Type I"),
    ("soc1", "SOC 1"),
    ("iso27001", "ISO 27001 certificate"),
    ("bridge_letter", "Bridge letter"),
    ("pentest", "Pentest / red team"),
    ("insurance", "Cyber insurance certificate"),
    ("questionnaire", "Completed questionnaire"),
    ("contract", "Contract / DPA / BAA"),
    ("other", "Other"),
)
LABELS = dict(TYPES)
# Earlier uploads used one bucket for SOC 2 and ISO. Still readable, no longer offered.
LEGACY = {"soc2": "SOC 2 / ISO"}

# A document of these types moves the matching evidence clock forward when it is
# uploaded with a "valid until" date later than the clock's current date.
FEEDS_CLOCK = {
    "soc2_type2": "soc2_expires", "soc2_type1": "soc2_expires", "soc1": "soc2_expires",
    "iso27001": "soc2_expires", "pentest": "pentest_expires",
}
# SOC reports and pentests describe a period. Without an explicit valid-until date,
# they go stale this long after the period ends.
STALE_AFTER_DAYS = 365
PERIOD_TYPES = {"soc2_type2", "soc2_type1", "soc1", "pentest", "bridge_letter", "soc2"}

META_FIELDS = ("period_end", "valid_until", "description")
DESC_MAX = 200
REVIEW_NOTE_MAX = 4000


def valid_kind(kind: str) -> str:
    return kind if kind in LABELS else "other"


def label(kind: str) -> str:
    return LABELS.get(kind) or LEGACY.get(kind) or "Other"


def _date(v) -> date | None:
    try:
        return date.fromisoformat(str(v or "")[:10])
    except ValueError:
        return None


def clean_meta(fields: dict) -> dict:
    """Upload metadata from a form: dates must be real dates, text is trimmed."""
    out = {}
    for key in ("period_end", "valid_until"):
        d = _date(fields.get(key))
        out[key] = d.isoformat() if d else ""
    out["description"] = " ".join(str(fields.get("description") or "").split())[:DESC_MAX]
    return out


def good_until(f: dict) -> date | None:
    """The date this document stops counting: valid_until if set, else period end + a year."""
    d = _date(f.get("valid_until"))
    if d:
        return d
    end = _date(f.get("period_end"))
    if end and f.get("kind") in PERIOD_TYPES:
        return end + timedelta(days=STALE_AFTER_DAYS)
    return None


def status(f: dict, today: date | None = None) -> tuple[str, str, str]:
    """(code, text, tone) for one document. code: expired | unreviewed | expiring | reviewed."""
    today = today or date.today()
    until = good_until(f)
    if until and until < today:
        return "expired", "Expired", "red"
    if not f.get("reviewed_by"):
        return "unreviewed", "Not reviewed", "amber"
    if until and until <= today + timedelta(days=30):
        return "expiring", "Expiring soon", "amber"
    return "reviewed", "Reviewed", "green"


def clock_update(rec: dict, f: dict) -> tuple[str, str] | None:
    """(clock field, new date) if this upload should move a clock forward, else None."""
    field = FEEDS_CLOCK.get(f.get("kind", ""))
    new = _date(f.get("valid_until"))
    if not field or not new:
        return None
    cur = _date(rec.get(field))
    if cur and cur >= new:
        return None
    return field, new.isoformat()


def find(rec: dict, doc_id: str) -> dict | None:
    return next((f for f in rec.get("evidence_files") or [] if f.get("id") == doc_id), None)


def guess_kind(text: str) -> str:
    """Type for a file a vendor uploaded against a document request, from the request's wording."""
    t = " ".join((text or "").lower().split())
    if "bridge" in t:
        return "bridge_letter"
    if "soc 1" in t or "soc1" in t:
        return "soc1"
    if re.search(r"\btype (i|1)\b", t):
        return "soc2_type1"
    if "soc 2" in t or "soc2" in t:
        return "soc2_type2"
    if "iso 27001" in t or "iso27001" in t:
        return "iso27001"
    if "pentest" in t or "pen test" in t or "penetration" in t:
        return "pentest"
    if "insurance" in t:
        return "insurance"
    return "other"
