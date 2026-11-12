from __future__ import annotations

import csv
from io import StringIO

import records
from records import load_vendor, save_vendor, slugify

KNOWN = {
    "vendor", "name", "website", "owner", "business", "renewal_date", "annual_spend",
    "contact", "mode", "stage", "authorization", "commercial_contact",
}
MODES = {"saas", "hybrid", "onprem", "unknown"}
STAGES = {"inquiry", "trial_30", "contracted", "renewal_due", "offboarded"}
AUTHS = {"not_authorized", "trial_only", "authorized", "blocked"}
MAX_ROWS = 2000


def _cut(v, n=300):
    return (v or "").strip()[:n]


def import_csv(text: str) -> int:
    """Create or update vendors from pasted CSV. Existing records keep their answers,
    evidence and history; only the columns present in the CSV are changed."""
    sample = (text or "").lstrip()
    if not sample:
        return 0
    reader = csv.DictReader(StringIO(sample))
    n = 0
    for raw in reader:
        if n >= MAX_ROWS:
            break
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items() if k}
        name = _cut(row.get("vendor") or row.get("name"), 200)
        if not name:
            continue
        slug = slugify(name)
        rec = load_vendor(slug) or {}
        rec["vendor"] = name
        rec["slug"] = slug
        for key in ("website", "owner", "business", "renewal_date", "annual_spend", "contact", "commercial_contact"):
            rec[key] = _cut(row.get(key)) or rec.get(key, "")
        mode = _cut(row.get("mode")).lower()
        stage = _cut(row.get("stage")).lower()
        auth = _cut(row.get("authorization")).lower()
        rec["mode"] = mode if mode in MODES else rec.get("mode") or "unknown"
        rec["stage"] = stage if stage in STAGES else rec.get("stage") or "inquiry"
        rec["authorization"] = auth if auth in AUTHS else rec.get("authorization") or "not_authorized"
        rec["source"] = rec.get("source") or "csv_import"
        extra = {k[:60]: v[:300] for k, v in row.items() if k not in KNOWN and v}
        if extra:
            rec["import_extra"] = extra
        save_vendor(rec)
        n += 1
    return n
