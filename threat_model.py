"""Vendor threat model: one per vendor, built from the vendor record and reviewed by a person.

What is generated (no model calls, no AI in any rating):
  - seven trust-boundary types, always present, each with a status (known | unknown)
  - systems and data flows derived from the record (vendor service, your tenant,
    connected apps, sub-processors and model provider, as declared)
  - threats: fixed STRIDE (and LINDDUN for privacy) prompts per boundary, each a draft
  - open questions: one per unknown boundary, plus each factsheet gap

What a person does: writes the scenario, rates likelihood and impact (1 to 5), chooses
a disposition, lists mitigations, answers questions, and reviews. Accepting a threat
needs an approver for its rating band (the same rule as risk acceptance). Review is
blocked while any threat is undecided or unrated.

Updates: the model is refreshed when the vendor's facts change (features, sub-processors,
connected apps, model provider, hosting, authorization). Analyst decisions survive a
refresh by threat id. A reviewed version stays current until someone reviews again,
and the page says what changed since.

Stored on the vendor record as rec["threat_model"]. Reviewed versions are appended to
history and never edited.
"""
from __future__ import annotations

import copy
import hashlib
from datetime import date, datetime, timezone

import risk_rules

DISPOSITIONS = ("open", "mitigate", "accept", "transfer", "eliminate")
DISPOSITIONS_LABEL = {"open": "Open", "mitigate": "Mitigate", "accept": "Accept",
                      "transfer": "Transfer", "eliminate": "Eliminate"}
MAX_MITIGATIONS = 10
SCALE = (1, 2, 3, 4, 5)

# Fixed order: boundary ids TB-1..TB-7 never change.
BOUNDARY_TYPES = [
    {"key": "intake", "name": "Customer data intake",
     "crosses": "Your people or customers submit data to the vendor.",
     "question": "What data do people submit, through which channels, and who can open the intake?"},
    {"key": "admin", "name": "Vendor access to your tenant",
     "crosses": "Connected apps, OAuth grants, admin roles and SSO into your environment.",
     "question": "Which accounts, apps and roles reach our tenant, how are they granted and removed?"},
    {"key": "egress", "name": "Data leaving the service",
     "crosses": "Exports, downloads, API pulls, email and shared links.",
     "question": "How can our data leave the service: exports, API, downloads, email, shared links?"},
    {"key": "personnel", "name": "Vendor staff access",
     "crosses": "Support, operations and remote sessions by the vendor's own people.",
     "question": "How do vendor staff reach our data for support or operations, and what is logged?"},
    {"key": "subprocessor", "name": "Sub-processors and model providers",
     "crosses": "Our data sent to hosting, analytics, inference or other processors.",
     "question": "Which sub-processors and model providers touch our data, and do any train on it?"},
    {"key": "jurisdiction", "name": "Location and transfers",
     "crosses": "Data stored or accessed from another country or region.",
     "question": "Where is our data stored and accessed from, and what transfer mechanism applies?"},
    {"key": "exit", "name": "Exit and deletion",
     "crosses": "Offboarding, backups, caches and copies after the contract ends.",
     "question": "What happens to our data and access at exit, including backups, and how is deletion verified?"},
]
TB_ID = {b["key"]: "TB-%d" % (i + 1) for i, b in enumerate(BOUNDARY_TYPES)}
BOUNDARY_BY_KEY = {b["key"]: b for b in BOUNDARY_TYPES}

# Prompts: key, STRIDE letter(s), lens, prompt text (also the default scenario).
PROMPTS = {
    "intake": [
        ("spoof_link", "S", "security", "A look-alike intake link or page collects data outside the vendor's real service."),
        ("open_intake", "I", "security", "Intake accepts submissions without sign-in, or results are shared through a public link."),
        ("reidentify", "I", "privacy", "Free text or small groups let someone identify the person behind a submission."),
    ],
    "admin": [
        ("over_access", "E", "security", "Connected apps or accounts hold more access than the job needs, including default entitlements."),
        ("lingering_grant", "E", "security", "A grant (OAuth app, token, service principal) keeps working after the contract or offboarding."),
        ("shared_acct", "R", "security", "Accounts are shared, so actions cannot be traced to one person."),
    ],
    "egress": [
        ("copy_out", "I", "security", "Exports, downloads or API pulls leave controlled storage with no record."),
        ("tamper_export", "T", "security", "Exported data can be altered without detection."),
        ("linkability", "I", "privacy", "Exported records can be linked back to individuals."),
    ],
    "personnel": [
        ("phished_staff", "S", "security", "A vendor employee's credentials are phished or reused, giving access to our data."),
        ("screen_capture", "I", "security", "Remote support or session tools let staff copy, print or record our data."),
        ("unlogged_actions", "R", "security", "Staff actions on our data are not logged or cannot be attributed."),
    ],
    "subprocessor": [
        ("training_use", "I", "security", "Our data is used to train models or is shared with other customers."),
        ("silent_swap", "T", "security", "A sub-processor or model provider changes without notice and is not reviewed."),
        ("retention_sub", "I", "privacy", "A sub-processor keeps personal data longer than the contract allows."),
    ],
    "jurisdiction": [
        ("unlawful_transfer", "I", "privacy", "Personal data about people in one region is processed in another without a transfer mechanism."),
        ("wide_access", "E", "security", "Vendor staff can reach our data from more regions than the service needs."),
    ],
    "exit": [
        ("residual_copies", "I", "security", "Copies (backups, caches, exports) remain after exit and cannot be verified as deleted."),
        ("access_after_exit", "E", "security", "Vendor access still works after the contract ends."),
    ],
}


class ModelError(ValueError):
    """Something a person must fix before the model can be saved or reviewed."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _qid(text: str) -> str:
    return "Q-" + hashlib.sha1(text.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]


def _fact(value, unknown="unknown") -> str:
    v = str(value or "").strip()
    return v if v and v.lower() != unknown else ""


# ------------------------------------------------------------------ inputs
def inputs(rec: dict) -> dict:
    """The facts the model depends on. Compared between refreshes to detect change."""
    fs = rec.get("factsheet") or {}
    answers = {}
    answers.update(rec.get("answers") or {})
    answers.update(rec.get("renewal_answers") or {})
    import access_store
    apps = sorted(
        "%s|%s" % (r.get("display_name", ""), ",".join(sorted(r.get("scopes") or [])))
        for r in access_store.rows(rec) if r.get("status") == "active"
    )
    return {
        "authorization": rec.get("authorization", ""),
        "stage": rec.get("stage", ""),
        "mode": rec.get("mode", ""),
        "ai_used": rec.get("ai_used", "") or fs.get("ai_used", ""),
        "model_provider": _fact(fs.get("model_provider")),
        "models": _fact(fs.get("models")),
        "hosting": _fact(fs.get("hosting")),
        "subprocessors": _fact(fs.get("subprocessors")),
        "sso": _fact(fs.get("sso")),
        "data_classes": _fact(fs.get("data_classes")),
        "trains": fs.get("trains_on_customer_content", ""),
        "tenancy": _fact(fs.get("tenancy")),
        "ai_region": _fact(answers.get("ai_region")),
        "connected_apps": apps,
        "gaps": sorted(fs.get("gaps") or []),
    }


def changes_between(old: dict | None, new: dict) -> list[str]:
    """Plain-language list of what changed. Empty when nothing material changed."""
    if not old:
        return []
    out = []
    labels = {
        "authorization": "Authorization", "stage": "Stage", "mode": "Delivery",
        "ai_used": "AI on our data", "model_provider": "Model provider", "models": "Models",
        "hosting": "Hosting", "subprocessors": "Sub-processors", "sso": "SSO / MFA",
        "data_classes": "Data collected", "trains": "Trains on our data", "tenancy": "Tenancy",
        "ai_region": "AI regions",
    }
    for key, label in labels.items():
        if (old.get(key) or "") != (new.get(key) or ""):
            out.append("%s changed" % label)
    before, after = set(old.get("connected_apps") or []), set(new.get("connected_apps") or [])
    added, removed = len(after - before), len(before - after)
    if added or removed:
        out.append("Connected apps changed (%d added, %d removed)" % (added, removed))
    gaps_before, gaps_after = set(old.get("gaps") or []), set(new.get("gaps") or [])
    if gaps_before != gaps_after:
        out.append("Factsheet gaps changed")
    return out


# ------------------------------------------------------------------ generation
def _boundary_status(key: str, inp: dict) -> str:
    known = {
        "intake": bool(inp["data_classes"] or inp["mode"]),
        "admin": bool(inp["connected_apps"] or inp["sso"]),
        "egress": False,
        "personnel": False,
        "subprocessor": bool(inp["subprocessors"] or inp["model_provider"]),
        "jurisdiction": bool(inp["hosting"] or inp["ai_region"]),
        "exit": False,
    }
    return "known" if known.get(key) else "unknown"


def _systems(rec: dict, inp: dict) -> list[dict]:
    import access_store
    out = [
        {"id": "S-service", "name": "Vendor service", "owner": "Vendor",
         "does": ("Delivered as %s" % mode_label(inp["mode"])) if inp["mode"] else "Delivery model not declared",
         "auth": inp["sso"] or "Not declared", "status": "known" if inp["sso"] or inp["mode"] else "unknown"},
        {"id": "S-tenant", "name": "Your tenant or environment", "owner": "You",
         "does": "Where the vendor's integrations and users reach your data",
         "auth": "Your identity provider", "status": "known"},
    ]
    for i, r in enumerate(access_store.rows(rec)):
        if r.get("status") != "active":
            continue
        out.append({"id": "S-app-%d" % (i + 1), "name": "Connected app: %s" % r["display_name"],
                    "owner": r.get("owner") or "Not on file",
                    "does": "Scopes: %s" % (", ".join(r.get("scopes") or []) or "none on file"),
                    "auth": "OAuth grant", "status": "known"})
    if inp["model_provider"] or inp["ai_used"] == "yes":
        out.append({"id": "S-model", "name": "Model provider", "owner": inp["model_provider"] or "Not declared",
                    "does": "Inference on our data" if inp["ai_used"] == "yes" else "Declared provider",
                    "auth": "Not recorded", "status": "known" if inp["model_provider"] else "unknown"})
    if inp["subprocessors"]:
        out.append({"id": "S-subs", "name": "Sub-processors (as declared)", "owner": "Vendor",
                    "does": inp["subprocessors"][:300], "auth": "Not recorded", "status": "known"})
    return out


def _flows(inp: dict) -> list[dict]:
    return [
        {"id": "F-1", "from": "Customer or employee", "to": "Vendor service", "data": inp["data_classes"] or "Not declared",
         "boundary": TB_ID["intake"]},
        {"id": "F-2", "from": "Your tenant", "to": "Connected apps", "data": "Scoped access per app",
         "boundary": TB_ID["admin"]},
        {"id": "F-3", "from": "Vendor service", "to": "Customer or other systems", "data": "Exports, API, downloads",
         "boundary": TB_ID["egress"]},
        {"id": "F-4", "from": "Vendor staff", "to": "Vendor service", "data": "Support and operations access",
         "boundary": TB_ID["personnel"]},
        {"id": "F-5", "from": "Vendor service", "to": "Sub-processors and model provider",
         "data": "Hosting, inference, analytics", "boundary": TB_ID["subprocessor"]},
        {"id": "F-6", "from": "Vendor service", "to": "Hosting regions", "data": inp["hosting"] or "Not declared",
         "boundary": TB_ID["jurisdiction"]},
        {"id": "F-7", "from": "Vendor service", "to": "Deletion and backups", "data": "On exit",
         "boundary": TB_ID["exit"]},
    ]


def _boundaries(inp: dict) -> list[dict]:
    out = []
    for b in BOUNDARY_TYPES:
        out.append({"id": TB_ID[b["key"]], "key": b["key"], "name": b["name"], "crosses": b["crosses"],
                    "status": _boundary_status(b["key"], inp)})
    return out


AI_PROMPTS = {"training_use", "silent_swap", "retention_sub"}


def _applies(key: str, prompt_key: str, inp: dict) -> bool:
    # Prompts about AI providers only apply when AI can touch our data. Unknown counts as yes.
    if prompt_key in AI_PROMPTS:
        return inp["ai_used"] != "no"
    return True


def _threats(inp: dict) -> list[dict]:
    out = []
    for b in BOUNDARY_TYPES:
        for key, stride, lens, text in PROMPTS[b["key"]]:
            out.append({
                "id": "%s.%s" % (TB_ID[b["key"]], key), "boundary": TB_ID[b["key"]], "prompt": key,
                "stride": stride, "lens": lens, "text": text, "applies": _applies(b["key"], key, inp),
            })
    return out


def _questions(inp: dict) -> list[dict]:
    out = []
    for b in BOUNDARY_TYPES:
        if _boundary_status(b["key"], inp) == "unknown":
            out.append({"id": _qid(b["question"]), "text": b["question"], "owner": "Vendor",
                        "relates_to": [TB_ID[b["key"]]]})
    for gap in inp["gaps"]:
        text = "Provide: %s" % gap
        out.append({"id": _qid(text), "text": text, "owner": "Vendor", "relates_to": []})
    return out


# ------------------------------------------------------------------ live model
# Everything the model shows is computed from the vendor record on each read. Only the
# analyst's decisions are stored, under rec["threat_model"]: decisions by threat id,
# answers by question id, the design statement, and the reviewed versions (history).
# So a change to the record shows up at once, with no refresh step, and a decision
# stays attached to its threat id.

def _ensure(rec: dict) -> dict:
    store = rec.get("threat_model")
    if not isinstance(store, dict):
        store = {}
    store.setdefault("decisions", {})
    store.setdefault("answers", {})
    store.setdefault("history", [])
    store.setdefault("version", 0)
    store.setdefault("design_statement", "")
    rec["threat_model"] = store
    return store


def rating_band(likelihood, impact) -> str:
    if not likelihood or not impact:
        return ""
    score = likelihood * impact
    if score >= 20:
        return "critical"
    if score >= 12:
        return "high"
    if score >= 6:
        return "medium"
    return "low"


def rating_label(band) -> str:
    return {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}.get(band or "", "Unrated")


def stride_label(code: str) -> str:
    names = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information disclosure",
             "D": "Denial of service", "E": "Elevation of privilege"}
    return names.get(code, code)


MODE_LABEL = {"saas": "SaaS", "on_prem": "On-premises", "on-prem": "On-premises", "api": "API"}


def mode_label(value) -> str:
    v = str(value or "").strip()
    if not v:
        return "Not recorded"
    return MODE_LABEL.get(v.lower(), v.replace("_", " ").capitalize())


def when(iso) -> str:
    """Timestamps for people to read: 2026-10-10 15:23 UTC."""
    v = str(iso or "").strip()
    if not v:
        return ""
    try:
        d = datetime.fromisoformat(v)
    except ValueError:
        return v
    if d.tzinfo is None:
        return d.strftime("%Y-%m-%d %H:%M")
    return d.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _merge(t: dict, d: dict, today: date) -> dict:
    likelihood, impact = d.get("likelihood"), d.get("impact")
    rating = rating_band(likelihood, impact) or None
    disposition = d.get("disposition", "open")
    until = d.get("accepted_until", "") if disposition == "accept" else ""
    expired = bool(until) and until < today.isoformat()
    decided = disposition != "open" and rating is not None and not expired
    return {
        **t, "scenario": d.get("scenario") or t["text"], "likelihood": likelihood, "impact": impact,
        "rating": rating, "rating_basis": d.get("rating_basis", ""),
        "mitigations": list(d.get("mitigations") or []), "disposition": disposition,
        "accepted_by": d.get("accepted_by", "") if until else "", "accepted_until": until,
        "expired": expired, "decided": decided, "status": "decided" if decided else "draft",
        "decided_by": d.get("by", ""), "decided_at": d.get("at", ""), "retired": False,
    }


def build(rec: dict, today: date | None = None) -> dict:
    """The whole model for this vendor, as of today. Computed; nothing here is saved."""
    today = today or date.today()
    store = rec.get("threat_model") or {}
    decisions = store.get("decisions") or {}
    answers = store.get("answers") or {}
    inp = inputs(rec)

    threats, retired = [], []
    for t in _threats(inp):
        d = decisions.get(t["id"], {})
        if t["applies"]:
            threats.append(_merge(t, d, today))
        elif d:  # no longer applies, but a person decided it: keep it visible
            retired.append({**_merge(t, d, today), "retired": True})

    questions = []
    for q in _questions(inp):
        a = answers.get(q["id"], {})
        questions.append({**q, "answer": a.get("answer", ""), "owner": a.get("owner") or q.get("owner") or "Vendor",
                          "status": "answered" if a.get("answer") else "open"})

    reviewed_at = store.get("reviewed_at", "")
    reviewed_ids = set(store.get("reviewed_threat_ids") or [])
    changes = changes_between(store.get("reviewed_snapshot") or None, inp) if reviewed_at else []
    undecided = [t for t in threats if not t["decided"]]
    if reviewed_at:
        new = [t for t in threats if t["id"] not in reviewed_ids]
        if new:
            changes.append("%d new threat%s to decide" % (len(new), "" if len(new) == 1 else "s"))
        expired = [t for t in threats if t["expired"]]
        if expired:
            changes.append("%d accepted threat%s past expiry" % (len(expired), "" if len(expired) == 1 else "s"))
    if not reviewed_at:
        state = "draft"
    elif changes or undecided:
        state = "needs_review"
    else:
        state = "current"

    # A boundary the record does not cover is confirmed once its open question is answered.
    answered = {tb for q in questions if q["status"] == "answered" for tb in q.get("relates_to") or []}
    boundaries = []
    for b in _boundaries(inp):
        if b["status"] != "known" and b["id"] in answered:
            b = {**b, "status": "known", "source": "answer"}
        boundaries.append(b)

    return {
        "inputs": inp,
        "boundaries": boundaries,
        "systems": _systems(rec, inp),
        "flows": _flows(inp),
        "threats": threats,
        "retired": retired,
        "questions": questions,
        "design_statement": store.get("design_statement", ""),
        "version": int(store.get("version") or 0),
        "reviewed_at": reviewed_at,
        "reviewed_by": store.get("reviewed_by", ""),
        "history": list(store.get("history") or []),
        "status": {
            "state": state, "changes": changes, "undecided": len(undecided),
            "open_questions": sum(1 for q in questions if q["status"] != "answered"),
            "version": int(store.get("version") or 0), "reviewed_at": reviewed_at,
        },
    }


def status(rec: dict, today: date | None = None) -> dict:
    return build(rec, today)["status"]


def _scale(fields: dict, name: str):
    raw = (fields.get(name) or "").strip()
    if raw == "":
        return None
    if not raw.isdigit() or int(raw) not in SCALE:
        raise ModelError("%s must be 1 to 5." % name.capitalize())
    return int(raw)


def set_threat(rec: dict, tid: str, fields: dict, who: str, level: str, today: date | None = None) -> dict:
    """Save one analyst decision. Validates everything first; nothing is saved on error."""
    model = build(rec, today)
    if not any(t["id"] == tid for t in model["threats"]):
        raise ModelError("That threat is not on the model.")
    scenario = (fields.get("scenario") or "").strip()[:1000]
    if not scenario:
        raise ModelError("Describe the scenario in a sentence.")
    likelihood = _scale(fields, "likelihood")
    impact = _scale(fields, "impact")
    rating = rating_band(likelihood, impact) or None

    disposition = fields.get("disposition", "open")
    if disposition not in DISPOSITIONS:
        raise ModelError("Pick a disposition.")
    mitigations = [m.strip()[:300] for m in (fields.get("mitigations") or "").splitlines() if m.strip()]
    if len(mitigations) > MAX_MITIGATIONS:
        raise ModelError("Keep to %d mitigations per threat." % MAX_MITIGATIONS)
    if disposition == "mitigate" and not mitigations:
        raise ModelError("Mitigate needs at least one mitigation. Use Open if none exists yet.")

    accepted_by = accepted_until = ""
    if disposition == "accept":
        if not rating:
            raise ModelError("Rate likelihood and impact before accepting.")
        # The tier is the rating band and cannot be set below it, the same rule as risk acceptance.
        problem = risk_rules.signer_problem(level, rating, rating)
        if problem:
            raise ModelError(problem)
        accepted_until = (fields.get("accepted_until") or "").strip()
        problem = risk_rules.expiry_problem(accepted_until)
        if problem:
            raise ModelError(problem)
        accepted_by = who

    store = _ensure(rec)
    store["decisions"][tid] = {
        "scenario": scenario, "likelihood": likelihood, "impact": impact,
        "rating_basis": (fields.get("rating_basis") or "").strip()[:500],
        "mitigations": mitigations, "disposition": disposition,
        "accepted_by": accepted_by, "accepted_until": accepted_until,
        "by": who, "at": _now(),
    }
    model = build(rec, today)
    return next(t for t in model["threats"] if t["id"] == tid)


def set_question(rec: dict, qid: str, answer: str, owner: str, who: str, today: date | None = None) -> None:
    if not any(q["id"] == qid for q in build(rec, today)["questions"]):
        raise ModelError("That question is not on the model.")
    store = _ensure(rec)
    store["answers"][qid] = {"answer": (answer or "").strip()[:1000], "owner": (owner or "").strip()[:80],
                             "by": who, "at": _now()}


def set_design(rec: dict, text: str) -> None:
    store = _ensure(rec)
    store["design_statement"] = (text or "").strip()[:3000]


def review(rec: dict, who: str, note: str = "", today: date | None = None) -> dict:
    """Record the model as it stands today as a reviewed version. Blocked while anything is undecided."""
    model = build(rec, today)
    if model["status"]["undecided"]:
        n = model["status"]["undecided"]
        raise ModelError("%d threat%s still open, unrated or past acceptance expiry. Decide each one before review." % (
            n, "" if n == 1 else "s"))
    store = _ensure(rec)
    version = model["version"] + 1
    reviewed_at = _now()
    summary = {
        "threats": len(model["threats"]),
        "retired": len(model["retired"]),
        "accepted": sum(1 for t in model["threats"] if t["disposition"] == "accept"),
        "open_questions": sum(1 for q in model["questions"] if q["status"] != "answered"),
    }
    store["version"] = version
    store["reviewed_at"] = reviewed_at
    store["reviewed_by"] = who
    store["reviewed_snapshot"] = copy.deepcopy(model["inputs"])
    store["reviewed_threat_ids"] = [t["id"] for t in model["threats"]]
    store["history"].append({
        "version": version, "reviewed_at": reviewed_at, "reviewed_by": who, "note": (note or "").strip()[:300],
        "summary": summary, "threats": copy.deepcopy(model["threats"]),
        "questions": copy.deepcopy(model["questions"]), "design_statement": model["design_statement"],
    })
    return store
