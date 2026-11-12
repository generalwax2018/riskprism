"""Turn submitted answers into follow-up flags. Does not invent findings.

Flags come from whole-word / per-sentence checks in textclass.py. When an answer is
ambiguous the flag asks a question instead of asserting a finding.
"""
from __future__ import annotations

import re
from datetime import date

import policy_store
import textclass as tc


def load_policy():
    return policy_store.load()


def _get(answers: dict, *keys: str) -> str:
    for k in keys:
        if answers.get(k):
            return str(answers[k])
    return ""


def _critical(answers: dict, record: dict) -> bool:
    klass = answers.get("data_class") or record.get("data_class") or ""
    data = answers.get("data") or ""
    return tc.is_critical(klass) or bool(tc.words(data, tc.CRITICAL_DATA_TERMS))


_EXEC_ONLY = ("executive", "exec summary", "management summary", "cover letter only", "no findings", "high level only")
_SOC_TYPE1 = re.compile(r"\btype\s*(i|1)\b", re.I)
_SOC_TYPE2 = re.compile(r"\btype\s*(ii|2)\b", re.I)
_SOC_EXC = re.compile(r"\b(exceptions?|qualified|emphasis of matter|modified opinion)\b", re.I)
_SOC_CLEAN = re.compile(
    r"\b(no|zero|without|not any)\b[^.;]{0,25}\b(exceptions?|qualif\w*)\b|\bunqualified\b|\bclean opinion\b", re.I)


def _ai_topics(record: dict):
    """None when the vendor has not answered an AI questionnaire; otherwise which of
    'soc2' / 'pentest' its approved questions asked about."""
    if record.get("ai_answers") is None:
        return None
    topics = set()
    for q in (record.get("ai_q") or {}).get("approved") or []:
        words = (q.get("feeds", "") + " " + q.get("doc_type", "") + " " + q.get("text", "")).lower()
        if q.get("feeds") == "soc2" or re.search(r"\bsoc ?2\b|\biso ?27001\b", words):
            topics.add("soc2")
        if q.get("feeds", "").startswith("pentest") or re.search(r"\bpen(etration)? ?test", words):
            topics.add("pentest")
    return topics


def scan(record: dict) -> list[dict]:
    policy = load_policy()
    answers = {}
    answers.update(record.get("answers") or {})
    answers.update(record.get("renewal_answers") or {})
    answers.update(record.get("followup_answers") or {})
    flags = []
    # On an AI questionnaire the approved questions decide whether a SOC 2 or pentest is
    # needed at all (a printer or food vendor may need neither), so "missing" only fires
    # when they were asked for. The other rules still judge whatever was answered.
    asked = _ai_topics(record)
    want_pentest = asked is None or "pentest" in asked
    want_soc2 = asked is None or "soc2" in asked

    pentest = _get(answers, "pentest_current", "pentest", "pentest_open")
    pl = pentest.lower()
    if pentest.strip() and any(w in pl for w in _EXEC_ONLY):
        flags.append({
            "id": "pentest_exec_only", "severity": "high",
            "title": "Pentest looks like executive summary only",
            "detail": "Need the full findings report, not the cover letter.",
            "ask": "Provide the full pentest findings (severity and open items), not the executive summary only.",
        })
    elif want_pentest and not pentest.strip() and not record.get("pentest_url") and not record.get("pentest_expires") and not record.get("evidence_files"):
        flags.append({
            "id": "pentest_missing", "severity": "high",
            "title": "No pentest evidence",
            "detail": "No report date, link, or description on file.",
            "ask": "Date, firm, and link to the full pentest findings — not an executive page.",
        })

    soc_text = " ".join(str(answers.get(k) or "") for k in ("soc2_current", "soc2", "soc2_exceptions")).strip()
    if want_soc2 and not soc_text and not record.get("soc2_url") and not record.get("soc2_expires") and not record.get("evidence_files"):
        flags.append({
            "id": "soc2_missing", "severity": "high",
            "title": "SOC 2 / ISO not provided",
            "detail": "No period, type, or request path.",
            "ask": "Current SOC 2 Type II or ISO 27001: period dates and any exceptions.",
        })
    elif soc_text:
        if _SOC_TYPE1.search(soc_text) and not _SOC_TYPE2.search(soc_text):
            flags.append({
                "id": "soc2_type1", "severity": "medium",
                "title": "SOC 2 Type I only",
                "detail": "Type I is point-in-time design. Ask for Type II.",
                "ask": "Do you have SOC 2 Type II and what period does it cover?",
            })
        if _SOC_EXC.search(soc_text) and not _SOC_CLEAN.search(soc_text):
            flags.append({
                "id": "soc2_exceptions", "severity": "high",
                "title": "SOC 2 exceptions called out",
                "detail": "Answer mentions exceptions or a qualified opinion.",
                "ask": "List each SOC 2 exception and remediation status.",
            })

    ai_yes = (
        record.get("ai_used") == "yes"
        or tc.yes_no(answers.get("ai_used", "")) == "yes"
        or bool((answers.get("ai_models") or "").strip())
    )
    models = _get(answers, "ai_models", "ai_provider", "ai_change")
    if ai_yes and not models.strip():
        flags.append({
            "id": "ai_models_unnamed", "severity": "high",
            "title": "AI in use — models not named",
            "detail": "Need vendor + model name for every model on the data path.",
            "ask": "List every model: vendor and name (e.g. OpenAI GPT-4o). Which ones can be disabled?",
        })
    if models.strip():
        low = models.lower()
        hits = [n.strip() for n in policy.get("restricted_models") or [] if n.strip() and n.strip().lower() in low]
        if hits:
            flags.append({
                "id": "ai_model_restricted", "severity": "high",
                "title": "Model on the customer restricted list",
                "detail": "Matched policy restricted_models: " + ", ".join(hits),
                "ask": "These model names match this customer's restricted list (" + ", ".join(hits) + "). Can this tenant run without them?",
            })

    if tc.training_default(answers.get("ai_train", "")) == "on":
        flags.append({
            "id": "ai_train_on", "severity": "high",
            "title": "Possible training on customer content",
            "detail": "The training answer says training is on by default.",
            "ask": "Does any model train on our content by default, and how do we turn that off?",
        })

    if _critical(answers, record) and policy.get("required_region_if_critical", True):
        region = _get(answers, "ai_region", "hosting", "ai_provider")
        if not region.strip():
            flags.append({
                "id": "critical_no_region", "severity": "high",
                "title": "Critical data — no region on file",
                "detail": "Critical classification requires inference and storage region.",
                "ask": "Exact countries/regions for storage and model inference. Can the tenant be pinned (EU / US / other)?",
            })
        else:
            terms = [n.strip() for n in policy.get("restricted_regions") or [] if n.strip()]
            rhits = tc.words(region, terms)
            if rhits:
                flags.append({
                    "id": "region_restricted", "severity": "high",
                    "title": "Region on the customer restricted list",
                    "detail": "Matched policy restricted_regions: " + ", ".join(rhits),
                    "ask": "Data or inference appears in a region this customer does not allow (" + ", ".join(rhits) + "). What is the pin option?",
                })

    flags.extend(integration_flags(answers))

    # Documents the AI questionnaire asked for and the vendor did not provide.
    import ai_questionnaire
    flags.extend(ai_questionnaire.document_flags(record))

    existing = {f["id"]: f for f in record.get("followups") or [] if f.get("status") == "open"}
    resolved = {f["id"]: f for f in record.get("followups") or [] if f.get("status") == "resolved"}
    out, seen = [], set()
    for f in flags:
        if f["id"] in seen:
            continue
        seen.add(f["id"])
        if f["id"] in resolved:
            # An analyst already closed this one; keep their decision and history.
            out.append(resolved[f["id"]])
            continue
        prev = existing.get(f["id"], {})
        f["status"] = prev.get("status") or "open"
        f["opened_at"] = prev.get("opened_at") or date.today().isoformat()
        out.append(f)
    for old in record.get("followups") or []:
        if old.get("id") in seen:
            continue
        if old.get("status") in ("open", "resolved"):
            out.append(old)
    return out


_NONE = re.compile(r"^\s*(none|no|n/a|not applicable|nothing|no connections?)\b", re.I)
_VERIFIED = re.compile(r"\b(sign|signed|signature|hmac|jwt|oauth|token|mtls|mutual tls|certificate|shared secret)\w*", re.I)


def integration_flags(answers: dict) -> list[dict]:
    """Follow-ups from the integrations section (fixed questionnaire or the AI questionnaire's
    required integrations question). They ask, they do not assert."""
    connect = (answers.get("int_connect") or "").strip().lower()
    listing = _get(answers, "int_list", "integrations")
    connects = connect == "yes" or (connect != "no" and listing.strip() and not _NONE.match(listing))
    out = []
    if not connects:
        if connect == "unsure":
            out.append({"id": "int_unsure", "severity": "medium", "title": "Vendor is not sure whether it connects to our systems",
                        "detail": "Integrations question answered 'Not sure'.",
                        "ask": "Please confirm whether your product connects to any of our systems or SaaS tenants, and how."})
        return out
    if not _get(answers, "int_permissions").strip() and "scope" not in listing.lower() and "permission" not in listing.lower():
        out.append({"id": "int_permissions_missing", "severity": "medium", "title": "Permissions for its connections not listed",
                    "detail": "The vendor connects to our systems but did not list the permissions, scopes or roles it needs.",
                    "ask": "List every permission, scope or role your product needs in each of our systems, exactly as named there, and why."})
    if (answers.get("int_admin") or "").strip().lower() == "yes":
        out.append({"id": "int_admin_rights", "severity": "high", "title": "Connection needs administrator or tenant-wide write rights",
                    "detail": "The vendor said a connection needs admin rights or tenant-wide write access.",
                    "ask": "Which connection needs administrator or tenant-wide write rights, for what, and can it be narrowed to specific objects?"})
    if not _get(answers, "int_credentials").strip() and "certificate" not in listing.lower() and "oauth" not in listing.lower():
        out.append({"id": "int_credentials_missing", "severity": "medium", "title": "How connections authenticate is not stated",
                    "detail": "No answer on credentials, storage or rotation for the vendor's connections.",
                    "ask": "How does each connection authenticate, where are the credentials stored, and can we rotate them or set them to expire?"})
    inbound = _get(answers, "int_inbound").strip()
    if inbound and not _NONE.match(inbound) and not _VERIFIED.search(inbound):
        out.append({"id": "int_inbound_unverified", "severity": "medium", "title": "Inbound calls may not be authenticated",
                    "detail": "The vendor needs an endpoint from us but did not say how its calls are signed or authenticated.",
                    "ask": "How are your calls to our endpoint signed or authenticated, and from which IP ranges do they come?"})
    return out


def apply(record: dict) -> dict:
    record["followups"] = scan(record)
    record["followup_open"] = sum(1 for f in record["followups"] if f.get("status") == "open")
    return record


def questions_for(record: dict) -> list[tuple[str, str]]:
    return [(f["id"], f.get("ask") or f.get("title")) for f in record.get("followups") or [] if f.get("status") == "open"]
