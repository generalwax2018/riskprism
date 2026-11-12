"""Turn submitted questionnaire answers into an AI factsheet + draft factors.

Everything here is a DRAFT for a human to confirm. Ambiguous text is "unknown",
never a guess in the vendor's favour.
"""
from __future__ import annotations

from datetime import date, datetime

import followup
import textclass as tc


def _txt(*vals):
    return " ".join(str(v or "") for v in vals).lower()


def _yn(text: str):
    return tc.yes_no(text)


def merged_answers(record: dict) -> dict:
    out = {}
    out.update(record.get("answers") or {})
    out.update(record.get("renewal_answers") or {})
    out.update(record.get("followup_answers") or {})
    return out


def factsheet(answers: dict, intake: dict | None = None) -> dict:
    intake = intake or {}
    ai_used = _yn(answers.get("ai_used", ""))
    if ai_used == "unknown" and intake.get("ai_used") in ("yes", "no"):
        ai_used = intake["ai_used"]
    train_flag = tc.training_default(answers.get("ai_train", ""))
    if train_flag == "unknown" and intake.get("ai_train") in ("off", "on"):
        train_flag = intake["ai_train"]
    data = answers.get("data", "")
    sensitive = bool(tc.words(data, tc.SENSITIVE_TERMS))
    models = (answers.get("ai_models") or answers.get("ai_change") or "").strip()
    return {
        "built_at": datetime.now().isoformat(timespec="seconds"),
        "source": "questionnaire_answers",
        "ai_used": ai_used,
        "models": models or "unknown",
        "trains_on_customer_content": train_flag,
        "model_provider": (answers.get("ai_provider") or "").strip() or "unknown",
        "hosting": (answers.get("hosting") or "").strip() or "unknown",
        "subprocessors": (answers.get("subprocessors") or "").strip() or "unknown",
        "soc2_path": (answers.get("soc2") or answers.get("soc2_current") or intake.get("soc2") or "").strip() or "unknown",
        "sso": (answers.get("sso") or "").strip() or "unknown",
        "data_classes": (data or "").strip() or "unknown",
        "sensitive_data_hint": sensitive,
        "tenancy": (answers.get("tenancy") or "").strip() or "unknown",
        "security_contact": (answers.get("sec_contact") or "").strip() or "unknown",
        "gaps": gaps(answers),
    }


def gaps(answers: dict) -> list:
    out = []
    for key, label in [
        ("data", "data types"),
        ("hosting", "hosting region"),
        ("soc2", "SOC 2 / ISO how-to-request"),
        ("ai_used", "whether a model touches customer content"),
        ("ai_models", "named models"),
        ("tenancy", "tenant isolation"),
        ("sec_contact", "security contact"),
    ]:
        if key == "soc2":
            v = (answers.get("soc2") or answers.get("soc2_current") or "").strip().lower()
        else:
            v = (answers.get(key) or "").strip().lower()
        if not v or v in ("unknown", "n/a", "na"):
            if key == "ai_models" and _yn(answers.get("ai_used", "")) != "yes":
                continue
            out.append("Missing: " + label)
    return out


def draft_factors(answers: dict, intake: dict | None = None) -> dict:
    """Draft 0-5 factor scores using the same keys score.py uses, so an onboarded
    vendor can be tiered like the sample portfolio. Factors the questionnaire cannot
    inform default to 3 and are listed in `unconfirmed` for the analyst."""
    intake = intake or {}
    data = _txt(answers.get("data"), intake.get("business"))
    mode = (intake.get("mode") or "saas").lower()
    ai_yes = _yn(answers.get("ai_used", "")) == "yes" or intake.get("ai_used") == "yes" or bool((answers.get("ai_models") or "").strip())
    train = tc.training_default(answers.get("ai_train", ""))

    ai = 3 if ai_yes else 1
    if ai_yes:
        ai = 4
        if train == "on":
            ai = 5
    sens = 3
    if tc.words(data, ("phi", "health", "payment", "card", "ssn", "hipaa", "pci")):
        sens = 5
    elif tc.words(data, ("pii", "email", "resume", "candidate", "recording")):
        sens = 4
    access = 3
    if tc.words(data, ("admin", "production")):
        access = 4
    if mode in ("onprem", "hybrid"):
        access = max(access, 4)
    factors = {
        "data_sensitivity": sens, "data_volume": 3, "access_level": access,
        "criticality": 3, "ai_involvement": ai,
        "blast_radius": 4 if mode == "saas" else 3,
        "substitutability": 3, "regulatory": 3,
    }
    return {
        **factors,
        "unconfirmed": ["data_volume", "criticality", "substitutability", "regulatory"],
        "note": "Draft from questionnaire only. Human must confirm before T1 residual is signed.",
    }


def apply(record: dict) -> dict:
    answers = merged_answers(record)
    record["factsheet"] = factsheet(answers, record)
    record["draft_factors"] = draft_factors(answers, record)
    record["parse_status"] = "draft"
    if (answers.get("ai_models") or answers.get("ai_change") or "").strip():
        record["models_affirmed_at"] = date.today().isoformat()
        record["models_list"] = (answers.get("ai_models") or answers.get("ai_change") or "").strip()
    followup.apply(record)
    return record
