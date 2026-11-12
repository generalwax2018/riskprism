from __future__ import annotations

from datetime import date, datetime, timedelta

import textclass


def _parse(d):
    if not d:
        return None
    try:
        return datetime.strptime(str(d)[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def uses_ai(rec: dict) -> bool:
    if rec.get("ai_used") == "yes":
        return True
    answers = {}
    answers.update(rec.get("answers") or {})
    answers.update(rec.get("renewal_answers") or {})
    if textclass.yes_no(answers.get("ai_used") or "") == "yes":
        return True
    if (answers.get("ai_models") or "").strip():
        return True
    fs = rec.get("factsheet") or {}
    return fs.get("ai_used") == "yes"


def critical(rec: dict) -> bool:
    answers = {}
    answers.update(rec.get("answers") or {})
    answers.update(rec.get("renewal_answers") or {})
    klass = answers.get("data_class") or rec.get("data_class") or ""
    return textclass.is_critical(klass)


def cadence_days(rec: dict) -> int:
    if not uses_ai(rec):
        return 0
    return 90 if critical(rec) else 365


def last_affirmed(rec: dict):
    return _parse(rec.get("models_affirmed_at"))


def due(rec: dict, today: date | None = None):
    """Return (due_date, days_overdue_or_none). None if AI not in scope."""
    today = today or date.today()
    days = cadence_days(rec)
    if not days:
        return None, None
    last = last_affirmed(rec) or _parse((rec.get("factsheet") or {}).get("built_at"))
    if not last:
        return today, 0
    target = last + timedelta(days=days)
    if today >= target:
        return target, (today - target).days
    if (target - today).days <= 30:
        return target, -(target - today).days
    return target, None
