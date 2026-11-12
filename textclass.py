"""Small, conservative classifiers for free-text questionnaire answers.

The rule everywhere: when an answer is ambiguous or contradicts itself, return
"unknown" and let a human decide. Never guess a Pass. Structured answers (the
radio buttons on the vendor form) are matched exactly first; free text falls
back to whole-word patterns, never substrings ("graphics" is not "phi",
"content" is not "on").
"""
from __future__ import annotations

import re

_UNKNOWN = re.compile(
    r"\b(unknown|not sure|unsure|don'?t know|do not know|no idea|tbd|n/?a|not applicable)\b", re.I)
_NEG = re.compile(
    r"(^\s*no\b|\b(do|does|did|will|would|can|could)\s+not\b|\b(don'?t|doesn'?t|didn'?t|won'?t|never|none|without|disabled|not used|not enabled)\b)", re.I)
_NEG_USE = re.compile(
    r"\b((do|does|did|will|would)\s+not|don'?t|doesn'?t|didn'?t|never)\s+(use|using|enable|utili[sz]e)\b", re.I)
_POS = re.compile(r"\b(yes|yep|we do|we use|uses?|using|enabled|default on|on by default|does)\b", re.I)


def yes_no(text: str) -> str:
    """'yes' | 'no' | 'unknown'."""
    t = (text or "").strip()
    if not t:
        return "unknown"
    low = t.lower()
    if low in ("yes", "y", "true"):
        return "yes"
    if low in ("no", "n", "false"):
        return "no"
    if _UNKNOWN.search(t):
        return "unknown"
    # "we do not use X" is one negative statement, not a negation plus a "we use".
    stripped = _NEG_USE.sub(" NEGUSE ", t)
    neg = bool(_NEG.search(stripped)) or "NEGUSE" in stripped
    pos = bool(_POS.search(stripped))
    if neg and pos:
        return "unknown"
    if neg:
        return "no"
    if pos:
        return "yes"
    return "unknown"


_TRAIN_OFF = re.compile(
    r"(\boff\b|default off|off by default|opt(ed)?[- ]?out|disabled|"
    r"\b(do|does|will)\s+not\s+train|\b(don'?t|doesn'?t|never)\s+train|no training|not (used )?(for|to) train|zero[- ]retention)", re.I)
_TRAIN_ON = re.compile(
    r"(default on|on by default|\bwe train\b|\btrain(s|ing)? (on|with) (your|our|customer)|improve (the|our) model)", re.I)


def training_default(text: str) -> str:
    """'off' | 'on' | 'unknown' for 'does the vendor train on customer content by default'.

    Each sentence is judged on its own; a negation inside a sentence wins for that
    sentence. If different sentences disagree the answer is 'unknown' for a human.
    """
    t = (text or "").strip()
    if not t:
        return "unknown"
    low = t.lower()
    if low in ("off", "no", "default off"):
        return "off"
    if low in ("on", "yes", "default on"):
        return "on"
    verdicts = set()
    for clause in re.split(r"[.;\n]+", t):
        if not clause.strip():
            continue
        if _TRAIN_OFF.search(clause):
            verdicts.add("off")
        elif _TRAIN_ON.search(clause):
            verdicts.add("on")
    if verdicts == {"off"}:
        return "off"
    if verdicts == {"on"}:
        return "on"
    return "unknown"


def words(text: str, terms) -> list[str]:
    """Whole-word matches of any term in text (case-insensitive)."""
    low = (text or "").lower()
    return [t for t in terms if re.search(r"(?<![a-z0-9])" + re.escape(t.lower()) + r"(?![a-z0-9])", low)]


def is_critical(text: str) -> bool:
    low = (text or "").lower()
    for m in re.finditer(r"\bcritical\b", low):
        before = low[max(0, m.start() - 8):m.start()]
        if not re.search(r"\b(not|non|isn'?t)\W*$", before):
            return True
    return False


SENSITIVE_TERMS = ("pii", "health", "phi", "payment", "card", "ssn", "candidate", "resume", "recording", "hipaa", "pci")
CRITICAL_DATA_TERMS = ("critical", "secret", "classified", "cui", "phi", "pci")
