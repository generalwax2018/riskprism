"""Rule-based flags from live_access. No model calls.

Findings are tuples matching alerts.flags: (code, text, severity).
They do not write followups; alerts.py surfaces them on the queue.
"""
from __future__ import annotations

from access_store import rows

# Scopes that usually mean write or mail/files — drift signal, not auto-fail.
WRITEISH = (
    "mail.send", "mail.readwrite", "files.readwrite", "directory.readwrite",
    "user.readwrite", "application.readwrite", "sites.fullcontrol",
)


def findings(rec: dict) -> list:
    if rec.get("stage") == "offboarded" or rec.get("authorization") == "blocked":
        live = [r for r in rows(rec) if r.get("status") == "active"]
        if live:
            names = ", ".join(r["display_name"] for r in live[:4])
            extra = " (+%d)" % (len(live) - 4) if len(live) > 4 else ""
            return [("access_after_offboard", "Access still active after offboard/block: " + names + extra, "high")]
        return []

    access = rows(rec)
    out = []
    if rec.get("authorization") == "authorized" and not access:
        out.append(("access_blind", "Authorized but no live integrations on file", "medium"))
        return out

    active = [r for r in access if r.get("status") == "active"]
    if not active:
        return out

    answers = {}
    answers.update(rec.get("answers") or {})
    answers.update(rec.get("renewal_answers") or {})
    claimed = (answers.get("integrations") or rec.get("notes") or "").lower()

    for r in active:
        scopes = [s.lower() for s in r.get("scopes") or []]
        if any(any(w in s for w in WRITEISH) for s in scopes):
            # Only flag if questionnaire never mentioned write/integrations.
            if "write" not in claimed and "mail" not in claimed:
                out.append((
                    "access_write_scope",
                    "%s has write-class scopes (%s)" % (r["display_name"], ", ".join(r.get("scopes") or [])[:180]),
                    "medium",
                ))
                break

    return out


def panel_rows(rec: dict) -> list:
    return rows(rec)
