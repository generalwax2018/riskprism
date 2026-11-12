#!/usr/bin/env python3
"""Document and email prompts. The model call itself lives in llm.py (any provider).
Name kept for history; nothing here is Grok-specific any more."""
from __future__ import annotations

import llm

GrokNotConfigured = llm.LLMError


def _chat(system: str, user: str) -> str:
    return llm.chat(system, user)


EXTRACT_SYSTEM = """You extract facts from security attestation text for third-party risk.
Return ONLY JSON with keys:
type (soc2|iso27001|pentest|dpa|other),
period_start, period_end, expires_on (YYYY-MM-DD or null),
auditor, report_date,
exceptions (list of strings),
ai_mentions (list),
controls_hinted (list),
gaps (what a TPRM analyst should still ask).
Unknown = null. Do not invent dates. Do not mark AI-01 Pass from SOC2 alone.
"""

EMAIL_SYSTEM = """You draft a short professional email from a security team to a vendor.
First line: Subject: ...
Ask only for the missing items. No threats. No invented legal authority.
"""


def extract_attestation(text: str, vendor: str = "") -> str:
    return _chat(EXTRACT_SYSTEM, "Vendor: " + vendor + "\n\nDocument text:\n" + text[:80000])


def draft_vendor_email(vendor: str, missing: list, context: str = "") -> str:
    bullets = "\n".join("- " + m for m in missing)
    return _chat(EMAIL_SYSTEM, "Vendor: " + vendor + "\nAsk for:\n" + bullets + "\nContext:\n" + context)
