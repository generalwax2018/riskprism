"""Control objectives: what every vendor relationship must achieve, checked against what RiskPrism holds.

A control objective is an outcome ("Integrations hold least privilege"), not a document. Each one has:
  checks      fixed rules over data RiskPrism already has (evidence dates, factsheet, live access,
              integrations, threat model, risk acceptances). No model calls.
  tiers       which vendors it applies to, by inherent tier (T1 most critical .. T4 least)
  refs        a starting map to NIST SP 800-53 Rev. 5, ISO/IEC 27001:2022, SOC 2 (2017 TSC),
              PCI DSS v4.0, HIPAA Security Rule, NERC CIP (CIP-004, CIP-005, CIP-007, CIP-011, CIP-013) and
              AI frameworks (NIST AI RMF, ISO/IEC 42001, EU AI Act). Requirement numbers are given without
              a version suffix. Confirm against the version you are audited to.

CO-17 to CO-20 are the NERC CIP-013 R1.2 vendor commitments that RiskPrism cannot observe for itself
(incident notification, incident coordination, software integrity, remote access controls). They ship
switched off and are attested by hand; an electric-sector customer switches them on.

The library ships with built-in objectives. A company can switch any of them off, change the
tiers they apply to, name an owner, and add its own objectives, either built from the same
checks or marked for manual attestation. An analyst can attest a result for one vendor (for
example a compensating control); the attestation is shown next to the automatic result, never
instead of hiding it.

Statuses, worst first: not_met, unknown, partial, met, na. Unknown is never treated as a pass.
"""
from __future__ import annotations

import json
import threading
from datetime import date, datetime, timezone

import config
import memo
import records

PATH = config.DATA_DIR / "objectives.json"
LOCK = threading.RLock()
TIERS = ("T1", "T2", "T3", "T4")
STATUSES = ("met", "partial", "not_met", "unknown", "na")
STATUS_LABEL = {"met": "Met", "partial": "Partly met", "not_met": "Not met", "unknown": "Unknown", "na": "Not applicable"}
WORST_ORDER = {"not_met": 0, "unknown": 1, "partial": 2, "met": 3, "na": 4}
FRAMEWORKS = [("nist", "NIST 800-53"), ("iso", "ISO 27001"), ("soc2", "SOC 2"), ("pci", "PCI DSS"),
              ("hipaa", "HIPAA"), ("cip", "NERC CIP"), ("ai", "AI (NIST AI RMF / ISO 42001 / EU AI Act)")]
DOMAINS = ["Assurance", "Identity and access", "Integrations and data", "AI and supply chain", "Governance"]


class ObjectiveError(ValueError):
    """Something a person must fix. Shown as is."""


# ------------------------------------------------------------------ checks
# Each check: (rec, ctx) -> (status, evidence). ctx is built once per vendor by _context().
def _date(v):
    try:
        return date.fromisoformat(str(v or "")[:10])
    except ValueError:
        return None


def _clock(rec, key, label):
    d = _date(rec.get(key))
    if d is None:
        return "unknown", "No %s date on file." % label
    if d < date.today():
        return "not_met", "%s expired on %s." % (label.capitalize(), d.isoformat())
    return "met", "%s valid until %s." % (label.capitalize(), d.isoformat())


def chk_soc2(rec, ctx):
    return _clock(rec, "soc2_expires", "SOC 2 or equivalent report")


def chk_pentest(rec, ctx):
    return _clock(rec, "pentest_expires", "penetration test")


def chk_review(rec, ctx):
    d = _date(rec.get("next_review"))
    if d is None:
        return "unknown", "No next review date set."
    if d < date.today():
        return "not_met", "Review was due on %s." % d.isoformat()
    return "met", "Next review due %s." % d.isoformat()


def chk_mfa(rec, ctx):
    sso = (ctx["inputs"]["sso"] or "").lower()
    if not sso:
        return "unknown", "SSO and MFA not recorded."
    if any(w in sso for w in ("no mfa", "without mfa", "none", "password only")) or sso in ("no", "n"):
        return "not_met", "Recorded: %s." % ctx["inputs"]["sso"]
    if "mfa" in sso or "2fa" in sso or "multi" in sso:
        return "met", "Recorded: %s." % ctx["inputs"]["sso"]
    return "partial", "SSO recorded but MFA not stated: %s." % ctx["inputs"]["sso"]


def _integration_check(ctx, high_codes, partial_codes, ok_text, what):
    rows = ctx["integrations"]
    if not rows:
        return "na", "No integrations recorded with this vendor."
    bad = [(r["name"], f[1]) for r in rows for f in r["findings"] if f[0] in high_codes]
    part = [(r["name"], f[1]) for r in rows for f in r["findings"] if f[0] in partial_codes]
    if bad:
        return "not_met", "%d %s: %s" % (len(bad), what, "; ".join("%s: %s" % b for b in bad[:2]))
    if part:
        return "partial", "%s" % "; ".join("%s: %s" % p for p in part[:2])
    return "met", ok_text % len(rows)


def chk_least_privilege(rec, ctx):
    return _integration_check(ctx, {"admin_scope", "app_write_all", "admin_identity"}, {"elevated_role", "app_send_all"},
                              "%d integration(s) checked; no admin or tenant-wide write grants.", "over-privileged grant(s)")


def chk_credentials(rec, ctx):
    return _integration_check(ctx, {"stale_secret"}, {"rotation_unknown", "static_secret"},
                              "%d integration(s) checked; credentials within rotation policy.", "credential(s) past rotation")


def chk_documented(rec, ctx):
    rows = ctx["integrations"]
    if not rows:
        return "na", "No integrations recorded with this vendor."
    missing = [r["name"] for r in rows if not r["owner"] or not r["flows"]]
    if len(missing) == len(rows):
        return "not_met", "No integration has both an owner and documented data flows."
    if missing:
        return "partial", "Missing owner or data flows: %s." % "; ".join(missing[:3])
    return "met", "All %d integration(s) have an owner and documented data flows." % len(rows)


def chk_access_matches(rec, ctx):
    live_flags = [f for f in ctx["access_flags"] if f[0] in ("access_after_offboard", "access_write_scope")]
    drift = [(r["name"], f[1]) for r in ctx["integrations"] for f in r["findings"] if f[0] in ("scope_drift", "retired_still_live")]
    if drift or any(f[2] == "high" for f in live_flags):
        items = ["%s: %s" % d for d in drift] + [f[1] for f in live_flags if f[2] == "high"]
        return "not_met", "; ".join(items[:2])
    if live_flags:
        return "partial", "; ".join(f[1] for f in live_flags[:2])
    if not ctx["live_access"] and not ctx["integrations"]:
        return "unknown", "No live access imported and no integrations recorded."
    if not ctx["live_access"]:
        return "unknown", "No live access imported to compare with what was approved."
    return "met", "Live access matches what was declared."


def chk_sensitive(rec, ctx):
    import integrations as ig
    slug = rec.get("slug")
    flows_in = [(r, f) for r in ctx["all_integrations"] if r["status"] != "retired" for f in r["flows"] if f["to"] == slug]
    if not flows_in:
        return "na", "No recorded data flows into this vendor."
    risky = [(r, f) for r, f in flows_in if any(ig.sensitive(d) for d in f["data"])]
    if not risky:
        return "met", "%d data flow(s) in; none carry sensitive data." % len(flows_in)
    if rec.get("stage") == "offboarded" or rec.get("authorization") != "authorized":
        r, f = risky[0]
        return "not_met", "Sensitive data (%s) flows in through %s, but this vendor is not authorized." % (
            ", ".join(d for d in f["data"] if ig.sensitive(d)), r["name"])
    return "met", "%d sensitive data flow(s) in; the vendor is authorized to receive them." % len(risky)


def chk_inbound(rec, ctx):
    rows = [r for r in ctx["integrations"] if r["network"]["ingress"] or r["mechanism"] == "webhook_in"]
    if not rows:
        return "na", "No inbound endpoints recorded."
    bad = [r["name"] for r in rows if any(f[0] == "inbound_unverified" for f in r["findings"])]
    part = [r["name"] for r in rows if any(f[0] == "no_allowlist" for f in r["findings"])]
    if bad:
        return "not_met", "Inbound calls not verified: %s." % "; ".join(bad[:3])
    if part:
        return "partial", "Verified, but not limited to known IP ranges: %s." % "; ".join(part[:3])
    return "met", "%d inbound endpoint(s) verified and allow-listed." % len(rows)


def chk_ai(rec, ctx):
    inp = ctx["inputs"]
    if inp["ai_used"] == "no":
        return "na", "No AI used on our data."
    trains = str(inp["trains"] or "").lower()
    if trains == "yes":
        return "not_met", "The vendor trains models on our data."
    if trains == "no" and inp["model_provider"]:
        return "met", "No training on our data; model provider %s." % inp["model_provider"]
    if not inp["ai_used"]:
        return "unknown", "AI use not recorded."
    return "unknown", "Training on our data or model provider not recorded."


def chk_subprocessors(rec, ctx):
    subs = ctx["inputs"]["subprocessors"]
    if subs:
        return "met", "Disclosed: %s." % subs[:160]
    return "unknown", "No sub-processor list on file."


def chk_residency(rec, ctx):
    import policy_store
    hosting = ctx["inputs"]["hosting"]
    if not hosting:
        return "unknown", "Hosting region not recorded."
    restricted = [r for r in policy_store.load().get("restricted_regions") or [] if r and r.lower() in hosting.lower()]
    if restricted:
        return "not_met", "Hosting %s includes a restricted region (%s)." % (hosting, ", ".join(restricted))
    return "met", "Hosting: %s." % hosting


def chk_threat_model(rec, ctx):
    import threat_model
    st = threat_model.status(rec)
    if st["state"] == "current":
        return "met", "Threat model version %d reviewed and current." % st["version"]
    if st["state"] == "needs_review":
        return "partial", "Reviewed, but changed since: %s." % "; ".join(st["changes"][:3])
    return "not_met", "Threat model not reviewed yet (%d threat(s) need a decision)." % st["undecided"]


def chk_risk_treated(rec, ctx):
    import risk_store
    high = [f for f in ctx["flags"] if f[2] == "high"]
    if not high:
        return "met", "No open high-severity flags."
    if "accepted" in ctx:  # precomputed for every vendor at once by matrix()
        accepted = set(ctx["accepted"])
    else:
        accepted = {a["detection_code"] for a in risk_store.acceptances(slug=rec.get("slug", "")) if risk_store.is_active(a)}
    open_ = [f for f in high if f[0] not in accepted]
    if open_:
        return "not_met", "%d high flag(s) with no decision: %s" % (len(open_), "; ".join(f[1] for f in open_[:2]))
    return "partial", "%d high flag(s), all covered by signed risk acceptances." % len(high)


def chk_offboarding(rec, ctx):
    if rec.get("stage") != "offboarded":
        return "na", "Vendor is not offboarded."
    live = [r for r in ctx["live_access"] if r.get("status") == "active"]
    if live:
        return "not_met", "%d app(s) still active after offboarding." % len(live)
    return "met", "No active access after offboarding."


CHECKS = {
    "soc2_current": ("SOC 2 or equivalent report is current", chk_soc2),
    "pentest_current": ("Penetration test is current", chk_pentest),
    "review_current": ("Next review is not overdue", chk_review),
    "mfa": ("SSO with MFA is recorded", chk_mfa),
    "least_privilege": ("Integrations have no admin or tenant-wide write grants", chk_least_privilege),
    "credentials": ("Integration credentials are within rotation", chk_credentials),
    "documented": ("Integrations have an owner and data flows", chk_documented),
    "access_matches": ("Live access matches what was declared", chk_access_matches),
    "sensitive_approved": ("Sensitive data goes only to authorized vendors", chk_sensitive),
    "inbound_verified": ("Inbound endpoints are verified", chk_inbound),
    "ai_governed": ("AI on our data: no training, provider declared", chk_ai),
    "subprocessors": ("Sub-processors disclosed", chk_subprocessors),
    "residency": ("Hosting region recorded and not restricted", chk_residency),
    "threat_model": ("Threat model reviewed and current", chk_threat_model),
    "risk_treated": ("High flags are fixed or formally accepted", chk_risk_treated),
    "offboarding": ("No access remains after offboarding", chk_offboarding),
}


# ------------------------------------------------------------------ built-in library
def _o(oid, domain, title, statement, checks, tiers=TIERS, **refs):
    return {"id": oid, "domain": domain, "title": title, "statement": statement, "checks": list(checks),
            "tiers": list(tiers), "refs": refs, "builtin": True, "enabled": True, "owner": ""}


def _optional(oid, domain, title, statement, **refs):
    """A built-in objective that ships switched off and is attested by hand (no automatic check)."""
    return {**_o(oid, domain, title, statement, [], ("T1", "T2"), **refs), "enabled": False}


BUILTIN = [
    _o("CO-01", "Assurance", "Independent assurance is current",
       "Each vendor holds a current independent security report (SOC 2 Type II, ISO 27001 certificate or equivalent).",
       ["soc2_current"], nist="SR-6", cip="CIP-013 R1.1", iso="A.5.22", soc2="CC9.2", pci="12.8.4", hipaa="164.308(b)(1)"),
    _o("CO-02", "Assurance", "Penetration testing is current",
       "Critical and high-tier vendors are penetration tested at least yearly and share the summary.",
       ["pentest_current"], ("T1", "T2"), nist="CA-8", cip="CIP-013 R1.2.4", iso="A.8.8", soc2="CC4.1", pci="11.4"),
    _o("CO-03", "Governance", "Vendor review is on schedule",
       "Each vendor is reassessed by its next review date.", ["review_current"],
       nist="SR-6", cip="CIP-013 R3", iso="A.5.22", soc2="CC9.2", pci="12.8.4"),
    _o("CO-04", "Identity and access", "Strong authentication protects the service",
       "Our people reach the vendor's service through our single sign-on with multi-factor authentication.",
       ["mfa"], nist="IA-2(1), IA-2(2)", cip="CIP-005 R2.3", iso="A.8.5", soc2="CC6.1", pci="8.4", hipaa="164.312(d)"),
    _o("CO-05", "Identity and access", "Integrations hold least privilege",
       "No integration with the vendor holds admin rights or tenant-wide write permissions it does not need.",
       ["least_privilege"], nist="AC-6", cip="CIP-004 R4.1", iso="A.8.2, A.5.15", soc2="CC6.3", pci="7.2"),
    _o("CO-06", "Identity and access", "Integration credentials are managed",
       "Secrets used by integrations are stored securely and rotated within policy.",
       ["credentials"], nist="IA-5", cip="CIP-007 R5.4, R5.6", iso="A.5.17", soc2="CC6.1", pci="8.6.3"),
    _o("CO-07", "Identity and access", "Actual access matches what was approved",
       "Access observed in our tenants matches what was declared and approved; nothing extra, nothing left behind.",
       ["access_matches"], nist="AC-2", cip="CIP-004 R4.2, R4.3; CIP-005 R2.4", iso="A.5.18", soc2="CC6.2", pci="7.2.4", hipaa="164.308(a)(4)"),
    _o("CO-08", "Integrations and data", "Data flows are documented and owned",
       "Every integration has a named owner and documented data flows.",
       ["documented"], nist="AC-4", cip="CIP-005 R1.3; CIP-011 R1.1", iso="A.5.14, A.5.9", pci="1.2.4", hipaa="164.308(a)(1)(ii)(A)"),
    _o("CO-09", "Integrations and data", "Sensitive data goes only to approved parties",
       "Email, HR, personal, health or payment data reaches only vendors that are authorized to receive it.",
       ["sensitive_approved"], nist="AC-4, SR-3", cip="CIP-011 R1.2; CIP-004 R6.1", iso="A.5.14, A.5.19", pci="12.8.2", hipaa="164.308(b)(1)"),
    _o("CO-10", "Integrations and data", "Inbound connections are verified",
       "Endpoints that accept calls from or for the vendor verify the caller and limit where calls come from.",
       ["inbound_verified"], ("T1", "T2", "T3"), nist="IA-9, SC-7", cip="CIP-005 R1.3, R2.1", iso="A.8.20", pci="1.3.1"),
    _o("CO-11", "AI and supply chain", "AI use on our data is governed",
       "Where the vendor uses AI on our data, it does not train on it and the model provider is known.",
       ["ai_governed"], ai="NIST AI RMF GOVERN 6.1; ISO/IEC 42001 A.10.3; EU AI Act Art. 25, Art. 26"),
    _o("CO-12", "AI and supply chain", "Sub-processors are disclosed",
       "The vendor discloses the sub-processors that handle our data.",
       ["subprocessors"], nist="SR-3", cip="CIP-013 R1.1", iso="A.5.21", soc2="CC9.2"),
    _o("CO-13", "Integrations and data", "Data stays in allowed regions",
       "Our data is stored in a recorded region that is not on the restricted list in Policy.",
       ["residency"], nist="SA-9(5)", cip="CIP-011 R1.2", iso="A.5.23"),
    _o("CO-14", "Governance", "Threat model is reviewed and current",
       "Critical and high-tier vendors have a reviewed threat model that reflects their current setup.",
       ["threat_model"], ("T1", "T2"), nist="RA-3", cip="CIP-013 R1.1", iso="Clause 6.1.2", soc2="CC3.2", pci="12.3.1",
       hipaa="164.308(a)(1)(ii)(A)"),
    _o("CO-15", "Governance", "High risks are treated",
       "Every high-severity issue is either fixed or covered by a signed, unexpired risk acceptance.",
       ["risk_treated"], nist="RA-7, PM-9", cip="CIP-013 R2", iso="Clause 6.1.3", soc2="CC9.1"),
    _o("CO-16", "Governance", "Access ends at offboarding",
       "When a vendor is offboarded, no integration or grant remains active.",
       ["offboarding"], nist="AC-2, PS-7", cip="CIP-013 R1.2.3; CIP-004 R5.1; CIP-005 R2.5", iso="A.5.18, A.5.20", soc2="CC6.2", pci="12.8"),
    # NERC CIP-013 R1.2 vendor commitments. Off until a company switches them on; attested by hand.
    _optional("CO-17", "AI and supply chain", "Vendor notifies us of its security incidents",
              "The contract requires the vendor to notify us of incidents in its products or services that pose a cyber "
              "security risk to us, within a stated window, and names who to notify.",
              cip="CIP-013 R1.2.1", nist="SR-8, IR-6(3)", iso="A.5.20, A.5.24"),
    _optional("CO-18", "AI and supply chain", "Incident response is coordinated with the vendor",
              "We and the vendor have agreed how to coordinate the response to a vendor incident that affects us.",
              cip="CIP-013 R1.2.2", nist="IR-4(10)", iso="A.5.26"),
    _optional("CO-19", "AI and supply chain", "Software integrity and authenticity are verified",
              "Software and patches from the vendor are verified as authentic and unaltered before use.",
              cip="CIP-013 R1.2.5; CIP-010 R1.6", nist="SI-7, SR-4", iso="A.8.19"),
    _optional("CO-20", "Identity and access", "Vendor remote access controls are coordinated",
              "Vendor-initiated remote access, interactive and system-to-system, goes through agreed controls, and we can "
              "see and end active vendor sessions.",
              cip="CIP-013 R1.2.6; CIP-005 R2.4, R2.5", nist="AC-17, MA-4", iso="A.8.20, A.5.19"),
]
OPTIONAL_PACKS = {"NERC CIP-013 vendor commitments": ["CO-17", "CO-18", "CO-19", "CO-20"]}


# ------------------------------------------------------------------ store
def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load() -> dict:
    if not PATH.exists():
        return {"overrides": {}, "custom": [], "attestations": {}}
    try:
        data = json.loads(PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    return {"overrides": data.get("overrides") or {}, "custom": data.get("custom") or [],
            "attestations": data.get("attestations") or {}}


def _save(data: dict) -> None:
    PATH.parent.mkdir(parents=True, exist_ok=True)
    records.atomic_write(PATH, json.dumps(data, indent=2, sort_keys=True))


def library(include_disabled: bool = True) -> list[dict]:
    """Built-in objectives with the company's overrides, then the company's own."""
    data = _load()
    out = []
    for o in BUILTIN:
        ov = data["overrides"].get(o["id"]) or {}
        out.append({**o, "enabled": ov.get("enabled", o["enabled"]), "tiers": ov.get("tiers") or o["tiers"],
                    "owner": ov.get("owner", "")})
    for c in data["custom"]:
        out.append({**c, "builtin": False})
    return [o for o in out if include_disabled or o["enabled"]]


def _clean_tiers(tiers) -> list[str]:
    t = [x for x in (tiers or []) if x in TIERS]
    if not t:
        raise ObjectiveError("Pick at least one tier the objective applies to.")
    return t


def update(oid: str, enabled: bool, tiers, owner: str, by: str) -> None:
    tiers = _clean_tiers(tiers)
    with LOCK:
        data = _load()
        if any(o["id"] == oid for o in BUILTIN):
            data["overrides"][oid] = {"enabled": bool(enabled), "tiers": tiers, "owner": (owner or "").strip()[:120],
                                      "by": by, "at": _now()}
        else:
            c = next((c for c in data["custom"] if c["id"] == oid), None)
            if not c:
                raise ObjectiveError("That objective does not exist.")
            c.update({"enabled": bool(enabled), "tiers": tiers, "owner": (owner or "").strip()[:120], "by": by, "at": _now()})
        _save(data)


def add_custom(fields: dict, checks, tiers, by: str) -> dict:
    title = (fields.get("title") or "").strip()[:160]
    if not title:
        raise ObjectiveError("Give the objective a title.")
    statement = (fields.get("statement") or "").strip()[:600]
    checks = [c for c in (checks or []) if c in CHECKS]
    domain = fields.get("domain") if fields.get("domain") in DOMAINS else "Governance"
    refs = {k: (fields.get("ref_" + k) or "").strip()[:120] for k, _l in FRAMEWORKS if (fields.get("ref_" + k) or "").strip()}
    with LOCK:
        data = _load()
        n = len(data["custom"]) + 1
        oid = "CO-C%02d" % n
        while any(c["id"] == oid for c in data["custom"]):
            n += 1
            oid = "CO-C%02d" % n
        obj = {"id": oid, "domain": domain, "title": title, "statement": statement, "checks": checks,
               "tiers": _clean_tiers(tiers), "refs": refs, "enabled": True, "owner": (fields.get("owner") or "").strip()[:120],
               "created_by": by, "created_at": _now()}
        data["custom"].append(obj)
        _save(data)
    return obj


def attest(slug: str, oid: str, status: str, note: str, by: str) -> None:
    if status not in STATUSES and status != "clear":
        raise ObjectiveError("Pick a result.")
    if not any(o["id"] == oid for o in library()):
        raise ObjectiveError("That objective does not exist.")
    note = (note or "").strip()[:600]
    if status != "clear" and not note:
        raise ObjectiveError("Say why: an attestation needs a note (for example the compensating control).")
    with LOCK:
        data = _load()
        per = data["attestations"].setdefault(slug, {})
        if status == "clear":
            per.pop(oid, None)
        else:
            per[oid] = {"status": status, "note": note, "by": by, "at": _now()}
        _save(data)


# ------------------------------------------------------------------ evaluation
def _tier_of(slug: str, rows: list[dict]) -> str:
    row = next((r for r in rows if r["slug"] == slug), None)
    return (row or {}).get("inh") or ""


def _attributed(all_integrations: list[dict]) -> dict[str, list[dict]]:
    """slug -> the live integrations that vendor answers for: the ones it initiates, and the ones that reach it
    from your own systems. Another vendor's app reaching your tenant at this vendor is that other vendor's
    integration, not this one's. One pass over the integrations for every vendor."""
    out: dict[str, list[dict]] = {}
    for r in all_integrations:
        if r["status"] == "retired":
            continue
        out.setdefault(r["source"], []).append(r)
        if r["target"] != r["source"] and (r["source"].startswith("sys-") or r["source"] == "you"):
            out.setdefault(r["target"], []).append(r)
    return out


def _context(rec: dict, all_integrations: list[dict], shared: dict | None = None) -> dict:
    import access_flags
    import access_store
    import alerts
    import threat_model
    slug = rec.get("slug", "")
    by_vendor = shared["attributed"] if shared else _attributed(all_integrations)
    ctx = {"inputs": threat_model.inputs(rec), "integrations": by_vendor.get(slug, []), "all_integrations": all_integrations,
           "live_access": access_store.rows(rec), "access_flags": list(access_flags.findings(rec)),
           "flags": list(alerts.flags(rec))}
    if shared:
        ctx["accepted"] = shared["accepted"].get(slug, {})
    return ctx


def combine(results: list[str]) -> str:
    real = [r for r in results if r != "na"]
    if not real:
        return "na"
    return min(real, key=lambda s: WORST_ORDER[s])


def evaluate(rec: dict, objectives: list[dict] | None = None, tier: str | None = None,
             all_integrations: list[dict] | None = None, attestations: dict | None = None,
             shared: dict | None = None) -> list[dict]:
    """One result per enabled objective for this vendor. `shared` (from matrix) carries what every vendor
    needs, worked out once: integrations by vendor and active risk acceptances."""
    import integrations
    import portfolio
    objectives = objectives if objectives is not None else library(include_disabled=False)
    if all_integrations is None:
        ov = integrations.overview()
        all_integrations = ov["rows"]
    tier = tier if tier is not None else _tier_of(rec.get("slug", ""), portfolio.rows())
    attestations = attestations if attestations is not None else _load()["attestations"].get(rec.get("slug", ""), {})
    ctx = _context(rec, all_integrations, shared)
    out = []
    for o in objectives:
        if tier and tier not in o["tiers"]:
            out.append({"objective": o, "status": "na", "auto": "na", "evidence": ["Applies to %s; this vendor is %s." % (
                ", ".join(o["tiers"]), tier)], "attested": None})
            continue
        if o["checks"]:
            parts = [CHECKS[c][1](rec, ctx) for c in o["checks"] if c in CHECKS]
            auto = combine([p[0] for p in parts])
            evidence = [p[1] for p in parts]
        else:
            auto, evidence = "unknown", ["Manual attestation only."]
        att = attestations.get(o["id"])
        out.append({"objective": o, "auto": auto, "status": att["status"] if att else auto, "evidence": evidence,
                    "attested": att})
    return out


def matrix() -> dict:
    """Every tracked vendor against every enabled objective, for the dashboard.
    Reused within a request (memo.py), so callers must not modify what it returns."""
    return memo.cached("co.matrix", _matrix)


def _matrix() -> dict:
    import integrations
    import portfolio
    import risk_store
    objectives = library(include_disabled=False)
    ig_rows = integrations.overview()["rows"]
    prow = portfolio.rows()
    att_all = _load()["attestations"]
    shared = {"attributed": _attributed(ig_rows), "accepted": risk_store.active_by_vendor()}
    tiers = {r["slug"]: r.get("inh") or "" for r in prow}
    vendors = sorted(records.list_vendors(), key=lambda r: (r.get("vendor") or "").lower())
    rows = []
    for rec in vendors:
        slug = rec.get("slug", "")
        tier = tiers.get(slug, "")
        res = evaluate(rec, objectives, tier, ig_rows, att_all.get(slug, {}), shared)
        counts = {s: sum(1 for r in res if r["status"] == s) for s in STATUSES}
        in_scope = len(res) - counts["na"]
        rows.append({"rec": rec, "slug": slug, "tier": tier, "results": res, "counts": counts,
                     "pct": round(100 * counts["met"] / in_scope) if in_scope else None})
    per_obj = []
    for i, o in enumerate(objectives):
        col = [r["results"][i]["status"] for r in rows]
        scope = [s for s in col if s != "na"]
        per_obj.append({"objective": o, "met": col.count("met"), "partial": col.count("partial"),
                        "not_met": col.count("not_met"), "unknown": col.count("unknown"), "in_scope": len(scope),
                        "pct": round(100 * col.count("met") / len(scope)) if scope else None})
    all_res = [x["status"] for r in rows for x in r["results"] if x["status"] != "na"]
    totals = {s: all_res.count(s) for s in STATUSES if s != "na"}
    return {"objectives": objectives, "rows": rows, "per_objective": per_obj, "totals": totals,
            "pct": round(100 * totals.get("met", 0) / len(all_res)) if all_res else None}
