"""One worklist of everything that needs someone to act, and a way to hand it to the ticketing system.

Sources (all computed live from data RiskPrism already has):
  integration   rule findings on recorded integrations (admin scopes, stale secrets, drift, no owner ...)
  control       control objectives a vendor does not meet
  shadow        open shadow IT items (unknown apps, unauthorized vendors, shadow SaaS)
  vendor        open vendor flags: expired evidence, overdue reviews, live-access findings

Each finding has a stable key, so a ticket is raised once and the worklist shows its reference afterwards.

Deadlines and trend (data/findings_state.json, written only when something changes):
  first seen   the day a finding first appeared. It gets a due date from the customer's own rule
               (Your environment: fix high / medium / low within N days) and is overdue after it.
               A finding that goes away and comes back within 14 days keeps its original date.
  snapshots    one line of counts per day the worklist was computed, kept for 400 days, so the
               executive summary and board pack can say whether things are getting better or worse.

Ticketing (optional, environment variables only; nothing is stored in data files):
  ServiceNow  ENTROPY_SNOW_INSTANCE  https://yourco.service-now.com
              ENTROPY_SNOW_USER / ENTROPY_SNOW_PASSWORD   an integration user with create rights on the table
              ENTROPY_SNOW_TABLE     table to create records in (default incident)
              ENTROPY_SNOW_GROUP     optional assignment group sys_id or name
  Jira        ENTROPY_JIRA_URL       https://yourco.atlassian.net
              ENTROPY_JIRA_EMAIL / ENTROPY_JIRA_TOKEN     an account email and API token
              ENTROPY_JIRA_PROJECT   project key, e.g. SEC
              ENTROPY_JIRA_ISSUETYPE issue type name (default Task)
              ENTROPY_JIRA_DUEDATE   set to 1 to send the finding's due date (the project's create screen must have Due date)

Without either, the CSV export imports into both (ServiceNow Import Sets, Jira CSV import), and a ticket
reference can be recorded by hand so the worklist still shows what is in hand.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import re
import threading
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from io import StringIO
from urllib.parse import quote, urlparse

import config
import records

PATH = config.DATA_DIR / "tickets.json"
STATE_PATH = config.DATA_DIR / "findings_state.json"
REOPEN_KEEPS_DATE_DAYS = 14
CLOSED_KEPT_DAYS = 180
SNAPSHOTS_KEPT_DAYS = 400
LOCK = threading.RLock()
SOURCES = {"integration": "Integration", "control": "Control objective", "shadow": "Shadow IT", "vendor": "Vendor"}
SEV_RANK = {"high": 3, "medium": 2, "low": 1}
MAX_PUSH = 50
TIMEOUT = 20


class TicketError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _key(*parts: str) -> str:
    return "F-" + hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:10]


# ------------------------------------------------------------------ collect
def collect() -> list[dict]:
    import alerts
    import control_objectives as co
    import integrations as ig
    import shadow

    out: list[dict] = []
    vendors = {r["slug"]: r for r in records.list_vendors() if r.get("slug")}

    ov = ig.overview()
    for r in ov["rows"]:
        vend = r["target"] if r["source"] == ig.YOU or r["source"].startswith("sys-") else r["source"]
        for code, text, sev in r["findings"]:
            out.append({"key": _key("integration", r["id"], code), "source": "integration", "severity": sev,
                        "title": "%s: %s" % (r["name"], text), "detail": "%s to %s. Finding: %s." % (
                            r["source_name"], r["target_name"], code.replace("_", " ")),
                        "vendor": vend if vend in vendors else "", "owner": r.get("owner") or "",
                        "link": "/integrations?vendor=%s" % quote(vend)})

    m = co.matrix()
    for row in m["rows"]:
        if row["rec"].get("stage") == "offboarded":
            continue
        for x in row["results"]:
            if x["status"] != "not_met":
                continue
            o = x["objective"]
            sev = {"T1": "high", "T2": "medium"}.get(row["tier"], "low")
            out.append({"key": _key("control", row["slug"], o["id"]), "source": "control", "severity": sev,
                        "title": "%s does not meet %s %s" % (row["rec"].get("vendor") or row["slug"], o["id"], o["title"]),
                        "detail": "%s Tier %s. Evidence: %s" % (o["statement"], row["tier"] or "unscored", "; ".join(x["evidence"])[:600]),
                        "vendor": row["slug"], "owner": o.get("owner") or row["rec"].get("owner") or "",
                        "link": "/vendor/%s#controls" % quote(row["slug"])})

    for it in shadow.queue()["items"]:
        out.append({"key": _key("shadow", it["id"]), "source": "shadow", "severity": it["severity"],
                    "title": "%s: %s" % (shadow.STATE_LABEL[it["kind"]], it["name"]),
                    "detail": "%s%s" % (it["evidence"], (". Permissions: " + ", ".join(it["scopes"][:10])) if it["scopes"] else ""),
                    "vendor": it["vendor"], "owner": "", "link": "/shadow"})

    for slug, rec in vendors.items():
        for code, text, sev in alerts.flags(rec):
            if sev not in ("high", "medium"):
                continue
            out.append({"key": _key("vendor", slug, code), "source": "vendor", "severity": sev,
                        "title": "%s: %s" % (rec.get("vendor") or slug, text), "detail": text,
                        "vendor": slug, "owner": rec.get("owner") or "", "link": "/vendor/%s" % quote(slug)})

    seen, uniq = set(), []
    for f in out:
        if f["key"] not in seen:
            seen.add(f["key"])
            uniq.append(f)
    tickets = _load()
    for f in uniq:
        f["ticket"] = tickets.get(f["key"])
    _track(uniq)
    uniq.sort(key=lambda f: (-SEV_RANK.get(f["severity"], 0), -f["overdue_days"], f["source"], f["title"].lower()))
    return uniq


# ------------------------------------------------------------------ deadlines and trend
def _load_state() -> dict:
    data = {}
    if STATE_PATH.exists():
        try:
            data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
    if not isinstance(data, dict):
        data = {}
    return {"first": data.get("first") or {}, "closed": data.get("closed") or {}, "snapshots": data.get("snapshots") or {}}


def _counts(items: list[dict]) -> dict:
    return {"total": len(items), "high": sum(1 for f in items if f["severity"] == "high"),
            "medium": sum(1 for f in items if f["severity"] == "medium"), "low": sum(1 for f in items if f["severity"] == "low"),
            "overdue": sum(1 for f in items if f["overdue_days"] > 0), "ticketed": sum(1 for f in items if f["ticket"])}


def _track(items: list[dict], today: date | None = None) -> None:
    """Stamp each finding with first seen, due date and days overdue, and keep the daily snapshot."""
    import environment
    today = today or date.today()
    day = today.isoformat()
    days = environment.finding_days()
    with LOCK:
        st = _load_state()
        before = json.dumps(st, sort_keys=True)
        open_keys = {f["key"] for f in items}
        for k in open_keys:
            closed = st["closed"].pop(k, None)
            if k not in st["first"] or (closed and (today - date.fromisoformat(closed)).days > REOPEN_KEEPS_DATE_DAYS):
                st["first"][k] = day
        for k in st["first"]:
            if k not in open_keys and k not in st["closed"]:
                st["closed"][k] = day
        cutoff = (today - timedelta(days=CLOSED_KEPT_DAYS)).isoformat()
        for k in [k for k, d in st["closed"].items() if d < cutoff]:
            st["closed"].pop(k)
            st["first"].pop(k, None)
        for f in items:
            first = date.fromisoformat(st["first"][f["key"]])
            due = first + timedelta(days=days.get(f["severity"], 180))
            f.update(first_seen=first.isoformat(), age_days=(today - first).days, due=due.isoformat(),
                     overdue_days=max(0, (today - due).days))
        st["snapshots"][day] = _counts(items)
        keep = (today - timedelta(days=SNAPSHOTS_KEPT_DAYS)).isoformat()
        st["snapshots"] = {d: v for d, v in st["snapshots"].items() if d >= keep}
        if json.dumps(st, sort_keys=True) != before:
            STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            records.atomic_write(STATE_PATH, json.dumps(st, indent=1, sort_keys=True))


def trend(items: list[dict], today: date | None = None, window: int = 30) -> dict:
    """Now against about `window` days ago, plus what opened and closed in between.
    'then' is None until there is a snapshot at least a week old."""
    today = today or date.today()
    st = _load_state()
    since = (today - timedelta(days=window)).isoformat()
    older = sorted(d for d in st["snapshots"] if d <= since)
    week = sorted(d for d in st["snapshots"] if d <= (today - timedelta(days=7)).isoformat())
    ref = older[-1] if older else (week[0] if week else None)
    now = _counts(items)
    then = st["snapshots"].get(ref) if ref else None
    open_keys = {f["key"] for f in items}
    start = ref or since
    return {"since": ref, "days": (today - date.fromisoformat(ref)).days if ref else None, "now": now, "then": then,
            "delta": {k: now[k] - then.get(k, 0) for k in now} if then else None,
            "opened": sum(1 for k, d in st["first"].items() if k in open_keys and d > start),
            "closed": sum(1 for d in st["closed"].values() if d > start)}


def trend_sentence(t: dict) -> str:
    if not t["then"]:
        return "Trend appears here once RiskPrism has a week of history."
    def moved(n):
        return "unchanged" if n == 0 else "%s %d" % ("up" if n > 0 else "down", abs(n))

    d = t["delta"]
    return ("Against %d days ago (%s): %d open findings (%s), %d high (%s), %d overdue (%s). "
            "%d opened and %d closed since." % (
                t["days"], t["since"], t["now"]["total"], moved(d["total"]), t["now"]["high"], moved(d["high"]),
                t["now"]["overdue"], moved(d["overdue"]), t["opened"], t["closed"]))


def summary(items: list[dict]) -> dict:
    return {"total": len(items), "open": sum(1 for f in items if not f["ticket"]),
            "overdue": sum(1 for f in items if f.get("overdue_days", 0) > 0),
            "ticketed": sum(1 for f in items if f["ticket"]),
            "by_severity": {s: sum(1 for f in items if f["severity"] == s) for s in ("high", "medium", "low")},
            "by_source": {s: sum(1 for f in items if f["source"] == s) for s in SOURCES}}


# ------------------------------------------------------------------ ticket references
def _load() -> dict:
    if not PATH.exists():
        return {}
    try:
        data = json.loads(PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    PATH.parent.mkdir(parents=True, exist_ok=True)
    records.atomic_write(PATH, json.dumps(data, indent=2, sort_keys=True))


def record_ticket(key: str, system: str, ref: str, url: str, by: str) -> dict:
    ref = (ref or "").strip()[:60]
    if not re.fullmatch(r"F-[0-9a-f]{10}", key or ""):
        raise TicketError("Unknown finding.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,59}", ref):
        raise TicketError("Enter the ticket number, e.g. INC0012345 or SEC-42.")
    if url and not re.match(r"^https?://", url):
        url = ""
    entry = {"system": system if system in ("servicenow", "jira", "manual") else "manual", "ref": ref,
             "url": (url or "")[:300], "by": by, "at": _now()}
    with LOCK:
        data = _load()
        data[key] = entry
        _save(data)
    return entry


def clear_ticket(key: str) -> None:
    with LOCK:
        data = _load()
        data.pop(key, None)
        _save(data)


# ------------------------------------------------------------------ ticketing systems
def systems() -> dict:
    """Configured ticketing systems. Read on every call; secrets never leave this module."""
    env = os.environ
    out = {}
    sn = (env.get("ENTROPY_SNOW_INSTANCE") or "").strip().rstrip("/")
    if sn and env.get("ENTROPY_SNOW_USER") and env.get("ENTROPY_SNOW_PASSWORD"):
        out["servicenow"] = {"label": "ServiceNow", "base": sn, "table": (env.get("ENTROPY_SNOW_TABLE") or "incident").strip(),
                             "user": env["ENTROPY_SNOW_USER"], "password": env["ENTROPY_SNOW_PASSWORD"],
                             "group": (env.get("ENTROPY_SNOW_GROUP") or "").strip()}
    jr = (env.get("ENTROPY_JIRA_URL") or "").strip().rstrip("/")
    if jr and env.get("ENTROPY_JIRA_EMAIL") and env.get("ENTROPY_JIRA_TOKEN") and env.get("ENTROPY_JIRA_PROJECT"):
        out["jira"] = {"label": "Jira", "base": jr, "project": env["ENTROPY_JIRA_PROJECT"].strip().upper(),
                       "issuetype": (env.get("ENTROPY_JIRA_ISSUETYPE") or "Task").strip(),
                       "user": env["ENTROPY_JIRA_EMAIL"], "password": env["ENTROPY_JIRA_TOKEN"],
                       "duedate": env.get("ENTROPY_JIRA_DUEDATE") == "1"}
    return out


def _check_base(base: str) -> None:
    u = urlparse(base)
    if u.scheme == "https" and u.hostname:
        return
    if u.scheme == "http" and u.hostname in config.LOOPBACK:  # a local test double only
        return
    raise TicketError("The ticketing address must start with https:// (got %s)." % base[:80])


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TicketError("The ticketing system redirected the request (HTTP %d). Check the instance address." % code)


_OPENER = urllib.request.build_opener(_NoRedirect)


def _post(url: str, payload: dict, user: str, password: str) -> dict:
    auth = base64.b64encode(("%s:%s" % (user, password)).encode("utf-8")).decode("ascii")
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json", "Authorization": "Basic " + auth,
        "User-Agent": "RiskPrism"})
    try:
        with _OPENER.open(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read(1_000_000).decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        detail = re.sub(r"\s+", " ", e.read(400).decode("utf-8", "replace"))
        raise TicketError("The ticketing system refused the request (HTTP %d): %s" % (e.code, detail[:200]))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise TicketError("Could not reach the ticketing system: %s" % str(getattr(e, "reason", e))[:120])
    except ValueError:
        raise TicketError("The ticketing system sent back something that is not JSON.")


def _description(f: dict, base_url: str) -> str:
    when = ("First seen: %s\nDue: %s\n" % (f["first_seen"], f["due"])) if f.get("first_seen") else ""
    return "%s\n\nSeverity: %s\nSource: %s\n%s%sRiskPrism finding %s: %s%s" % (
        f["detail"], f["severity"], SOURCES[f["source"]], ("Owner: %s\n" % f["owner"]) if f["owner"] else "", when,
        f["key"], base_url, f["link"])


def _create(system: str, cfg: dict, f: dict, base_url: str) -> dict:
    _check_base(cfg["base"])
    summary_ = f["title"][:250]
    if system == "servicenow":
        if not re.fullmatch(r"[a-z0-9_]{1,80}", cfg["table"]):
            raise TicketError("ENTROPY_SNOW_TABLE is not a table name.")
        impact, urgency = {"high": ("1", "2"), "medium": ("2", "2"), "low": ("2", "3")}[f["severity"]]
        payload = {"short_description": summary_, "description": _description(f, base_url), "impact": impact,
                   "urgency": urgency, "correlation_id": f["key"], "correlation_display": "RiskPrism"}
        if f.get("due"):
            payload["due_date"] = f["due"] + " 23:59:59"
        if cfg["group"]:
            payload["assignment_group"] = cfg["group"]
        res = _post("%s/api/now/table/%s" % (cfg["base"], cfg["table"]), payload, cfg["user"], cfg["password"]).get("result") or {}
        ref, sys_id = str(res.get("number") or ""), str(res.get("sys_id") or "")
        if not ref:
            raise TicketError("ServiceNow did not return a record number.")
        return {"ref": ref, "url": "%s/nav_to.do?uri=%s.do?sys_id=%s" % (cfg["base"], cfg["table"], quote(sys_id)) if sys_id else ""}
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,19}", cfg["project"]):
        raise TicketError("ENTROPY_JIRA_PROJECT is not a project key.")
    payload = {"fields": {"project": {"key": cfg["project"]}, "issuetype": {"name": cfg["issuetype"]},
                          "summary": summary_, "description": _description(f, base_url),
                          "labels": ["riskprism", "severity-" + f["severity"], f["key"]]}}
    if f.get("due") and cfg.get("duedate"):
        payload["fields"]["duedate"] = f["due"]
    res = _post(cfg["base"] + "/rest/api/2/issue", payload, cfg["user"], cfg["password"])
    ref = str(res.get("key") or "")
    if not ref:
        raise TicketError("Jira did not return an issue key.")
    return {"ref": ref, "url": "%s/browse/%s" % (cfg["base"], quote(ref))}


def push(keys: list[str], system: str, by: str, base_url: str = "") -> tuple[list[dict], list[str]]:
    """Raise one ticket per selected finding that has none yet. Returns (created, errors)."""
    cfg = systems().get(system)
    if not cfg:
        raise TicketError("%s is not configured on this server." % {"servicenow": "ServiceNow", "jira": "Jira"}.get(system, "That system"))
    keys = list(dict.fromkeys(k for k in keys if k))[:MAX_PUSH]
    if not keys:
        raise TicketError("Tick at least one finding.")
    by_key = {f["key"]: f for f in collect()}
    created, errors = [], []
    for k in keys:
        f = by_key.get(k)
        if not f:
            errors.append("%s is no longer open." % k)
            continue
        if f["ticket"]:
            continue
        try:
            t = _create(system, cfg, f, base_url or config.BASE_URL)
        except TicketError as e:
            errors.append("%s: %s" % (f["title"][:80], e))
            if len(errors) >= 3 and not created:
                break  # the system is clearly refusing; stop rather than hammer it
            continue
        record_ticket(k, system, t["ref"], t["url"], by)
        created.append({"key": k, **t})
    return created, errors


# ------------------------------------------------------------------ CSV
def _safe(v: str) -> str:
    v = str(v or "")
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def csv_text(items: list[dict], base_url: str = "") -> str:
    buf = StringIO()
    w = csv.writer(buf)
    w.writerow(["Key", "Summary", "Description", "Severity", "Priority", "Source", "Vendor", "Owner", "Link", "Ticket",
                "First seen", "Due", "Days overdue"])
    for f in items:
        w.writerow([_safe(x) for x in (
            f["key"], f["title"], _description(f, base_url or config.BASE_URL), f["severity"],
            {"high": "High", "medium": "Medium", "low": "Low"}[f["severity"]], SOURCES[f["source"]],
            f["vendor"].replace("_", " "), f["owner"], (base_url or config.BASE_URL) + f["link"],
            (f["ticket"] or {}).get("ref", ""), f.get("first_seen", ""), f.get("due", ""), f.get("overdue_days", 0))])
    return buf.getvalue()
