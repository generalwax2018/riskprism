#!/usr/bin/env python3
"""RiskPrism TPRM server (standard library only).

Run:   python serve.py            -> http://127.0.0.1:8765  (no login, loopback only)
Cloud: set ENTROPY_HOST, ENTROPY_AUTH and ENTROPY_BASE_URL (see config.py and docs/AZURE_DEPLOY.md).
"""
from __future__ import annotations

import re
import sys
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

import ai_questionnaire
import access_import
import accounts
import access_store
import audit
import auth
import config
import csv_import
import documents
import entra_import
import evidence_store
import expiry_ai
import llm
import mailer
import memo
import multipart
import notes_store
import policy_store
import portfolio
import risk_rules
import risk_store
import tokens
import anticipate
import catalog
import control_objectives
import controls_views
import environment
import environment_views
import executive
import oidc
import ops
import ops_views
import findings
import findings_views
import integrations
import shadow
import shadow_views
import integrations_demo
import integrations_views
import threat_diagram
import threat_export
import threat_model
import tpl
import vendor_research
import views
from followup import questions_for
from parse_answers import apply as parse_apply
from questionnaire import ai_allowed_ids, allowed_ids, questions as q_questions, render_ai_html, render_fields_html, render_followup_html
from records import BadSlug, delete_vendor, exists, load_vendor, save_vendor, slugify, update_vendor, valid_slug
from seed import run as seed_run
from tpl import esc

BASE = config.BASE
STATIC = BASE / "static"
CONTENT_TYPES = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml",
                 ".png": "image/png", ".ico": "image/x-icon", ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8"}

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; "
       "font-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'")

VENDOR_FIELDS = ("vendor", "mode", "website", "contact", "owner", "business", "authorization", "stage", "ai_used", "ai_train",
                 "connects", "connects_to", "category", "notes")
ENUMS = {
    "mode": {v for v, _ in views.MODES}, "authorization": {v for v, _ in views.AUTHS}, "stage": {v for v, _ in views.STAGES},
    "ai_used": {"unknown", "yes", "no"}, "ai_train": {"unknown", "off", "on"}, "connects": {"unknown", "yes", "no"},
    "category": {k for k, _ in anticipate.CATEGORIES},
}
MAXLEN = {"vendor": 200, "website": 300, "contact": 200, "owner": 200, "business": 300, "connects_to": 300, "notes": 4000}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class Reject(Exception):
    def __init__(self, code: int, text: str):
        super().__init__(text)
        self.code, self.text = code, text


def clean_vendor_fields(fields: dict) -> dict:
    """Keep only known fields, trimmed, with enums and lengths enforced. No mass assignment."""
    out = {}
    for key in VENDOR_FIELDS:
        if key not in fields:
            continue
        val = str(fields.get(key, "")).strip()
        if key in ENUMS:
            if val not in ENUMS[key]:
                continue
        else:
            val = val[:MAXLEN.get(key, 300)]
        out[key] = val
    return out


def valid_date(v: str) -> str:
    v = (v or "").strip()
    if not v:
        return ""
    if not DATE_RE.match(v):
        raise Reject(400, "Dates must look like 2026-09-21.")
    try:
        datetime.strptime(v, "%Y-%m-%d")
    except ValueError:
        raise Reject(400, "That is not a real date.")
    return v


def valid_url(v: str) -> str:
    v = (v or "").strip()[:500]
    if v and not re.match(r"^https?://[^\s<>\"']+$", v, re.I):
        raise Reject(400, "Links must start with http:// or https://")
    return v


def is_admin(who: str) -> bool:
    """People, org units and approvers. Everyone on a no-login local run; otherwise ENTROPY_ADMINS,
    plus accounts marked admin in accounts mode."""
    if config.AUTH_MODE == "none":
        return True
    if is_viewer(who):
        return False
    if (who or "").lower() in config.ADMINS:
        return True
    if config.AUTH_MODE == "accounts" and who:
        u = accounts.by_email(who)
        return bool(u and u["is_admin"] and u["status"] == "active")
    return False


def requester(trec: dict) -> dict:
    """Who a vendor link comes from, in words a vendor can check: the organisation, the person, how to reach them."""
    org = environment.org_name() if environment.org_is_named() else ""
    by = (trec.get("by") or "").strip()
    name, email = "", ""
    if mailer.valid_address(by):
        email = by
        if config.AUTH_MODE == "accounts":
            u = accounts.by_email(by)
            name = (u or {}).get("name") or ""
    contact = environment.security_contact() or email
    return {"org": org, "team": ("%s's security team" % org) if org else "the customer's security team",
            "name": name, "email": email, "contact": contact}


VIEWER_MESSAGE = "Your account is view-only. Ask an admin if you need to make changes."
VIEWER_MAY_POST = {"/logout", "/account"}


def is_viewer(who: str) -> bool:
    """View-only people can open every page and export, and every change they try is refused."""
    if config.AUTH_MODE == "none" or not who:
        return False
    if who.lower() in config.VIEWERS:
        return True
    if config.AUTH_MODE == "accounts":
        u = accounts.by_email(who)
        return bool(u and u.get("view_only"))
    return False


LOGIN_FIELDS = {
    "password": ('<label for="pw">Analyst password</label>'
                 '<input id="pw" type="password" name="password" autocomplete="current-password" required autofocus>'),
    "accounts": ('<label for="em">Email</label><input id="em" type="email" name="email" autocomplete="username" required autofocus maxlength="200">'
                 '<label for="pw">Password</label><input id="pw" type="password" name="password" autocomplete="current-password" required maxlength="200">'
                 '<label for="cd">Code from your authenticator app</label>'
                 '<input id="cd" name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" required>'),
}


def _int_or_none(v: str):
    v = (v or "").strip()
    if not v:
        return None
    if not v.isdigit():
        raise Reject(400, "That unit id is not valid.")
    return int(v)


def _base_url(handler) -> str:
    if config.BASE_URL:
        return config.BASE_URL
    host = handler.headers.get("Host") or "%s:%s" % (config.HOST, config.PORT)
    return "http://" + host


class Handler(BaseHTTPRequestHandler):
    server_version = "RiskPrism"
    sys_version = ""
    timeout = config.REQUEST_TIMEOUT

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # ------------------------------------------------------------ output
    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None, cache=False):
        if not isinstance(body, bytes):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        if self._secure_cookie():
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        if not cache:
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Robots-Tag", "noindex, nofollow")
        for k, v in (headers or {}).items():
            for one in (v if isinstance(v, list) else [v]):
                self.send_header(k, one)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _redirect(self, loc, headers=None):
        self.send_response(303)
        self.send_header("Location", loc)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _page(self, code, title, active, content, who):
        self._send(code, self._page_html(title, active, content, who))

    def _page_html(self, title, active, content, who):
        counts = views.high_count()
        orgs_link = ('<a class="%s" href="/admin/orgs"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" '
                     'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="3" width="6" height="5" rx="1"></rect>'
                     '<rect x="3" y="16" width="6" height="5" rx="1"></rect><rect x="15" y="16" width="6" height="5" rx="1"></rect>'
                     '<path d="M12 8v4M6 16v-4h12v4"></path></svg>Org units</a>' % ("on" if active == "orgs" else "")) if is_admin(who) else ""
        if config.AUTH_MODE == "accounts" and is_admin(who):
            orgs_link += ('<a class="%s" href="/people"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" '
                          'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="9" cy="8" r="3.5"></circle>'
                          '<path d="M2.5 20c.8-3.5 3.4-5.5 6.5-5.5s5.7 2 6.5 5.5"></path><path d="M16 4.5a3.5 3.5 0 0 1 0 7M18 14.8c1.9.8 3.1 2.6 3.5 5.2"></path></svg>People</a>'
                          % ("on" if active == "people" else ""))
        if is_admin(who):
            orgs_link += ('<a class="%s" href="/admin/data"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
                          'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><ellipse cx="12" cy="5" rx="8" ry="3"></ellipse>'
                          '<path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"></path><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"></path></svg>Data and audit</a>'
                          % ("on" if active == "data" else ""))
        if orgs_link:
            orgs_link = ('<section class="group"><div class="group-title">Admin</div><nav class="nav" aria-label="Admin">%s</nav></section>'
                         % orgs_link)
        logout = ""
        if config.AUTH_MODE in ("password", "accounts"):
            logout = '<form method="post" action="/logout" class="keep"><button class="linkbtn" type="submit">Sign out</button></form>'
        if config.AUTH_MODE == "accounts":
            logout = '<a class="gold small" href="/account">Your account</a>' + logout
        html = tpl.render("layout.html", title=title, content=content, high=counts, who=who or "", orgs_link=orgs_link,
                          **{"on_" + k: ("on" if k == active else "") for k in ("portfolio", "executive", "findings", "data", "alerts", "risk", "integrations", "environment", "controls", "shadow",
                                               "documents", "policy", "report", "import")},
                          show_badge="" if not counts else "yes", logout=logout,
                          ai_note=('' if llm.enabled() else '<div class="muted small ai-off">AI: off (enforced)</div>')
                          + ('<div class="muted small ai-off">View-only account</div>' if is_viewer(who) else ''),
                          body_class="viewer" if is_viewer(who) else "")
        return tpl.add_csrf(html, auth.csrf_token(who or ""))

    def _err(self, code, title, text, who=None, back="/"):
        if who:
            self._page(code, title, "", views.error_page(title, text, back), who)
        else:
            self._send(code, tpl.render("bare_error.html", title=title, text=text))

    # ------------------------------------------------------------ helpers
    def _ip(self):
        fwd = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        return fwd or self.client_address[0]

    def _body(self, limit):
        if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            raise Reject(411, "Chunked uploads are not supported.")
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise Reject(400, "Bad Content-Length.")
        if n < 0:
            raise Reject(400, "Bad Content-Length.")
        if n > limit:
            raise Reject(413, "That request is too large.")
        return self.rfile.read(n) if n else b""

    def _form(self, limit=config.MAX_FORM_BYTES):
        raw = self._body(limit)
        parsed = parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
        return {k: (v[0] if v else "") for k, v in parsed.items()}

    def _secure_cookie(self):
        return config.BASE_URL.startswith("https://") or (self.headers.get("X-Forwarded-Proto") or "") == "https"

    def _who(self, path):
        """Return the analyst identity or send a login redirect / 401 and return None."""
        who = auth.principal(self.headers)
        if who:
            return who
        if config.AUTH_MODE in ("password", "accounts"):
            self._redirect("/login")
        else:
            self._err(401, "Sign in required", "Sign in with your organisation account to use this page.")
        return None

    # ------------------------------------------------------------ GET / HEAD
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        with memo.request():
            self._do_get()

    def _do_get(self):
        try:
            self._get()
        except Reject as e:
            self._err(e.code, "Request refused", e.text)
        except BadSlug:
            self._err(404, "Not found", "That record does not exist.")
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception as e:  # never leak a traceback to the browser
            sys.stderr.write("GET %s failed: %r\n" % (self.path, e))
            self._err(500, "Something went wrong", "The request failed. Check the server log.")

    def _get(self):
        path = unquote(urlparse(self.path).path)
        if path == "/healthz":
            return self._send(200, "ok", "text/plain; charset=utf-8")
        if not auth.host_ok(self.headers):
            return self._send(400, "Unexpected Host header", "text/plain; charset=utf-8")
        if path.startswith("/static/"):
            target = STATIC / Path(path).name
            if not target.is_file():
                return self._send(404, "Not found", "text/plain; charset=utf-8")
            return self._send(200, target.read_bytes(), CONTENT_TYPES.get(target.suffix, "application/octet-stream"), cache=True,
                              headers={"Cache-Control": "public, max-age=31536000, immutable" if target.suffix == ".woff2"
                                       else "public, max-age=300"})
        if path.startswith("/q/"):
            return self._vendor_form(path.split("/q/", 1)[1])
        if path == "/login":
            if config.AUTH_MODE not in LOGIN_FIELDS:
                return self._redirect("/")
            return self._login_page(200)
        if path == "/login/sso":
            return self._sso_begin()
        if path == "/login/sso/callback":
            return self._sso_callback()
        if path.startswith("/setup/"):
            return self._setup_page(path.split("/setup/", 1)[1])

        who = self._who(path)
        if not who:
            return
        self._sweep()
        if path in ("/", "/index.html"):
            return self._page(200, "Portfolio", "portfolio", views.portfolio_page(), who)
        if path == "/alerts":
            seed_ok = config.AUTH_MODE == "none" or config.ALLOW_SEED
            return self._page(200, "Renewals and evidence", "alerts", views.alerts_page(seed_ok), who)
        if path == "/policy":
            return self._page(200, "Policy", "policy", views.policy_page(), who)
        if path == "/intake":
            return self._page(200, "New vendor", "", views.intake_page({}, edit=False), who)
        if path == "/report":
            return self._page(200, "Report a tool", "report", views.report_page(), who)
        if path == "/import":
            return self._page(200, "Import", "import", views.import_page(), who)
        if path == "/risk":
            org = (parse_qs(urlparse(self.path).query).get("org") or [""])[0]
            return self._page(200, "Risk acceptance", "risk", views.risk_page(_int_or_none(org)), who)
        if path == "/documents":
            q = parse_qs(urlparse(self.path).query)
            pick = {k: (q.get(k) or [""])[0][:100] for k in ("type", "status", "q")}
            return self._page(200, "Documents", "documents", views.documents_page(pick), who)
        if path == "/account":
            me = auth.current_user(self.headers)
            if not me:
                return self._err(404, "Not found", "Accounts are not switched on for this server.", who)
            return self._page(200, "Your account", "", views.account_page(me), who)
        if path == "/people":
            me = auth.current_user(self.headers)
            if not me:
                return self._err(404, "Not found", "Accounts are not switched on for this server.", who)
            if not is_admin(who):
                return self._err(403, "Admins only", "Ask an admin to manage people.", who)
            return self._page(200, "People", "people", views.people_page(me), who)
        if path == "/admin/orgs":
            if not is_admin(who):
                return self._err(403, "Admins only", "Ask an admin to add you to ENTROPY_ADMINS.", who)
            return self._page(200, "Org units", "orgs", views.orgs_page(who), who)
        if path.startswith("/evidence/"):
            rest = path.split("/evidence/", 1)[1].split("/")
            rec = load_vendor(rest[0])
            if not rec:
                return self._err(404, "Not found", "Vendor not found.", who)
            if len(rest) == 3 and rest[1] == "file":
                return self._download(rest[0], rest[2], rec)
            return self._page(200, "Evidence", "", views.evidence_page(rec), who)
        if path.startswith("/edit/"):
            rec = load_vendor(path.split("/edit/", 1)[1])
            if not rec:
                return self._err(404, "Not found", "Vendor not found.", who)
            return self._page(200, "Edit vendor", "", views.intake_page(rec, edit=True, slug=rec.get("slug", "")), who)
        if path.startswith("/share/"):
            return self._share(path.split("/share/", 1)[1], who)
        if path.startswith("/ai/"):
            if not llm.enabled():
                return self._err(403, "AI is switched off", config.AI_OFF_MESSAGE, who)
            rec = load_vendor(path.split("/ai/", 1)[1])
            if not rec:
                return self._err(404, "Not found", "Start tracking this vendor first.", who)
            return self._page(200, "AI questionnaire", "", views.ai_page(rec), who)
        if path.startswith("/threat/"):
            return self._threat_get(path.split("/threat/", 1)[1], who)
        if self._extra_get(path, who):
            return
        if path == "/integrations":
            q = parse_qs(urlparse(self.path).query)
            vendor = (q.get("vendor") or [""])[0]
            vendor = vendor if vendor in integrations.party_names() else ""
            return self._page(200, "Integrations", "integrations", integrations_views.dashboard(
                vendor, seed_button=config.AUTH_MODE == "none" or config.ALLOW_SEED), who)
        if path.startswith("/vendor/"):
            slug = path.split("/vendor/", 1)[1]
            rec = load_vendor(slug)
            demo = portfolio.match_demo(slug) if valid_slug(slug) else None
            if rec:
                return self._page(200, rec.get("vendor", "Vendor"), "", views.record_page(rec, tracked=True, demo=demo, who=who), who)
            if demo:
                stub = {"vendor": demo.vendor, "slug": slug, "business": demo.product, "notes": demo.notes, "website": demo.website}
                return self._page(200, demo.vendor, "", views.record_page(stub, tracked=False, demo=demo, who=who), who)
            return self._err(404, "Not found", "Vendor not found.", who)
        return self._err(404, "Not found", "That page does not exist.", who)

    def _sweep(self):
        """Record acceptances that lapsed since the last request. Their detections are
        already open again (reads check the date); this only writes the audit line."""
        for row in risk_store.sweep_expired():
            audit.log("system", "acceptance_expired", row["vendor_slug"],
                      "#%d %s, expired %s" % (row["id"], row["detection_code"], row["expires_on"]), "")

    def _download(self, slug, stored_as, rec):
        p = evidence_store.local_path(slug, stored_as)
        if not p:
            return self._err(404, "Not found", "File not found.", auth.principal(self.headers))
        audit.log(auth.principal(self.headers) or "", "evidence_download", slug, stored_as, self._ip())
        name = next((f.get("filename") for f in rec.get("evidence_files") or [] if f.get("stored_as") == stored_as), stored_as)
        return self._send(200, p.read_bytes(), "application/octet-stream",
                          headers={"Content-Disposition": 'attachment; filename="%s"' % evidence_store.safe_name(name)})

    # ------------------------------------------------------------ threat model (a tab on the vendor record)
    def _threat_get(self, rest, who):
        parts = rest.split("/")
        slug = parts[0]
        rec = load_vendor(slug) if valid_slug(slug) else None
        if not rec:
            return self._err(404, "Not found", "Vendor not found.", who)
        if len(parts) == 1:
            return self._redirect("/vendor/%s#threat" % quote(slug))
        if len(parts) == 2 and parts[1] in ("export.docx", "export.pdf"):
            return self._threat_export(rec, who, parts[1] == "export.pdf")
        if len(parts) == 2 and parts[1] == "diagram.svg":
            audit.log(who, "threat_diagram_exported", slug, "svg", self._ip())
            return self._send(200, threat_diagram.svg(threat_diagram.layout(rec)), "image/svg+xml",
                              headers={"Content-Disposition": 'attachment; filename="threat-diagram-%s.svg"' % slug,
                                       "Cache-Control": "no-store"})
        return self._err(404, "Not found", "That page does not exist.", who)

    def _threat_export(self, rec, who, pdf):
        slug = rec.get("slug", "")
        model = threat_model.build(rec)
        vendor = rec.get("vendor", slug)
        blocks = threat_export.blocks(rec, model, model["status"], vendor)
        version = "v%d" % model["version"] if model["reviewed_at"] else "draft"
        ext = "pdf" if pdf else "docx"
        name = "threat-model-%s-%s.%s" % (slug, version, ext)
        if pdf:
            body = threat_export.pdf_bytes(blocks, title="Threat model: %s" % vendor)
            ctype = "application/pdf"
        else:
            body = threat_export.docx_bytes(blocks)
            ctype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        audit.log(who, "threat_model_exported", slug, "%s %s" % (ext, version), self._ip())
        return self._send(200, body, ctype, headers={"Content-Disposition": 'attachment; filename="%s"' % name,
                                                     "Cache-Control": "no-store"})

    def _threat_error(self, slug, who, message, draft=None):
        rec = load_vendor(slug)
        return self._page(400, rec.get("vendor", "Vendor"), "", views.record_page(
            rec, tracked=True, who=who, threat_error=message, threat_draft=draft, tab="threat"), who)

    def _threat_post(self, rest, who, fields, ip):
        parts = rest.split("/")
        slug = parts[0]
        action = parts[1] if len(parts) == 2 else ""
        if not valid_slug(slug) or not action:
            raise Reject(404, "That page does not exist.")
        rec = load_vendor(slug)
        if not rec:
            raise Reject(404, "Vendor not found. Start tracking it first.")
        level = risk_store.approver_level(who)
        done = {}
        back = "/vendor/%s#threat" % quote(slug)
        try:
            if action == "threat":
                tid = fields.get("tid", "")

                def fn(r):
                    done["t"] = threat_model.set_threat(r, tid, fields, who, level)
                    return r
                update_vendor(slug, fn)
                t = done["t"]
                audit.log(who, "threat_decided", slug, "%s: %s, %s" % (
                    t["id"], t["disposition"], threat_model.rating_label(t["rating"])), ip)
                if t["disposition"] == "accept":
                    audit.log(who, "threat_accepted", slug, "%s until %s (%s)" % (t["id"], t["accepted_until"], level), ip)
                return self._redirect("/vendor/%s#threat" % quote(slug))

            if action == "question":
                qid = fields.get("qid", "")

                def fn(r):
                    threat_model.set_question(r, qid, fields.get("answer", ""), fields.get("owner", ""), who)
                    return r
                update_vendor(slug, fn)
                audit.log(who, "threat_question_answered", slug, qid, ip)
                return self._redirect(back)

            if action == "design":
                def fn(r):
                    threat_model.set_design(r, fields.get("design", ""))
                    return r
                update_vendor(slug, fn)
                audit.log(who, "threat_design_saved", slug, "", ip)
                return self._redirect(back)

            if action == "review":
                done["store"] = None

                def fn(r):
                    done["store"] = threat_model.review(r, who, fields.get("note", ""))
                    return r
                update_vendor(slug, fn)
                audit.log(who, "threat_model_reviewed", slug, "v%s" % done["store"]["version"], ip)
                return self._redirect(back)
        except threat_model.ModelError as e:
            draft = dict(fields) if action == "threat" else None
            return self._threat_error(slug, who, str(e), draft)

        raise Reject(404, "That page does not exist.")

    # ------------------------------------------------------------------ controls, environment, executive, shadow IT
    def _upload_text(self, files):
        if "file" not in files or not files["file"][1]:
            raise ValueError("Choose a file first.")
        fname, data = files["file"]
        try:
            return fname, data.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise ValueError("That file is not UTF-8 text. Export it as CSV or JSON.")

    def _extra_get(self, path, who):
        """Pages added with the data layer. Returns True when the path was handled."""
        q = parse_qs(urlparse(self.path).query)
        if path == "/controls":
            self._page(200, "Control objectives", "controls", controls_views.dashboard((q.get("fw") or ["nist"])[0]), who)
            return True
        if path == "/environment":
            self._page(200, "Your environment", "environment", environment_views.page(), who)
            return True
        if path.startswith("/environment/"):
            sid = path.split("/environment/", 1)[1]
            if not environment.get(sid):
                self._err(404, "Not found", "That system is not in your environment.", who)
            else:
                self._page(200, environment.get(sid)["name"], "environment", environment_views.system_page(sid), who)
            return True
        if path == "/executive":
            self._page(200, "Executive summary", "executive", executive.page(), who)
            return True
        if path == "/executive/board.pdf":
            audit.log(who, "board_pack_exported", "", "", self._ip())
            self._send(200, executive.board_pdf(), "application/pdf", headers={
                "Content-Disposition": 'attachment; filename="board-summary-%s.pdf"' % date.today().isoformat(), "Cache-Control": "no-store"})
            return True
        if path == "/shadow":
            self._page(200, "Shadow IT", "shadow", shadow_views.page(), who)
            return True
        if path.startswith("/admin/data"):
            if not is_admin(who):
                self._err(403, "Admins only", "Ask an admin for a copy of the data or the audit log.", who)
                return True
            if path == "/admin/data":
                self._page(200, "Data and audit", "data", ops_views.page(), who)
            elif path == "/admin/data/export.zip":
                audit.log(who, "data_exported", "", "", self._ip())
                self._send(200, ops.export_zip(who), "application/zip", headers={
                    "Content-Disposition": 'attachment; filename="riskprism-export-%s.zip"' % date.today().isoformat(), "Cache-Control": "no-store"})
            elif path == "/admin/data/audit.csv":
                audit.log(who, "audit_log_exported", "", "", self._ip())
                self._send(200, audit.csv_text().encode("utf-8"), "text/csv; charset=utf-8", headers={
                    "Content-Disposition": 'attachment; filename="riskprism-audit-%s.csv"' % date.today().isoformat(), "Cache-Control": "no-store"})
            elif path.startswith("/admin/data/backup/"):
                p = ops.backup_file(path.rsplit("/", 1)[1])
                if not p:
                    self._err(404, "Not found", "That backup does not exist.", who)
                else:
                    audit.log(who, "backup_downloaded", "", p.name, self._ip())
                    self._send(200, p.read_bytes(), "application/gzip", headers={
                        "Content-Disposition": 'attachment; filename="%s"' % p.name, "Cache-Control": "no-store"})
            else:
                self._err(404, "Not found", "That page does not exist.", who)
            return True
        if path == "/findings":
            src = (q.get("source") or [""])[0]
            self._page(200, "Findings", "findings", findings_views.page(src, (q.get("show") or ["open"])[0]), who)
            return True
        if path == "/findings.csv":
            src = (q.get("source") or [""])[0]
            items = [f for f in findings.collect() if not src or f["source"] == src]
            audit.log(who, "findings_exported", "", "%d findings" % len(items), self._ip())
            self._send(200, findings.csv_text(items, _base_url(self)).encode("utf-8"), "text/csv; charset=utf-8", headers={
                "Content-Disposition": 'attachment; filename="riskprism-findings-%s.csv"' % date.today().isoformat(), "Cache-Control": "no-store"})
            return True
        if path == "/integrations/catalog.json":
            audit.log(who, "catalog_exported", "", "", self._ip())
            self._send(200, catalog.export_json(), "application/json", headers={
                "Content-Disposition": 'attachment; filename="riskprism-catalog-%s.json"' % date.today().isoformat(), "Cache-Control": "no-store"})
            return True
        return False

    def _extra_post(self, path, who, fields, files, ip):
        """Form posts added with the data layer. Returns True when the path was handled."""
        if path.startswith("/admin/data/"):
            if not is_admin(who):
                raise Reject(403, "Admins only.")
            page = lambda code, **kw: self._page(code, "Data and audit", "data", ops_views.page(**kw), who)  # noqa: E731
            if path == "/admin/data/backup":
                try:
                    p = ops.backup_now(by=who)
                except (OSError, ops.OpsError) as e:
                    audit.log(who, "backup_failed", "", str(e)[:200], ip)
                    page(500, error="The backup failed: %s" % e)
                    return True
                audit.log(who, "backup_made", "", p.name, ip)
                page(200, ok="Backup written: %s." % p.name)
            elif path == "/admin/data/verify":
                v = audit.verify()
                audit.log(who, "audit_log_checked", "", "intact" if v["ok"] else "BROKEN at %s" % v["first_bad"], ip)
                page(200, verify=v)
            elif path == "/admin/data/sample":
                found = ops.remove_sample_data(who)
                audit.log(who, "sample_data_removed", "", "%d vendors, %d integrations" % (len(found["vendors"]), found["integrations"]), ip)
                page(200, ok="Sample data removed." if found["any"] else "There was no sample data to remove.")
            elif path == "/admin/data/delete":
                if (fields.get("confirm") or "").strip() != ops.DELETE_PHRASE:
                    page(400, error="Nothing was deleted. Type %s exactly to confirm." % ops.DELETE_PHRASE)
                    return True
                out = ops.delete_all(who, ip, fields.get("backups") == "1")
                page(200, ok="All data deleted: %d vendors and everything attached to them%s.%s" % (
                    out["vendors"], ", and the backups on this server" if out["backups_removed"] else "",
                    (" " + out["azure"]) if out["azure"] else ""))
            elif path in ("/admin/data/test-email", "/admin/data/digest"):
                try:
                    if path.endswith("test-email"):
                        to = mailer.clean_address(fields.get("to", ""))
                        mailer.send(to, "RiskPrism test message", "This is a test from RiskPrism at %s. Email works." % _base_url(self))
                        audit.log(who, "test_email_sent", "", to, ip)
                        msg = "Test message sent to %s." % to
                    else:
                        n = ops.send_digest(_base_url(self), by=who)
                        msg = "Digest sent to %d recipient%s." % (n, "" if n == 1 else "s")
                except mailer.MailError as e:
                    page(400, error=str(e))
                    return True
                page(200, ok=msg)
            else:
                raise Reject(404, "That page does not exist.")
            return True
        if path == "/share/send":
            token = fields.get("token", "")
            rec = tokens.lookup(token)
            if not rec:
                raise Reject(404, "That link is unknown, expired or replaced by a newer one.")
            ask = requester(rec)
            link = _base_url(self) + "/q/" + token
            try:
                to = mailer.clean_address(fields.get("to", ""))
                subject, body = mailer.vendor_request(rec.get("vendor", ""), ask["org"], link, (rec.get("expires_at") or "")[:10],
                                                      rec.get("kind", "onboard"), ask["name"], ask["contact"], urlparse(link).netloc)
                mailer.send(to, subject, body, reply_to=ask["contact"])
            except mailer.MailError as e:
                self._page(400, "Send link", "", self._share_html(token, rec, error=str(e)), who)
                return True
            audit.log(who, "vendor_link_emailed", rec.get("slug", ""), "%s link to %s" % (rec.get("kind", "onboard"), to), ip)
            self._page(200, "Send link", "", self._share_html(token, rec, ok="Sent to %s." % to), who)
            return True
        if path.startswith("/controls/"):
            try:
                if path == "/controls/objective":
                    control_objectives.update(fields.get("oid", ""), fields.get("enabled") == "on",
                                              [t for t in control_objectives.TIERS if fields.get("tier_" + t) == "on"], fields.get("owner", ""), who)
                    audit.log(who, "objective_updated", "", fields.get("oid", ""), ip)
                    self._redirect("/controls#library")
                elif path == "/controls/add":
                    obj = control_objectives.add_custom(fields, [k for k in control_objectives.CHECKS if fields.get("check_" + k) == "on"],
                                                        [t for t in control_objectives.TIERS if fields.get("tier_" + t) == "on"], who)
                    audit.log(who, "objective_added", "", "%s %s" % (obj["id"], obj["title"]), ip)
                    self._redirect("/controls#library")
                elif path == "/controls/attest":
                    slug = fields.get("slug", "")
                    if not (valid_slug(slug) and load_vendor(slug)):
                        raise Reject(404, "Vendor not found.")
                    control_objectives.attest(slug, fields.get("oid", ""), fields.get("status", ""), fields.get("note", ""), who)
                    audit.log(who, "objective_attested", slug, "%s: %s" % (fields.get("oid", ""), fields.get("status", "")), ip)
                    self._redirect("/vendor/%s#controls" % quote(slug))
                else:
                    raise Reject(404, "That page does not exist.")
            except control_objectives.ObjectiveError as e:
                if path == "/controls/attest" and load_vendor(fields.get("slug", "")):
                    rec = load_vendor(fields["slug"])
                    self._page(400, rec.get("vendor", "Vendor"), "", views.record_page(rec, tracked=True, who=who, tab="controls",
                                                                                       controls_error=str(e)), who)
                else:
                    self._page(400, "Control objectives", "controls", controls_views.dashboard(error=str(e)), who)
            return True
        if path.startswith("/environment/"):
            try:
                if path == "/environment/setup":
                    n = environment.apply_setup(fields, who)
                    audit.log(who, "environment_setup", "", "%d systems" % n, ip)
                    return self._page(200, "Your environment", "environment", environment_views.page(ok="Saved. %d systems from setup." % n), who) or True
                if path == "/environment/import":
                    fname, text = self._upload_text(files)
                    n = environment.import_rows(environment.parse_import(text, fname))
                    audit.log(who, "environment_imported", "", "%s: %d systems" % (fname[:80], n), ip)
                    return self._page(200, "Your environment", "environment", environment_views.page(ok="Imported %d systems from %s." % (n, fname)), who) or True
                if path == "/environment/system":
                    row = environment.upsert(fields, "manual")
                    audit.log(who, "environment_system_added", "", row["id"], ip)
                    return self._redirect("/environment/" + quote(row["id"])) or True
                if path.endswith("/remove"):
                    sid = path[len("/environment/"):-len("/remove")]
                    environment.remove(sid)
                    audit.log(who, "environment_system_removed", "", sid, ip)
                    return self._redirect("/environment") or True
            except (environment.EnvironmentError_, ValueError) as e:
                return self._page(400, "Your environment", "environment", environment_views.page(error=str(e)), who) or True
            raise Reject(404, "That page does not exist.")
        if path == "/integrations/anticipate":
            slug = fields.get("slug", "")
            rec = load_vendor(slug) if valid_slug(slug) else None
            if not rec:
                raise Reject(404, "Vendor not found.")
            item = next((i for i in anticipate.connections(rec) if i["key"] == fields.get("key")), None)
            if not item:
                raise Reject(400, "That anticipated connection no longer applies. Reload the page.")
            row = integrations.add(anticipate.to_integration(rec, item), who)
            audit.log(who, "integration_anticipated", slug, "%s (%s)" % (row["name"], row["id"]), ip)
            self._redirect("/vendor/%s#integrations" % quote(slug))
            return True
        if path == "/integrations/catalog":
            try:
                fname, text = self._upload_text(files)
                n = catalog.import_json(text, who)
            except ValueError as e:
                self._page(400, "Integrations", "integrations", integrations_views.dashboard(error=str(e)), who)
                return True
            audit.log(who, "catalog_imported", "", "%s: %d products" % (fname[:80], n), ip)
            self._page(200, "Integrations", "integrations", integrations_views.dashboard(ok="Imported %d product profiles." % n), who)
            return True
        if path.startswith("/findings/"):
            try:
                if path == "/findings/push":
                    keys = [k[2:] for k, v in fields.items() if k.startswith("k_") and v == "on"]
                    system = fields.get("system", "")
                    created, errors = findings.push(keys, system, who, _base_url(self))
                    for c in created:
                        audit.log(who, "ticket_created", "", "%s %s %s" % (system, c["ref"], c["key"]), ip)
                    ok = ("Created %d ticket%s: %s." % (len(created), "" if len(created) == 1 else "s", ", ".join(c["ref"] for c in created))) if created else ""
                    self._page(200 if created or not errors else 502, "Findings", "findings",
                               findings_views.page(error=" ".join(errors), ok=ok), who)
                elif path == "/findings/ticket":
                    t = findings.record_ticket(fields.get("key", ""), "manual", fields.get("ref", ""), fields.get("url", "").strip(), who)
                    audit.log(who, "ticket_recorded", "", "%s %s" % (fields.get("key", ""), t["ref"]), ip)
                    self._redirect("/findings")
                elif path == "/findings/untrack":
                    findings.clear_ticket(fields.get("key", ""))
                    audit.log(who, "ticket_cleared", "", fields.get("key", "")[:20], ip)
                    self._redirect("/findings?show=all")
                else:
                    raise Reject(404, "That page does not exist.")
            except findings.TicketError as e:
                self._page(400, "Findings", "findings", findings_views.page(error=str(e)), who)
            return True
        if path.startswith("/shadow/"):
            try:
                if path == "/shadow/apps":
                    fname, text = self._upload_text(files)
                    n = shadow.import_apps(text, fname, fields.get("source", "entra"), who)
                    audit.log(who, "shadow_apps_imported", "", "%s: %d apps" % (fname[:80], n), ip)
                    self._page(200, "Shadow IT", "shadow", shadow_views.page(ok="Read %d connected apps." % n), who)
                elif path == "/shadow/domains":
                    fname, text = self._upload_text(files)
                    n = shadow.import_domains(text, fname, who)
                    audit.log(who, "shadow_domains_imported", "", "%s: %d domains" % (fname[:80], n), ip)
                    self._page(200, "Shadow IT", "shadow", shadow_views.page(ok="Read %d domains." % n), who)
                elif path == "/shadow/track":
                    slug = shadow.track(fields.get("id", ""), who)
                    audit.log(who, "shadow_tracked", slug, fields.get("id", ""), ip)
                    self._redirect("/vendor/%s#integrations" % quote(slug))
                elif path == "/shadow/decide":
                    if not (fields.get("note") or "").strip():
                        raise ValueError("Say why it is fine: a note is required.")
                    shadow.decide(fields.get("id", ""), fields.get("state", "known"), fields.get("note", ""), who)
                    audit.log(who, "shadow_marked", "", "%s %s: %s" % (fields.get("id", ""), fields.get("state", ""), fields.get("note", "")[:120]), ip)
                    self._redirect("/shadow")
                else:
                    raise Reject(404, "That page does not exist.")
            except ValueError as e:
                self._page(400, "Shadow IT", "shadow", shadow_views.page(error=str(e)), who)
            return True
        return False

    # ------------------------------------------------------------ integrations data layer
    def _integrations_post(self, path, who, fields, ip):
        back = fields.get("back", "")
        back = back if back in integrations.party_names() and back != integrations.YOU else ""
        dest = ("/vendor/%s#integrations" % quote(back)) if back else "/integrations"
        if path == "/integrations/seed":
            if config.AUTH_MODE != "none" and not config.ALLOW_SEED:
                raise Reject(403, "Sample data is switched off on this server.")
            n = integrations_demo.run()
            audit.log(who, "integrations_sample_loaded", "", "%d integrations" % n, ip)
            return self._redirect("/integrations")
        if path == "/integrations/draft":
            slug = fields.get("slug", "")
            rec = load_vendor(slug) if valid_slug(slug) else None
            if not rec:
                raise Reject(404, "Vendor not found.")
            try:
                row = integrations.add(integrations.draft_from_answers(rec), who)
            except integrations.IntegrationError as e:
                raise Reject(400, str(e))
            audit.log(who, "integration_drafted", slug, "%s (%s) from questionnaire answers" % (row["name"], row["id"]), ip)
            return self._redirect("/vendor/%s#integrations" % quote(slug))
        if path == "/integrations/add":
            try:
                row = integrations.add(integrations_views.form_to_raw(fields), who)
            except integrations.IntegrationError as e:
                return self._page(400, "Integrations", "integrations", integrations_views.dashboard(back, error=str(e)), who)
            for party in {row["source"], row["target"]} - {integrations.YOU}:
                audit.log(who, "integration_added", party, "%s (%s)" % (row["name"], row["id"]), ip)
            return self._redirect(dest)
        parts = path.split("/")
        if len(parts) == 4 and parts[3] == "retire":
            try:
                row = integrations.set_status(parts[2], "retired", who)
            except integrations.IntegrationError as e:
                raise Reject(404, str(e))
            for party in {row["source"], row["target"]} - {integrations.YOU}:
                audit.log(who, "integration_retired", party, "%s (%s)" % (row["name"], row["id"]), ip)
            return self._redirect(dest)
        raise Reject(404, "That page does not exist.")

    def _share(self, token, who):
        rec = tokens.lookup(token)
        if not rec:
            return self._err(404, "Link", "That link is unknown, expired or replaced by a newer one.", who)
        return self._page(200, "Send link", "", self._share_html(token, rec), who)

    def _share_html(self, token, rec, error="", ok=""):
        kind = rec.get("kind", "onboard")
        link = _base_url(self) + "/q/" + token
        ask = requester(rec)
        expires = (rec.get("expires_at") or "")[:10]
        subject, body = mailer.vendor_request(rec.get("vendor", ""), ask["org"], link, expires, kind, ask["name"], ask["contact"],
                                              urlparse(link).netloc)
        recd = load_vendor(rec.get("slug", "")) or {}
        if mailer.configured():
            send = ('<form method="post" action="/share/send" class="form"><input type="hidden" name="token" value="%s">'
                    '<label for="sh-to">Or send it from RiskPrism: the vendor contact\'s email</label>'
                    '<div class="row-inline"><input id="sh-to" name="to" type="email" maxlength="200" required value="%s">'
                    '<button class="btn primary" type="submit">Send email</button></div>'
                    '<p class="muted small">Sends the message above from %s. Replies go to %s.</p></form>' % (
                        esc(token), esc(mailer.find_address(recd.get("contact") or "")), esc(mailer.settings()["from"]),
                        esc(ask["contact"] or mailer.settings()["from"])))
        else:
            send = ('<p class="muted small">Email is not set up on this server, so paste the message into your own mail. '
                    'An admin can switch it on with the ENTROPY_SMTP settings.</p>')
        hint = "" if ask["org"] else ('<div class="notice">Vendors are more likely to answer when the form names your organisation. '
                                      'Add it, and a security contact, under <a class="gold" href="/environment">Your environment</a>.</div>')
        return tpl.render("share.html", vendor=rec.get("vendor", ""), kind={"ai": "security review"}.get(kind, kind.replace("_", " ")), link=link,
                          expires=expires, slug=rec.get("slug", ""), message="Subject: %s\n\n%s" % (subject, body), send=send, hint=hint,
                          error=views.notice("error", error), ok=views.notice("ok", ok))

    # ------------------------------------------------------------ vendor form (token = the only credential)
    def _vendor_form(self, token):
        rec = tokens.lookup(token)
        if not rec:
            return self._send(404, tpl.render("bare_error.html", title="This link no longer works",
                                              text="It may have expired or been replaced. Ask your contact at the customer for a new one."))
        recd = load_vendor(rec["slug"]) or {"vendor": rec["vendor"], "mode": "saas"}
        return self._send(200, self._render_qform(recd, rec, token))

    def _render_qform(self, recd, trec, token, error=""):
        kind = trec.get("kind", "onboard")
        enctype = ""
        if kind == "followup":
            fields, sections = render_followup_html(questions_for(recd)), ["Follow-up"]
        elif kind == "ai":
            approved = ai_questionnaire.ordered((recd.get("ai_q") or {}).get("approved") or [])
            fields = render_ai_html(approved, ai_questionnaire.AREA_LABEL, recd.get("ai_docs"),
                                    ",".join(sorted(config.ALLOWED_UPLOAD_EXT)))
            if any(q.get("kind") == "document" for q in approved):
                enctype = ' enctype="multipart/form-data"'
            sections = list(dict.fromkeys(ai_questionnaire.AREA_LABEL.get(q["area"], q["area"]) for q in approved))
        else:
            fields = render_fields_html(recd.get("mode", "saas"), kind if kind in ("onboard", "renewal") else "onboard")
            sections = [t for t, _ in q_questions(recd.get("mode", "saas"), kind)]
        title = {"renewal": "Annual security review", "followup": "Security follow-up"}.get(kind, "Vendor security questionnaire")
        return tpl.render(
            "qform.html", vendor=recd.get("vendor", trec.get("vendor", "")), title=title, mode={"saas": "SaaS", "hybrid": "Hybrid", "onprem": "On-prem"}.get(recd.get("mode") or "saas", "Unknown"),
            url=recd.get("website") or "not given", contact=recd.get("contact") or "not given",
            date=date.today().isoformat(), expires=(trec.get("expires_at") or "")[:10], action="/q/" + token,
            fields=fields, error=views.notice("error", error), steps="".join("<li>%s</li>" % esc(s) for s in sections), enctype=enctype,
            **self._asker(trec),
        )

    def _asker(self, trec):
        """Template values that tell the vendor who is asking and how to check."""
        ask = requester(trec)
        if ask["name"] and ask["email"]:
            sent_by = "This form was sent by %s (%s)." % (ask["name"], ask["email"])
        elif ask["email"]:
            sent_by = "This form was sent by %s." % ask["email"]
        else:
            sent_by = ""
        check = ("Not expecting it, or have a question? Write to %s before answering." % ask["contact"]) if ask["contact"] else \
            "Not expecting it? Check with your contact at the customer before answering."
        return {"team": ask["team"], "org": ask["org"] or "The customer", "sent_by": sent_by, "check": check,
                "portal_host": urlparse(_base_url(self)).netloc}

    def _vendor_submit(self, token):
        trec = tokens.lookup(token)
        if not trec:
            return self._send(403, tpl.render("bare_error.html", title="This link no longer works",
                                              text="It may have expired or been replaced. Your answers were not saved."))
        kind = trec.get("kind", "onboard")
        files = {}
        ctype = self.headers.get("Content-Type", "")
        if kind == "ai" and "multipart/form-data" in ctype.lower():
            try:
                raw, files = multipart.parse(self._body(config.MAX_UPLOAD_BYTES + 1024 * 1024), ctype)
            except multipart.BadMultipart:
                return self._send(400, tpl.render("bare_error.html", title="That upload could not be read",
                                                  text="Go back and try again. Your answers were not saved."))
        else:
            raw = self._form()
        slug = trec["slug"]
        recd = load_vendor(slug)
        if not recd:
            return self._send(410, tpl.render("bare_error.html", title="This review was closed",
                                              text="The customer removed this vendor record. Your answers were not saved."))
        approved = (recd.get("ai_q") or {}).get("approved") or []

        # Requested documents: each file goes through the same checks as an analyst upload.
        new_files, rejected, doc_input = [], [], {}
        for q in approved if kind == "ai" else []:
            if q.get("kind") != "document":
                continue
            fname, data = files.get("file_" + q["id"], ("", b""))
            got = []
            if fname and data:
                ev_kind = documents.guess_kind(q.get("doc_type", "") + " " + q["text"])
                try:
                    meta = evidence_store.store(slug, fname, data, ev_kind, "vendor:" + slug)
                    meta.update(question_id=q["id"], doc_type=q.get("doc_type", ""))
                    new_files.append(meta)
                    got.append(meta["stored_as"])
                except evidence_store.UploadRejected as e:
                    rejected.append("%s: %s" % (evidence_store.safe_name(fname), e))
            doc_input[q["id"]] = (q, got, raw.get(q["id"] + "__none") == "yes", str(raw.get(q["id"], "")).strip())
        if kind == "followup":
            allowed = {f.get("id") for f in recd.get("followups") or [] if f.get("id")}
        elif kind == "ai":
            allowed = ai_allowed_ids(approved)
        else:
            allowed = allowed_ids(recd.get("mode", "saas"), kind if kind in ("onboard", "renewal") else "onboard")
        answers = {k: str(v).strip()[:4000] for k, v in raw.items() if k in allowed}

        def apply(rec):
            if kind == "ai":
                # Copy answers to questions tagged with a rule field into that field, so the fixed rules still run.
                mapped = {q["feeds"]: answers[q["id"]] for q in approved if q.get("feeds") and answers.get(q["id"])}
                if answers.get("ai_train_how"):
                    mapped["ai_train_how"] = answers["ai_train_how"]
                rec.setdefault("answers", {}).update(mapped)
                rec["ai_mapped_keys"] = sorted(set(rec.get("ai_mapped_keys") or []) | set(mapped))
                rec["ai_answers"] = {k: v for k, v in answers.items() if k != "ai_train_how" and not k.endswith("__none")}
                rec.setdefault("evidence_files", []).extend(new_files)
                docs = dict(rec.get("ai_docs") or {})
                for qid, (q, got, declined, note) in doc_input.items():
                    docs[qid] = ai_questionnaire.document_status(rec, q, got, declined, note)
                rec["ai_docs"] = docs
                rec["questionnaire_status"] = "submitted"
            else:
                key, status = {"renewal": ("renewal_answers", "renewal_status"), "followup": ("followup_answers", "followup_status")}.get(
                    kind, ("answers", "questionnaire_status"))
                rec[key] = answers
                rec[status] = "submitted"
            subs = rec.setdefault("submissions", [])
            subs.append({"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "kind": kind, "answers": answers})
            rec["submissions"] = subs[-20:]
            return parse_apply(rec)

        update_vendor(slug, apply)
        tokens.touch(token)
        audit.log("vendor:" + slug, "vendor_submitted_" + kind, slug, "%d answers, %d files" % (len(answers), len(new_files)), self._ip())
        for m in new_files:
            audit.log("vendor:" + slug, "evidence_uploaded", slug, "%s (%s) by vendor" % (m["filename"], m.get("doc_type") or m["kind"]), self._ip())
        note = ("<div class=\"notice error\" role=\"alert\">These files were not accepted: %s. Your answers were saved; "
                "reopen your link to upload them again.</div>" % esc("; ".join(rejected))) if rejected else ""
        return self._send(200, tpl.render("received.html", vendor=trec.get("vendor", ""), expires=(trec.get("expires_at") or "")[:10],
                                          token=token, notice=note, team=requester(trec)["team"]))

    # ------------------------------------------------------------ POST
    def do_POST(self):
        with memo.request():
            self._do_post()

    def _do_post(self):
        try:
            self._post()
        except Reject as e:
            who = auth.principal(self.headers)
            self._err(e.code, "Request refused", e.text, who)
        except BadSlug:
            self._err(400, "Bad request", "That record id is not valid.", auth.principal(self.headers))
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception as e:
            sys.stderr.write("POST %s failed: %r\n" % (self.path, e))
            self._err(500, "Something went wrong", "The request failed. Check the server log.", auth.principal(self.headers))

    def _post(self):
        path = urlparse(self.path).path
        if not auth.host_ok(self.headers):
            return self._send(400, "Unexpected Host header", "text/plain; charset=utf-8")
        if path.startswith("/q/"):
            return self._vendor_submit(path.split("/q/", 1)[1])
        if path == "/login":
            return self._login()
        if path.startswith("/setup/"):
            return self._setup_submit(path.split("/setup/", 1)[1])

        who = self._who(path)
        if not who:
            return
        ctype = self.headers.get("Content-Type", "")
        if path in ("/evidence", "/import/entra", "/import/access", "/environment/import", "/shadow/apps", "/shadow/domains",
                    "/integrations/catalog"):
            raw = self._body(config.MAX_UPLOAD_BYTES + 1024 * 1024)
            try:
                fields, files = multipart.parse(raw, ctype)
            except multipart.BadMultipart:
                raise Reject(400, "That upload could not be read.")
        else:
            fields, files = self._form(), {}
        if not auth.csrf_ok(who, fields.get("_csrf", "")):
            raise Reject(403, "This form expired or did not come from this site. Reload the page and try again.")
        ip = self._ip()
        if path not in VIEWER_MAY_POST and is_viewer(who):  # one gate for every change in the app
            audit.log(who, "view_only_refused", "", path[:120], ip)
            raise Reject(403, VIEWER_MESSAGE)

        def go(loc):
            self._redirect(loc)

        if path.startswith("/threat/"):
            return self._threat_post(path.split("/threat/", 1)[1], who, fields, ip)
        if self._extra_post(path, who, fields, files, ip):
            return
        if path.startswith("/integrations/"):
            return self._integrations_post(path, who, fields, ip)

        if path == "/logout":
            audit.log(who, "logout", "", "", ip)
            return self._redirect("/login", {"Set-Cookie": auth.clear_cookie_header()})

        if path in ("/account", "/people"):
            me = auth.current_user(self.headers)
            if not me:
                raise Reject(404, "Accounts are not switched on for this server.")
            if path == "/account":
                try:
                    accounts.change_password(me["id"], fields.get("current", ""), fields.get("password", ""),
                                             fields.get("password2", ""), fields.get("code", ""))
                except accounts.AccountError as e:
                    audit.log(who, "password_change_failed", "", "", ip)
                    return self._page(400, "Your account", "", views.account_page(me, error=str(e)), who)
                audit.log(who, "password_changed", "", "", ip)
                me = accounts.get(me["id"])
                cookie = auth.session_cookie_header(auth.account_session(me), self._secure_cookie())
                body = self._page_html("Your account", "", views.account_page(me, ok="Password changed. Other devices are signed out."), who)
                return self._send(200, body, headers={"Set-Cookie": cookie})
            if not is_admin(who):
                raise Reject(403, "Only admins can manage people.")
            return self._people_post(me, fields, who, ip)

        if path == "/policy":
            policy_store.save(fields.get("restricted_models", "")[:5000], fields.get("restricted_regions", "")[:5000],
                              fields.get("required_region_if_critical") == "yes")
            audit.log(who, "policy_saved", "", "", ip)
            return self._page(200, "Policy", "policy", views.policy_page(saved=True), who)

        if path == "/seed":
            if config.AUTH_MODE != "none" and not config.ALLOW_SEED:
                raise Reject(403, "Sample data is switched off on this server.")
            seed_run()
            audit.log(who, "seed_loaded", "", "", ip)
            return go("/alerts")

        if path == "/import":
            text = fields.get("csv", "")
            n = csv_import.import_csv(text)
            audit.log(who, "csv_import", "", "%d rows" % n, ip)
            if n == 0:
                return self._page(400, "Import", "import", views.import_page(error="No rows were imported. The CSV needs a header row with a vendor or name column."), who)
            return go("/")

        if path == "/import/access":
            vendor = fields.get("vendor", "")
            source = fields.get("source", "")
            rec = load_vendor(vendor) if valid_slug(vendor) else None
            if not rec:
                return self._page(400, "Import", "import", views.import_page(access_error="Choose a vendor you are tracking."), who)
            if "file" not in files:
                return self._page(400, "Import", "import", views.import_page(access_error="Choose the export file first."), who)
            fname, data = files["file"]
            try:
                text = data.decode("utf-8-sig")
            except UnicodeDecodeError:
                return self._page(400, "Import", "import", views.import_page(access_error="That file is not UTF-8 text. Export it as CSV or JSON."), who)
            try:
                result = access_import.parse(text, fname, source)
            except access_import.ImportError_ as e:
                return self._page(400, "Import", "import", views.import_page(access_error=str(e), access_vendor=vendor, access_source=source), who)
            previous = len(access_store.rows(rec))
            update_vendor(vendor, lambda r: access_store.replace_rows(r, result["rows"]))
            audit.log(who, "live_access_imported", vendor, "%s: %d apps from %s, was %d" % (fname[:80], len(result["rows"]), source, previous), ip)
            return self._page(200, "Import", "import", views.import_page(
                access_ok=access_import.summary(result, previous), access_vendor=vendor), who)

        if path == "/import/entra":
            if "file" not in files:
                return self._page(400, "Import", "import", views.import_page(error="Choose the Entra users CSV first."), who)
            try:
                text = files["file"][1].decode("utf-8-sig")
            except UnicodeDecodeError:
                return self._page(400, "Import", "import", views.import_page(error="That file is not UTF-8 text. Download it from Entra again as CSV."), who)
            stats = entra_import.import_users(text, who)
            if stats.get("no_column"):
                return self._page(400, "Import", "import", views.import_page(
                    error="That CSV has no department column. In Entra ID use Users, then Download users."), who)
            audit.log(who, "entra_import", "", "%d users, %d departments, %d new units" % (stats["rows"], stats["seen"], stats["created"]), ip)
            return self._page(200, "Import", "import", views.import_page(ok=views.entra_result(stats)), who)

        if path.startswith("/admin/"):
            if not is_admin(who):
                raise Reject(403, "Only admins can change org units and approvers.")
            try:
                msg = self._admin_post(path, fields, who, ip)
            except risk_store.OrgError as e:
                return self._page(400, "Org units", "orgs", views.orgs_page(who, error=str(e)), who)
            if msg is None:
                return self._err(404, "Not found", "That action does not exist.", who)
            return self._page(200, "Org units", "orgs", views.orgs_page(who, ok=msg), who)

        if path == "/intake":
            vals = clean_vendor_fields(fields)
            if not vals.get("vendor"):
                return self._page(400, "New vendor", "", views.intake_page(vals, edit=False, error="Vendor name is required."), who)
            slug = slugify(vals["vendor"])
            try:
                save_vendor({**vals, "source": "intake", "created_by": who}, replace=False)
            except FileExistsError:
                return self._page(409, "New vendor", "", views.intake_page(
                    vals, edit=False, error="%s is already in the portfolio. Open it and use Edit instead of creating it again." % vals["vendor"]), who)
            audit.log(who, "vendor_created", slug, "", ip)
            return go("/share/" + tokens.issue(vals["vendor"], slug, "onboard", by=who))

        if path == "/report":
            vals = {k: str(fields.get(k, "")).strip()[:MAXLEN.get(k, 300)] for k in ("vendor", "website", "owner", "business", "notes")}
            vals["found_via"] = fields.get("found_via") if fields.get("found_via") in {v for v, _ in views.FOUND_VIA} else "other"
            if not vals["vendor"]:
                return self._page(400, "Report a tool", "report", views.report_page(vals, "Tool name is required."), who)
            slug = slugify(vals["vendor"])
            report = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "by": who, **{k: vals[k] for k in ("found_via", "owner", "business", "notes")}}
            existing = load_vendor(slug)
            if existing:
                # Someone else already tracks this. Add the report; never touch its status.
                update_vendor(slug, lambda r: r.setdefault("reports", []).append(report))
                audit.log(who, "tool_reported_again", slug, "", ip)
            else:
                save_vendor({"vendor": vals["vendor"], "website": vals["website"], "owner": vals["owner"], "business": vals["business"],
                             "notes": vals["notes"], "found_via": vals["found_via"], "source": "employee_report",
                             "authorization": "not_authorized", "stage": "inquiry", "reports": [report], "created_by": who}, replace=False)
                audit.log(who, "tool_reported", slug, "", ip)
            return go("/vendor/" + quote(slug))

        slug = fields.get("slug", "")

        if path == "/track":
            demo = portfolio.match_demo(slug) if valid_slug(slug) else None
            if not demo:
                raise Reject(404, "That vendor is not in the sample portfolio.")
            if not exists(slug):
                save_vendor({"vendor": demo.vendor, "slug": slug, "business": demo.product, "website": demo.website, "notes": demo.notes,
                             "source": "demo_csv", "authorization": "not_authorized", "stage": "inquiry", "created_by": who}, replace=False)
                audit.log(who, "tracking_started", slug, "", ip)
            return go("/vendor/" + quote(slug))

        if path == "/evidence":
            rec = load_vendor(slug)
            if not rec:
                raise Reject(404, "Vendor not found.")
            back = "/vendor/%s#documents" % quote(slug) if fields.get("back") == "vendor" else "/evidence/" + quote(slug)
            if "file" not in files or not files["file"][0]:
                return self._page(400, "Documents", "", views.evidence_page(rec, "Choose a file first."), who)
            fname, data = files["file"]
            try:
                meta = evidence_store.store(slug, fname, data, fields.get("kind", "other"), who, documents.clean_meta(fields))
            except evidence_store.UploadRejected as e:
                return self._page(400, "Documents", "", views.evidence_page(rec, str(e)), who)
            moved = []

            def add_file(r):
                r.setdefault("evidence_files", []).append(meta)
                step = documents.clock_update(r, meta)
                if step:
                    r[step[0]] = step[1]
                    moved.append(step)
                return parse_apply(r)
            update_vendor(slug, add_file)
            audit.log(who, "evidence_uploaded", slug, "%s (%s)" % (meta["filename"], documents.label(meta["kind"])), ip)
            for field, value in moved:
                audit.log(who, "clock_from_document", slug, "%s -> %s from %s" % (field, value, meta["filename"]), ip)
            return go(back)

        rec = load_vendor(slug)
        if not rec:
            raise Reject(404, "Vendor not found. Start tracking it first.")

        if path == "/note":
            corrects = _int_or_none(fields.get("corrects", ""))
            try:
                nid = notes_store.add(slug, fields.get("kind", "general"), fields.get("body", ""), who, corrects=corrects)
            except notes_store.NoteError as e:
                return self._page(400, rec.get("vendor", "Vendor"), "", views.record_page(
                    rec, tracked=True, demo=portfolio.match_demo(slug), error=str(e), who=who), who)
            audit.log(who, "note_corrected" if corrects else "note_added", slug,
                      "#%d%s" % (nid, (" corrects #%d" % corrects) if corrects else ""), ip)
            return go("/vendor/%s#notes" % quote(slug))

        if path == "/document/review":
            doc_id = fields.get("doc_id", "")[:40]
            f = documents.find(rec, doc_id)
            if not f:
                raise Reject(404, "That document is not on this vendor.")
            note = str(fields.get("note", "")).strip()[:documents.REVIEW_NOTE_MAX]
            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

            def mark(r):
                for x in r.get("evidence_files") or []:
                    if x.get("id") == doc_id:
                        x["reviewed_by"], x["reviewed_at"] = who, stamp
                return r
            update_vendor(slug, mark)
            if note:
                notes_store.add(slug, "doc_review", "%s: %s" % (f.get("filename", "document"), note), who, doc_id=doc_id)
            audit.log(who, "document_reviewed", slug, "%s (%s)" % (f.get("filename", ""), documents.label(f.get("kind", ""))), ip)
            back = {"evidence": "/evidence/" + quote(slug), "library": "/documents"}.get(fields.get("back"), "/vendor/%s#documents" % quote(slug))
            return go(back)

        if path in ("/ai/draft", "/ai/questions", "/accept/suggest") and not llm.enabled():
            raise Reject(403, config.AI_OFF_MESSAGE)

        if path == "/ai/draft":
            if not llm.configured():
                raise Reject(400, "No model is configured on this server. Set LLM_BASE_URL, LLM_API_KEY and LLM_MODEL (or XAI_API_KEY).")
            source = fields.get("source_url", "").strip()[:500] or rec.get("website", "")
            context = fields.get("context", "").strip()[:2000]
            if source:
                try:
                    source = vendor_research.public_url(source)
                except vendor_research.ResearchError as e:
                    return self._page(400, "AI questionnaire", "", views.ai_page(rec, error=str(e)), who)
            if not ai_questionnaire.start_draft(slug, who, source, context):
                return self._page(409, "AI questionnaire", "", views.ai_page(rec, error="A draft is already running for this vendor."), who)
            audit.log(who, "ai_draft_started", slug, source or "no website", ip)
            return go("/ai/" + quote(slug))

        if path == "/ai/questions":
            s = ai_questionnaire.state(rec)
            qs = ai_questionnaire.questions_from_form(fields, s.get("draft") or [])
            if not qs:
                return self._page(400, "AI questionnaire", "", views.ai_page(rec, error="Keep or add at least one question."), who)
            approve = fields.get("do") == "approve"
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")

            def apply(r):
                st = r.setdefault("ai_q", {})
                st["draft"] = qs
                if approve:
                    st.update(approved=qs, approved_at=now, approved_by=who)
                return r
            update_vendor(slug, apply)
            if not approve:
                audit.log(who, "ai_questions_saved", slug, "%d questions" % len(qs), ip)
                return self._page(200, "AI questionnaire", "", views.ai_page(load_vendor(slug), ok="Changes saved."), who)
            token = tokens.issue(rec.get("vendor", slug), slug, "ai", by=who)
            audit.log(who, "ai_questions_approved", slug, "%d questions (%d added by analyst)" % (
                len(qs), sum(1 for q in qs if q["source"] == "analyst")), ip)
            return go("/share/" + token)

        if path == "/edit":
            vals = clean_vendor_fields(fields)
            vals.pop("vendor", None) if not vals.get("vendor") else None
            changed = []

            def apply(r):
                for k, v in vals.items():
                    if r.get(k) != v:
                        changed.append(k)
                    r[k] = v
                return parse_apply(r) if r.get("answers") or r.get("renewal_answers") else r
            update_vendor(slug, apply)
            audit.log(who, "vendor_edited", slug, ", ".join(changed), ip)
            return go("/vendor/" + quote(slug))

        if path == "/clock":
            dates = {k: valid_date(fields.get(k, "")) for k in ("soc2_expires", "pentest_expires", "next_review", "contract_end")}
            urls = {k: valid_url(fields.get(k, "")) for k in ("soc2_url", "pentest_url")}
            update_vendor(slug, lambda r: parse_apply({**r, **dates, **urls}))
            audit.log(who, "clocks_saved", slug, "", ip)
            return go("/vendor/" + quote(slug))

        accept_draft = {k: str(fields.get(k, ""))[:4000] for k in ("detection", "org_unit_id", "risk_tier", "until", "justification", "controls")}

        if path == "/accept/suggest":
            # AI draft of an expiry date. Suggestion only: re-renders the form with what the
            # signer typed plus the suggestion. Nothing is stored or signed here.
            det = next((d for d in risk_rules.detections(rec) if d["code"] == fields.get("detection", "")), None)
            if not det:
                accept_draft["ai_error"] = "That detection is no longer open on this vendor. Reload the page and pick again."
            else:
                try:
                    accept_draft["ai"] = expiry_ai.suggest(rec, det, fields.get("risk_tier", ""))
                    audit.log(who, "expiry_suggested", slug, "%s: %s (%s)" % (det["code"], accept_draft["ai"]["date"], llm.describe()), ip)
                except llm.LLMError as e:
                    accept_draft["ai_error"] = "No AI suggestion: %s" % e
            return self._page(200, rec.get("vendor", "Vendor"), "", views.record_page(
                rec, tracked=True, demo=portfolio.match_demo(slug), who=who, accept_draft=accept_draft), who)

        if path == "/accept":
            if config.AUTH_MODE == "password":
                raise Reject(403, "Risk acceptances need per-person sign-in. Switch this server to ENTROPY_AUTH=accounts.")
            det = next((d for d in risk_rules.detections(rec) if d["code"] == fields.get("detection", "")), None)
            until = valid_date(fields.get("until", ""))
            tier = fields.get("risk_tier", "")
            level = risk_store.approver_level(who)
            unit_id = _int_or_none(fields.get("org_unit_id", ""))
            unit = risk_store.unit(unit_id) if unit_id is not None else None
            justification = fields.get("justification", "").strip()[:4000]
            controls = fields.get("controls", "").strip()[:4000]
            if not det:
                problem = "That detection is no longer open on this vendor. Reload the page and pick again."
            else:
                problem = (risk_rules.expiry_problem(until) or risk_rules.signer_problem(level, tier, det["floor"])
                           or ("" if unit and unit["merged_into"] is None else "Choose the org unit that owns this risk.")
                           or ("" if justification and controls else "A justification and the compensating controls are both required."))
            if problem:
                return self._page(400, rec.get("vendor", "Vendor"), "", views.record_page(
                    rec, tracked=True, demo=portfolio.match_demo(slug), error=problem, who=who, accept_draft=accept_draft), who)
            entry = risk_rules.build_entry(rec, det, unit_id=unit_id, accepter=who, level=level, tier=tier,
                                           justification=justification, controls=controls, until=until, recorded_by=who)
            new_id, superseded = risk_store.add_acceptance(entry)
            for old in superseded:
                audit.log(who, "acceptance_superseded", slug, "#%d replaced by #%d" % (old, new_id), ip)
            audit.log(who, "risk_accepted", slug, "#%d %s, %s, until %s, %s (%s) for %s" % (
                new_id, det["code"], tier, until, who, level, unit["name"]), ip)
            return go("/vendor/" + quote(slug) + "#risk-acceptance")

        if path == "/offboard":
            def apply(r):
                r.update(stage="offboarded", authorization="blocked", offboarded_at=date.today().isoformat())
                return r
            update_vendor(slug, apply)
            tokens.revoke_slug(slug)
            audit.log(who, "offboarded", slug, "", ip)
            return go("/vendor/" + quote(slug))

        if path in ("/renewal", "/followup", "/link"):
            kind = {"/renewal": "renewal", "/followup": "followup", "/link": "onboard"}[path]

            def apply(r):
                if path == "/renewal":
                    r["renewal_status"] = "sent"
                elif path == "/followup":
                    parse_apply(r)
                    r["followup_status"] = "sent"
                return r
            rec = update_vendor(slug, apply)
            token = tokens.issue(rec.get("vendor", slug), slug, kind, by=who)
            audit.log(who, "link_issued_" + kind, slug, "", ip)
            return go("/share/" + token)

        if path == "/parse":
            update_vendor(slug, parse_apply)
            audit.log(who, "factsheet_rebuilt", slug, "", ip)
            return go("/vendor/" + quote(slug))

        if path == "/resolve":
            fid = fields.get("fid", "")

            def apply(r):
                for f in r.get("followups") or []:
                    if f.get("id") == fid and f.get("status") == "open":
                        f["status"], f["resolved_at"], f["resolved_by"] = "resolved", date.today().isoformat(), who
                r["followup_open"] = sum(1 for f in r.get("followups") or [] if f.get("status") == "open")
                return r
            update_vendor(slug, apply)
            audit.log(who, "followup_resolved", slug, fid, ip)
            return go("/vendor/" + quote(slug))

        if path == "/purge":
            if fields.get("confirm", "").strip() != rec.get("vendor", ""):
                raise Reject(400, "The name you typed does not match, so nothing was deleted.")
            delete_vendor(slug)
            audit.log(who, "purged", slug, rec.get("vendor", ""), ip)
            return go("/")

        return self._err(404, "Not found", "That action does not exist.", who)

    def _admin_post(self, path, fields, who, ip):
        """Org units, aliases and approvers. Returns the confirmation text, or None for an unknown path."""
        if path == "/admin/unit":
            uid, parent = _int_or_none(fields.get("unit_id", "")), _int_or_none(fields.get("parent_id", ""))
            name, owner = fields.get("name", ""), fields.get("owner", "")
            if uid is None:
                uid = risk_store.create_unit(name, parent_id=parent, owner=owner, by=who)
                audit.log(who, "org_unit_created", "", "#%d %s" % (uid, name.strip()[:120]), ip)
                return "Unit added."
            risk_store.save_unit(uid, name=name, parent_id=parent, owner=owner)
            audit.log(who, "org_unit_saved", "", "#%d %s, owner %s" % (uid, name.strip()[:120], owner.strip()[:200] or "none"), ip)
            return "Unit saved and marked reviewed."
        if path == "/admin/merge":
            src, dst = _int_or_none(fields.get("from_id", "")), _int_or_none(fields.get("into_id", ""))
            if src is None or dst is None:
                raise risk_store.OrgError("Pick both units.")
            risk_store.merge_units(src, dst)
            audit.log(who, "org_units_merged", "", "#%d into #%d" % (src, dst), ip)
            return "Units merged."
        if path == "/admin/alias":
            key, uid = fields.get("alias_key", "")[:200], _int_or_none(fields.get("org_unit_id", ""))
            if uid is None:
                raise risk_store.OrgError("Pick a unit.")
            risk_store.move_alias(key, uid)
            audit.log(who, "alias_moved", "", "%s -> #%d" % (key, uid), ip)
            return "Department string moved."
        if path == "/admin/approver":
            principal, level = fields.get("principal", "").strip().lower(), fields.get("level", "")
            if config.AUTH_MODE != "none" and principal == who.lower():
                raise risk_store.OrgError("You cannot change your own approver level. Ask another admin.")
            risk_store.set_approver(principal, level, who)
            audit.log(who, "approver_removed" if level == "remove" else "approver_set", "", "%s %s" % (principal[:200], level), ip)
            return "Approver removed." if level == "remove" else "Approver saved."
        return None

    def _login_page(self, code, error=""):
        fields = LOGIN_FIELDS.get(config.AUTH_MODE, "")
        sso = ""
        if oidc.enabled():
            sso = ('<a class="btn %s sso-btn" href="/login/sso">%s</a>' % (
                "primary" if oidc.sso_only() else "ghost", esc(oidc.settings()["label"])))
            if oidc.sso_only():
                fields = ""
            else:
                sso += '<p class="muted small sso-or">or with your RiskPrism password</p>'
        return self._send(code, tpl.render("login.html", error=error, csrf=auth.csrf_token("login"), fields=fields, sso=sso,
                                           hide_submit="hidden" if not fields else ""))

    def _sso_redirect_uri(self):
        return _base_url(self) + "/login/sso/callback"

    def _sso_begin(self):
        if not oidc.enabled():
            return self._redirect("/login")
        try:
            url, cookie = oidc.begin(auth.sign, self._sso_redirect_uri())
        except oidc.OIDCError as e:
            sys.stderr.write("SSO start failed: %s\n" % e)
            return self._login_page(502, "Single sign-on is not available right now: %s" % e)
        return self._redirect(url, {"Set-Cookie": oidc.cookie_header(cookie, self._secure_cookie())})

    def _sso_callback(self):
        if not oidc.enabled():
            return self._redirect("/login")
        ip = self._ip()
        if auth.throttled(ip):
            return self._login_page(429, "Too many attempts. Wait a few minutes.")
        query = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
        try:
            email = oidc.finish(auth.sign, auth._cookie_value(self.headers, oidc.COOKIE), query, self._sso_redirect_uri())
            u = accounts.sso_login(email)
        except (oidc.OIDCError, accounts.AccountError) as e:
            auth.record_failure(ip)
            audit.log("unknown", "sso_failed", "", str(e)[:160], ip)
            return self._login_page(401, str(e))
        audit.log(u["email"], "login", "", "single sign-on", ip)
        # A same-site page hop, so the SameSite=Strict session cookie is sent on the next request.
        body = ('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=/">'
                '<title>Signed in</title></head><body><p>Signed in. <a href="/">Continue</a></p></body></html>')
        return self._send(200, body, headers={"Set-Cookie": [
            auth.session_cookie_header(auth.account_session(u), self._secure_cookie()), oidc.clear_cookie_header()]})

    def _people_post(self, me, fields, who, ip):
        action = fields.get("action", "")
        try:
            if action == "invite":
                email = accounts.clean_email(fields.get("email", ""))
                admin = fields.get("role") == "admin" or fields.get("admin") == "1"
                viewer = fields.get("role") == "viewer"
                tok = accounts.invite(email, fields.get("name", ""), admin=admin, viewer=viewer, by=who)
                audit.log(who, "user_invited", "", email + (" (admin)" if admin else " (view-only)" if viewer else ""), ip)
                link, ok, err = _base_url(self) + "/setup/" + tok, "Invite created for %s." % email, ""
                if fields.get("email_link") == "1":
                    try:
                        org = environment.org_name() if environment.org_is_named() else ""
                        mailer.send(email, *mailer.invite_message(org, link, accounts.INVITE_HOURS, me.get("name") or who))
                        audit.log(who, "invite_emailed", "", email, ip)
                        ok = "Invite created and emailed to %s." % email
                    except mailer.MailError as e:
                        err = "The invite was created, but the email was not sent: %s Send the link below yourself." % e
                return self._page(200, "People", "people", views.people_page(me, ok=ok, error=err, link=link, link_for=email), who)
            uid = _int_or_none(fields.get("uid", ""))
            target = accounts.get(uid) if uid is not None else None
            if not target:
                raise accounts.AccountError("No such account.")
            if action == "reset":
                if target["id"] == me["id"]:
                    raise accounts.AccountError("You cannot reset your own sign-in. Ask another admin.")
                tok = accounts.reset(target["id"])
                audit.log(who, "user_reset", "", target["email"], ip)
                return self._page(200, "People", "people", views.people_page(
                    me, ok="%s is signed out everywhere and needs to set up again." % target["email"],
                    link=_base_url(self) + "/setup/" + tok, link_for=target["email"]), who)
            if action in ("disable", "enable"):
                accounts.set_status(target["id"], "disabled" if action == "disable" else "active", me["id"])
                audit.log(who, "user_" + action + "d", "", target["email"], ip)
                msg = "%s %s." % (target["email"], "is disabled and signed out" if action == "disable" else "can sign in again")
            elif action in ("admin", "unadmin"):
                accounts.set_admin(target["id"], action == "admin", me["id"])
                audit.log(who, "user_admin_" + ("on" if action == "admin" else "off"), "", target["email"], ip)
                msg = "%s %s." % (target["email"], "is now an admin" if action == "admin" else "is no longer an admin")
            elif action in ("viewer", "unviewer"):
                accounts.set_view_only(target["id"], action == "viewer", me["id"])
                audit.log(who, "user_view_only_" + ("on" if action == "viewer" else "off"), "", target["email"], ip)
                msg = "%s %s." % (target["email"], "is now view-only" if action == "viewer" else "can make changes again")
            else:
                return self._err(404, "Not found", "That action does not exist.", who)
        except accounts.AccountError as e:
            return self._page(400, "People", "people", views.people_page(me, error=str(e)), who)
        return self._page(200, "People", "people", views.people_page(me, ok=msg), who)

    def _setup_page(self, token, error="", code=200, name=None):
        if config.AUTH_MODE != "accounts":
            return self._redirect("/")
        u = accounts.by_invite(token)
        if not u:
            return self._send(404, tpl.render("bare_error.html", title="This setup link no longer works",
                                              text="It expired or was already used. Ask an admin for a new one."))
        return self._send(code, tpl.render(
            "setup.html", token=token, email=u["email"], person_name=u["name"] if name is None else name,
            expires=views._when(u["invite_expires"]) + " UTC", csrf=auth.csrf_token("setup|" + token), error=error,
            qr=accounts.qr_svg(accounts.otpauth_uri(u["email"], u["totp_secret"])),
            secret=" ".join(u["totp_secret"][i:i + 4] for i in range(0, len(u["totp_secret"]), 4))))

    def _setup_submit(self, token):
        if config.AUTH_MODE != "accounts":
            return self._redirect("/")
        ip = self._ip()
        fields = self._form()
        if not auth.csrf_ok("setup|" + token, fields.get("_csrf", "")):
            raise Reject(403, "This form expired. Reload the page and try again.")
        if auth.throttled(ip):
            return self._setup_page(token, "Too many attempts. Wait a few minutes.", 429, fields.get("name", ""))
        try:
            u = accounts.complete_setup(token, fields.get("name", ""), fields.get("password", ""),
                                        fields.get("password2", ""), fields.get("code", ""))
        except accounts.AccountError as e:
            auth.record_failure(ip)
            return self._setup_page(token, str(e), 400, fields.get("name", ""))
        audit.log(u["email"], "account_setup_done", "", "", ip)
        return self._redirect("/", {"Set-Cookie": auth.session_cookie_header(auth.account_session(u), self._secure_cookie())})

    def _login(self):
        ip = self._ip()
        if config.AUTH_MODE not in LOGIN_FIELDS:
            return self._redirect("/")
        fields = self._form()
        if not auth.csrf_ok("login", fields.get("_csrf", "")):
            raise Reject(403, "This form expired. Reload the page and try again.")
        if auth.throttled(ip):
            return self._login_page(429, "Too many attempts. Wait a few minutes.")
        if oidc.sso_only():
            return self._login_page(403, "Password sign-in is switched off. Use single sign-on.")
        if config.AUTH_MODE == "accounts":
            email = fields.get("email", "").strip().lower()[:200]
            try:
                u = accounts.authenticate(email, fields.get("password", ""), fields.get("code", ""))
            except accounts.AccountError as e:
                auth.record_failure(ip)
                audit.log("unknown", "login_failed", "", email, ip)
                return self._login_page(401, str(e))
            audit.log(u["email"], "login", "", "", ip)
            return self._redirect("/", {"Set-Cookie": auth.session_cookie_header(auth.account_session(u), self._secure_cookie())})
        if auth.check_password(fields.get("password", "")):
            audit.log("analyst", "login", "", "", ip)
            return self._redirect("/", {"Set-Cookie": auth.session_cookie_header(auth.make_session(), self._secure_cookie())})
        auth.record_failure(ip)
        audit.log("unknown", "login_failed", "", "", ip)
        return self._login_page(401, "That password is not right.")


def main():
    try:  # startup lines reach journalctl or a log file straight away, not when a buffer fills
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass
    problems = config.check_startup()
    if problems:
        for p in problems:
            print("Config error:", p, file=sys.stderr)
        sys.exit(2)
    ThreadingHTTPServer.daemon_threads = True
    print("RiskPrism  http://%s:%s   auth=%s" % (config.HOST, config.PORT, config.AUTH_MODE))
    print("Data folder:", config.DATA_DIR)
    moved = risk_rules.migrate_legacy()
    if moved:
        print("Moved %d earlier risk acceptances into %s" % (moved, config.RISK_DB_PATH.name))
    print("Azure blob:", evidence_store.azure_status())
    print("AI:", "off (ENTROPY_AI=off): no model calls, no vendor website fetches" if not llm.enabled() else llm.describe())
    if oidc.enabled():
        print("Single sign-on:", oidc.settings()["issuer"], "(password sign-in off)" if oidc.sso_only() else "")
    tk = findings.systems()
    if tk:
        print("Ticketing:", ", ".join(v["label"] for v in tk.values()))
    bset = ops.backup_settings()
    print("Backups:", "off" if bset["mode"] == "off" else "nightly to %s, keeping %d" % (bset["dir"], bset["keep"]))
    print("Email:", ("via %s, weekly digest %s" % (mailer.settings()["host"], mailer.settings()["digest"])) if mailer.configured() else "off")
    ops.start_scheduler(config.BASE_URL or "http://%s:%s" % (config.HOST, config.PORT))
    if config.AUTH_MODE == "none":
        print("No login: this is only safe on your own machine.")
    if config.AUTH_MODE == "accounts" and accounts.count() == 0:
        print("No accounts yet. Create the first admin, then open the link it prints:")
        print('  python accounts.py invite you@example.com --admin --name "Your Name"')
    try:
        ThreadingHTTPServer((config.HOST, config.PORT), Handler).serve_forever()
    except OSError as e:
        print("Port %s busy." % config.PORT, file=sys.stderr)
        print(e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
