"""Security and logic tests. Run from the project folder:  python -m unittest discover -s tests -v

The tests start the real server on a random port with a throwaway data folder.
"""
from __future__ import annotations

import http.client
import os
import re
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_TMP = tempfile.mkdtemp(prefix="es-test-")
os.environ["ENTROPY_DATA_DIR"] = _TMP
os.environ["ENTROPY_AUTH"] = "none"
os.environ["ENTROPY_HOST"] = "127.0.0.1"

import auth  # noqa: E402
import config  # noqa: E402
import followup  # noqa: E402
import portfolio  # noqa: E402
import serve  # noqa: E402
import textclass as tc  # noqa: E402
import tokens  # noqa: E402
from parse_answers import apply as parse_apply  # noqa: E402
from records import load_vendor, save_vendor, valid_slug  # noqa: E402


class Client:
    def __init__(self, port, host=None):
        self.port, self.host, self.cookie = port, host, ""

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": self.host} if self.host else {}
        if self.cookie:
            h["Cookie"] = self.cookie
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read().decode("utf-8", "replace")
        sc = r.getheader("Set-Cookie")
        if sc:
            self.cookie = sc.split(";", 1)[0]
        out = (r.status, data, {k.lower(): v for k, v in r.getheaders()})
        c.close()
        return out

    def get(self, path, **kw):
        return self.req("GET", path, **kw)

    def csrf(self, page="/intake"):
        _s, html, _h = self.get(page)
        m = re.search(r'name="_csrf" value="([^"]+)"', html)
        return m.group(1) if m else ""

    def post(self, path, fields, csrf=True, page="/intake"):
        f = dict(fields)
        if csrf:
            f["_csrf"] = self.csrf(page)
        return self.req("POST", path, urlencode(f), {"Content-Type": "application/x-www-form-urlencoded"})


class ServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), serve.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.c = Client(cls.port)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def make_vendor(self, name, **extra):
        s, _b, h = self.c.post("/intake", {"vendor": name, **extra})
        self.assertEqual(s, 303, "intake should redirect to the share page")
        return h["location"].rsplit("/", 1)[1]  # token


class SecurityTests(ServerCase):
    def test_vendor_answer_cannot_inject_script(self):
        tok = self.make_vendor("XSS Test Co")
        payload = "</pre><img src=x onerror=alert(1)><script>alert(2)</script>"
        s, _b, _h = self.c.req("POST", "/q/" + tok, urlencode({"data": payload, "hosting": payload}),
                               {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(s, 200)
        _s, page, _h = self.c.get("/vendor/XSS_Test_Co")
        self.assertNotIn("<img src=x", page)
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;img src=x", page)

    def test_vendor_names_are_escaped_everywhere(self):
        name = "<img src=x onerror=alert(9)>Evil"
        self.make_vendor(name)
        for path in ("/", "/alerts", "/vendor/" + "_img_src_x_onerror_alert_9__Evil", "/edit/_img_src_x_onerror_alert_9__Evil"):
            _s, page, _h = self.c.get(path)
            self.assertNotIn("<img src=x onerror", page, path)

    def test_slug_cannot_escape_data_folder(self):
        for bad in ("../../pwned", "..\\..\\pwned", "/etc/passwd", "a/../../b", ".hidden", ""):
            self.assertFalse(valid_slug(bad), bad)
        s, _b, _h = self.c.post("/edit", {"slug": "../../pwned", "vendor": "x", "notes": "x"})
        self.assertIn(s, (400, 404))
        self.assertFalse(Path(_TMP, "..", "pwned.json").resolve().exists())
        s, _b, _h = self.c.post("/purge", {"slug": "../../x", "confirm": "x"})
        self.assertIn(s, (400, 404))

    def test_upload_traversal_and_types(self):
        self.make_vendor("Upload Co")
        csrf = self.c.csrf()
        boundary = "XBOUNDARY"

        def upload(slug, fname, data, kind="soc2"):
            parts = []
            for k, v in (("_csrf", csrf), ("slug", slug), ("kind", kind)):
                parts.append('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (boundary, k, v))
            head = '--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n' % (boundary, fname)
            body = "".join(parts).encode() + head.encode() + data + ("\r\n--%s--\r\n" % boundary).encode()
            return self.c.req("POST", "/evidence", body, {"Content-Type": "multipart/form-data; boundary=" + boundary})

        s, _b, _h = upload("../../escaped", "a.pdf", b"%PDF-1.4 x")
        self.assertIn(s, (400, 404))
        s, _b, _h = upload("Upload_Co", "evil.exe", b"MZ....")
        self.assertEqual(s, 400)
        s, _b, _h = upload("Upload_Co", "fake.pdf", b"not really a pdf")
        self.assertEqual(s, 400)
        s, _b, _h = upload("Upload_Co", "../../../etc/report.pdf", b"%PDF-1.4 real enough")
        self.assertEqual(s, 303)
        stored = list(Path(_TMP, "evidence", "Upload_Co").glob("*report.pdf"))
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].parent.resolve(), Path(_TMP, "evidence", "Upload_Co").resolve())

    def test_upload_size_limit(self):
        self.make_vendor("Big Upload Co")
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.putrequest("POST", "/evidence")
        c.putheader("Content-Type", "multipart/form-data; boundary=B")
        c.putheader("Content-Length", str(40 * 1024 * 1024))
        c.endheaders()
        self.assertEqual(c.getresponse().status, 413)

    def test_post_without_csrf_is_refused(self):
        self.make_vendor("Csrf Co")
        s, _b, _h = self.c.post("/purge", {"slug": "Csrf_Co", "confirm": "Csrf Co"}, csrf=False)
        self.assertEqual(s, 403)
        self.assertIsNotNone(load_vendor("Csrf_Co"))
        s, _b, _h = self.c.post("/purge", {"slug": "Csrf_Co", "confirm": "Csrf Co"})
        self.assertEqual(s, 303)
        self.assertIsNone(load_vendor("Csrf_Co"))

    def test_purge_needs_the_name(self):
        self.make_vendor("Purge Co")
        s, _b, _h = self.c.post("/purge", {"slug": "Purge_Co", "confirm": "nope"})
        self.assertEqual(s, 400)
        self.assertIsNotNone(load_vendor("Purge_Co"))

    def test_existing_vendor_is_never_overwritten(self):
        self.make_vendor("Keep Me Co", authorization="authorized", stage="contracted")
        self.c.post("/clock", {"slug": "Keep_Me_Co", "soc2_expires": "2027-01-01"})
        s, _b, _h = self.c.post("/intake", {"vendor": "Keep Me Co", "authorization": "blocked"})
        self.assertEqual(s, 409)
        s, _b, _h = self.c.post("/report", {"vendor": "Keep Me Co", "notes": "seen again"})
        self.assertEqual(s, 303)
        rec = load_vendor("Keep_Me_Co")
        self.assertEqual(rec["authorization"], "authorized")
        self.assertEqual(rec["soc2_expires"], "2027-01-01")
        self.assertEqual(len(rec["reports"]), 1)

    def test_no_mass_assignment(self):
        self.make_vendor("Mass Co")
        self.c.post("/edit", {"slug": "Mass_Co", "vendor": "Mass Co", "notes": "ok", "exception": "injected", "answers": "x", "authorization": "root"})
        rec = load_vendor("Mass_Co")
        self.assertNotIn("exception", rec)
        self.assertNotEqual(rec.get("authorization"), "root")
        self.assertEqual(rec["notes"], "ok")

    def test_vendor_answers_keep_history_and_drop_unknown_keys(self):
        tok = self.make_vendor("History Co")
        for text in ("first", "second"):
            self.c.req("POST", "/q/" + tok, urlencode({"data": text, "hosting": "US", "evil_key": "x"}),
                       {"Content-Type": "application/x-www-form-urlencoded"})
        rec = load_vendor("History_Co")
        self.assertEqual(rec["answers"]["data"], "second")
        self.assertNotIn("evil_key", rec["answers"])
        self.assertEqual(len(rec["submissions"]), 2)

    def test_tokens_expire_and_are_replaced(self):
        t1 = tokens.issue("Tok Co", "Tok_Co", "renewal")
        self.assertIsNotNone(tokens.lookup(t1))
        t2 = tokens.issue("Tok Co", "Tok_Co", "renewal")
        self.assertIsNone(tokens.lookup(t1), "old link must stop working")
        self.assertIsNotNone(tokens.lookup(t2))
        expired = tokens.issue("Tok Co", "Tok_Co", "followup", days=-1)
        self.assertIsNone(tokens.lookup(expired))
        raw = Path(config.TOKENS_PATH).read_text()
        self.assertNotIn(t2, raw, "raw tokens must not be stored")

    def test_bad_token_is_404(self):
        s, _b, _h = self.c.get("/q/not-a-real-token")
        self.assertEqual(s, 404)

    def test_security_headers(self):
        _s, _b, h = self.c.get("/")
        self.assertIn("default-src 'none'", h["content-security-policy"])
        self.assertEqual(h["x-frame-options"], "DENY")
        self.assertEqual(h["referrer-policy"], "no-referrer")
        self.assertEqual(h["cache-control"], "no-store")

    def test_hsts_only_over_https(self):
        self.assertNotIn("strict-transport-security", self.c.get("/")[2])
        _s, _b, h = self.c.get("/", headers={"X-Forwarded-Proto": "https"})
        self.assertIn("strict-transport-security", h)

    def test_head_and_health(self):
        self.assertEqual(self.c.req("HEAD", "/")[0], 200)
        self.assertEqual(self.c.get("/healthz")[0], 200)

    def test_dns_rebinding_host_is_refused(self):
        evil = Client(self.port, host="evil.example.com")
        self.assertEqual(evil.get("/")[0], 400)

    def test_seed_button_only_in_no_auth_mode(self):
        self.assertEqual(self.c.post("/seed", {})[0], 303)

    def test_startup_refuses_open_bind(self):
        old = (config.HOST, config.AUTH_MODE, config.ALLOW_INSECURE)
        try:
            config.HOST, config.AUTH_MODE, config.ALLOW_INSECURE = "0.0.0.0", "none", False
            self.assertTrue(config.check_startup())
            config.AUTH_MODE = "password"
            config.ANALYST_PASSWORD = "short"
            self.assertTrue(config.check_startup())
        finally:
            config.HOST, config.AUTH_MODE, config.ALLOW_INSECURE = old
            config.ANALYST_PASSWORD = ""


class PasswordModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved = (config.AUTH_MODE, config.ANALYST_PASSWORD)
        config.AUTH_MODE, config.ANALYST_PASSWORD = "password", "correct horse battery"
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), serve.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        config.AUTH_MODE, config.ANALYST_PASSWORD = cls.saved

    def test_login_flow(self):
        c = Client(self.port)
        s, _b, h = c.get("/")
        self.assertEqual((s, h["location"]), (303, "/login"))
        self.assertEqual(c.get("/vendor/AWS")[0], 303)
        self.assertEqual(c.get("/static/app.css")[0], 200, "static stays public")
        _s, page, _h = c.get("/login")
        csrf = re.search(r'name="_csrf" value="([^"]+)"', page).group(1)
        s, _b, _h = c.req("POST", "/login", urlencode({"password": "wrong", "_csrf": csrf}), {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(s, 401)
        s, _b, _h = c.req("POST", "/login", urlencode({"password": "correct horse battery"}), {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(s, 403, "login without its CSRF token is refused")
        s, _b, h = c.req("POST", "/login", urlencode({"password": "correct horse battery", "_csrf": csrf}), {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(s, 303)
        self.assertEqual(c.get("/")[0], 200)

    def test_vendor_form_needs_no_login(self):
        tok = tokens.issue("Portal Co", "Portal_Co", "onboard")
        save_vendor({"vendor": "Portal Co", "slug": "Portal_Co"})
        self.assertEqual(Client(self.port).get("/q/" + tok)[0], 200)

    def test_seed_disabled_when_auth_on(self):
        c = Client(self.port)
        _s, page, _h = c.get("/login")
        csrf = re.search(r'name="_csrf" value="([^"]+)"', page).group(1)
        c.req("POST", "/login", urlencode({"password": "correct horse battery", "_csrf": csrf}), {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(c.post("/seed", {}, page="/alerts")[0], 403)


class EasyAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved = (config.AUTH_MODE, config.ALLOWED_USERS)
        config.AUTH_MODE = "easyauth"
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), serve.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        config.AUTH_MODE, config.ALLOWED_USERS = cls.saved

    def test_requires_platform_identity(self):
        c = Client(self.port)
        self.assertEqual(c.get("/")[0], 401)
        self.assertEqual(c.get("/", headers={"X-MS-CLIENT-PRINCIPAL-NAME": "ana@example.com"})[0], 200)
        config.ALLOWED_USERS = {"boss@example.com"}
        self.assertEqual(c.get("/", headers={"X-MS-CLIENT-PRINCIPAL-NAME": "ana@example.com"})[0], 401)
        config.ALLOWED_USERS = set()


class LogicTests(unittest.TestCase):
    def test_yes_no(self):
        for text, want in [("We do not use AI", "no"), ("I don't know", "unknown"), ("not sure", "unknown"), ("No", "no"),
                           ("yes we use a model on the lease text", "yes"), ("Yes", "yes"), ("", "unknown"),
                           ("we do not train but we use a model", "unknown"), ("unsure", "unknown")]:
            self.assertEqual(tc.yes_no(text), want, text)

    def test_training_default(self):
        for text, want in [("No training on customer content", "off"), ("We never train on your data", "off"),
                           ("default on to improve the model", "on"), ("Default off", "off"), ("on", "on"), ("unsure", "unknown"),
                           ("Training on customer data is disabled; we do not train on customer data.", "off"),
                           ("Yes, we train on customer content", "on"), ("Default on. Opt out available.", "unknown"), ("", "unknown")]:
            self.assertEqual(tc.training_default(text), want, text)

    def test_whole_word_matching(self):
        self.assertEqual(tc.words("Photo graphics and specific cuisine menus", tc.CRITICAL_DATA_TERMS), [])
        self.assertEqual(tc.words("Stores PHI and card data", ("phi", "card")), ["phi", "card"])
        self.assertFalse(tc.is_critical("not critical"))
        self.assertFalse(tc.is_critical("standard"))
        self.assertTrue(tc.is_critical("critical"))

    def test_followups_do_not_misfire(self):
        rec = {"answers": {"ai_train": "Training on customer data is disabled; we do not train.", "ai_used": "no",
                           "data": "Photo graphics", "soc2": "Type II, no exceptions noted", "pentest_current": "Full report attached",
                           "ai_provider": "Inference run by OpenAI in the US", "hosting": "us-east", "data_class": "standard"}}
        ids = {f["id"] for f in followup.scan(rec)}
        self.assertEqual(ids, set(), ids)

    def test_followups_still_catch_real_problems(self):
        rec = {"answers": {"data_class": "critical", "ai_used": "yes we use a model", "ai_train": "default on to improve the model",
                           "soc2": "Type I last year", "pentest_current": "Executive summary only", "ai_region": "Hosted in Russia"}}
        ids = {f["id"] for f in followup.scan(rec)}
        self.assertTrue({"pentest_exec_only", "soc2_type1", "ai_models_unnamed", "ai_train_on", "region_restricted"} <= ids, ids)

    def test_resolved_followups_stay_resolved(self):
        rec = {"answers": {"pentest_current": "Executive summary only"}}
        followup.apply(rec)
        self.assertGreaterEqual(len(rec["followups"]), 1)
        for f in rec["followups"]:
            f["status"] = "resolved"
        followup.apply(rec)
        self.assertEqual(rec["followup_open"], 0)
        self.assertTrue(all(f["status"] == "resolved" for f in rec["followups"]))

    def test_onboarded_vendor_gets_a_tier(self):
        rec = {"vendor": "Scored Co", "slug": "Scored_Co", "business": "Payments", "mode": "saas",
               "answers": {"data": "payment card data", "ai_used": "yes", "ai_models": "OpenAI GPT-4o", "ai_train": "off"}}
        parse_apply(rec)
        save_vendor(rec)
        row = next(r for r in portfolio.rows() if r["slug"] == "Scored_Co")
        self.assertIn(row["inh"], ("T1", "T2", "T3", "T4"))
        self.assertTrue(row["provisional"] and row["human"])

    def test_demo_residuals_use_the_controls_file(self):
        row = next(r for r in portfolio.rows() if r["name"] == "OpenAI")
        self.assertEqual(row["res"], "T3")


if __name__ == "__main__":
    unittest.main()
