"""Per-person accounts with authenticator MFA (ENTROPY_AUTH=accounts).

Run from the project folder:  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import re
import sys
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_app import Client  # noqa: E402  (sets up the throwaway data folder first)

import accounts  # noqa: E402
import config  # noqa: E402
import notes_store  # noqa: E402
import serve  # noqa: E402
from records import save_vendor  # noqa: E402

FORM = {"Content-Type": "application/x-www-form-urlencoded"}
PW = "a long walk on the beach"


def _csrf(html):
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    return m.group(1) if m else ""


def _secret(html):
    m = re.search(r'<p class="mono key">([A-Z2-7 ]+)</p>', html)
    return m.group(1).replace(" ", "")


def _next_code(secret, after_step=0):
    """A code for a step the server has not seen yet (codes are single use)."""
    step = int(time.time() // 30)
    if step <= after_step:
        step = after_step + 1
    return accounts._hotp(secret, step)


class TotpTests(unittest.TestCase):
    def test_rfc6238_vector(self):
        # RFC 6238 appendix B, SHA1, T=59 -> 94287082 (8 digits); 6-digit form is the last six.
        secret = __import__("base64").b32encode(b"12345678901234567890").decode()
        self.assertEqual(accounts._hotp(secret, 59 // 30), "287082")

    def test_codes_are_single_use(self):
        s = accounts.new_totp_secret()
        code = accounts.totp_now(s)
        step = accounts._totp_step_ok(s, code, 0)
        self.assertTrue(step)
        self.assertEqual(accounts._totp_step_ok(s, code, step), 0)

    def test_password_rules(self):
        self.assertTrue(accounts.password_problem("short"))
        self.assertTrue(accounts.password_problem("aaaaaaaaaaaaaaaa"))
        self.assertTrue(accounts.password_problem("mypassword is long", "x@y.com"))
        self.assertTrue(accounts.password_problem("michael likes boats", "michael@y.com"))
        self.assertEqual(accounts.password_problem(PW, "ana@example.com"), "")

    def test_hash_is_not_plaintext(self):
        h = accounts.hash_password(PW)
        self.assertNotIn(PW, h)
        self.assertTrue(accounts._check_hash(PW, h))
        self.assertFalse(accounts._check_hash(PW + "x", h))

    def test_qr_is_plain_svg(self):
        svg = accounts.qr_svg(accounts.otpauth_uri("a@b.co", accounts.new_totp_secret()))
        self.assertTrue(svg.startswith("<svg"))
        self.assertNotIn("<script", svg)


class AccountsModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved = config.AUTH_MODE
        config.AUTH_MODE = "accounts"
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), serve.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        config.AUTH_MODE = cls.saved
        serve.auth._failures.clear()

    def setUp(self):
        serve.auth._failures.clear()  # every test client is 127.0.0.1, so the per-IP throttle would carry over

    # helpers
    def setup_account(self, email, admin=False, name="Test Person"):
        tok = accounts.invite(email, name, admin=admin, by="test")
        c = Client(self.port)
        s, page, _h = c.get("/setup/" + tok)
        self.assertEqual(s, 200)
        secret = _secret(page)
        body = {"_csrf": _csrf(page), "name": name, "password": PW, "password2": PW, "code": accounts.totp_now(secret)}
        s, _b, h = c.req("POST", "/setup/" + tok, urlencode(body), FORM)
        self.assertEqual(s, 303, _b[:300])
        self.assertIn("es_session=", h.get("set-cookie", ""))
        return c, secret, tok

    def login(self, email, password, code):
        c = Client(self.port)
        _s, page, _h = c.get("/login")
        s, body, _h = c.req("POST", "/login", urlencode({"_csrf": _csrf(page), "email": email, "password": password, "code": code}), FORM)
        return c, s, body

    # tests
    def test_signed_out_goes_to_login_and_vendor_portal_stays_public(self):
        c = Client(self.port)
        s, _b, h = c.get("/")
        self.assertEqual((s, h.get("location")), (303, "/login"))
        _s, page, _h = c.get("/login")
        self.assertIn('name="code"', page)
        self.assertIn('name="email"', page)
        self.assertEqual(c.get("/static/app.css")[0], 200)

    def test_setup_then_sign_in_and_notes_name_the_person(self):
        c, secret, tok = self.setup_account("ana@example.com")
        self.assertEqual(c.get("/")[0], 200, "setup signs the person in")
        self.assertIn("ana@example.com", c.get("/")[1])
        self.assertEqual(Client(self.port).get("/setup/" + tok)[0], 404, "setup link is single use")
        save_vendor({"vendor": "Acme Notes", "slug": "Acme_Notes"})
        s, _b, _h = c.post("/note", {"slug": "Acme_Notes", "kind": "general", "body": "Checked the SOC 2."}, page="/vendor/Acme_Notes")
        self.assertEqual(s, 303)
        self.assertEqual(notes_store.for_vendor("Acme_Notes")[0]["author"], "ana@example.com")

    def test_login_needs_password_and_fresh_code(self):
        _c, secret, _t = self.setup_account("ben@example.com")
        u = accounts.by_email("ben@example.com")
        good = _next_code(secret, u["totp_last_step"])
        self.assertEqual(self.login("ben@example.com", "wrong password here", good)[1], 401)
        self.assertEqual(self.login("ben@example.com", PW, "000000")[1], 401)
        self.assertEqual(self.login("nobody@example.com", PW, good)[1], 401)
        c, s, _b = self.login("ben@example.com", PW, good)
        self.assertEqual(s, 303)
        self.assertEqual(c.get("/")[0], 200)
        self.assertEqual(self.login("ben@example.com", PW, good)[1], 401, "the same code cannot be replayed")

    def test_lockout_after_repeated_failures(self):
        _c, secret, _t = self.setup_account("cal@example.com")
        serve.auth._failures.clear()
        for _ in range(accounts.LOCK_AFTER):
            with self.assertRaises(accounts.AccountError):
                accounts.authenticate("cal@example.com", "not the password!", "123456")
        u = accounts.by_email("cal@example.com")
        with self.assertRaises(accounts.AccountError) as e:
            accounts.authenticate("cal@example.com", PW, _next_code(secret, u["totp_last_step"]))
        self.assertIn("locked", str(e.exception))

    def test_disable_signs_out_and_people_page_is_admin_only(self):
        admin_c, _s, _t = self.setup_account("boss@example.com", admin=True)
        user_c, _s2, _t2 = self.setup_account("dee@example.com")
        self.assertEqual(user_c.get("/people")[0], 403)
        _s, page, _h = admin_c.get("/people")
        self.assertIn("dee@example.com", page)
        dee = accounts.by_email("dee@example.com")
        s, page, _h = admin_c.req("POST", "/people", urlencode({"_csrf": _csrf(page), "action": "disable", "uid": dee["id"]}), FORM)
        self.assertEqual(s, 200)
        self.assertEqual(user_c.get("/")[0], 303, "disabled person is signed out at once")
        me = accounts.by_email("boss@example.com")
        s, page, _h = admin_c.req("POST", "/people", urlencode({"_csrf": _csrf(page), "action": "disable", "uid": me["id"]}), FORM)
        self.assertEqual(s, 400, "cannot disable yourself")

    def test_invite_from_people_page_shows_one_time_link(self):
        admin_c, _s, _t = self.setup_account("lead@example.com", admin=True)
        _s, page, _h = admin_c.get("/people")
        s, page, _h = admin_c.req("POST", "/people", urlencode({"_csrf": _csrf(page), "action": "invite", "email": "New@Example.com", "name": "New"}), FORM)
        self.assertEqual(s, 200)
        link = re.search(r'<code id="setup-link">[^<]*/setup/([A-Za-z0-9_\-]+)</code>', page)
        self.assertTrue(link)
        self.assertEqual(Client(self.port).get("/setup/" + link.group(1))[0], 200)
        self.assertEqual(accounts.by_email("new@example.com")["status"], "invited")
        s, page, _h = admin_c.req("POST", "/people", urlencode({"_csrf": _csrf(page), "action": "invite", "email": "new@example.com"}), FORM)
        self.assertEqual(s, 400, "no duplicate accounts")

    def test_reset_kills_sessions_and_old_link(self):
        user_c, _s, tok = self.setup_account("eve@example.com")
        eve = accounts.by_email("eve@example.com")
        new_tok = accounts.reset(eve["id"])
        self.assertEqual(user_c.get("/")[0], 303)
        self.assertIsNone(accounts.by_invite(tok))
        self.assertIsNotNone(accounts.by_invite(new_tok))

    def test_change_password_keeps_this_device_signed_in(self):
        c, secret, _t = self.setup_account("fay@example.com")
        u = accounts.by_email("fay@example.com")
        new = "another long sentence here"
        s, page, h = c.post("/account", {"current": PW, "password": new, "password2": new, "code": _next_code(secret, u["totp_last_step"])}, page="/account")
        self.assertEqual(s, 200, page[:300])
        self.assertEqual(c.get("/")[0], 200)
        with self.assertRaises(accounts.AccountError):
            accounts.authenticate("fay@example.com", PW, _next_code(secret, accounts.by_email("fay@example.com")["totp_last_step"]))

    def test_last_admin_cannot_be_removed(self):
        _c, _s, _t = self.setup_account("only@example.com", admin=True)
        other_c, _s2, _t2 = self.setup_account("other-admin@example.com", admin=True)
        for u in accounts.list_users():
            if u["is_admin"] and u["email"] not in ("only@example.com", "other-admin@example.com"):
                accounts.set_status(u["id"], "disabled", -1)
        only = accounts.by_email("only@example.com")
        other = accounts.by_email("other-admin@example.com")
        accounts.set_admin(other["id"], False, only["id"])
        with self.assertRaises(accounts.AccountError):
            accounts.set_status(only["id"], "disabled", other["id"])
        self.assertEqual(accounts.by_email("only@example.com")["status"], "active")


if __name__ == "__main__":
    unittest.main()
