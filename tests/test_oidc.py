"""Analyst SSO with OpenID Connect, against a local fake identity provider with a throwaway RSA key."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import random
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_app import Client  # noqa: E402  (sets up the throwaway data folder first)

import accounts  # noqa: E402
import config  # noqa: E402
import oidc  # noqa: E402
import serve  # noqa: E402


# ------------------------------------------------------------------ a throwaway RSA key, stdlib only
def _is_prime(n: int, rng: random.Random) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(24):
        x = pow(rng.randrange(2, n - 2), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int, rng: random.Random) -> int:
    while True:
        c = rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _is_prime(c, rng):
            return c


def make_key(seed: int) -> dict:
    rng = random.Random(seed)
    e = 65537
    while True:
        p, q = _prime(1024, rng), _prime(1024, rng)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            break
    return {"n": p * q, "e": e, "d": pow(e, -1, phi)}


def sign(key: dict, header: dict, claims: dict) -> str:
    h = oidc.b64url(json.dumps(header).encode())
    p = oidc.b64url(json.dumps(claims).encode())
    k = (key["n"].bit_length() + 7) // 8
    t = oidc._SHA256_PREFIX + hashlib.sha256((h + "." + p).encode()).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    s = pow(int.from_bytes(em, "big"), key["d"], key["n"]).to_bytes(k, "big")
    return h + "." + p + "." + oidc.b64url(s)


KEY = make_key(7)
OTHER = make_key(11)


def jwk(key: dict, kid: str) -> dict:
    return {"kty": "RSA", "use": "sig", "kid": kid, "alg": "RS256",
            "n": oidc.b64url(key["n"].to_bytes((key["n"].bit_length() + 7) // 8, "big")), "e": oidc.b64url(key["e"].to_bytes(3, "big"))}


class FakeIdP(BaseHTTPRequestHandler):
    issuer = ""
    email = "ana@example.com"
    claims_extra: dict = {}
    sign_with = KEY
    codes: dict = {}
    last_token_request: dict = {}

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            return self._json({"issuer": FakeIdP.issuer, "authorization_endpoint": FakeIdP.issuer + "/authorize",
                               "token_endpoint": FakeIdP.issuer + "/token", "jwks_uri": FakeIdP.issuer + "/keys"})
        if self.path == "/keys":
            return self._json({"keys": [jwk(KEY, "k1")]})
        if self.path.startswith("/authorize"):
            q = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
            code = "code-%d" % len(FakeIdP.codes)
            FakeIdP.codes[code] = q
            self.send_response(302)
            self.send_header("Location", q["redirect_uri"] + "?code=%s&state=%s" % (code, q["state"]))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._json({"error": "nope"}, 404)

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        form = {k: v[0] for k, v in parse_qs(body).items()}
        FakeIdP.last_token_request = {"form": form, "auth": self.headers.get("Authorization", "")}
        q = FakeIdP.codes.pop(form.get("code", ""), None)
        if not q:
            return self._json({"error": "invalid_grant"}, 400)
        challenge = oidc.b64url(hashlib.sha256(form.get("code_verifier", "").encode()).digest())
        if challenge != q["code_challenge"]:
            return self._json({"error": "invalid_grant", "error_description": "PKCE"}, 400)
        now = int(time.time())
        claims = {"iss": FakeIdP.issuer, "aud": "riskprism-test", "sub": "u1", "email": FakeIdP.email,
                  "iat": now, "exp": now + 300, "nonce": q["nonce"], **FakeIdP.claims_extra}
        self._json({"id_token": sign(FakeIdP.sign_with, {"alg": "RS256", "kid": "k1"}, claims), "token_type": "Bearer"})


class OIDCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved = config.AUTH_MODE
        config.AUTH_MODE = "accounts"
        cls.idp = ThreadingHTTPServer(("127.0.0.1", 0), FakeIdP)
        threading.Thread(target=cls.idp.serve_forever, daemon=True).start()
        FakeIdP.issuer = "http://127.0.0.1:%d" % cls.idp.server_address[1]
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), serve.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.env = mock.patch.dict(os.environ, {"ENTROPY_OIDC_ISSUER": FakeIdP.issuer, "ENTROPY_OIDC_CLIENT_ID": "riskprism-test",
                                               "ENTROPY_OIDC_CLIENT_SECRET": "s3cret"})
        cls.env.start()
        if not accounts.by_email("ana@example.com"):
            accounts.invite("ana@example.com", "Ana", admin=True, by="test")
        if not accounts.by_email("off@example.com"):
            accounts.invite("off@example.com", "Off", by="test")
            with accounts._db(write=True) as con:
                con.execute("UPDATE users SET status = 'disabled' WHERE email = 'off@example.com'")

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.httpd.shutdown()
        cls.idp.shutdown()
        config.AUTH_MODE = cls.saved
        serve.auth._failures.clear()

    def setUp(self):
        serve.auth._failures.clear()
        oidc._cache.clear()
        FakeIdP.email, FakeIdP.claims_extra, FakeIdP.sign_with = "ana@example.com", {}, KEY

    def _req(self, path, cookie=""):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", path, headers={"Cookie": cookie} if cookie else {})
        r = c.getresponse()
        body = r.read().decode("utf-8", "replace")
        out = (r.status, body, r.getheader("Location") or "", r.msg.get_all("Set-Cookie") or [])
        c.close()
        return out

    def _sign_in(self):
        s, _b, loc, cookies = self._req("/login/sso")
        self.assertEqual(s, 303)
        self.assertTrue(loc.startswith(FakeIdP.issuer + "/authorize?"))
        q = {k: v[0] for k, v in parse_qs(urlparse(loc).query).items()}
        self.assertEqual(q["code_challenge_method"], "S256")
        self.assertIn("SameSite=Lax", cookies[0])
        flow_cookie = cookies[0].split(";", 1)[0]
        c = http.client.HTTPConnection("127.0.0.1", self.idp.server_address[1], timeout=10)
        c.request("GET", loc[len(FakeIdP.issuer):])
        back = c.getresponse().getheader("Location")
        c.close()
        return self._req(urlparse(back).path + "?" + urlparse(back).query, flow_cookie)

    def test_login_page_offers_sso(self):
        s, page, _l, _c = self._req("/login")
        self.assertIn('href="/login/sso"', page)
        self.assertIn('name="password"', page)

    def test_full_sign_in(self):
        s, body, _l, cookies = self._sign_in()
        self.assertEqual(s, 200, body)
        session = next(c for c in cookies if c.startswith("es_session="))
        self.assertIn("SameSite=Strict", session)
        self.assertTrue(any(c.startswith("es_oidc=;") for c in cookies))
        s, page, _l, _c = self._req("/", session.split(";", 1)[0])
        self.assertEqual(s, 200)
        self.assertIn("ana@example.com", page)
        self.assertEqual(accounts.by_email("ana@example.com")["status"], "active")
        self.assertIn("Basic ", FakeIdP.last_token_request["auth"])
        self.assertNotIn("client_secret", FakeIdP.last_token_request["form"])

    def test_unknown_and_disabled_people_are_refused(self):
        for email, words in (("stranger@example.com", "no RiskPrism account"), ("off@example.com", "disabled")):
            FakeIdP.email = email
            s, body, _l, cookies = self._sign_in()
            self.assertEqual(s, 401)
            self.assertIn(words, body)
            self.assertFalse(any(c.startswith("es_session=") and not c.startswith("es_session=;") for c in cookies))

    def test_forged_and_misaddressed_tokens_are_refused(self):
        for extra, sign_with, words in (({}, OTHER, "signature"), ({"aud": "someone-else"}, KEY, "different application"),
                                        ({"iss": "https://evil.example"}, KEY, "someone else"),
                                        ({"exp": int(time.time()) - 3600}, KEY, "expired"), ({"nonce": "replayed"}, KEY, "this sign-in")):
            FakeIdP.claims_extra, FakeIdP.sign_with = extra, sign_with
            s, body, _l, _c = self._sign_in()
            self.assertEqual(s, 401, extra)
            self.assertIn(words, body, extra)

    def test_callback_without_flow_cookie_or_wrong_state(self):
        s, body, _l, _c = self._req("/login/sso/callback?code=x&state=y")
        self.assertEqual(s, 401)
        self.assertIn("expired or was started somewhere else", body)

    def test_alg_none_is_refused(self):
        tok = oidc.b64url(b'{"alg":"none"}') + "." + oidc.b64url(b'{"iss":"x"}') + "."
        with self.assertRaises(oidc.OIDCError):
            oidc.verify_id_token(tok, "n")

    def test_sso_only_switches_off_passwords(self):
        with mock.patch.dict(os.environ, {"ENTROPY_OIDC_ONLY": "1"}):
            _s, page, _l, _c = self._req("/login")
            self.assertNotIn('name="password"', page)
            cl = Client(self.port)
            _s, html, _h = cl.get("/login")
            import re
            tok = re.search(r'name="_csrf" value="([^"]+)"', html).group(1)
            s, _b, _h = cl.req("POST", "/login", "email=ana%40example.com&password=x&code=1&_csrf=" + tok,
                               {"Content-Type": "application/x-www-form-urlencoded"})
            self.assertEqual(s, 403)

    def test_startup_checks(self):
        with mock.patch.dict(os.environ, {"ENTROPY_OIDC_ISSUER": "http://idp.example"}):
            self.assertTrue(any("https://" in p for p in oidc.startup_problems()))
        with mock.patch.object(config, "AUTH_MODE", "password"):
            self.assertTrue(any("ENTROPY_AUTH=accounts" in p for p in oidc.startup_problems()))


if __name__ == "__main__":
    unittest.main()
