"""Analyst authentication, CSRF tokens and Host-header checks.

Modes (ENTROPY_AUTH):
  none      no login. Only allowed on a loopback bind (see config.check_startup).
  accounts  one account per person: email, password and an authenticator app (accounts.py).
            Use this for a team. Every note, review and acceptance names the person.
  password  one shared analyst password, signed session cookie. Fine for a small demo VM.
  easyauth  Azure App Service / Container Apps built-in authentication (Microsoft Entra ID).
            The platform signs the user in and passes the identity in
            X-MS-CLIENT-PRINCIPAL-NAME. The app must only be reachable through that
            front end, and /q/*, /static/* and /healthz must be excluded from the
            platform's login requirement so vendors can reach their form.

Vendor questionnaire links (/q/<token>) are their own capability and never use these.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from http.cookies import SimpleCookie

import config

COOKIE = "es_session"
SESSION_SECONDS = 8 * 3600
_failures: dict[str, list[float]] = {}


def _sig(msg: str) -> str:
    return hmac.new(config.SECRET, msg.encode(), hashlib.sha256).hexdigest()


def _cookie_value(headers, name: str = COOKIE) -> str:
    raw = headers.get("Cookie") or ""
    try:
        c = SimpleCookie()
        c.load(raw)
        return c[name].value if name in c else ""
    except Exception:
        return ""


def sign(msg: str) -> str:
    return _sig(msg)


def make_session() -> str:
    exp = str(int(time.time()) + SESSION_SECONDS)
    return exp + "." + _sig("session|" + exp)


def session_valid(value: str) -> bool:
    try:
        exp, sig = value.split(".", 1)
        return int(exp) > time.time() and hmac.compare_digest(sig, _sig("session|" + exp))
    except (ValueError, AttributeError):
        return False


def account_session(user: dict) -> str:
    import accounts
    return accounts.session_value(user, _sig, SESSION_SECONDS)


def current_user(headers) -> dict | None:
    """The signed-in account in accounts mode, else None."""
    if config.AUTH_MODE != "accounts":
        return None
    import accounts
    return accounts.session_user(_cookie_value(headers), _sig)


def check_password(candidate: str) -> bool:
    return bool(config.ANALYST_PASSWORD) and hmac.compare_digest(
        hashlib.sha256(candidate.encode()).digest(),
        hashlib.sha256(config.ANALYST_PASSWORD.encode()).digest(),
    )


def throttled(ip: str) -> bool:
    now = time.time()
    hits = [t for t in _failures.get(ip, []) if now - t < 300]
    _failures[ip] = hits
    return len(hits) >= 5


def record_failure(ip: str) -> None:
    _failures.setdefault(ip, []).append(time.time())


def principal(headers) -> str | None:
    """Return the analyst identity, or None when the caller is not signed in."""
    mode = config.AUTH_MODE
    if mode == "none":
        return "local-analyst"
    if mode == "password":
        return "analyst" if session_valid(_cookie_value(headers)) else None
    if mode == "accounts":
        u = current_user(headers)
        return u["email"] if u else None
    if mode == "easyauth":
        name = (headers.get("X-MS-CLIENT-PRINCIPAL-NAME") or "").strip()
        if not name:
            return None
        if config.ALLOWED_USERS and name.lower() not in config.ALLOWED_USERS:
            return None
        return name[:200]
    return None


def csrf_token(who: str) -> str:
    return _sig("csrf|" + who)[:40]


def csrf_ok(who: str, supplied: str) -> bool:
    return bool(supplied) and hmac.compare_digest(csrf_token(who), supplied)


def host_ok(headers) -> bool:
    """Reject unexpected Host headers (DNS rebinding against a loopback server)."""
    host = (headers.get("Host") or "").lower()
    bare = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
    bare = bare.strip("[]")
    if config.ALLOWED_HOSTS:
        return host in config.ALLOWED_HOSTS or bare in config.ALLOWED_HOSTS
    if config.is_loopback(config.HOST) and not config.BASE_URL:
        return bare in config.LOOPBACK
    return True


def session_cookie_header(value: str, secure: bool) -> str:
    parts = [COOKIE + "=" + value, "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=%d" % SESSION_SECONDS]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def clear_cookie_header() -> str:
    return COOKIE + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
