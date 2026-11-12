"""Per-person analyst accounts with authenticator-app MFA (ENTROPY_AUTH=accounts).

Stored in DATA_DIR/riskprism.db next to notes and acceptances, in a `users` table.

  - An admin invites someone by email. The invite is a single-use link that expires
    after INVITE_HOURS. Only a hash of the link is stored.
  - The person opens the link, sets a password (scrypt-hashed) and enrolls an
    authenticator app (TOTP, RFC 6238). Both are required to sign in.
  - Sessions carry the user id and a session version. Disabling a person or resetting
    their sign-in bumps the version, which signs them out everywhere at once.
  - Five wrong sign-ins lock the account for LOCK_MINUTES.
  - Authenticator secrets are encrypted at rest with a key derived from the server secret
    (ENTROPY_SECRET or DATA_DIR/secret.key): an HMAC-SHA256 keystream with an HMAC tag, so a copy
    of the database alone cannot mint codes. Plaintext secrets from older versions are encrypted
    the first time the database is opened. Losing the server secret means everyone resets sign-in.

The identity the rest of the app sees is the lower-case email address, so notes,
reviews, approvers and the audit log all name a real person.

Create the first admin from the server shell:

    python accounts.py invite you@example.com --admin --name "Your Name"
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import struct
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import config
from records import LOCK

INVITE_HOURS = 72
LOCK_AFTER = 5
LOCK_MINUTES = 15
PW_MIN, PW_MAX = 12, 200
TOTP_STEP, TOTP_DIGITS = 30, 6
ISSUER = "RiskPrism"

EMAIL_RE = re.compile(r"^[^@\s<>\"']{1,100}@[^@\s<>\"']{1,150}\.[^@\s<>\"'.]{2,40}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id              INTEGER PRIMARY KEY,
  email           TEXT NOT NULL UNIQUE,
  name            TEXT NOT NULL DEFAULT '',
  status          TEXT NOT NULL CHECK (status IN ('invited', 'active', 'disabled')),
  is_admin        INTEGER NOT NULL DEFAULT 0,
  view_only       INTEGER NOT NULL DEFAULT 0,
  pw_hash         TEXT NOT NULL DEFAULT '',
  totp_secret     TEXT NOT NULL DEFAULT '',
  totp_last_step  INTEGER NOT NULL DEFAULT 0,
  invite_hash     TEXT NOT NULL DEFAULT '',
  invite_expires  TEXT NOT NULL DEFAULT '',
  session_ver     INTEGER NOT NULL DEFAULT 1,
  failed          INTEGER NOT NULL DEFAULT 0,
  locked_until    REAL NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL,
  created_by      TEXT NOT NULL DEFAULT '',
  last_login      TEXT NOT NULL DEFAULT ''
);
"""

_ready: set[str] = set()


class AccountError(ValueError):
    """Something a person can fix: bad email, weak password, wrong code, last admin..."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def _db(write: bool = False):
    path = config.RISK_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path), timeout=10)
    con.row_factory = sqlite3.Row
    try:
        if str(path) not in _ready:
            with LOCK:
                con.executescript(_SCHEMA)
                _add_missing_columns(con)
                _encrypt_plaintext(con)
                _ready.add(str(path))
        if write:
            with LOCK, con:
                yield con
        else:
            yield con
    finally:
        con.close()


# ------------------------------------------------------------------ authenticator secrets at rest
_ENC = "enc1:"


def _keys() -> tuple[bytes, bytes]:
    return (hmac.new(config.SECRET, b"riskprism totp encryption v1", hashlib.sha256).digest(),
            hmac.new(config.SECRET, b"riskprism totp mac v1", hashlib.sha256).digest())


def _stream(key: bytes, nonce: bytes, n: int) -> bytes:
    out, i = b"", 0
    while len(out) < n:
        out += hmac.new(key, nonce + struct.pack(">I", i), hashlib.sha256).digest()
        i += 1
    return out[:n]


def seal(secret_b32: str) -> str:
    if not secret_b32:
        return ""
    ek, mk = _keys()
    nonce = secrets.token_bytes(16)
    pt = secret_b32.encode("ascii")
    ct = bytes(a ^ b for a, b in zip(pt, _stream(ek, nonce, len(pt))))
    tag = hmac.new(mk, nonce + ct, hashlib.sha256).digest()[:16]
    return _ENC + base64.urlsafe_b64encode(nonce + ct + tag).decode("ascii")


def unseal(stored: str) -> str:
    """The base32 secret, or "" when it cannot be read (wrong server secret, tampered row)."""
    if not stored:
        return ""
    if not stored.startswith(_ENC):
        return stored  # pre-encryption row; _encrypt_plaintext converts these on first open
    try:
        raw = base64.urlsafe_b64decode(stored[len(_ENC):].encode("ascii"))
    except (ValueError, TypeError):
        return ""
    if len(raw) < 33:
        return ""
    nonce, ct, tag = raw[:16], raw[16:-16], raw[-16:]
    ek, mk = _keys()
    if not hmac.compare_digest(tag, hmac.new(mk, nonce + ct, hashlib.sha256).digest()[:16]):
        return ""
    return bytes(a ^ b for a, b in zip(ct, _stream(ek, nonce, len(ct)))).decode("ascii", "replace")


def _add_missing_columns(con) -> None:
    """Databases created before a column existed get it added, with its default."""
    have = {r[1] for r in con.execute("PRAGMA table_info(users)")}
    if "view_only" not in have:
        con.execute("ALTER TABLE users ADD COLUMN view_only INTEGER NOT NULL DEFAULT 0")


def _encrypt_plaintext(con) -> int:
    rows = con.execute("SELECT id, totp_secret FROM users WHERE totp_secret != '' AND totp_secret NOT LIKE 'enc1:%'").fetchall()
    with con:
        for r in rows:
            con.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (seal(r[1]), r[0]))
    return len(rows)


def _user(r) -> dict | None:
    if not r:
        return None
    d = dict(r)
    d["totp_secret"] = unseal(d.get("totp_secret") or "")
    return d


# ------------------------------------------------------------------ passwords
def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = 2 ** 14, 8, 1
    dk = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt$%d$%d$%d$%s$%s" % (n, r, p, salt.hex(), dk.hex())


def _check_hash(pw: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        got = hashlib.scrypt(pw.encode("utf-8"), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=len(dk) // 2)
        return hmac.compare_digest(got.hex(), dk)
    except (ValueError, TypeError):
        return False


_DUMMY = None


def _burn(pw: str) -> None:
    """Spend the same time on an unknown email as on a real one."""
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password(secrets.token_hex(8))
    _check_hash(pw, _DUMMY)


def password_problem(pw: str, email: str = "") -> str:
    if len(pw) < PW_MIN:
        return "Use at least %d characters. A short sentence is easiest to remember." % PW_MIN
    if len(pw) > PW_MAX:
        return "That password is too long."
    low = pw.lower()
    if len(set(pw)) < 5:
        return "That password repeats too few characters."
    local = (email or "").split("@")[0].lower()
    if local and len(local) >= 4 and local in low:
        return "Do not put your email name in your password."
    if any(w in low for w in ("password", "riskprism", "123456789", "qwertyuiop")):
        return "That password is too easy to guess."
    return ""


# ------------------------------------------------------------------ TOTP
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def totp_now(secret_b32: str, at: float | None = None) -> str:
    return _hotp(secret_b32, int((at if at is not None else time.time()) // TOTP_STEP))


def _totp_step_ok(secret_b32: str, code: str, last_step: int) -> int:
    """Return the matching time step (one step of clock drift either way), or 0. Never reuses a step."""
    code = re.sub(r"\s+", "", code or "")
    if not secret_b32 or not re.fullmatch(r"\d{%d}" % TOTP_DIGITS, code):
        return 0
    now = int(time.time() // TOTP_STEP)
    for step in (now - 1, now, now + 1):
        if step > last_step and hmac.compare_digest(_hotp(secret_b32, step), code):
            return step
    return 0


def otpauth_uri(email: str, secret_b32: str) -> str:
    label = quote("%s:%s" % (ISSUER, email))
    return "otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d" % (
        label, secret_b32, quote(ISSUER), TOTP_DIGITS, TOTP_STEP)


def qr_svg(text: str) -> str:
    """Inline SVG QR code (no scripts, so it passes the page's CSP)."""
    import qrcodegen
    qr = qrcodegen.QrCode.encode_text(text, qrcodegen.QrCode.Ecc.MEDIUM)
    border, size = 3, qr.get_size()
    parts = ["M%d,%dh1v1h-1z" % (x + border, y + border) for y in range(size) for x in range(size) if qr.get_module(x, y)]
    dim = size + border * 2
    return ('<svg class="qr" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" role="img" aria-label="QR code for your authenticator app">'
            '<rect width="100%%" height="100%%" fill="#fff"/><path d="%s" fill="#000"/></svg>' % (dim, dim, " ".join(parts)))


# ------------------------------------------------------------------ users
def clean_email(email: str) -> str:
    e = (email or "").strip().lower()
    if not EMAIL_RE.match(e):
        raise AccountError("That does not look like an email address.")
    return e


def _hash_token(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


def count() -> int:
    with _db() as con:
        return con.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def list_users() -> list[dict]:
    with _db() as con:
        return [{**dict(r), "totp_secret": ""} for r in con.execute("SELECT * FROM users ORDER BY status = 'disabled', email")]


def get(uid: int) -> dict | None:
    with _db() as con:
        return _user(con.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone())


def by_email(email: str) -> dict | None:
    with _db() as con:
        return _user(con.execute("SELECT * FROM users WHERE email = ?", ((email or "").strip().lower(),)).fetchone())


def _new_invite(con, uid: int) -> str:
    tok = secrets.token_urlsafe(32)
    exp = (datetime.now(timezone.utc) + timedelta(hours=INVITE_HOURS)).isoformat(timespec="seconds")
    con.execute("UPDATE users SET status = 'invited', pw_hash = '', totp_secret = ?, totp_last_step = 0, invite_hash = ?, "
                "invite_expires = ?, session_ver = session_ver + 1, failed = 0, locked_until = 0 WHERE id = ?",
                (seal(new_totp_secret()), _hash_token(tok), exp, uid))
    return tok


def invite(email: str, name: str = "", *, admin: bool = False, viewer: bool = False, by: str = "") -> str:
    """Create an invited account and return the one-time setup token."""
    email = clean_email(email)
    if admin and viewer:
        raise AccountError("A view-only account cannot be an admin. Pick one.")
    with _db(write=True) as con:
        if con.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            raise AccountError("%s already has an account. Use Reset sign-in to send a new link." % email)
        cur = con.execute("INSERT INTO users (email, name, status, is_admin, view_only, created_at, created_by) "
                          "VALUES (?, ?, 'invited', ?, ?, ?, ?)",
                          (email, (name or "").strip()[:120], 1 if admin else 0, 1 if viewer else 0, _now(), (by or "")[:200]))
        return _new_invite(con, int(cur.lastrowid))


def reset(uid: int) -> str:
    """Wipe password and authenticator, sign the person out everywhere, return a new setup token."""
    with _db(write=True) as con:
        if not con.execute("SELECT 1 FROM users WHERE id = ?", (uid,)).fetchone():
            raise AccountError("No such account.")
        return _new_invite(con, uid)


def by_invite(token: str) -> dict | None:
    if not token or len(token) > 100:
        return None
    with _db() as con:
        r = con.execute("SELECT * FROM users WHERE invite_hash = ? AND status = 'invited'", (_hash_token(token),)).fetchone()
    if not r or (r["invite_expires"] or "") < _now():
        return None
    return _user(r)


def complete_setup(token: str, name: str, pw: str, pw2: str, code: str) -> dict:
    u = by_invite(token)
    if not u:
        raise AccountError("This setup link has expired or was already used. Ask an admin for a new one.")
    if pw != pw2:
        raise AccountError("The two passwords do not match.")
    problem = password_problem(pw, u["email"])
    if problem:
        raise AccountError(problem)
    step = _totp_step_ok(u["totp_secret"], code, 0)
    if not step:
        raise AccountError("That code did not match. Check the phone's clock and enter the current 6-digit code.")
    with _db(write=True) as con:
        con.execute("UPDATE users SET status = 'active', name = ?, pw_hash = ?, totp_last_step = ?, invite_hash = '', invite_expires = '', last_login = ?, "
                    "failed = 0, locked_until = 0 WHERE id = ? AND invite_hash = ?",
                    ((name or u["name"]).strip()[:120], hash_password(pw), step, _now(), u["id"], u["invite_hash"]))
    return get(u["id"])


def authenticate(email: str, pw: str, code: str) -> dict:
    """Return the user, or raise AccountError with one deliberately vague message."""
    vague = AccountError("Email, password or code is not right.")
    u = by_email(email)
    if not u or u["status"] != "active":
        _burn(pw)
        raise vague
    if u["locked_until"] > time.time():
        _burn(pw)
        raise AccountError("Too many attempts. This account is locked for a few minutes.")
    step = _totp_step_ok(u["totp_secret"], code, u["totp_last_step"]) if _check_hash(pw, u["pw_hash"]) else 0
    if not step:
        with _db(write=True) as con:  # commit the counter first; raising inside would roll it back
            failed = con.execute("SELECT failed FROM users WHERE id = ?", (u["id"],)).fetchone()[0] + 1
            locked = time.time() + LOCK_MINUTES * 60 if failed >= LOCK_AFTER else 0
            con.execute("UPDATE users SET failed = ?, locked_until = ? WHERE id = ?", (0 if locked else failed, locked, u["id"]))
        raise vague
    with _db(write=True) as con:
        con.execute("UPDATE users SET failed = 0, locked_until = 0, totp_last_step = ?, last_login = ? WHERE id = ?", (step, _now(), u["id"]))
    return get(u["id"])


def sso_login(email: str) -> dict:
    """Sign in a person the identity provider has already authenticated. Their account must exist (an admin
    invited them); an invited account becomes active, a disabled one is refused."""
    u = by_email(email)
    if not u:
        raise AccountError("There is no RiskPrism account for %s. Ask an admin to invite you." % email)
    if u["status"] == "disabled":
        raise AccountError("Your RiskPrism account is disabled. Ask an admin.")
    with _db(write=True) as con:
        con.execute("UPDATE users SET status = 'active', invite_hash = '', invite_expires = '', failed = 0, locked_until = 0, "
                    "last_login = ? WHERE id = ?", (_now(), u["id"]))
    return get(u["id"])


def change_password(uid: int, current: str, new: str, new2: str, code: str) -> None:
    u = get(uid)
    if not u or u["status"] != "active":
        raise AccountError("No such account.")
    step = _totp_step_ok(u["totp_secret"], code, u["totp_last_step"]) if _check_hash(current, u["pw_hash"]) else 0
    if not step:
        raise AccountError("Current password or code is not right.")
    if new != new2:
        raise AccountError("The two new passwords do not match.")
    problem = password_problem(new, u["email"])
    if problem:
        raise AccountError(problem)
    with _db(write=True) as con:
        con.execute("UPDATE users SET pw_hash = ?, totp_last_step = ?, session_ver = session_ver + 1 WHERE id = ?", (hash_password(new), step, uid))


def _active_admins(con) -> int:
    n = con.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND status = 'active'").fetchone()[0]
    return n + len(config.ADMINS)


def set_status(uid: int, status: str, by_uid: int) -> dict:
    if status not in ("active", "disabled"):
        raise AccountError("Unknown status.")
    if uid == by_uid:
        raise AccountError("You cannot disable or re-enable your own account.")
    with _db(write=True) as con:
        u = con.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if not u:
            raise AccountError("No such account.")
        if status == "active" and not u["pw_hash"] and not u["last_login"]:  # SSO-only people have no password
            raise AccountError("This person never finished setup. Use Reset sign-in to send a new link.")
        con.execute("UPDATE users SET status = ?, session_ver = session_ver + 1, failed = 0, locked_until = 0 WHERE id = ?", (status, uid))
        if status == "disabled" and u["is_admin"] and _active_admins(con) == 0:
            raise AccountError("That would leave no admin. Make someone else an admin first.")
    return get(uid)


def set_admin(uid: int, on: bool, by_uid: int) -> dict:
    if uid == by_uid:
        raise AccountError("You cannot change your own admin rights. Ask another admin.")
    with _db(write=True) as con:
        if not con.execute("SELECT 1 FROM users WHERE id = ?", (uid,)).fetchone():
            raise AccountError("No such account.")
        if on and con.execute("SELECT view_only FROM users WHERE id = ?", (uid,)).fetchone()[0]:
            raise AccountError("This account is view-only. Allow changes first, then make it an admin.")
        con.execute("UPDATE users SET is_admin = ? WHERE id = ?", (1 if on else 0, uid))
        if not on and _active_admins(con) == 0:
            raise AccountError("That would leave no admin. Make someone else an admin first.")
    return get(uid)


def set_view_only(uid: int, on: bool, by_uid: int) -> dict:
    """A view-only person can read everything and change nothing. They cannot also be an admin."""
    if uid == by_uid:
        raise AccountError("You cannot change your own access. Ask another admin.")
    with _db(write=True) as con:
        u = con.execute("SELECT is_admin FROM users WHERE id = ?", (uid,)).fetchone()
        if not u:
            raise AccountError("No such account.")
        if on and u["is_admin"]:
            raise AccountError("Remove admin first. An admin cannot be view-only.")
        con.execute("UPDATE users SET view_only = ? WHERE id = ?", (1 if on else 0, uid))
    return get(uid)


# ------------------------------------------------------------------ sessions
def session_value(u: dict, sign, seconds: int) -> str:
    exp = str(int(time.time()) + seconds)
    body = "a.%d.%d.%s" % (u["id"], u["session_ver"], exp)
    return body + "." + sign("acct|" + body)


def session_user(value: str, sign) -> dict | None:
    try:
        tag, uid, ver, exp, sig = value.split(".")
        body = "%s.%s.%s.%s" % (tag, uid, ver, exp)
        if tag != "a" or int(exp) < time.time() or not hmac.compare_digest(sig, sign("acct|" + body)):
            return None
        u = get(int(uid))
    except (ValueError, AttributeError):
        return None
    if not u or u["status"] != "active" or u["session_ver"] != int(ver):
        return None
    return u


def setup_link(token: str) -> str:
    base = config.BASE_URL or "http://%s:%s" % (config.HOST, config.PORT)
    return base + "/setup/" + token


# ------------------------------------------------------------------ command line
def _cli(argv: list[str]) -> int:
    usage = ("usage:\n  python accounts.py invite EMAIL [--admin] [--name \"Full Name\"]\n"
             "  python accounts.py reset EMAIL\n  python accounts.py list")
    if not argv or argv[0] not in ("invite", "reset", "list"):
        print(usage)
        return 2
    import audit
    try:
        if argv[0] == "list":
            for u in list_users():
                print("%-40s %-9s %s %s" % (u["email"], u["status"], "admin" if u["is_admin"] else "     ", u["last_login"] or "never signed in"))
            return 0
        if len(argv) < 2:
            print(usage)
            return 2
        if argv[0] == "invite":
            name = argv[argv.index("--name") + 1] if "--name" in argv and argv.index("--name") + 1 < len(argv) else ""
            tok = invite(argv[1], name, admin="--admin" in argv, by="shell")
            audit.log("shell", "user_invited", "", argv[1].lower() + (" (admin)" if "--admin" in argv else ""))
        else:
            u = by_email(argv[1])
            if not u:
                raise AccountError("No account for %s." % argv[1])
            tok = reset(u["id"])
            audit.log("shell", "user_reset", "", u["email"])
    except AccountError as e:
        print("Error:", e)
        return 1
    print("Data folder:", config.DATA_DIR, "(must match the running server's ENTROPY_DATA_DIR)")
    print("Send this one-time setup link to the person (expires in %d hours):" % INVITE_HOURS)
    print(setup_link(tok))
    if not config.BASE_URL:
        print("(Set ENTROPY_BASE_URL so the link uses your public https address.)")
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
