"""Runtime configuration. Everything comes from environment variables so nothing
needs editing in source when the app moves to Azure.

ENTROPY_HOST            bind address (default 127.0.0.1)
ENTROPY_PORT / PORT     port (default 8765)
ENTROPY_BASE_URL        public URL used in vendor links, e.g. https://tprm.example.com
ENTROPY_DATA_DIR        where vendor JSON, tokens, audit log and evidence live (default ./data)
ENTROPY_AUTH            none | accounts | password | easyauth   (default none, loopback only)
ENTROPY_ANALYST_PASSWORD  required when ENTROPY_AUTH=password
ENTROPY_ALLOWED_USERS   optional comma list of emails allowed when ENTROPY_AUTH=easyauth
ENTROPY_SECRET          signing key for cookies and CSRF (generated and stored if unset)
ENTROPY_ALLOWED_HOSTS   optional comma list of Host header values to accept
ENTROPY_ALLOW_INSECURE  set to 1 to allow a non-loopback bind with ENTROPY_AUTH=none (do not)
ENTROPY_ALLOW_SEED      set to 1 to allow the sample-data button when auth is on
ENTROPY_TOKEN_DAYS      vendor link lifetime in days (default 30)
ENTROPY_ADMINS          comma list of identities that may edit org units and approvers (everyone when ENTROPY_AUTH=none)
ENTROPY_VIEWERS         comma list of identities that may read everything and change nothing (for easyauth;
                        in accounts mode set people to view-only on the People page instead)
ENTROPY_ACCEPT_MAX_DAYS longest a risk acceptance may run, in days (default 365)
ENTROPY_AI              on | off (default on). off hides every AI control, refuses model calls and never fetches
                        vendor websites, even when LLM_* variables are set. Everything else works by hand.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE = Path(__file__).resolve().parent


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


DATA_DIR = Path(os.environ.get("ENTROPY_DATA_DIR") or (BASE / "data")).resolve()
HOST = os.environ.get("ENTROPY_HOST", "127.0.0.1")
PORT = _int("ENTROPY_PORT", _int("PORT", 8765))
BASE_URL = (os.environ.get("ENTROPY_BASE_URL") or "").rstrip("/")
AUTH_MODE = (os.environ.get("ENTROPY_AUTH") or "none").strip().lower()
ANALYST_PASSWORD = os.environ.get("ENTROPY_ANALYST_PASSWORD", "")
ALLOWED_USERS = {u.strip().lower() for u in (os.environ.get("ENTROPY_ALLOWED_USERS") or "").split(",") if u.strip()}
ALLOWED_HOSTS = {h.strip().lower() for h in (os.environ.get("ENTROPY_ALLOWED_HOSTS") or "").split(",") if h.strip()}
ALLOW_INSECURE = os.environ.get("ENTROPY_ALLOW_INSECURE") == "1"
ALLOW_SEED = os.environ.get("ENTROPY_ALLOW_SEED") == "1"
TOKEN_DAYS = _int("ENTROPY_TOKEN_DAYS", 30)
VIEWERS = {u.strip().lower() for u in (os.environ.get("ENTROPY_VIEWERS") or "").split(",") if u.strip()}
ADMINS = {u.strip().lower() for u in (os.environ.get("ENTROPY_ADMINS") or "").split(",") if u.strip()}
ACCEPT_MAX_DAYS = max(1, _int("ENTROPY_ACCEPT_MAX_DAYS", 365))
AI_ENABLED = (os.environ.get("ENTROPY_AI") or "on").strip().lower() not in ("off", "0", "false", "no")
AI_OFF_MESSAGE = "AI is switched off on this server (ENTROPY_AI=off). Everything else works without it."

MAX_FORM_BYTES = 256 * 1024
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_UPLOAD_EXT = {".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv", ".png", ".jpg", ".jpeg", ".md"}
REQUEST_TIMEOUT = 30

LOOPBACK = {"127.0.0.1", "localhost", "::1"}

VDIR = DATA_DIR / "vendors"
EVIDENCE_DIR = DATA_DIR / "evidence"
TOKENS_PATH = DATA_DIR / "tokens.json"
AUDIT_PATH = DATA_DIR / "audit.log"
SECRET_PATH = DATA_DIR / "secret.key"
RISK_DB_PATH = DATA_DIR / "riskprism.db"


def is_loopback(host: str) -> bool:
    return host in LOOPBACK


def check_startup() -> list[str]:
    """Return a list of fatal configuration problems. Empty means OK."""
    problems = []
    ai = (os.environ.get("ENTROPY_AI") or "on").strip().lower()
    if ai not in ("on", "off", "1", "0", "true", "false", "yes", "no"):
        problems.append("ENTROPY_AI must be on or off (got %r)." % ai)
    if AUTH_MODE not in ("none", "accounts", "password", "easyauth"):
        problems.append("ENTROPY_AUTH must be none, accounts, password or easyauth (got %r)." % AUTH_MODE)
    import mailer
    import oidc
    problems.extend(oidc.startup_problems())
    problems.extend(mailer.startup_problems())
    import ops
    problems.extend(ops.startup_problems())
    import llm
    if AI_ENABLED and llm.transport_problem():
        problems.append(llm.transport_problem())
    if AUTH_MODE == "password" and len(ANALYST_PASSWORD) < 12:
        problems.append("ENTROPY_AUTH=password needs ENTROPY_ANALYST_PASSWORD of at least 12 characters.")
    if AUTH_MODE == "none" and not is_loopback(HOST) and not ALLOW_INSECURE:
        problems.append(
            "Refusing to bind %s with no authentication. Set ENTROPY_AUTH=accounts, password or easyauth, "
            "or bind 127.0.0.1." % HOST
        )
    return problems


def secret() -> bytes:
    env = os.environ.get("ENTROPY_SECRET")
    if env:
        return env.encode()
    try:
        SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
        if SECRET_PATH.is_file():
            return SECRET_PATH.read_bytes().strip()
        key = secrets.token_hex(32).encode()
        fd = os.open(str(SECRET_PATH), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        return key
    except OSError:
        return secrets.token_hex(32).encode()


SECRET = secret()
