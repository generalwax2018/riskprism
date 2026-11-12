"""Optional outgoing email over SMTP (standard library only). Off until ENTROPY_SMTP_HOST is set.

ENTROPY_SMTP_HOST      mail server, e.g. smtp.office365.com, smtp.gmail.com, email-smtp.us-east-1.amazonaws.com
ENTROPY_SMTP_PORT      default 587
ENTROPY_SMTP_TLS       starttls (default) | ssl (port 465) | none (accepted only for a loopback host)
ENTROPY_SMTP_USER / ENTROPY_SMTP_PASSWORD   sign-in for the mail server, if it needs one
ENTROPY_SMTP_FROM      the From address, e.g. "Acme Security <security@acme.example>" (required)
ENTROPY_DIGEST         weekly (default when email is on) | off
ENTROPY_DIGEST_TO      extra comma-separated addresses for the weekly digest (admins get it in accounts mode)

What is sent, and only when a person asks or the weekly digest is due:
  - a vendor's questionnaire link, to the address the analyst types
  - a new analyst's one-time setup link, when the admin ticks the box
  - a weekly digest of counts and the top decisions, to admins

Plain text only. No tracking, no images, no links other than this RiskPrism's own address. The password
is read from the environment and never written to disk or the audit log.
"""
from __future__ import annotations

import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr

import config

ADDRESS_RE = re.compile(r"^[^@\s<>\"',;:\\]{1,100}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,150})\.[A-Za-z]{2,40}$")
TIMEOUT = 20


class MailError(RuntimeError):
    """Something a person can act on: not configured, bad address, the server refused."""


def settings() -> dict:
    env = os.environ
    try:
        port = int(env.get("ENTROPY_SMTP_PORT") or 587)
    except ValueError:
        port = 587
    return {"host": (env.get("ENTROPY_SMTP_HOST") or "").strip(), "port": port,
            "tls": (env.get("ENTROPY_SMTP_TLS") or "starttls").strip().lower(),
            "user": env.get("ENTROPY_SMTP_USER") or "", "password": env.get("ENTROPY_SMTP_PASSWORD") or "",
            "from": (env.get("ENTROPY_SMTP_FROM") or "").strip(),
            "digest": (env.get("ENTROPY_DIGEST") or "weekly").strip().lower(),
            "digest_to": [a.strip() for a in (env.get("ENTROPY_DIGEST_TO") or "").split(",") if a.strip()]}


def configured() -> bool:
    s = settings()
    return bool(s["host"] and s["from"])


def startup_problems() -> list[str]:
    s = settings()
    if not s["host"]:
        return []
    out = []
    if not s["from"] or not valid_address(parseaddr(s["from"])[1]):
        out.append("ENTROPY_SMTP_HOST is set, so ENTROPY_SMTP_FROM must be an address such as security@yourco.com.")
    if s["tls"] not in ("starttls", "ssl", "none"):
        out.append("ENTROPY_SMTP_TLS must be starttls, ssl or none (got %r)." % s["tls"])
    if s["tls"] == "none" and not config.is_loopback(s["host"]):
        out.append("ENTROPY_SMTP_TLS=none sends mail and the password unencrypted. It is accepted only for a mail server on this machine.")
    if not config.BASE_URL.startswith("https://") and not config.is_loopback(config.HOST):
        out.append("Email is on, so set ENTROPY_BASE_URL to this server's https:// address: links in messages are built from it.")
    if s["digest"] not in ("weekly", "off"):
        out.append("ENTROPY_DIGEST must be weekly or off (got %r)." % s["digest"])
    return out


def valid_address(addr: str) -> bool:
    return bool(ADDRESS_RE.fullmatch((addr or "").strip()))


def clean_address(addr: str) -> str:
    addr = (addr or "").strip()
    if not valid_address(addr):
        raise MailError("That does not look like an email address: %s" % addr[:80])
    return addr


def find_address(text: str) -> str:
    """The first email address inside free text (a vendor's 'security contact' field), or ''."""
    for word in re.split(r"[\s,;<>()]+", text or ""):
        if valid_address(word.strip(".")):
            return word.strip(".")
    return ""


def _one_line(text: str, limit: int = 200) -> str:
    return re.sub(r"[\x00-\x1f\x7f\x85\u2028\u2029]+", " ", text or "").strip()[:limit]


def send(to: str | list[str], subject: str, body: str, reply_to: str = "") -> int:
    """Send one plain-text message. Returns the number of recipients. Raises MailError."""
    s = settings()
    if not configured():
        raise MailError("Email is not set up on this server. Set ENTROPY_SMTP_HOST and ENTROPY_SMTP_FROM.")
    recipients = [clean_address(a) for a in ([to] if isinstance(to, str) else to)]
    if not recipients:
        raise MailError("No one to send to.")
    msg = EmailMessage()
    try:
        _headers(msg, s, recipients, subject, reply_to)
    except ValueError as e:
        raise MailError("The message could not be built: %s" % _one_line(str(e), 120))
    msg.set_content(body)
    return _deliver(s, msg, recipients)


def _headers(msg, s, recipients, subject, reply_to) -> None:
    msg["From"] = s["from"]
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = _one_line(subject)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=(parseaddr(s["from"])[1].split("@")[-1] or "riskprism.local"))
    if reply_to and valid_address(reply_to):
        msg["Reply-To"] = reply_to
    msg["Auto-Submitted"] = "auto-generated"


def _deliver(s: dict, msg, recipients: list[str]) -> int:
    try:
        if s["tls"] == "ssl":
            server = smtplib.SMTP_SSL(s["host"], s["port"], timeout=TIMEOUT, context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(s["host"], s["port"], timeout=TIMEOUT)
        with server:
            if s["tls"] == "starttls":
                server.starttls(context=ssl.create_default_context())
            elif s["tls"] == "none" and not config.is_loopback(s["host"]):
                raise MailError("Refusing to send mail unencrypted to %s." % s["host"])
            if s["user"]:
                server.login(s["user"], s["password"])
            refused = server.send_message(msg)
    except MailError:
        raise
    except smtplib.SMTPAuthenticationError:
        raise MailError("The mail server refused the sign-in. Check ENTROPY_SMTP_USER and ENTROPY_SMTP_PASSWORD.")
    except smtplib.SMTPRecipientsRefused:
        raise MailError("The mail server refused that recipient.")
    except (smtplib.SMTPException, ssl.SSLError) as e:
        raise MailError("The mail server refused the message: %s" % _one_line(str(e), 160))
    except (OSError, TimeoutError) as e:
        raise MailError("Could not reach the mail server %s:%d: %s" % (s["host"], s["port"], _one_line(str(e), 120)))
    if refused:
        raise MailError("The mail server refused: %s" % ", ".join(sorted(refused))[:200])
    return len(recipients)


# ------------------------------------------------------------------ message texts
def vendor_request(vendor: str, org: str, link: str, expires: str, kind: str, sender_name: str, contact: str, host: str) -> tuple[str, str]:
    """(subject, body) for the message that carries a vendor's questionnaire link."""
    who = org or "our security team"
    what = {"renewal": "annual security review", "followup": "security follow-up questions"}.get(kind, "security questionnaire")
    subject = "%s for %s%s" % (what.capitalize(), vendor, (", requested by %s" % org) if org else "")
    lines = [
        "Hello,",
        "",
        "%s is reviewing the security of the vendors it works with, and %s is one of them." % (who[:1].upper() + who[1:], vendor),
        "Please complete the %s by %s:" % (what, expires),
        "",
        link,
        "",
        "The link opens the form only and needs no sign-in. You can reopen it and change your answers until %s." % expires,
        "%s uses RiskPrism to run these reviews, which is why the form is on %s." % (who[:1].upper() + who[1:], host),
        "Please do not paste passwords or production secrets into the form.",
        "",
        ("Questions, or not expecting this? Write to %s before answering." % contact) if contact
        else "Questions, or not expecting this? Reply to the person who sent you this message before answering.",
        "",
        "Thank you,",
        sender_name or who,
    ]
    return subject, "\n".join(lines)


def invite_message(org: str, link: str, hours: int, by: str) -> tuple[str, str]:
    subject = "Set up your RiskPrism account%s" % ((" for %s" % org) if org else "")
    body = "\n".join([
        "Hello,", "",
        "%s invited you to RiskPrism, the vendor security review tool%s." % (by or "An admin", (" used by %s" % org) if org else ""),
        "Open this one-time link to choose a password and add an authenticator app:", "",
        link, "",
        "The link works once and expires in %d hours. Do not forward it." % hours,
        "If you were not expecting this, ignore the message and tell your security team.",
    ])
    return subject, body
