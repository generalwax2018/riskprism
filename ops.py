"""Looking after a customer's data: backups and restore, export, delete-all, removing sample data,
and the weekly email digest. Standard library only.

Backups
  ENTROPY_BACKUP        daily (default) | off
  ENTROPY_BACKUP_DIR    where backups go (default DATA_DIR/backups). Point it at a mounted Azure Files
                        share or another disk so a lost VM does not take its backups with it.
  ENTROPY_BACKUP_KEEP   how many to keep (default 14)
  A backup is one .tar.gz of the data folder: vendor files, documents, the database (copied with
  SQLite's online backup, so it is consistent while the server runs) and the JSON stores.
  secret.key is NOT included: keep one copy of it somewhere safe and separate. Without it, restored
  authenticator apps stop working and the audit log no longer verifies.

Command line (run with the same environment as the service):
  python ops.py backup                       make a backup now
  python ops.py restore FILE [--force]       restore into the data folder (stop the service first)
  python ops.py verify-audit                 check the audit log's seals
"""
from __future__ import annotations

import csv
import io
import json
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import config
import records

STATE_PATH = config.DATA_DIR / "ops_state.json"
SKIP_IN_BACKUP = {"backups", "secret.key", "ops_state.json"}
ASIDE_PREFIX = "before-restore-"
DIGEST_HOUR = 8
BACKUP_HOUR = 2
_lock = threading.Lock()


class OpsError(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp() -> str:
    return _now().strftime("%Y%m%d-%H%M%S")


def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.environ.get(name) or default)))
    except ValueError:
        return default


def backup_settings() -> dict:
    d = (os.environ.get("ENTROPY_BACKUP_DIR") or "").strip()
    return {"mode": (os.environ.get("ENTROPY_BACKUP") or "daily").strip().lower(),
            "dir": Path(d).resolve() if d else config.DATA_DIR / "backups",
            "keep": _int_env("ENTROPY_BACKUP_KEEP", 14, 1, 365)}


def startup_problems() -> list[str]:
    b = backup_settings()
    out = []
    if b["mode"] not in ("daily", "off"):
        out.append("ENTROPY_BACKUP must be daily or off (got %r)." % b["mode"])
    return out


# ------------------------------------------------------------------ state
def _state() -> dict:
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _set_state(**kw) -> None:
    with _lock:
        st = _state()
        st.update(kw)
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        records.atomic_write(STATE_PATH, json.dumps(st, indent=1, sort_keys=True))


# ------------------------------------------------------------------ backups
def _db_files() -> list[Path]:
    return [p for p in config.DATA_DIR.glob("*.db") if p.is_file()]


def backup_now(by: str = "system") -> Path:
    """Write one backup and prune old ones. Returns the backup's path."""
    b = backup_settings()
    b["dir"].mkdir(parents=True, exist_ok=True)
    for stale in b["dir"].glob("riskprism-*.part"):  # left by an interrupted backup
        stale.unlink(missing_ok=True)
    target = b["dir"] / ("riskprism-%s.tar.gz" % _stamp())
    tmp = Path(tempfile.mkdtemp(prefix="rp-backup-"))
    try:
        # A moment-in-time copy of everything that changes, taken quickly so the app is held up as little as
        # possible: the JSON stores and vendor files are copied under the write lock, the databases through
        # SQLite's online backup. Uploaded documents never change once written, so they are read in place.
        snap = tmp / "snap"
        snap.mkdir()
        with records.LOCK:
            for p in sorted(config.DATA_DIR.iterdir()):
                if p.name in SKIP_IN_BACKUP or p.name.startswith(ASIDE_PREFIX) or p.suffix == ".db" \
                        or p.name.endswith(("-wal", "-shm", "-journal", ".part")) or p.resolve() == b["dir"].resolve() \
                        or p.resolve() == config.EVIDENCE_DIR.resolve():
                    continue
                if p.is_dir():
                    shutil.copytree(p, snap / p.name)
                elif p.is_file():
                    shutil.copy2(p, snap / p.name)
            for db in _db_files():
                src = sqlite3.connect(str(db), timeout=30)
                dst = sqlite3.connect(str(snap / db.name))
                try:
                    src.backup(dst)
                finally:
                    dst.close()
                    src.close()
        part = target.with_suffix(".part")
        with tarfile.open(part, "w:gz") as tar:
            for p in sorted(snap.iterdir()):
                tar.add(str(p), arcname=p.name)
            if config.EVIDENCE_DIR.is_dir():
                tar.add(str(config.EVIDENCE_DIR), arcname=config.EVIDENCE_DIR.name)
            info = tarfile.TarInfo("BACKUP.json")
            meta = json.dumps({"created_at": _now().isoformat(timespec="seconds"), "by": by, "data_dir": str(config.DATA_DIR),
                               "key_fingerprint": key_fingerprint(),
                               "note": "secret.key is not included; restore it separately."}, indent=1).encode()
            info.size, info.mtime = len(meta), int(time.time())
            tar.addfile(info, io.BytesIO(meta))
        os.replace(part, target)
        try:
            os.chmod(target, 0o600)
        except OSError:  # some network shares do not support permissions
            pass
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for old in list_backups()[b["keep"]:]:
        try:
            old["path"].unlink()
        except OSError:
            pass
    _set_state(last_backup=_now().isoformat(timespec="seconds"), last_backup_file=target.name, last_backup_error="",
               last_backup_attempt=_now().isoformat(timespec="seconds"))
    return target


def key_fingerprint() -> str:
    """A short value derived from the server secret, so a restore can tell whether the same key is in place.
    It cannot be turned back into the key."""
    import hashlib
    import hmac
    return hmac.new(config.SECRET, b"riskprism backup key check", hashlib.sha256).hexdigest()[:16]


def list_backups() -> list[dict]:
    d = backup_settings()["dir"]
    if not d.is_dir():
        return []
    out = [{"path": p, "name": p.name, "bytes": p.stat().st_size,
            "at": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat(timespec="seconds")}
           for p in d.glob("riskprism-*.tar.gz") if p.is_file()]
    return sorted(out, key=lambda x: x["name"], reverse=True)


def backup_file(name: str) -> Path | None:
    for b in list_backups():
        if b["name"] == name:
            return b["path"]
    return None


def _safe_members(tar: tarfile.TarFile):
    for m in tar.getmembers():
        parts = Path(m.name).parts
        if m.name.startswith(("/", "\\")) or ".." in parts or not (m.isfile() or m.isdir()):
            raise OpsError("The backup contains an unsafe path (%s). Refusing to restore it." % m.name[:80])
        yield m


def restore(path: str | Path, force: bool = False) -> dict:
    """Restore a backup into DATA_DIR. The current contents are moved aside, never deleted.
    Stop the service first: a running server would keep writing to the old files."""
    path = Path(path).resolve()
    if not path.is_file():
        raise OpsError("No such backup: %s" % path)
    data = config.DATA_DIR
    work = Path(tempfile.mkdtemp(prefix="rp-restore-"))
    try:
        return _restore(path, data, work, force)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _restore(path: Path, data: Path, work: Path, force: bool) -> dict:
    # Read and check the whole archive before touching the data folder, from a copy outside it.
    copy = work / "backup.tar.gz"
    shutil.copy2(path, copy)
    unpacked = work / "unpacked"
    try:
        with tarfile.open(copy, "r:gz") as tar:
            members = list(_safe_members(tar))
            unpacked.mkdir()
            if sys.version_info >= (3, 12):
                tar.extractall(str(unpacked), members=members, filter="data")
            else:
                tar.extractall(str(unpacked), members=members)
    except (tarfile.TarError, OSError, EOFError) as e:
        raise OpsError("That file could not be read as a RiskPrism backup (%s). Nothing was changed." % str(e)[:160])
    if not (unpacked / "BACKUP.json").is_file():
        raise OpsError("That archive is not a RiskPrism backup (no BACKUP.json). Nothing was changed.")
    present = [p for p in data.iterdir() if p.name not in ("secret.key", "backups") and not p.name.startswith(ASIDE_PREFIX)] \
        if data.is_dir() else []
    moved = None
    if present:
        if not force:
            raise OpsError("The data folder %s is not empty. Stop the service and run again with --force; "
                           "the current contents are moved into %s<date> inside it, not deleted." % (data, ASIDE_PREFIX))
        moved = data / (ASIDE_PREFIX + _stamp())  # inside the data folder: the service user can always write there
        moved.mkdir()
        for p in present:
            shutil.move(str(p), str(moved / p.name))
    data.mkdir(parents=True, exist_ok=True)
    for p in unpacked.iterdir():
        shutil.move(str(p), str(data / p.name))
    meta_p = data / "BACKUP.json"
    meta = json.loads(meta_p.read_text()) if meta_p.is_file() else {}
    meta_p.unlink(missing_ok=True)
    saved_fp = meta.get("key_fingerprint", "")
    if saved_fp and saved_fp != key_fingerprint():
        warn = ("This backup was made with a different server key than the one in place now. Put the saved secret.key from that "
                "server into %s (or set the same ENTROPY_SECRET) before starting, or authenticator codes and the audit log check "
                "will fail." % data)
    elif not saved_fp:
        warn = "This backup does not record which server key it was made with. Make sure the original secret.key is in place."
    else:
        warn = ""
    return {"restored_from": str(path), "created_at": meta.get("created_at", ""), "moved_aside": str(moved) if moved else "", "warning": warn}


# ------------------------------------------------------------------ export (the customer's own copy)
def _csv(rows: list[dict], cols: list[str]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([_safe_cell(r.get(c, "")) for c in cols])
    return buf.getvalue().encode("utf-8")


def _safe_cell(v) -> str:
    v = "" if v is None else (json.dumps(v) if isinstance(v, (dict, list)) else str(v))
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def export_zip(by: str) -> bytes:
    """Everything the customer put into RiskPrism, in open formats. No secrets: no password hashes,
    authenticator secrets, vendor link hashes or the server key."""
    import accounts
    import audit
    import findings
    import notes_store
    import risk_store
    buf = io.BytesIO()
    vendors = records.list_vendors()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("README.txt", "RiskPrism export, %s, by %s.\n\n"
                   "vendors/        one JSON file per vendor record (answers, factsheet, live access, threat model, document list)\n"
                   "documents/      every uploaded document, by vendor\n"
                   "stores/         integrations, your environment, control objectives, shadow IT, catalog, tickets (JSON)\n"
                   "*.csv           findings, risk acceptances, analyst notes, org units, people, audit log\n\n"
                   "Not included: passwords, authenticator secrets, vendor link tokens and the server key.\n" % (
                       _now().isoformat(timespec="seconds"), by))
        for rec in vendors:
            z.writestr("vendors/%s.json" % rec.get("slug", "vendor"), json.dumps(rec, indent=2, ensure_ascii=False))
        if config.EVIDENCE_DIR.is_dir():
            for p in sorted(config.EVIDENCE_DIR.rglob("*")):
                if p.is_file():
                    z.write(str(p), "documents/" + p.relative_to(config.EVIDENCE_DIR).as_posix())
        for name in ("integrations.json", "environment.json", "objectives.json", "shadow.json", "catalog.json", "tickets.json",
                     "findings_state.json", "policy.json"):
            p = config.DATA_DIR / name
            if p.is_file():
                z.write(str(p), "stores/" + name)
        items = findings.collect()
        z.writestr("findings.csv", findings.csv_text(items))
        acc = risk_store.acceptances()
        z.writestr("risk_acceptances.csv", _csv(acc, ["id", "vendor_name", "vendor_slug", "detection_code", "detection_text", "risk_tier",
                                                      "accepter", "accepter_level", "justification", "compensating_controls", "signed_at",
                                                      "expires_on", "status", "org_unit_id", "risk_snapshot"]))
        notes = [n for rec in vendors for n in notes_store.for_vendor(rec.get("slug", ""))]
        z.writestr("analyst_notes.csv", _csv(notes, sorted({k for n in notes for k in n}) or ["id"]))
        z.writestr("org_units.csv", _csv(risk_store.units(include_merged=True), ["id", "name", "parent_id", "accountable_owner",
                                                                                  "needs_review", "merged_into", "created_at"]))
        z.writestr("approvers.csv", _csv(risk_store.approvers(), ["principal", "level", "set_by", "set_at"]))
        if config.AUTH_MODE == "accounts":
            z.writestr("people.csv", _csv(accounts.list_users(), ["email", "name", "status", "is_admin", "view_only", "created_at", "last_login"]))
        z.writestr("audit_log.csv", audit.csv_text(limit=10_000_000))
        v = audit.verify()
        z.writestr("audit_log_check.txt", "Seal check at export: %s\nEntries: %d\nHead seal: %s\n%s\n" % (
            "intact" if v["ok"] else "BROKEN", v["count"], audit.head(), v["reason"]))
    return buf.getvalue()


# ------------------------------------------------------------------ sample data
SAMPLE_SHADOW_FILES = ("entra-enterprise-apps.csv", "proxy-top-domains.csv")


def _is_sample_vendor(rec: dict, demo: dict, seed_slugs: set) -> bool:
    """Only records the sample loaders made. A vendor the customer added with the same name is theirs.
    Records from before the loaders marked their output count only if untouched since: the sample's own
    description, and no documents, answers or live access of the customer's."""
    slug = rec.get("slug", "")
    if slug in seed_slugs and rec.get("source") == "seed":
        return True
    if slug not in demo:
        return False
    if rec.get("source") == "demo":
        return True
    return (not rec.get("source") and rec.get("business") == demo[slug].get("business")
            and not rec.get("evidence_files") and not rec.get("submissions") and not rec.get("created_by"))


def _sample_system_ids() -> set:
    import environment
    import integrations_demo
    return {s["id"] for s in environment.setup_systems(integrations_demo.ENVIRONMENT)[1]}


def sample_present() -> dict:
    import environment
    import integrations
    import integrations_demo
    import seed
    from records import slugify
    demo = {v["slug"]: v for v in integrations_demo.VENDORS}
    seed_slugs = {slugify(s["vendor"]) for s in seed.SAMPLES}
    vendors = [r for r in records.list_vendors() if _is_sample_vendor(r, demo, seed_slugs)]
    ints = [r for r in integrations.all_rows() if r["id"].startswith("int-demo-")]
    shadow_p = config.DATA_DIR / "shadow.json"
    shadow_sample = shadow_p.is_file() and any(f in shadow_p.read_text(encoding="utf-8") for f in SAMPLE_SHADOW_FILES)
    sample_ids = _sample_system_ids()
    systems = [s["id"] for s in environment.systems() if s["id"] in sample_ids and s.get("source") == "setup"]
    profile_sample = environment.profile().get("org_name") == integrations_demo.ENVIRONMENT["org_name"]
    demo_rows = sum(1 for r in records.list_vendors() for a in (r.get("live_access") or []) if a.get("source") == "demo")
    return {"vendors": [r["slug"] for r in vendors], "integrations": len(ints), "shadow": bool(shadow_sample),
            "systems": systems, "environment": bool(systems) or profile_sample, "profile": profile_sample,
            "demo_access_rows": demo_rows, "any": bool(vendors or ints or shadow_sample or systems or profile_sample or demo_rows)}


def remove_sample_data(by: str) -> dict:
    import environment
    import integrations
    import shadow
    found = sample_present()
    for slug in found["vendors"]:
        records.delete_vendor(slug)
        shutil.rmtree(config.EVIDENCE_DIR / slug, ignore_errors=True)
    if found["integrations"]:
        with integrations.LOCK:
            integrations._save([r for r in integrations.all_rows() if not r["id"].startswith("int-demo-")])
    if found["shadow"]:
        with shadow.LOCK:
            data = shadow._load()
            if any(f in data.get("apps_source", "") for f in SAMPLE_SHADOW_FILES):
                data["apps"], data["apps_source"] = [], ""
            if any(f in data.get("domains_source", "") for f in SAMPLE_SHADOW_FILES):
                data["domains"], data["domains_source"] = [], ""
            shadow._save(data)
            still = {it["id"] for it in shadow.queue(include_decided=True)["all"]}
            data = shadow._load()
            data["decisions"] = {k: v for k, v in data["decisions"].items() if k in still}  # only the sample items' decisions go
            shadow._save(data)
    if found["systems"]:
        environment.remove_systems(set(found["systems"]))
    if found["profile"]:
        environment.reset_profile()
    if found["demo_access_rows"]:
        for rec in records.list_vendors():
            rows = rec.get("live_access") or []
            keep = [a for a in rows if a.get("source") != "demo"]
            if len(keep) != len(rows):
                records.update_vendor(rec["slug"], lambda r, k=keep: {**r, "live_access": k})
    return found


# ------------------------------------------------------------------ delete everything
DELETE_PHRASE = "DELETE ALL DATA"


def delete_all(by: str, ip: str, include_backups: bool) -> dict:
    """End of a pilot: remove every vendor, document, store, note, acceptance and audit entry.
    People's accounts and the server key stay so the admin can still sign in; the audit log restarts
    with one entry recording the wipe."""
    import audit
    import environment
    out = {"vendors": len(records.list_vendors())}
    with records.LOCK:
        for folder in (config.VDIR, records.QDIR, records.ADIR, config.EVIDENCE_DIR):
            shutil.rmtree(folder, ignore_errors=True)
        for name in ("integrations.json", "environment.json", "objectives.json", "shadow.json", "catalog.json", "tickets.json",
                     "findings_state.json", "tokens.json", "ops_state.json", "audit.log.imported", "audit.log", "policy.json"):
            (config.DATA_DIR / name).unlink(missing_ok=True)
        for aside in config.DATA_DIR.glob(ASIDE_PREFIX + "*"):  # earlier copies kept by a restore
            shutil.rmtree(aside, ignore_errors=True)
        environment._CACHE.update(key=None, data=None)
        con = sqlite3.connect(str(config.RISK_DB_PATH), timeout=30)
        try:
            with con:
                for t in ("acceptances", "approvers", "org_aliases", "org_units", "vendor_notes"):
                    con.execute("DROP TABLE IF EXISTS %s" % t)
        finally:
            con.close()
        import notes_store
        import risk_store
        risk_store._ready.clear()
        notes_store._ready.clear()
    if include_backups:
        for b in list_backups():
            b["path"].unlink(missing_ok=True)
    out["azure"] = _delete_azure_evidence()
    audit.wipe(by, ip)
    import memo
    memo.bump()
    out["backups_removed"] = include_backups
    return out


def _delete_azure_evidence() -> str:
    """Documents copied to Azure Blob storage. '' when Azure is not in use, else what happened."""
    import evidence_store
    if not evidence_store.azure_configured():
        return ""
    client = evidence_store._client()
    if client is None:
        return "Azure Blob is configured but could not be reached: delete the '%s' container's contents yourself." % evidence_store.CONTAINER
    try:
        container = client.get_container_client(evidence_store.CONTAINER)
        n = 0
        for blob in container.list_blobs():
            container.delete_blob(blob.name)
            n += 1
        return "%d document copies deleted from Azure Blob storage." % n
    except Exception as e:  # the SDK raises many types; report, never hide
        return "Deleting the Azure Blob copies failed (%s): delete the '%s' container's contents yourself." % (str(e)[:120], evidence_store.CONTAINER)


# ------------------------------------------------------------------ weekly digest
def digest_recipients() -> list[str]:
    import accounts
    import mailer
    out = list(mailer.settings()["digest_to"])
    if config.AUTH_MODE == "accounts":
        out += [u["email"] for u in accounts.list_users() if u["is_admin"] and u["status"] == "active"]
    return sorted({a.lower() for a in out if mailer.valid_address(a)})


def digest_text(base_url: str) -> tuple[str, str]:
    import executive
    s = executive.summary()
    f = s["findings"]
    lines = ["RiskPrism weekly summary for %s, %s." % (s["org"], s["date"]), "",
             executive._headline(s), executive._trend_line(s), "",
             "Findings open: %d (high %d, overdue %d, with a ticket %d)." % (f["total"], f["by_severity"]["high"], f["overdue"], f["ticketed"]),
             "Risk acceptances expiring in 30 days: %d." % len(s["expiring"]),
             "Shadow IT items needing a decision: %d." % s["shadow"], "", "What needs a decision:"]
    for d in s["decisions"][:10]:
        lines.append("- [%s] %s (%s; owner %s)" % (d["sev"].upper(), d["what"][:220], d["area"], d["who"]))
    if not s["decisions"]:
        lines.append("- Nothing needs a decision.")
    lines += ["", "Open the executive summary: %s/executive" % base_url.rstrip("/"),
              "You get this because you are a RiskPrism admin or listed in ENTROPY_DIGEST_TO."]
    return "RiskPrism weekly: %d findings open, %d overdue" % (f["total"], f["overdue"]), "\n".join(lines)


def send_digest(base_url: str, by: str = "system") -> int:
    import audit
    import mailer
    to = digest_recipients()
    if not to:
        raise mailer.MailError("No one to send the digest to: no active admins with an email, and ENTROPY_DIGEST_TO is empty.")
    subject, body = digest_text(base_url)
    mailer.send(to, subject, body)
    _set_state(last_digest=_now().isoformat(timespec="seconds"))
    audit.log(by, "digest_emailed", "", "to %d recipient%s" % (len(to), "" if len(to) == 1 else "s"), "")
    return len(to)


# ------------------------------------------------------------------ scheduler
def _due_backup(now_local: datetime) -> bool:
    if backup_settings()["mode"] != "daily" or now_local.hour < BACKUP_HOUR:
        return False
    st = _state()
    attempt = st.get("last_backup_attempt", "")
    if attempt and (now_local - datetime.fromisoformat(attempt).astimezone()) < timedelta(hours=2):
        return False  # after a failure, wait before trying again
    last = st.get("last_backup", "")
    return not last or datetime.fromisoformat(last).astimezone().date() < now_local.date()


def _due_digest(now_local: datetime) -> bool:
    import mailer
    if not mailer.configured() or mailer.settings()["digest"] != "weekly":
        return False
    if now_local.weekday() != 0 or now_local.hour < DIGEST_HOUR:  # Monday morning
        return False
    last = _state().get("last_digest", "")
    return not last or (now_local - datetime.fromisoformat(last).astimezone()) > timedelta(days=6)


def tick(base_url: str, now_local: datetime | None = None) -> list[str]:
    """One pass of the scheduler. Returns what it did. Errors are recorded, never raised."""
    import audit
    import mailer
    import memo
    now_local = now_local or datetime.now().astimezone()
    done = []
    with memo.request():
        if _due_backup(now_local):
            try:
                p = backup_now()
                audit.log("system", "backup_made", "", p.name, "")
                done.append("backup")
            except (OSError, sqlite3.Error, tarfile.TarError) as e:
                _set_state(last_backup_error="%s: %s" % (_now().isoformat(timespec="seconds"), str(e)[:200]),
                           last_backup_attempt=_now().isoformat(timespec="seconds"))
                audit.log("system", "backup_failed", "", str(e)[:200], "")
                sys.stderr.write("Backup failed: %s\n" % e)
        if _due_digest(now_local):
            try:
                send_digest(base_url)
                done.append("digest")
            except mailer.MailError as e:
                _set_state(last_digest=_now().isoformat(timespec="seconds"), last_digest_error=str(e)[:200])
                audit.log("system", "digest_failed", "", str(e)[:200], "")
                sys.stderr.write("Weekly digest not sent: %s\n" % e)
    return done


def start_scheduler(base_url: str, every_seconds: int = 900) -> threading.Thread:
    def loop():
        while True:
            try:
                tick(base_url)
            except Exception as e:  # the scheduler must never take the server down
                sys.stderr.write("Scheduler error: %r\n" % e)
            time.sleep(every_seconds)
    t = threading.Thread(target=loop, name="riskprism-scheduler", daemon=True)
    t.start()
    return t


def status() -> dict:
    import mailer
    st = _state()
    return {"backup": backup_settings(), "backups": list_backups(), "last_backup": st.get("last_backup", ""),
            "last_backup_error": st.get("last_backup_error", ""), "email": mailer.configured(),
            "digest": mailer.settings()["digest"] if mailer.configured() else "off", "last_digest": st.get("last_digest", ""),
            "last_digest_error": st.get("last_digest_error", ""), "digest_to": digest_recipients() if mailer.configured() else []}


# ------------------------------------------------------------------ command line
def _cli(argv: list[str]) -> int:
    import audit
    usage = "usage: python ops.py backup | restore FILE [--force] | verify-audit"
    if not argv:
        print(usage)
        return 2
    try:
        if argv[0] == "backup":
            p = backup_now(by="command line")
            print("Backup written:", p)
            print("Remember: secret.key is not in the backup. Keep a separate copy of", config.SECRET_PATH)
            return 0
        if argv[0] == "restore" and len(argv) >= 2:
            r = restore(argv[1], force="--force" in argv)
            print("Restored from", r["restored_from"], "(made %s)" % (r["created_at"] or "unknown"))
            if r["moved_aside"]:
                print("Previous contents moved to", r["moved_aside"])
            if r["warning"]:
                print("Warning:", r["warning"])
            print("Start the service again: sudo systemctl start entropy")
            return 0
        if argv[0] == "verify-audit":
            v = audit.verify()
            print("Audit log %s: %d entries, head seal %s" % ("intact" if v["ok"] else "BROKEN", v["count"], v["head"]))
            if not v["ok"]:
                print(v["reason"])
            return 0 if v["ok"] else 1
    except OpsError as e:
        print("Error:", e)
        return 1
    print(usage)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
