"""Backups, restore, export, delete-all, sample data, the scheduler, and email (against a local fake SMTP server)."""
from __future__ import annotations

import io
import os
import socketserver
import sys
import tarfile
import tempfile
import threading
import unittest
import zipfile
from datetime import datetime
from email import message_from_bytes
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_app import ServerCase  # noqa: E402  (sets up the throwaway data folder first)

import accounts  # noqa: E402
import audit  # noqa: E402
import config  # noqa: E402
import environment as env  # noqa: E402
import integrations as ig  # noqa: E402
import integrations_demo  # noqa: E402
import mailer  # noqa: E402
import notes_store  # noqa: E402
import ops  # noqa: E402
import records  # noqa: E402

DEMO = tuple(v["slug"] for v in integrations_demo.VENDORS)


class FakeSMTP(socketserver.StreamRequestHandler):
    """Just enough SMTP for smtplib: EHLO, MAIL, RCPT, DATA, QUIT. Keeps every message."""
    messages: list = []
    refuse_rcpt = False

    def w(self, line):
        self.wfile.write((line + "\r\n").encode())

    def handle(self):
        self.w("220 fake ESMTP")
        rcpt, mail_from = [], ""
        while True:
            line = self.rfile.readline().decode(errors="replace").strip()
            if not line:
                return
            cmd = line[:4].upper()
            if cmd in ("EHLO", "HELO"):
                self.w("250-fake")
                self.w("250 8BITMIME")
            elif cmd == "MAIL":
                mail_from = line
                self.w("250 ok")
            elif cmd == "RCPT":
                if FakeSMTP.refuse_rcpt:
                    self.w("550 no such user")
                else:
                    rcpt.append(line)
                    self.w("250 ok")
            elif cmd == "DATA":
                self.w("354 go")
                data = b""
                while True:
                    chunk = self.rfile.readline()
                    if chunk in (b".\r\n", b".\n", b""):
                        break
                    data += chunk
                FakeSMTP.messages.append({"from": mail_from, "rcpt": rcpt, "msg": message_from_bytes(data)})
                self.w("250 queued")
            elif cmd == "QUIT":
                self.w("221 bye")
                return
            else:
                self.w("250 ok")


class MailCase(ServerCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.smtp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), FakeSMTP)
        threading.Thread(target=cls.smtp.serve_forever, daemon=True).start()
        cls.mail_env = {"ENTROPY_SMTP_HOST": "127.0.0.1", "ENTROPY_SMTP_PORT": str(cls.smtp.server_address[1]),
                        "ENTROPY_SMTP_TLS": "none", "ENTROPY_SMTP_FROM": "Pilot Security <security@pilot.example>"}

    @classmethod
    def tearDownClass(cls):
        cls.smtp.shutdown()
        cls.smtp.server_close()
        super().tearDownClass()

    def setUp(self):
        FakeSMTP.messages, FakeSMTP.refuse_rcpt = [], False


class MailerTests(MailCase):
    def test_send_and_refuse(self):
        with mock.patch.dict(os.environ, self.mail_env):
            self.assertTrue(mailer.configured())
            self.assertEqual(mailer.send("ana@vendor.example", "Hi\r\nBcc: evil@x.example", "Body", reply_to="sec@pilot.example"), 1)
            m = FakeSMTP.messages[0]["msg"]
            self.assertEqual(m["Subject"], "Hi Bcc: evil@x.example")
            self.assertIsNone(m["Bcc"])
            self.assertEqual(m["Reply-To"], "sec@pilot.example")
            self.assertEqual(m["Auto-Submitted"], "auto-generated")
            with self.assertRaises(mailer.MailError):
                mailer.send("not an address", "x", "y")
            FakeSMTP.refuse_rcpt = True
            with self.assertRaises(mailer.MailError):
                mailer.send("ana@vendor.example", "x", "y")

    def test_startup_rules(self):
        with mock.patch.dict(os.environ, {"ENTROPY_SMTP_HOST": "smtp.example.com", "ENTROPY_SMTP_TLS": "none", "ENTROPY_SMTP_FROM": "x"}):
            probs = mailer.startup_problems()
            self.assertTrue(any("ENTROPY_SMTP_FROM" in p for p in probs))
            self.assertTrue(any("unencrypted" in p for p in probs))
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ENTROPY_SMTP_HOST", None)
            self.assertEqual(mailer.startup_problems(), [])
            self.assertFalse(mailer.configured())

    def test_vendor_sees_who_is_asking_and_link_can_be_emailed(self):
        env.apply_setup({"org_name": "Pilot Health", "security_contact": "security@pilot.example"}, "test")
        tok = self.make_vendor("Mail Vendor Co", contact="Jo Smith jo@mailvendor.example")
        _s, form, _h = self.c.get("/q/" + tok)
        self.assertIn("Requested by Pilot Health&#x27;s security team", form)
        self.assertIn("Pilot Health</strong> uses RiskPrism", form)
        self.assertIn("security@pilot.example", form)
        _s, share, _h = self.c.get("/share/" + tok)
        self.assertIn("Pilot Health is reviewing the security", share.replace("&#x27;", "'"))
        self.assertIn("Email is not set up", share)
        with mock.patch.dict(os.environ, self.mail_env):
            _s, share, _h = self.c.get("/share/" + tok)
            self.assertIn('value="jo@mailvendor.example"', share)
            s, page, _h = self.c.post("/share/send", {"token": tok, "to": "jo@mailvendor.example"}, page="/share/" + tok)
            self.assertEqual(s, 200, page[:400])
            self.assertIn("Sent to jo@mailvendor.example", page)
            m = FakeSMTP.messages[-1]["msg"]
            body = m.get_payload(decode=True).decode()
            self.assertIn("/q/" + tok, body)
            self.assertIn("Pilot Health", m["Subject"])
            self.assertEqual(m["Reply-To"], "security@pilot.example")
            s, _p, _h = self.c.post("/share/send", {"token": "nope", "to": "jo@mailvendor.example"}, page="/share/" + tok)
            self.assertEqual(s, 404)
        self.assertTrue(any(e["action"] == "vendor_link_emailed" for e in audit.recent(20)))
        _s, done, _h = self.c.req("POST", "/q/" + tok, "hosting=Azure", {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertIn("Pilot Health&#x27;s security team", done)

    def test_digest_text_and_recipients(self):
        with mock.patch.dict(os.environ, {**self.mail_env, "ENTROPY_DIGEST_TO": "ciso@pilot.example, bad address"}):
            self.assertEqual(ops.digest_recipients(), ["ciso@pilot.example"])
            subject, body = ops.digest_text("https://riskprism.example")
            self.assertIn("findings open", subject)
            self.assertIn("https://riskprism.example/executive", body)
            self.assertEqual(ops.send_digest("https://riskprism.example"), 1)
            self.assertEqual(FakeSMTP.messages[-1]["msg"]["To"], "ciso@pilot.example")


class SchedulerTests(unittest.TestCase):
    def test_backup_is_due_once_a_night_after_two(self):
        with mock.patch.object(ops, "_state", return_value={}):
            self.assertFalse(ops._due_backup(datetime(2026, 11, 10, 1, 30).astimezone()))
            self.assertTrue(ops._due_backup(datetime(2026, 11, 10, 2, 5).astimezone()))
        with mock.patch.object(ops, "_state", return_value={"last_backup": datetime(2026, 11, 10, 2, 5).astimezone().isoformat()}):
            self.assertFalse(ops._due_backup(datetime(2026, 11, 10, 23, 0).astimezone()))
            self.assertTrue(ops._due_backup(datetime(2026, 11, 11, 2, 1).astimezone()))
        with mock.patch.dict(os.environ, {"ENTROPY_BACKUP": "off"}), mock.patch.object(ops, "_state", return_value={}):
            self.assertFalse(ops._due_backup(datetime(2026, 11, 11, 3, 0).astimezone()))

    def test_digest_is_due_monday_morning_with_email_on(self):
        on = {"ENTROPY_SMTP_HOST": "127.0.0.1", "ENTROPY_SMTP_FROM": "a@b.example"}
        with mock.patch.dict(os.environ, on), mock.patch.object(ops, "_state", return_value={}):
            self.assertTrue(ops._due_digest(datetime(2026, 11, 9, 8, 30).astimezone()))   # Monday
            self.assertFalse(ops._due_digest(datetime(2026, 11, 10, 8, 30).astimezone()))  # Tuesday
            self.assertFalse(ops._due_digest(datetime(2026, 11, 9, 7, 30).astimezone()))
        with mock.patch.dict(os.environ, on), mock.patch.object(ops, "_state", return_value={"last_digest": datetime(2026, 11, 9, 8, 0).astimezone().isoformat()}):
            self.assertFalse(ops._due_digest(datetime(2026, 11, 9, 9, 30).astimezone()))
            self.assertTrue(ops._due_digest(datetime(2026, 11, 16, 8, 1).astimezone()))


class OpsTests(ServerCase):
    def setUp(self):
        integrations_demo.run()

    def tearDown(self):
        for slug in DEMO + ("Own_Vendor", "Delete_Me"):
            records.delete_vendor(slug)

    def test_backup_then_restore_round_trip(self):
        records.save_vendor({"vendor": "Own Vendor", "slug": "Own_Vendor", "stage": "active"})
        notes_store.add("Own_Vendor", "general", "Backed up note", "test")
        p = ops.backup_now(by="test")
        self.assertTrue(p.name.startswith("riskprism-"))
        with tarfile.open(p) as t:
            names = t.getnames()
        self.assertIn("riskprism.db", names)
        self.assertIn("vendors/Own_Vendor.json", names)
        self.assertNotIn("secret.key", names)
        self.assertFalse(any(n.startswith("backups") for n in names))
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "data"
            with mock.patch.object(config, "DATA_DIR", target):
                r = ops.restore(p)
            self.assertTrue((target / "vendors" / "Own_Vendor.json").is_file())
            self.assertEqual(r["warning"], "")  # same server key in place
            import sqlite3
            con = sqlite3.connect(str(target / "riskprism.db"))
            self.assertEqual(con.execute("SELECT body FROM vendor_notes WHERE vendor_slug = 'Own_Vendor'").fetchone()[0], "Backed up note")
            con.close()
            with mock.patch.object(config, "DATA_DIR", target):
                with self.assertRaises(ops.OpsError):
                    ops.restore(p)
                with mock.patch.object(config, "SECRET", b"a different server"):
                    r = ops.restore(p, force=True)
            self.assertTrue(Path(r["moved_aside"]).is_dir())
            self.assertEqual(Path(r["moved_aside"]).parent, target)
            self.assertIn("different server key", r["warning"])
            with mock.patch.object(config, "DATA_DIR", target):
                again = ops.backup_now()
            with tarfile.open(again) as t:
                self.assertFalse(any(n.startswith(ops.ASIDE_PREFIX) for n in t.getnames()))

    def test_restore_refuses_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "riskprism-bad.tar.gz"
            with tarfile.open(bad, "w:gz") as t:
                info = tarfile.TarInfo("../escape.txt")
                info.size = 1
                t.addfile(info, io.BytesIO(b"x"))
            with mock.patch.object(config, "DATA_DIR", Path(d) / "data"):
                with self.assertRaises(ops.OpsError):
                    ops.restore(bad)
            self.assertFalse((Path(d) / "escape.txt").exists())

    def test_retention_keeps_the_newest(self):
        with mock.patch.dict(os.environ, {"ENTROPY_BACKUP_KEEP": "2"}):
            for i in range(3):
                with mock.patch.object(ops, "_stamp", return_value="20261111-00000%d" % i):
                    ops.backup_now()
            self.assertEqual([b["name"] for b in ops.list_backups()], ["riskprism-20261111-000002.tar.gz", "riskprism-20261111-000001.tar.gz"])

    def test_export_has_the_data_and_no_secrets(self):
        if config.AUTH_MODE == "none":
            pass
        data = ops.export_zip("test")
        z = zipfile.ZipFile(io.BytesIO(data))
        names = set(z.namelist())
        for n in ("README.txt", "findings.csv", "risk_acceptances.csv", "analyst_notes.csv", "audit_log.csv", "audit_log_check.txt",
                  "stores/integrations.json", "vendors/ServiceNow.json"):
            self.assertIn(n, names)
        blob = b"".join(z.read(n) for n in names)
        self.assertNotIn(config.SECRET, blob)
        self.assertNotIn(b"scrypt$", blob)
        self.assertNotIn(b"enc1:", blob)
        self.assertFalse(any("tokens" in n or "secret" in n for n in names))
        s, body, h = self.c.get("/admin/data/export.zip")
        self.assertEqual((s, h["content-type"]), (200, "application/zip"))

    def test_remove_sample_data_keeps_real_vendors(self):
        records.save_vendor({"vendor": "Own Vendor", "slug": "Own_Vendor", "stage": "active"})
        found = ops.sample_present()
        self.assertTrue(found["any"])
        s, page, _h = self.c.post("/admin/data/sample", {}, page="/admin/data")
        self.assertEqual(s, 200)
        self.assertIn("Sample data removed", page)
        for slug in DEMO:
            self.assertIsNone(records.load_vendor(slug))
        self.assertIsNotNone(records.load_vendor("Own_Vendor"))
        self.assertFalse([r for r in ig.all_rows() if r["id"].startswith("int-demo-")])
        self.assertFalse(ops.sample_present()["any"])

    def test_delete_all_needs_the_phrase_and_keeps_people(self):
        records.save_vendor({"vendor": "Delete Me", "slug": "Delete_Me", "stage": "active"})
        notes_store.add("Delete_Me", "general", "to be wiped", "test")
        if not accounts.by_email("keeper@example.com"):
            accounts.invite("keeper@example.com", "Keeper", by="test")
        s, page, _h = self.c.post("/admin/data/delete", {"confirm": "delete all data"}, page="/admin/data")
        self.assertEqual(s, 400)
        self.assertIsNotNone(records.load_vendor("Delete_Me"))
        ops.backup_now()
        s, page, _h = self.c.post("/admin/data/delete", {"confirm": ops.DELETE_PHRASE, "backups": "1"}, page="/admin/data")
        self.assertEqual(s, 200, page[:300])
        self.assertEqual(records.list_vendors(), [])
        self.assertEqual(notes_store.for_vendor("Delete_Me"), [])
        self.assertEqual(ops.list_backups(), [])
        self.assertIsNotNone(accounts.by_email("keeper@example.com"))
        self.assertEqual(audit.count(), 1)
        self.assertEqual(audit.recent(1)[0]["action"], "audit_log_wiped")
        self.assertTrue(audit.verify()["ok"])
        self.assertEqual(self.c.get("/")[0], 200)
        self.make_vendor("After Wipe Co")  # the app keeps working
        self.assertEqual(self.c.get("/vendor/After_Wipe_Co")[0], 200)
        records.delete_vendor("After_Wipe_Co")

    def test_admin_page_and_audit_check(self):
        s, page, _h = self.c.get("/admin/data")
        self.assertEqual(s, 200)
        for text in ("Backups", "Audit log", "Export everything", "Sample data", "Delete all data", "Latest seal"):
            self.assertIn(text, page)
        s, page, _h = self.c.post("/admin/data/verify", {}, page="/admin/data")
        self.assertIn("Intact", page)
        s, page, _h = self.c.post("/admin/data/backup", {}, page="/admin/data")
        self.assertIn("Backup written", page)
        name = ops.list_backups()[0]["name"]
        s, body, h = self.c.get("/admin/data/backup/" + name)
        self.assertEqual((s, h["content-type"]), (200, "application/gzip"))
        self.assertEqual(self.c.get("/admin/data/backup/..%2Fsecret.key")[0], 404)
        s, csvtext, _h = self.c.get("/admin/data/audit.csv")
        self.assertTrue(csvtext.startswith("id,at,actor"))


if __name__ == "__main__":
    unittest.main()
