"""View-only accounts, and the sealed audit log."""
from __future__ import annotations

import json
import sqlite3
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_app import Client, ServerCase  # noqa: E402  (sets up the throwaway data folder first)
from test_accounts import FORM, PW, _csrf, _secret  # noqa: E402

import accounts  # noqa: E402
import audit  # noqa: E402
import config  # noqa: E402
import serve  # noqa: E402
from records import load_vendor, save_vendor  # noqa: E402


class ViewOnlyTests(unittest.TestCase):
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
        serve.auth._failures.clear()

    def account(self, email, **kw):
        tok = accounts.invite(email, "Role Test", by="test", **kw)
        c = Client(self.port)
        _s, page, _h = c.get("/setup/" + tok)
        body = {"_csrf": _csrf(page), "name": "Role Test", "password": PW, "password2": PW, "code": accounts.totp_now(_secret(page))}
        s, _b, _h = c.req("POST", "/setup/" + tok, urlencode(body), FORM)
        self.assertEqual(s, 303)
        return c

    def test_viewer_reads_everything_and_changes_nothing(self):
        save_vendor({"vendor": "Viewer Co", "slug": "Viewer_Co", "stage": "active"})
        c = self.account("viewer@example.com", viewer=True)
        for path in ("/", "/findings", "/executive", "/vendor/Viewer_Co", "/findings.csv", "/executive/board.pdf",
                     "/threat/Viewer_Co/export.pdf", "/integrations", "/controls", "/documents"):
            self.assertEqual(c.get(path)[0], 200, path)
        _s, page, _h = c.get("/vendor/Viewer_Co")
        self.assertIn('<body class="viewer">', page)
        self.assertIn("View-only account", page)
        before = json.dumps(load_vendor("Viewer_Co"), sort_keys=True)
        for path, fields in (("/intake", {"vendor": "Should Not Exist"}), ("/note", {"slug": "Viewer_Co", "kind": "general", "body": "x"}),
                             ("/offboard", {"slug": "Viewer_Co"}), ("/purge", {"slug": "Viewer_Co", "confirm": "Viewer Co"}),
                             ("/link", {"slug": "Viewer_Co", "kind": "onboard"}), ("/integrations/seed", {}),
                             ("/controls/attest", {"slug": "Viewer_Co", "oid": "CO-01", "status": "met", "note": "x"}),
                             ("/findings/ticket", {"key": "F-0000000000", "ref": "INC1"}), ("/shadow/decide", {"id": "x", "state": "known", "note": "x"})):
            s, body, _h = c.post(path, fields)
            self.assertEqual(s, 403, path)
            self.assertIn("view-only", body)
        self.assertEqual(json.dumps(load_vendor("Viewer_Co"), sort_keys=True), before)
        self.assertIsNone(load_vendor("Should_Not_Exist"))
        self.assertEqual(c.get("/people")[0], 403)
        self.assertTrue(any(e["action"] == "view_only_refused" for e in audit.recent(50)))

    def test_viewer_can_still_sign_out(self):
        c = self.account("viewer2@example.com", viewer=True)
        self.assertEqual(c.post("/logout", {})[0], 303)

    def test_admin_and_view_only_are_exclusive_and_switchable(self):
        with self.assertRaises(accounts.AccountError):
            accounts.invite("both@example.com", admin=True, viewer=True)
        admin = self.account("roleadmin@example.com", admin=True)
        self.account("switch@example.com")
        uid = accounts.by_email("switch@example.com")["id"]
        s, page, _h = admin.post("/people", {"action": "viewer", "uid": uid}, page="/people")
        self.assertEqual(s, 200)
        self.assertTrue(accounts.by_email("switch@example.com")["view_only"])
        s, page, _h = admin.post("/people", {"action": "admin", "uid": uid}, page="/people")
        self.assertEqual(s, 400)
        self.assertIn("view-only", page)
        admin.post("/people", {"action": "unviewer", "uid": uid}, page="/people")
        self.assertFalse(accounts.by_email("switch@example.com")["view_only"])
        s, _p, _h = admin.post("/people", {"action": "invite", "email": "newviewer@example.com", "role": "viewer"}, page="/people")
        self.assertEqual(s, 200)
        self.assertTrue(accounts.by_email("newviewer@example.com")["view_only"])

    def test_env_list_makes_an_identity_view_only(self):
        with mock.patch.object(config, "VIEWERS", {"auditor@example.com"}), mock.patch.object(config, "ADMINS", {"auditor@example.com"}):
            self.assertTrue(serve.is_viewer("Auditor@example.com"))
            self.assertFalse(serve.is_admin("auditor@example.com"))


class NoLoginIsNeverViewOnly(ServerCase):
    def test_local_run_is_unaffected(self):
        self.assertFalse(serve.is_viewer("local-analyst"))
        _s, page, _h = self.c.get("/")
        self.assertNotIn('class="viewer"', page)


class AuditTests(unittest.TestCase):
    def test_entries_are_chained_and_verify(self):
        audit.log("ana@example.com", "test_event", "Audit_Chain", "first")
        audit.log("ana@example.com", "test_event", "Audit_Chain", "second")
        v = audit.verify()
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["head"], audit.head())
        rows = audit.for_slug("Audit_Chain")
        self.assertEqual([r["detail"] for r in rows[:2]], ["second", "first"])
        self.assertIn("seal", audit.csv_text().splitlines()[0])

    def test_database_refuses_edits_and_deletes(self):
        audit.log("ana@example.com", "test_event", "Audit_Frozen")
        con = sqlite3.connect(str(config.RISK_DB_PATH))
        try:
            for sql in ("UPDATE audit SET actor = 'mallory'", "DELETE FROM audit"):
                with self.assertRaises(sqlite3.DatabaseError):
                    con.execute(sql)
        finally:
            con.close()

    def test_tampering_is_detected(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "riskprism.db"
            with mock.patch.object(config, "RISK_DB_PATH", db), mock.patch.object(audit, "PATH", Path(d) / "audit.log"):
                for i in range(5):
                    audit.log("ana@example.com", "evt", "V", "n%d" % i)
                self.assertTrue(audit.verify()["ok"])
                con = sqlite3.connect(str(db))
                con.executescript("DROP TRIGGER audit_no_update; UPDATE audit SET detail = 'changed' WHERE id = 3;")
                con.commit()
                v = audit.verify()
                self.assertEqual((v["ok"], v["first_bad"]), (False, 3))
                con.executescript("UPDATE audit SET detail = 'n2' WHERE id = 3; DROP TRIGGER audit_no_delete; DELETE FROM audit WHERE id = 2;")
                con.commit()
                con.close()
                v = audit.verify()
                self.assertEqual((v["ok"], v["first_bad"]), (False, 3))
                self.assertIn("removed", v["reason"])
                with mock.patch.object(config, "SECRET", b"a different server secret"):
                    self.assertFalse(audit.verify()["ok"])
            audit._ready.discard(str(db))
            self.assertFalse(os.path.exists(str(db) + "-nope"))

    def test_older_text_log_is_imported_once_in_order(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            db, legacy = Path(d) / "riskprism.db", Path(d) / "audit.log"
            lines = [{"at": "2026-10-0%dT00:00:00+00:00" % i, "actor": "ana", "action": "old_%d" % i, "slug": "Old_Co", "detail": "", "ip": ""}
                     for i in range(1, 4)]
            legacy.write_text("\n".join(json.dumps(x) for x in lines) + "\nnot json\n", encoding="utf-8")
            with mock.patch.object(config, "RISK_DB_PATH", db), mock.patch.object(audit, "PATH", legacy):
                rows = audit.for_slug("Old_Co")
                self.assertEqual([r["action"] for r in rows], ["old_3", "old_2", "old_1"])
                self.assertEqual(audit.recent(1)[0]["action"], "audit_log_imported")
                self.assertFalse(legacy.exists())
                self.assertTrue((Path(d) / "audit.log.imported").exists())
                self.assertTrue(audit.verify()["ok"])
                self.assertEqual(audit.count(), 4)
            audit._ready.discard(str(db))


if __name__ == "__main__":
    unittest.main()
