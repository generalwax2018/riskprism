"""Regression tests for problems found in review: sample removal, restore safety, delete-all, the audit
chain across processes, email headers, backup retries."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_app import ServerCase  # noqa: E402  (sets up the throwaway data folder first)

import audit  # noqa: E402
import config  # noqa: E402
import environment as env  # noqa: E402
import integrations_demo  # noqa: E402
import mailer  # noqa: E402
import ops  # noqa: E402
import records  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEMO = tuple(v["slug"] for v in integrations_demo.VENDORS)


class SampleRemovalKeepsCustomerData(ServerCase):
    def tearDown(self):
        for slug in DEMO:
            records.delete_vendor(slug)
        env.PATH.unlink(missing_ok=True)
        env._CACHE.update(key=None, data=None)

    def test_customer_vendor_with_a_sample_name_is_not_sample(self):
        records.save_vendor({"vendor": "Microsoft 365", "slug": "Microsoft_365", "stage": "active", "business": "Our tenant",
                             "evidence_files": [{"id": "x"}]})
        self.assertNotIn("Microsoft_365", ops.sample_present()["vendors"])
        ops.remove_sample_data("test")
        self.assertIsNotNone(records.load_vendor("Microsoft_365"))

    def test_sample_vendors_are_marked_and_removed(self):
        integrations_demo.run()
        self.assertEqual(records.load_vendor("ServiceNow")["source"], "demo")
        self.assertIn("ServiceNow", ops.sample_present()["vendors"])
        ops.remove_sample_data("test")
        self.assertIsNone(records.load_vendor("ServiceNow"))

    def test_own_systems_survive_and_own_setup_is_never_overwritten(self):
        integrations_demo.run()
        env.upsert({"name": "Customer Billing DB", "kind": "data_store"}, "import")
        n_before = len(env.systems())
        ops.remove_sample_data("test")
        self.assertEqual([s["name"] for s in env.systems()], ["Customer Billing DB"])
        self.assertLess(1, n_before)
        env.apply_setup({"org_name": "Real Co", "idp": "Okta", "security_contact": "sec@real.example"}, "admin")
        integrations_demo.run()
        self.assertEqual(env.org_name(), "Real Co")
        self.assertEqual(env.security_contact(), "sec@real.example")
        self.assertFalse(ops.sample_present()["profile"])


class RestoreSafety(unittest.TestCase):
    def test_a_backup_inside_the_data_folder_restores(self):
        with tempfile.TemporaryDirectory() as d:
            data = Path(d) / "data"
            with mock.patch.object(config, "DATA_DIR", data), mock.patch.object(config, "EVIDENCE_DIR", data / "evidence"), \
                    mock.patch.object(config, "VDIR", data / "vendors"):
                (data / "vendors").mkdir(parents=True)
                (data / "vendors" / "A.json").write_text('{"vendor": "A", "slug": "A"}')
                p = ops.backup_now()
                inside = data / "my-copy.tar.gz"
                inside.write_bytes(p.read_bytes())
                r = ops.restore(inside, force=True)
                self.assertTrue((data / "vendors" / "A.json").is_file())
                self.assertTrue(r["moved_aside"])

    def test_a_bad_file_changes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            data = Path(d) / "data"
            (data / "vendors").mkdir(parents=True)
            (data / "vendors" / "A.json").write_text("{}")
            junk = Path(d) / "riskprism-junk.tar.gz"
            junk.write_bytes(b"not a tarball")
            with mock.patch.object(config, "DATA_DIR", data):
                with self.assertRaises(ops.OpsError):
                    ops.restore(junk, force=True)
            self.assertEqual(sorted(p.name for p in data.iterdir()), ["vendors"])


class DeleteAllIsComplete(ServerCase):
    def test_restore_copies_and_policy_go_too(self):
        aside = config.DATA_DIR / (ops.ASIDE_PREFIX + "20260101-000000")
        aside.mkdir(exist_ok=True)
        (aside / "old.json").write_text("{}")
        (config.DATA_DIR / "policy.json").write_text("{}")
        out = ops.delete_all("test", "", include_backups=True)
        self.assertFalse(aside.exists())
        self.assertFalse((config.DATA_DIR / "policy.json").exists())
        self.assertEqual(out["azure"], "")
        self.assertTrue(audit.verify()["ok"])


class AuditAcrossProcesses(unittest.TestCase):
    def test_concurrent_processes_keep_one_chain(self):
        with tempfile.TemporaryDirectory() as d:
            code = ("import os,sys; os.environ['ENTROPY_DATA_DIR']=%r; os.environ['ENTROPY_SECRET']='s'*64; sys.path.insert(0,%r)\n"
                    "import audit\nfor i in range(60): audit.log('p','evt','',str(i))\n") % (d, str(ROOT))
            procs = [subprocess.Popen([sys.executable, "-c", code]) for _ in range(4)]
            for p in procs:
                self.assertEqual(p.wait(120), 0)
            check = ("import os,sys,json; os.environ['ENTROPY_DATA_DIR']=%r; os.environ['ENTROPY_SECRET']='s'*64; sys.path.insert(0,%r)\n"
                     "import audit; print(json.dumps(audit.verify()))") % (d, str(ROOT))
            out = subprocess.run([sys.executable, "-c", check], capture_output=True, text=True, timeout=60)
            import json
            v = json.loads(out.stdout)
            self.assertTrue(v["ok"], v)
            self.assertEqual(v["count"], 240)


class EmailHeaders(unittest.TestCase):
    def test_control_characters_never_crash_or_inject(self):
        self.assertEqual(mailer._one_line("Acme\x0bNotes Bcc: x@y.z\x85"), "Acme Notes Bcc: x@y.z")
        with mock.patch.dict(os.environ, {"ENTROPY_SMTP_HOST": "127.0.0.1", "ENTROPY_SMTP_PORT": "1", "ENTROPY_SMTP_TLS": "none",
                                          "ENTROPY_SMTP_FROM": "a@b.example"}):
            with self.assertRaises(mailer.MailError):  # unreachable port: a MailError, not a crash
                mailer.send("x@vendor.example", "Acme\x0bNotes", "body")

    def test_email_needs_a_public_base_url_on_a_server(self):
        with mock.patch.dict(os.environ, {"ENTROPY_SMTP_HOST": "smtp.example.com", "ENTROPY_SMTP_FROM": "a@b.example"}), \
                mock.patch.object(config, "HOST", "0.0.0.0"), mock.patch.object(config, "BASE_URL", ""):
            self.assertTrue(any("ENTROPY_BASE_URL" in p for p in mailer.startup_problems()))
        with mock.patch.dict(os.environ, {"ENTROPY_SMTP_HOST": "smtp.example.com", "ENTROPY_SMTP_FROM": "a@b.example"}), \
                mock.patch.object(config, "HOST", "0.0.0.0"), mock.patch.object(config, "BASE_URL", "https://riskprism.example"):
            self.assertEqual(mailer.startup_problems(), [])


class BackupRetries(unittest.TestCase):
    def test_waits_two_hours_after_a_failure(self):
        now = datetime(2026, 11, 11, 3, 0).astimezone()
        with mock.patch.object(ops, "_state", return_value={"last_backup_attempt": (now - timedelta(minutes=30)).isoformat()}):
            self.assertFalse(ops._due_backup(now))
        with mock.patch.object(ops, "_state", return_value={"last_backup_attempt": (now - timedelta(hours=3)).isoformat()}):
            self.assertTrue(ops._due_backup(now))

    def test_stale_part_files_are_cleaned(self):
        b = ops.backup_settings()["dir"]
        b.mkdir(parents=True, exist_ok=True)
        stale = b / "riskprism-20200101-000000.part"
        stale.write_bytes(b"x")
        ops.backup_now()
        self.assertFalse(stale.exists())


if __name__ == "__main__":
    unittest.main()
