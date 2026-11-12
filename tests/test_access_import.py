"""Live access import (queue item 4): parsing, replace semantics, flags and the upload route.

Run from the project folder:  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import re
import unittest

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_app import ServerCase  # sets up the throwaway data folder first

import access_flags
import access_import as ai
import access_store
from records import load_vendor, save_vendor

ENTRA_CSV = (
    "Display name,Application ID,Permissions,Last sign-in,Owner\n"
    "LeaseAI Abstract,11111111-aaaa,Files.ReadWrite.All Mail.Send,2026-09-30,ops@example.com\n"
    "Calendar Sync,22222222-bbbb,\"Calendars.Read; User.Read\",2026-08-02,\n"
)
OKTA_CSV = (
    "label,client_id,scopes,last_used,status\n"
    "Slack,0oa123,chat:write channels:read,2026-10-01,ACTIVE\n"
    "Old Tool,0oa999,users.read,2026-01-05,INACTIVE\n"
)


class ParseTests(unittest.TestCase):
    def test_entra_csv_maps_loose_headers(self):
        r = ai.parse(ENTRA_CSV, "apps.csv", "entra")
        self.assertEqual(r["read"], 2)
        self.assertEqual(len(r["rows"]), 2)
        first = r["rows"][0]
        self.assertEqual(first["display_name"], "LeaseAI Abstract")
        self.assertEqual(first["app_id"], "11111111-aaaa")
        self.assertEqual(first["scopes"], ["Files.ReadWrite.All", "Mail.Send"])
        self.assertEqual(first["source"], "entra")
        self.assertEqual(first["last_seen"], "2026-09-30")
        self.assertEqual(r["rows"][1]["scopes"], ["Calendars.Read", "User.Read"])
        self.assertEqual(r["missing"], [])

    def test_okta_status_and_id_columns(self):
        r = ai.parse(OKTA_CSV, "okta.csv", "okta")
        self.assertEqual([x["display_name"] for x in r["rows"]], ["Slack", "Old Tool"])
        self.assertEqual(r["rows"][0]["id"], "0oa123", "client_id is used as the stable id")
        self.assertEqual(r["rows"][1]["status"], "stale")
        self.assertEqual(r["rows"][0]["source"], "okta")

    def test_json_list_and_wrapped_value(self):
        data = [{"displayName": "Gong", "appId": "g1", "permissions": ["Calendars.Read"]}]
        r = ai.parse(json.dumps(data), "apps.json", "entra")
        self.assertEqual(r["rows"][0]["display_name"], "Gong")
        self.assertEqual(r["rows"][0]["scopes"], ["Calendars.Read"])
        r2 = ai.parse(json.dumps({"value": data}), "apps.json", "entra")
        self.assertEqual(len(r2["rows"]), 1)

    def test_missing_name_column_is_a_clear_error(self):
        with self.assertRaises(ai.ImportError_) as e:
            ai.parse("foo,bar\n1,2\n", "x.csv", "entra")
        self.assertIn("foo, bar", str(e.exception))

    def test_bad_rows_are_counted_not_silent(self):
        text = "name,scopes\n,Mail.Send\nGood,Mail.Read\nGood,Mail.Read\n"
        r = ai.parse(text, "x.csv", "manual")
        self.assertEqual(len(r["rows"]), 1)
        self.assertEqual(r["skipped"], 2)
        self.assertEqual(r["reasons"], {"no app name": 1, "duplicate app": 1})

    def test_row_limit_and_size_limit(self):
        many = "name\n" + "\n".join("app%d" % i for i in range(ai.MAX_ROWS + 1)) + "\n"
        with self.assertRaises(ai.ImportError_):
            ai.parse(many, "big.csv", "entra")
        with self.assertRaises(ai.ImportError_):
            ai.parse("name\n" + "x" * (ai.MAX_BYTES + 10) + "\n", "huge.csv", "entra")

    def test_empty_and_bad_source(self):
        with self.assertRaises(ai.ImportError_):
            ai.parse("   ", "x.csv", "entra")
        with self.assertRaises(ai.ImportError_):
            ai.parse(ENTRA_CSV, "x.csv", "ftp")
        with self.assertRaises(ai.ImportError_):
            ai.parse("[not json", "x.json", "entra")

    def test_unknown_dates_are_kept_not_invented(self):
        r = ai.parse("name,last sign-in\nWeird,10/03/2026\n", "x.csv", "manual")
        self.assertEqual(r["rows"][0]["last_seen"], "10/03/2026")

    def test_summary_names_what_was_skipped_and_missing(self):
        r = ai.parse("name\nA\n,\n", "x.csv", "manual")
        text = ai.summary(r, previous=3)
        self.assertIn("Skipped 1", text)
        self.assertIn("Replaces the 3 rows", text)
        self.assertIn("Not in this file", text)


class ReplaceAndFlagTests(unittest.TestCase):
    def test_replace_drops_rows_no_longer_in_the_export(self):
        rec = {"vendor": "V", "live_access": []}
        access_store.replace_rows(rec, ai.parse(ENTRA_CSV, "a.csv", "entra")["rows"])
        self.assertEqual(len(access_store.rows(rec)), 2)
        access_store.replace_rows(rec, ai.parse("name,scopes\nOnly One,Mail.Send\n", "b.csv", "entra")["rows"])
        self.assertEqual([r["display_name"] for r in access_store.rows(rec)], ["Only One"])

    def test_import_raises_write_scope_flag_when_questionnaire_is_silent(self):
        rec = {"vendor": "V", "authorization": "authorized", "answers": {}, "live_access": []}
        access_store.replace_rows(rec, ai.parse(ENTRA_CSV, "a.csv", "entra")["rows"])
        codes = [f[0] for f in access_flags.findings(rec)]
        self.assertIn("access_write_scope", codes)

    def test_import_after_offboard_raises_high_flag(self):
        rec = {"vendor": "V", "stage": "offboarded", "live_access": []}
        access_store.replace_rows(rec, ai.parse(ENTRA_CSV, "a.csv", "entra")["rows"])
        flags = access_flags.findings(rec)
        self.assertEqual(flags[0][0], "access_after_offboard")
        self.assertEqual(flags[0][2], "high")


class UploadRouteTests(ServerCase):
    def _upload(self, slug, data, fname="apps.csv", source="entra"):
        csrf = self.c.csrf("/import")
        boundary = "XBOUNDARY"
        parts = []
        for k, v in (("_csrf", csrf), ("vendor", slug), ("source", source)):
            parts.append('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (boundary, k, v))
        head = ('--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
                'Content-Type: application/octet-stream\r\n\r\n' % (boundary, fname))
        body = "".join(parts).encode() + head.encode() + data + ("\r\n--%s--\r\n" % boundary).encode()
        return self.c.req("POST", "/import/access", body, {"Content-Type": "multipart/form-data; boundary=" + boundary})

    def test_upload_replaces_live_access_and_audits(self):
        save_vendor({"vendor": "Route Co", "slug": "Route_Co", "authorization": "authorized"})
        s, body, _h = self._upload("Route_Co", ENTRA_CSV.encode())
        self.assertEqual(s, 200, body[:200])
        self.assertIn("Read 2 apps; kept 2.", body)
        rec = load_vendor("Route_Co")
        self.assertEqual(len(access_store.rows(rec)), 2)
        self.assertTrue(rec.get("live_access_synced_at"))
        s, body, _h = self._upload("Route_Co", b"name\nOnly\n")
        self.assertEqual(len(access_store.rows(load_vendor("Route_Co"))), 1)
        self.assertIn("Replaces the 2 rows", body)

    def test_untracked_vendor_and_bad_file_are_refused_nicely(self):
        s, body, _h = self._upload("Nobody_Here", ENTRA_CSV.encode())
        self.assertEqual(s, 400)
        self.assertIn("tracking", body)
        save_vendor({"vendor": "Bad File Co", "slug": "Bad_File_Co"})
        s, body, _h = self._upload("Bad_File_Co", b"foo,bar\n1,2\n")
        self.assertEqual(s, 400)
        self.assertIn("No app name column", body)
        self.assertEqual(access_store.rows(load_vendor("Bad_File_Co")), [])

    def test_upload_is_audited(self):
        save_vendor({"vendor": "Audit Co", "slug": "Audit_Co"})
        self._upload("Audit_Co", ENTRA_CSV.encode(), fname="entra-apps.csv")
        import audit
        last = [e for e in audit.for_slug("Audit_Co") if e.get("action") == "live_access_imported"]
        self.assertTrue(last)
        self.assertIn("entra-apps.csv", last[-1]["detail"])


if __name__ == "__main__":
    unittest.main()
