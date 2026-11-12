"""Findings worklist, CSV export and ticket push to ServiceNow and Jira (against local fakes)."""
from __future__ import annotations

import base64
import csv
import io
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_app import ServerCase  # sets up the throwaway data folder first

import control_objectives as co  # noqa: E402
import environment as env  # noqa: E402
import findings  # noqa: E402
import integrations as ig  # noqa: E402
import integrations_demo  # noqa: E402
import shadow  # noqa: E402
from records import delete_vendor  # noqa: E402

DEMO = tuple(v["slug"] for v in integrations_demo.VENDORS)


class FakeTickets(BaseHTTPRequestHandler):
    calls: list = []
    fail = False

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeTickets.calls.append((self.path, self.headers.get("Authorization"), body))
        if FakeTickets.fail:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":"bad credentials"}')
            return
        n = len(FakeTickets.calls)
        if self.path.startswith("/api/now/table/"):
            out = {"result": {"number": "INC%07d" % n, "sys_id": "abc%d" % n}}
        else:
            out = {"key": "SEC-%d" % n, "id": str(n)}
        data = json.dumps(out).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def setUpModule():
    integrations_demo.run()


def tearDownModule():
    for slug in DEMO:
        delete_vendor(slug)
    for p in (ig.PATH, env.PATH, shadow.PATH, co.PATH, findings.PATH):
        if p.exists():
            p.unlink()


class FindingsTests(ServerCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.fake = ThreadingHTTPServer(("127.0.0.1", 0), FakeTickets)
        threading.Thread(target=cls.fake.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.fake.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.fake.shutdown()
        super().tearDownClass()

    def setUp(self):
        FakeTickets.calls, FakeTickets.fail = [], False
        if findings.PATH.exists():
            findings.PATH.unlink()

    def test_collect_has_every_source_and_stable_keys(self):
        a = findings.collect()
        b = findings.collect()
        self.assertEqual([f["key"] for f in a], [f["key"] for f in b])
        self.assertEqual(len({f["key"] for f in a}), len(a))
        sources = {f["source"] for f in a}
        for s in ("integration", "shadow", "control"):
            self.assertIn(s, sources)
        ranks = [findings.SEV_RANK[f["severity"]] for f in a]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_csv_is_import_ready_and_formula_safe(self):
        items = findings.collect()
        items[0] = {**items[0], "title": "=HYPERLINK(\"http://evil\")"}
        rows = list(csv.reader(io.StringIO(findings.csv_text(items, "https://riskprism.example"))))
        self.assertEqual(rows[0][:5], ["Key", "Summary", "Description", "Severity", "Priority"])
        self.assertTrue(rows[1][1].startswith("'="))
        self.assertIn("https://riskprism.example/", rows[1][8])
        s, body, h = self.c.get("/findings.csv")
        self.assertEqual(s, 200)
        self.assertIn("text/csv", h["content-type"])

    def test_page_without_ticketing(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            for k in [k for k in os.environ if k.startswith(("ENTROPY_SNOW", "ENTROPY_JIRA"))]:
                os.environ.pop(k)
            s, page, _h = self.c.get("/findings")
            self.assertEqual(s, 200)
            self.assertIn("No ticketing system is connected", page)
            s, _b, _h = self.c.post("/findings/push", {"system": "jira", "k_F-0000000000": "on"})
            self.assertEqual(s, 400)

    def test_servicenow_push_once_per_finding(self):
        env_ = {"ENTROPY_SNOW_INSTANCE": self.base, "ENTROPY_SNOW_USER": "svc", "ENTROPY_SNOW_PASSWORD": "pw", "ENTROPY_SNOW_TABLE": "incident"}
        with mock.patch.dict(os.environ, env_):
            keys = [f["key"] for f in findings.collect()[:2]]
            s, page, _h = self.c.get("/findings")
            self.assertIn('name="system"', page)
            s, page, _h = self.c.post("/findings/push", {"system": "servicenow", **{"k_" + k: "on" for k in keys}})
            self.assertEqual(s, 200)
            self.assertIn("Created 2 tickets", page)
            path, authz, body = FakeTickets.calls[0]
            self.assertEqual(path, "/api/now/table/incident")
            self.assertEqual(authz, "Basic " + base64.b64encode(b"svc:pw").decode())
            self.assertEqual(body["correlation_id"], keys[0])
            self.assertIn(keys[0], body["description"])
            # again: nothing new is raised, and the references show
            self.c.post("/findings/push", {"system": "servicenow", **{"k_" + k: "on" for k in keys}})
            self.assertEqual(len(FakeTickets.calls), 2)
            by = {f["key"]: f for f in findings.collect()}
            self.assertEqual(by[keys[0]]["ticket"]["ref"], "INC0000001")
            _s, page, _h = self.c.get("/findings?show=all")
            self.assertIn("INC0000001", page)
            self.assertNotIn("pw", findings.PATH.read_text())

    def test_jira_push_and_refusal(self):
        env_ = {"ENTROPY_JIRA_URL": self.base, "ENTROPY_JIRA_EMAIL": "a@b.example", "ENTROPY_JIRA_TOKEN": "tok", "ENTROPY_JIRA_PROJECT": "sec"}
        with mock.patch.dict(os.environ, env_):
            key = findings.collect()[0]["key"]
            created, errors = findings.push([key], "jira", "tester")
            self.assertEqual(errors, [])
            self.assertEqual(created[0]["ref"], "SEC-1")
            self.assertTrue(created[0]["url"].endswith("/browse/SEC-1"))
            body = FakeTickets.calls[0][2]
            self.assertEqual(body["fields"]["project"]["key"], "SEC")
            self.assertIn(key, body["fields"]["labels"])
            FakeTickets.fail = True
            other = findings.collect()[1]["key"]
            created, errors = findings.push([other], "jira", "tester")
            self.assertEqual(created, [])
            self.assertIn("HTTP 401", errors[0])

    def test_remote_ticketing_must_be_https(self):
        with mock.patch.dict(os.environ, {"ENTROPY_JIRA_URL": "http://jira.example", "ENTROPY_JIRA_EMAIL": "a",
                                          "ENTROPY_JIRA_TOKEN": "t", "ENTROPY_JIRA_PROJECT": "SEC"}):
            created, errors = findings.push([findings.collect()[0]["key"]], "jira", "tester")
            self.assertEqual(created, [])
            self.assertIn("https://", errors[0])
            self.assertEqual(FakeTickets.calls, [])

    def test_manual_ticket_reference(self):
        key = findings.collect()[0]["key"]
        s, _b, _h = self.c.post("/findings/ticket", {"key": key, "ref": "CHG0042", "url": "javascript:alert(1)"})
        self.assertEqual(s, 303)
        t = {f["key"]: f for f in findings.collect()}[key]["ticket"]
        self.assertEqual(t["ref"], "CHG0042")
        self.assertEqual(t["url"], "")
        s, _b, _h = self.c.post("/findings/ticket", {"key": key, "ref": "<script>"})
        self.assertEqual(s, 400)
        self.c.post("/findings/untrack", {"key": key})
        self.assertIsNone({f["key"]: f for f in findings.collect()}[key]["ticket"])


if __name__ == "__main__":
    unittest.main()
