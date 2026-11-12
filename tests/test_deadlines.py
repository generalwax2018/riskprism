"""Finding deadlines and trend, and the NERC CIP mapping."""
from __future__ import annotations

import csv
import io
import sys
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_app import ServerCase  # noqa: E402  (sets up the throwaway data folder first)

import control_objectives as co  # noqa: E402
import environment as env  # noqa: E402
import executive  # noqa: E402
import findings  # noqa: E402
import integrations as ig  # noqa: E402
import integrations_demo  # noqa: E402
import shadow  # noqa: E402
from records import delete_vendor  # noqa: E402

DEMO = tuple(v["slug"] for v in integrations_demo.VENDORS)
TODAY = date(2026, 6, 1)


def setUpModule():
    integrations_demo.run()


def tearDownModule():
    for slug in DEMO:
        delete_vendor(slug)
    for p in (ig.PATH, env.PATH, shadow.PATH, co.PATH, findings.PATH, findings.STATE_PATH):
        if p.exists():
            p.unlink()


def item(key, sev="high"):
    return {"key": key, "severity": sev, "ticket": None, "source": "vendor", "title": key, "detail": "", "vendor": "", "owner": "", "link": "/"}


class DeadlineTests(unittest.TestCase):
    def setUp(self):
        if findings.STATE_PATH.exists():
            findings.STATE_PATH.unlink()
        rule = mock.patch.object(env, "finding_days", return_value=dict(env.DEFAULT_FINDING_DAYS))
        rule.start()
        self.addCleanup(rule.stop)

    def test_first_seen_due_and_overdue_follow_the_customers_rule(self):
        self.assertEqual(env.DEFAULT_FINDING_DAYS, {"high": 30, "medium": 90, "low": 180})
        a, b = item("F-aaaaaaaaaa", "high"), item("F-bbbbbbbbbb", "low")
        findings._track([a, b], TODAY)
        self.assertEqual((a["first_seen"], a["due"], a["overdue_days"]), ("2026-06-01", "2026-07-01", 0))
        self.assertEqual(b["due"], "2026-11-28")
        a2, b2 = item("F-aaaaaaaaaa", "high"), item("F-bbbbbbbbbb", "low")
        findings._track([a2, b2], TODAY + timedelta(days=40))
        self.assertEqual((a2["first_seen"], a2["age_days"], a2["overdue_days"]), ("2026-06-01", 40, 10))
        self.assertEqual(b2["overdue_days"], 0)

    def test_close_and_quick_reopen_keeps_the_clock_but_a_late_return_restarts_it(self):
        findings._track([item("F-aaaaaaaaaa")], TODAY)
        findings._track([], TODAY + timedelta(days=5))
        st = findings._load_state()
        self.assertEqual(st["closed"], {"F-aaaaaaaaaa": "2026-06-06"})
        back = item("F-aaaaaaaaaa")
        findings._track([back], TODAY + timedelta(days=10))
        self.assertEqual(back["first_seen"], "2026-06-01")
        findings._track([], TODAY + timedelta(days=20))
        late = item("F-aaaaaaaaaa")
        findings._track([late], TODAY + timedelta(days=60))
        self.assertEqual(late["first_seen"], "2026-07-31")

    def test_trend_compares_with_a_month_ago(self):
        old = [item("F-%010d" % i) for i in range(5)]
        findings._track(old, TODAY)
        self.assertIsNone(findings.trend(old, TODAY)["then"])
        self.assertIn("week of history", findings.trend_sentence(findings.trend(old, TODAY)))
        later = TODAY + timedelta(days=31)
        now = [item("F-%010d" % i) for i in range(2, 9)]  # 2 closed, 4 new
        findings._track(now, later)
        t = findings.trend(now, later)
        self.assertEqual((t["since"], t["days"]), ("2026-06-01", 31))
        self.assertEqual((t["delta"]["total"], t["opened"], t["closed"]), (2, 4, 2))
        self.assertEqual(t["delta"]["overdue"], 3)  # the three that stayed open are a day past 30
        text = findings.trend_sentence(t)
        self.assertIn("7 open findings (up 2)", text)
        self.assertIn("4 opened and 2 closed", text)

    def test_nothing_is_written_when_nothing_changed(self):
        findings._track([item("F-aaaaaaaaaa")], TODAY)
        m = findings.STATE_PATH.stat().st_mtime_ns
        findings._track([item("F-aaaaaaaaaa")], TODAY)
        self.assertEqual(findings.STATE_PATH.stat().st_mtime_ns, m)

    def test_old_closed_findings_and_snapshots_are_pruned(self):
        findings._track([item("F-aaaaaaaaaa")], TODAY)
        findings._track([], TODAY + timedelta(days=1))
        findings._track([], TODAY + timedelta(days=500))
        st = findings._load_state()
        self.assertEqual((st["first"], st["closed"]), ({}, {}))
        self.assertEqual(list(st["snapshots"]), [(TODAY + timedelta(days=500)).isoformat()])


class DeadlinePagesTests(ServerCase):
    def test_worklist_csv_and_executive_show_deadlines(self):
        items = findings.collect()
        self.assertTrue(all(f["first_seen"] and f["due"] for f in items))
        _s, page, _h = self.c.get("/findings")
        self.assertIn("Overdue", page)
        self.assertIn("Due ", page)
        rows = list(csv.reader(io.StringIO(self.c.get("/findings.csv")[1])))
        self.assertEqual(rows[0][-3:], ["First seen", "Due", "Days overdue"])
        s = executive.summary()
        self.assertEqual(s["findings"]["total"], len(items))
        _s, page, _h = self.c.get("/executive")
        self.assertIn("Findings overdue", page)
        pdf = self.c.get("/executive/board.pdf")
        self.assertEqual(pdf[0], 200)

    def test_customer_can_change_the_rule_and_set_a_contact(self):
        s, page, _h = self.c.post("/environment/setup", {"org_name": "Deadline Co", "due_high": "7", "due_medium": "14", "due_low": "21",
                                                         "security_contact": "security@deadline.example"}, page="/environment")
        self.assertEqual(s, 200)
        self.assertEqual(env.finding_days(), {"high": 7, "medium": 14, "low": 21})
        self.assertEqual(env.security_contact(), "security@deadline.example")
        s, page, _h = self.c.post("/environment/setup", {"security_contact": "not an email"}, page="/environment")
        self.assertEqual(s, 400)
        self.assertEqual(env.security_contact(), "security@deadline.example")


class CipMappingTests(ServerCase):
    def test_cip_references_show_on_the_controls_page(self):
        _s, page, _h = self.c.get("/controls?fw=cip")
        self.assertIn("NERC CIP", page)
        self.assertIn("CIP-013 R1.2.3", page)
        self.assertIn("CIP-005 R2.3", page)

    def test_cip013_pack_is_off_until_switched_on_and_is_attested_by_hand(self):
        ids = [o["id"] for o in co.library(include_disabled=False)]
        self.assertNotIn("CO-17", ids)
        co.update("CO-17", True, ["T1", "T2", "T3", "T4"], "Supply chain lead", "test")
        try:
            row = next(r for r in co.matrix()["rows"] if r["slug"] == "ServiceNow")
            res = next(x for x in row["results"] if x["objective"]["id"] == "CO-17")
            self.assertEqual((res["status"], res["evidence"]), ("unknown", ["Manual attestation only."]))
            co.attest("ServiceNow", "CO-17", "met", "MSA clause 14.2: 24 hour notice", "test")
            row = next(r for r in co.matrix()["rows"] if r["slug"] == "ServiceNow")
            self.assertEqual(next(x for x in row["results"] if x["objective"]["id"] == "CO-17")["status"], "met")
        finally:
            co.update("CO-17", False, ["T1", "T2"], "", "test")
            co.attest("ServiceNow", "CO-17", "clear", "", "test")


if __name__ == "__main__":
    unittest.main()
