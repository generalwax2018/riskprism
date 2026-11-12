"""Integration data layer: scope rules, findings, validation, roll-ups and routes.

Run from the project folder:  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import unittest
from datetime import date, timedelta

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_app import ServerCase  # sets up the throwaway data folder first

import access_store
import integrations as ig
import integrations_demo
from records import delete_vendor, load_vendor, save_vendor

CREATED = ("Ig_Alpha", "Ig_Beta", "Ig_Shadow")


def setUpModule():
    save_vendor({"vendor": "Ig Alpha", "slug": "Ig_Alpha", "authorization": "authorized", "stage": "active"})
    save_vendor({"vendor": "Ig Beta", "slug": "Ig_Beta", "authorization": "authorized", "stage": "active"})
    save_vendor({"vendor": "Ig Shadow", "slug": "Ig_Shadow", "authorization": "not_authorized", "stage": "inquiry"})


def tearDownModule():
    for slug in CREATED + tuple(v["slug"] for v in integrations_demo.VENDORS):
        delete_vendor(slug)
    if ig.PATH.exists():
        ig.PATH.unlink()


def make(**kw):
    base = {"name": "Test integration", "source": "Ig_Alpha", "target": "Ig_Beta", "mechanism": "oauth_app",
            "owner": "Team", "reviewed": date.today().isoformat(),
            "auth": {"method": "certificate", "credential": "certificate", "rotated": date.today().isoformat()}}
    base.update(kw)
    return ig.normalize(base)


def codes(row):
    return [f[0] for f in ig.findings(row)]


class ScopeRuleTests(unittest.TestCase):
    def test_classes(self):
        cases = {
            ("Directory.ReadWrite.All", "application"): "admin",
            ("RoleManagement.ReadWrite.Directory", "application"): "admin",
            ("User.ReadWrite.All", "application"): "write",
            ("Mail.Send", "delegated"): "write",
            ("IMAP.AccessAsUser.All", "delegated"): "write",
            ("DeviceManagementManagedDevices.Read.All", "application"): "read",
            ("Calendars.Read", "delegated"): "read",
            ("openid", "delegated"): "identity",
            ("offline_access", "delegated"): "session",
            ("admin", "role"): "admin",
            ("user_admin", "role"): "write",
            ("itil", "role"): "write",
            ("knowledge", "role"): "read",
        }
        for (name, grant), want in cases.items():
            self.assertEqual(ig.scope_class(name, grant), want, name)

    def test_tenant_wide(self):
        self.assertTrue(ig.tenant_wide("User.Read.All", "application"))
        self.assertTrue(ig.tenant_wide("Files.Read.All", "delegated"))
        self.assertFalse(ig.tenant_wide("ExternalItem.ReadWrite.OwnedBy", "application"))
        self.assertFalse(ig.tenant_wide("Mail.Read", "delegated"))


class FindingTests(unittest.TestCase):
    def test_clean_integration_has_no_findings(self):
        self.assertEqual(codes(make(scopes=[{"name": "User.Read.All", "grant": "application"}])), [])

    def test_app_only_write_and_admin_are_high(self):
        row = make(scopes=[{"name": "Group.ReadWrite.All", "grant": "application"},
                           {"name": "Directory.ReadWrite.All", "grant": "application"}])
        fs = ig.findings(row)
        self.assertEqual(ig.worst(fs), "high")
        self.assertIn("app_write_all", [f[0] for f in fs])
        self.assertIn("admin_scope", [f[0] for f in fs])

    def test_send_permission_is_medium(self):
        self.assertIn("app_send_all", codes(make(scopes=[{"name": "TeamsActivity.Send", "grant": "application"}])))

    def test_secret_rotation(self):
        old = (date.today() - timedelta(days=400)).isoformat()
        row = make(auth={"method": "basic", "credential": "password", "rotated": old, "rotation_days": 365})
        self.assertIn("stale_secret", codes(row))
        self.assertIn("static_secret", codes(row))
        self.assertIn("rotation_unknown", codes(make(auth={"method": "oauth_client_credentials", "credential": "client secret"})))

    def test_admin_identity(self):
        self.assertIn("admin_identity", codes(make(auth={"method": "certificate", "credential": "certificate",
                                                         "rotated": date.today().isoformat(), "roles": ["admin"]})))

    def test_sensitive_data_to_unapproved_vendor(self):
        row = make(target="Ig_Shadow", flows=[{"from": "Ig_Alpha", "to": "Ig_Shadow", "data": ["email content"]}])
        self.assertIn("data_to_unapproved", codes(row))
        row = make(target="Ig_Shadow", flows=[{"from": "Ig_Alpha", "to": "Ig_Shadow", "data": ["device names"]}])
        self.assertNotIn("data_to_unapproved", codes(row))

    def test_inbound_endpoint_without_verification(self):
        row = make(mechanism="webhook_in", network={"ingress": ["hooks.example/in"]})
        self.assertIn("inbound_unverified", codes(row))
        self.assertIn("no_allowlist", codes(row))

    def test_declared_scopes_are_compared_with_live_access(self):
        rec = load_vendor("Ig_Beta")
        access_store.replace_rows(rec, [access_store.normalize_row({
            "display_name": "Alpha app", "app_id": "alpha-1", "scopes": ["User.Read.All", "Mail.ReadWrite"], "source": "entra"})])
        save_vendor(rec)
        row = make(app_id="alpha-1", scopes=[{"name": "User.Read.All", "grant": "application"}])
        self.assertIn("scope_drift", codes(row))
        retired = make(app_id="alpha-1", status="retired")
        self.assertEqual(codes(retired), ["retired_still_live"])

    def test_missing_owner_and_review(self):
        row = make(owner="", reviewed="")
        self.assertIn("no_owner", codes(row))
        self.assertIn("not_reviewed", codes(row))


class StoreTests(unittest.TestCase):
    def test_validation(self):
        for bad, msg in (({"name": ""}, "name"), ({"target": "Nobody"}, "both ends"), ({"target": "Ig_Alpha"}, "different"),
                         ({"reviewed": "10/01/2026"}, "YYYY-MM-DD"),
                         ({"flows": [{"from": "Ig_Alpha", "to": "Ig_Shadow", "data": "x"}]}, "two ends")):
            with self.assertRaisesRegex(ig.IntegrationError, msg):
                ig.add({**{"name": "N", "source": "Ig_Alpha", "target": "Ig_Beta"}, **bad}, "t")

    def test_add_and_retire(self):
        row = ig.add({"name": "Kept", "source": "Ig_Alpha", "target": "Ig_Beta", "mechanism": "api_key"}, "tester")
        self.assertTrue(row["id"].startswith("int-"))
        self.assertEqual(ig.get(row["id"])["created_by"], "tester")
        ig.set_status(row["id"], "retired", "tester")
        self.assertEqual(ig.get(row["id"])["status"], "retired")
        self.assertNotIn(row["id"], [r["id"] for r in ig.for_party("Ig_Alpha")])


class DemoRollupTests(unittest.TestCase):
    def test_demo_rollup(self):
        n = integrations_demo.run()
        ov = ig.overview()
        self.assertEqual(ov["metrics"]["integrations"], n)
        self.assertGreaterEqual(ov["metrics"]["high"], 2)
        self.assertEqual(ov["metrics"]["drift"], 1)
        self.assertTrue(any(p["path"][-1] == "Fieldnote AI" for p in ov["paths"]))
        snow = ig.overview("ServiceNow")
        self.assertTrue(all("ServiceNow" in (r["source"], r["target"]) for r in snow["rows"]))
        self.assertEqual(ov["scopes"][0]["class"], "admin", "most powerful grants first")

    def test_onward_paths_stop_at_cycles_and_hop_limit(self):
        flows = [{"from": "A", "to": "B", "data": ["email content"], "sensitive": ["email content"], "integration": "1"},
                 {"from": "B", "to": "C", "data": ["x"], "sensitive": [], "integration": "2"},
                 {"from": "C", "to": "A", "data": ["x"], "sensitive": [], "integration": "3"},
                 {"from": "C", "to": "D", "data": ["x"], "sensitive": [], "integration": "4"},
                 {"from": "D", "to": "E", "data": ["x"], "sensitive": [], "integration": "5"}]
        paths = ig.onward_paths(flows, {})
        self.assertEqual(paths[0]["path"], ["A", "B", "C", "D"])


class QuestionTests(unittest.TestCase):
    def test_every_onboarding_asks_about_integrations(self):
        import questionnaire as qn
        for mode in ("saas", "hybrid", "on_prem"):
            ids = qn.allowed_ids(mode, "onboard")
            for qid in ("int_connect", "int_list", "int_permissions", "int_admin", "int_credentials", "int_data", "int_inbound"):
                self.assertIn(qid, ids, mode)
        self.assertIn("int_change", qn.allowed_ids("saas", "renewal"))
        html = qn.render_fields_html("saas")
        self.assertIn('name="int_connect" value="yes"', html, "yes/no questions are multiple choice")
        self.assertIn("Integrations and permissions", html)

    def test_ai_questionnaire_always_includes_the_integrations_question(self):
        import ai_questionnaire as aq
        _profile, qs = aq.clean_result({"questions": [{"text": "Describe your encryption at rest.", "area": "encryption"}]}, set())
        self.assertTrue(any(q["feeds"] == "integrations" for q in qs))
        kept = aq.questions_from_form({"n": "1", "q0_id": qs[0]["id"], "q0_keep": "on", "q0_text": qs[0]["text"],
                                       "q0_area": "encryption"}, qs)
        self.assertTrue(any(q["feeds"] == "integrations" for q in kept), "an analyst cannot remove it")
        self.assertEqual(sum(1 for q in aq.ensure_integrations(kept) if q["feeds"] == "integrations"), 1)

    def test_followups_from_integration_answers(self):
        import followup
        ids = lambda a: [f["id"] for f in followup.integration_flags(a)]
        self.assertEqual(ids({"int_connect": "no"}), [])
        self.assertEqual(ids({"int_connect": "unsure"}), ["int_unsure"])
        got = ids({"int_connect": "yes", "int_admin": "yes", "int_inbound": "We call https://hooks.example/in"})
        self.assertEqual(set(got), {"int_permissions_missing", "int_admin_rights", "int_credentials_missing", "int_inbound_unverified"})
        self.assertNotIn("int_inbound_unverified", ids({"int_connect": "yes", "int_inbound": "Calls are signed with HMAC-SHA256"}))
        self.assertIn("int_permissions_missing", ids({"integrations": "Connects to Microsoft 365 for mail"}),
                      "the AI questionnaire's integrations answer is checked too")
        self.assertEqual(ids({"integrations": "None"}), [])

    def test_coverage_and_draft_from_answers(self):
        integrations_demo.run()
        gaps = {g["slug"]: g["state"] for g in ig.coverage()}
        self.assertEqual(gaps.get("Ledgerline_Billing"), "unrecorded")
        self.assertNotIn("ServiceNow", gaps)
        draft = ig.draft_from_answers(load_vendor("Ledgerline_Billing"))
        self.assertEqual(draft["target"], "Microsoft_365")
        self.assertEqual(draft["status"], "planned")
        self.assertEqual([(s["name"], s["grant"]) for s in draft["scopes"]], [("Mail.Send", "application"), ("User.Read.All", "application")])
        self.assertIn("api.ledgerline.example", draft["network"]["egress"])
        row = ig.add(draft, "t")
        self.assertIn("app_send_all", [f[0] for f in ig.findings(row)])
        self.assertNotIn("Ledgerline_Billing", {g["slug"] for g in ig.coverage()})
        self.assertIn("Who owns this integration and answers for it?", ig.owner_questions(row))


class RouteTests(ServerCase):
    def test_dashboard_seed_add_retire(self):
        s, body, _h = self.c.get("/integrations")
        self.assertEqual(s, 200)
        s, _b, _h = self.c.post("/integrations/seed", {}, page="/integrations")
        self.assertEqual(s, 303)
        s, body, _h = self.c.get("/integrations")
        self.assertIn("ServiceNow Entra ID spoke", body)
        self.assertIn('class="ig-map"', body)
        s, body, _h = self.c.get("/integrations?vendor=ServiceNow")
        self.assertNotIn("Fieldnote AI calendar and mail grant", body)

        s, body, _h = self.c.post("/integrations/add", {"name": "Bad", "source": "ServiceNow", "target": "ServiceNow"},
                                  page="/integrations")
        self.assertEqual(s, 400)
        self.assertIn("must be different", body)
        s, _b, h = self.c.post("/integrations/add", {
            "name": "Route added", "source": "ServiceNow", "target": "Microsoft_365", "mechanism": "oauth_app",
            "scopes": "Mail.ReadWrite | application", "flows": "from | email content | hourly | graph.microsoft.com",
            "back": "ServiceNow"}, page="/integrations")
        self.assertEqual(s, 303)
        self.assertEqual(h["location"], "/vendor/ServiceNow#integrations")
        row = next(r for r in ig.all_rows() if r["name"] == "Route added")
        self.assertEqual(row["flows"][0]["from"], "Microsoft_365", "'from' reverses the direction")
        self.assertEqual(row["scopes"][0]["grant"], "application")

        s, body, _h = self.c.get("/vendor/ServiceNow")
        self.assertIn('data-tab="integrations"', body)
        self.assertIn("Route added", body)
        s, _b, _h = self.c.post("/integrations/%s/retire" % row["id"], {"back": "ServiceNow"}, page="/integrations")
        self.assertEqual(s, 303)
        self.assertEqual(ig.get(row["id"])["status"], "retired")

    def test_draft_route_and_intake_field(self):
        integrations_demo.run()
        s, body, _h = self.c.get("/vendor/Ledgerline_Billing")
        self.assertIn("no integration is recorded", body)
        s, _b, h = self.c.post("/integrations/draft", {"slug": "Ledgerline_Billing"}, page="/integrations")
        self.assertEqual(s, 303)
        self.assertTrue(any(r["source"] == "Ledgerline_Billing" and r["status"] == "planned" for r in ig.all_rows()))
        s, _b, h = self.c.post("/intake", {"vendor": "Intake Connects Co", "connects": "yes", "connects_to": "Slack"})
        self.assertEqual(s, 303)
        rec = load_vendor("Intake_Connects_Co")
        self.assertEqual((rec["connects"], rec["connects_to"]), ("yes", "Slack"))
        delete_vendor("Intake_Connects_Co")

    def test_csrf_and_unknown(self):
        s, _b, _h = self.c.post("/integrations/seed", {}, csrf=False)
        self.assertEqual(s, 403)
        s, _b, _h = self.c.post("/integrations/int-nope/retire", {}, page="/integrations")
        self.assertEqual(s, 404)


if __name__ == "__main__":
    unittest.main()
