"""Control objectives, your environment, anticipated connections, product catalog, shadow IT, executive summary.

Run from the project folder:  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import http.client
import json
import unittest

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_app import ServerCase  # sets up the throwaway data folder first

import anticipate
import catalog
import control_objectives as co
import environment as env
import executive
import integrations as ig
import integrations_demo
import shadow
from records import delete_vendor, load_vendor, save_vendor

DEMO = tuple(v["slug"] for v in integrations_demo.VENDORS)


def setUpModule():
    integrations_demo.run()


def tearDownModule():
    for slug in DEMO + ("PDF_Converter_Pro", "Cmdb_Co"):
        delete_vendor(slug)
    for p in (ig.PATH, env.PATH, shadow.PATH, co.PATH, catalog.PATH):
        if p.exists():
            p.unlink()


class EnvironmentTests(unittest.TestCase):
    def test_setup_builds_the_customer_stack(self):
        ids = {s["id"] for s in env.systems()}
        for sid in ("sys-idp-microsoft-entra-id", "sys-collab-microsoft-365", "sys-cloud-aws", "sys-store-claims-database"):
            self.assertIn(sid, ids)
        self.assertEqual(env.get("sys-collab-microsoft-365")["vendor"], "Microsoft_365", "tenant linked to the vendor that hosts it")
        self.assertEqual(env.org_name(), "Northwind Health (demo)")

    def test_customer_terms_make_data_sensitive(self):
        self.assertTrue(ig.sensitive("Weekly claims data extract"), "the customer's own label")
        self.assertTrue(ig.sensitive("Restricted research notes"))
        self.assertFalse(ig.sensitive("device names"))
        self.assertEqual(env.rotation_days(), 365)

    def test_vendor_integrations_land_on_the_main_tenant_only(self):
        ex = {e["system"]["id"]: e for e in env.exposure()}
        self.assertIn("Fieldnote_AI", ex["sys-collab-microsoft-365"]["unapproved"])
        self.assertEqual(ex["sys-cloud-azure"]["reach"], [], "Azure is hosted by Microsoft but no integration reaches it")
        self.assertTrue(ex["sys-idp-microsoft-entra-id"]["strong"], "the Entra spoke holds directory write")

    def test_cmdb_import_maps_columns_loosely(self):
        text = ("name,sys_class_name,owned_by,business_criticality,data_classification\n"
                "Billing DB,cmdb_ci_database,dba@example.com,1 - most critical,PCI\n"
                "Prod AWS,cmdb_ci_cloud_service_account,cloud@example.com,2,\n")
        rows = env.parse_import(text, "cmdb.csv")
        self.assertEqual([(r["name"], r["kind"], r["criticality"]) for r in rows],
                         [("Billing DB", "data_store", "high"), ("Prod AWS", "cloud_account", "medium")])
        with self.assertRaises(env.EnvironmentError_):
            env.parse_import("foo,bar\n1,2\n", "x.csv")


class ControlTests(unittest.TestCase):
    def test_library_and_combination(self):
        builtin = [o for o in co.library() if o["id"].startswith("CO-") and not o["id"].startswith("CO-C")]
        self.assertEqual(len(builtin), 20)
        self.assertEqual(sorted(o["id"] for o in builtin if not o["enabled"]), ["CO-17", "CO-18", "CO-19", "CO-20"])
        self.assertEqual(len([o for o in co.library(include_disabled=False) if o["builtin"]]), 16)
        self.assertTrue(all(o["refs"].get("cip") for o in builtin if o["id"] != "CO-11"))
        self.assertEqual(co.combine(["met", "na", "partial"]), "partial")
        self.assertEqual(co.combine(["met", "unknown"]), "unknown", "unknown is never a pass")
        self.assertEqual(co.combine(["na", "na"]), "na")

    def test_vendor_results_follow_the_evidence(self):
        res = {r["objective"]["id"]: r for r in co.evaluate(load_vendor("ServiceNow"))}
        self.assertEqual(res["CO-01"]["status"], "met")
        self.assertEqual(res["CO-02"]["status"], "not_met", "pentest expired in the sample")
        self.assertEqual(res["CO-05"]["status"], "not_met", "the Entra spoke holds Directory.ReadWrite.All")
        m365 = {r["objective"]["id"]: r for r in co.evaluate(load_vendor("Microsoft_365"))}
        self.assertNotEqual(m365["CO-07"]["status"], "not_met", "another vendor's drift is not Microsoft's")
        fn = {r["objective"]["id"]: r for r in co.evaluate(load_vendor("Fieldnote_AI"))}
        self.assertEqual(fn["CO-07"]["status"], "not_met", "the note-taker holds an undeclared scope")

    def test_company_can_tune_and_add_objectives(self):
        co.update("CO-02", False, ["T1"], "AppSec", "t")
        self.assertNotIn("CO-02", [o["id"] for o in co.library(include_disabled=False)])
        co.update("CO-02", True, ["T1", "T2"], "AppSec", "t")
        with self.assertRaises(co.ObjectiveError):
            co.update("CO-02", True, [], "", "t")
        obj = co.add_custom({"title": "Vendor carries cyber insurance", "domain": "Governance", "ref_nist": "SR-6"}, [], ["T1", "T2"], "t")
        res = {r["objective"]["id"]: r for r in co.evaluate(load_vendor("ServiceNow"))}
        self.assertEqual(res[obj["id"]]["status"], "unknown", "manual objectives start unknown")
        with self.assertRaisesRegex(co.ObjectiveError, "note"):
            co.attest("ServiceNow", obj["id"], "met", "", "t")
        co.attest("ServiceNow", obj["id"], "met", "Certificate on file, expires 2027-04", "t")
        res = {r["objective"]["id"]: r for r in co.evaluate(load_vendor("ServiceNow"))}
        self.assertEqual((res[obj["id"]]["status"], res[obj["id"]]["auto"]), ("met", "unknown"), "attested, automatic result kept")

    def test_tiers_scope_objectives(self):
        rec = load_vendor("Workday")
        res = {r["objective"]["id"]: r for r in co.evaluate(rec, tier="T4")}
        self.assertEqual(res["CO-02"]["status"], "na", "pentest objective applies to T1 and T2 only")


class AnticipateTests(unittest.TestCase):
    def test_predictions_use_the_customer_stack(self):
        items = {i["key"]: i for i in anticipate.connections(load_vendor("Fieldnote_AI"))}
        self.assertIn("Microsoft Entra ID", items["sso"]["title"])
        self.assertIn("OnlineMeetings.Read", [n for n, _g in items["workspace"]["scopes"]])
        self.assertTrue(items["workspace"]["recorded"], "the recorded grant matches the prediction")
        self.assertFalse(items["sso"]["recorded"])
        row = ig.add(anticipate.to_integration(load_vendor("Fieldnote_AI"), items["sso"]), "t")
        self.assertEqual((row["status"], row["source"], row["target"]), ("planned", "sys-idp-microsoft-entra-id", "Fieldnote_AI"))
        stack = anticipate.their_stack(load_vendor("Fieldnote_AI"))
        self.assertTrue(any(c["component"].startswith("Model provider") and not c["declared"] for c in stack))

    def test_security_tool_gets_cloud_roles(self):
        save_vendor({"vendor": "Cmdb Co", "slug": "Cmdb_Co", "category": "security_tool", "authorization": "authorized"})
        keys = [i["key"] for i in anticipate.connections(load_vendor("Cmdb_Co"))]
        self.assertIn("cloud-sys-cloud-aws", keys)
        self.assertIn("cloud-sys-cloud-azure", keys)


class CatalogTests(unittest.TestCase):
    def test_matching(self):
        self.assertEqual(catalog.match_domain("https://yourco.service-now.com/api"), "servicenow")
        self.assertEqual(catalog.match_domain("chatgpt.com"), "openai")
        self.assertEqual(catalog.match_app("Otter.ai"), "otter")
        self.assertEqual(catalog.match_domain("weather.example.org"), "")

    def test_learned_export_strips_customer_details(self):
        learned = catalog.learned()
        self.assertIn("servicenow", learned)
        text = catalog.export_json()
        for secret in ("yourco", "svc_entra_provisioning", "IAM team", "northwind"):
            self.assertNotIn(secret, text)
        self.assertIn("*.service-now.com", text)
        n = catalog.import_json(text, "t")
        self.assertGreaterEqual(n, 1)
        prof = catalog.profile_for("ServiceNow")
        self.assertTrue(prof["builtin"] and prof["learned"] and prof["imported"])
        with self.assertRaises(ValueError):
            catalog.import_json('{"not": "a catalog"}', "t")


class ShadowTests(unittest.TestCase):
    def test_queue_classifies_apps_and_traffic(self):
        q = shadow.queue()
        kinds = {(i["kind"], i["name"]) for i in q["items"]}
        self.assertIn(("not_authorized", "Fieldnote AI"), kinds)
        self.assertIn(("unknown_app", "PDF Converter Pro"), kinds)
        self.assertIn(("shadow_saas", "ChatGPT (OpenAI)"), kinds)
        self.assertNotIn("ServiceNow Entra spoke", {i["name"] for i in q["items"]}, "recorded integrations are not shadow")
        self.assertNotIn(("shadow_saas", "Otter.ai"), kinds, "traffic is merged into the matching app item")
        pdf = next(i for i in q["items"] if i["name"] == "PDF Converter Pro")
        self.assertEqual(pdf["severity"], "high", "Files.ReadWrite.All")

    def test_track_and_decide(self):
        q = shadow.queue()
        pdf = next(i for i in q["items"] if i["name"] == "PDF Converter Pro")
        slug = shadow.track(pdf["id"], "t")
        rec = load_vendor(slug)
        self.assertEqual((rec["authorization"], rec["source"]), ("not_authorized", "shadow_it"))
        self.assertTrue(any(r["display_name"] == "PDF Converter Pro" for r in rec["live_access"]))
        zoom = next(i for i in shadow.queue()["items"] if i["name"] == "Zoom")
        shadow.decide(zoom["id"], "known", "Approved under the collaboration standard", "t")
        self.assertNotIn(zoom["id"], [i["id"] for i in shadow.queue()["items"]])


class ExecutiveTests(unittest.TestCase):
    def test_summary_and_board_pack(self):
        s = executive.summary()
        self.assertEqual(s["org"], "Northwind Health (demo)")
        self.assertTrue(s["decisions"] and s["decisions"][0]["sev"] == "high")
        self.assertTrue(all(d["link"].startswith("/") for d in s["decisions"]), "every line links to the engineer's detail")
        pdf = executive.board_pdf()
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))


class RouteTests(ServerCase):
    def _raw(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", path)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data, {k.lower(): v for k, v in r.getheaders()}

    def test_pages_render(self):
        for path, text in (("/executive", "What needs a decision"), ("/environment", "Environment map"),
                           ("/environment/sys-collab-microsoft-365", "Who can reach it"), ("/controls", "Vendors against objectives"),
                           ("/shadow", "Queue"), ("/vendor/ServiceNow", 'data-tab="controls"')):
            s, body, _h = self.c.get(path)
            self.assertEqual(s, 200, path)
            self.assertIn(text, body, path)
        s, body, _h = self.c.get("/vendor/Fieldnote_AI")
        self.assertIn("Anticipated from your stack", body)
        s, _b, _h = self.c.get("/environment/sys-nope")
        self.assertEqual(s, 404)

    def test_exports(self):
        s, data, h = self._raw("/executive/board.pdf")
        self.assertEqual((s, h["content-type"]), (200, "application/pdf"))
        s, data, h = self._raw("/integrations/catalog.json")
        self.assertEqual(s, 200)
        self.assertEqual(json.loads(data)["riskprism_catalog"], 1)

    def test_forms(self):
        s, _b, h = self.c.post("/controls/attest", {"slug": "Workday", "oid": "CO-03", "status": "met",
                                                    "note": "Review held 2026-10-02; date not yet updated"}, page="/controls")
        self.assertEqual(s, 303)
        s, body, _h = self.c.post("/controls/attest", {"slug": "Workday", "oid": "CO-03", "status": "met", "note": ""}, page="/controls")
        self.assertEqual(s, 400)
        self.assertIn("needs a note", body)
        s, _b, h = self.c.post("/environment/system", {"name": "Data lake", "kind": "data_store", "criticality": "high",
                                                       "data_classes": "claims data"}, page="/environment")
        self.assertEqual(s, 303)
        self.assertTrue(env.get("sys-data-lake"))
        s, _b, _h = self.c.post("/shadow/decide", {"id": "sh-x", "state": "known", "note": ""}, page="/shadow")
        self.assertEqual(s, 400)
        s, _b, _h = self.c.post("/controls/objective", {"oid": "CO-04", "enabled": "on", "tier_T1": "on"}, csrf=False)
        self.assertEqual(s, 403)


if __name__ == "__main__":
    unittest.main()
