"""Threat model: generation, decisions, review gate, change detection, Word/PDF export, routes.

Run from the project folder:  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import http.client
import io
import re
import unittest
import xml.etree.ElementTree as ET
import zipfile
from datetime import date, timedelta

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_app import ServerCase  # sets up the throwaway data folder first

import audit
import risk_store
import threat_export as te
import threat_model as tm
from records import load_vendor, save_vendor

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def fictional(**extra) -> dict:
    rec = {
        "vendor": "Fictional Notes Co", "slug": "Fictional_Notes_Co", "authorization": "authorized",
        "stage": "active", "mode": "saas", "business": "Meeting notes", "live_access": [],
        "factsheet": {
            "hosting": "EU (Ireland)", "sso": "SAML SSO with MFA", "ai_used": "yes",
            "model_provider": "Example Model Co", "models": "example-large", "data_classes": "Meeting notes, names",
            "trains_on_customer_content": "no", "tenancy": "multi-tenant",
            "subprocessors": "Example Host Ltd", "gaps": [],
        },
    }
    rec.update(extra)
    return rec


def decide_all(rec: dict, who: str = "tester", level: str = "vp") -> None:
    for t in tm.build(rec)["threats"]:
        if t.get("retired"):
            continue
        tm.set_threat(rec, t["id"], {"scenario": "Scenario for " + t["id"], "likelihood": "1", "impact": "2",
                                     "disposition": "eliminate", "mitigations": ""}, who, level)


class ModelTests(unittest.TestCase):
    def test_seven_boundaries_and_stable_threat_ids(self):
        rec = fictional()
        m = tm.build(rec)
        self.assertEqual([b["id"] for b in m["boundaries"]], ["TB-%d" % i for i in range(1, 8)])
        ids = [t["id"] for t in m["threats"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("TB-1.spoof_link", ids)
        self.assertIn("TB-5.training_use", ids, "AI prompts apply when AI touches our data")
        again = [t["id"] for t in tm.build(rec)["threats"]]
        self.assertEqual(ids, again, "same record gives the same ids")

    def test_unknown_boundaries_raise_questions(self):
        rec = fictional(factsheet={"ai_used": "no", "gaps": []})
        m = tm.build(rec)
        statuses = {b["id"]: b["status"] for b in m["boundaries"]}
        self.assertEqual(statuses["TB-7"], "unknown", "exit is never known from the record alone")
        self.assertTrue(any(q["relates_to"] == ["TB-7"] for q in m["questions"]))
        self.assertFalse(any(t["id"].startswith("TB-5.") and t["prompt"] == "training_use" for t in m["threats"] if not t.get("retired")),
                         "AI prompts do not apply when no AI is used")

    def test_decisions_survive_refresh_and_ai_prompts_are_retired_not_deleted(self):
        rec = fictional()
        tm.set_threat(rec, "TB-5.training_use", {"scenario": "Our notes train the model", "likelihood": "3", "impact": "4",
                                                 "disposition": "mitigate", "mitigations": "Contract bans training"}, "t", "vp")
        t = next(x for x in tm.build(rec)["threats"] if x["id"] == "TB-5.training_use")
        self.assertEqual(t["scenario"], "Our notes train the model")
        self.assertEqual(t["rating"], "high")
        self.assertEqual(t["mitigations"], ["Contract bans training"])

        rec["factsheet"]["ai_used"] = "no"
        m = tm.build(rec)
        self.assertNotIn("TB-5.training_use", [t["id"] for t in m["threats"]])
        kept = next(x for x in m["retired"] if x["id"] == "TB-5.training_use")
        self.assertEqual(kept["scenario"], "Our notes train the model", "decision kept, marked retired")

    def test_rating_bands(self):
        self.assertEqual(tm.rating_band(5, 5), "critical")
        self.assertEqual(tm.rating_band(4, 5), "critical")
        self.assertEqual(tm.rating_band(3, 4), "high")
        self.assertEqual(tm.rating_band(2, 3), "medium")
        self.assertEqual(tm.rating_band(1, 5), "low")
        self.assertEqual(tm.rating_band(None, 5), "")

    def test_validation_messages(self):
        rec = fictional()
        base = {"scenario": "x", "likelihood": "4", "impact": "4", "disposition": "mitigate", "mitigations": ""}
        with self.assertRaisesRegex(tm.ModelError, "Mitigate needs"):
            tm.set_threat(rec, "TB-1.spoof_link", base, "t", "vp")
        with self.assertRaisesRegex(tm.ModelError, "1 to 5"):
            tm.set_threat(rec, "TB-1.spoof_link", {**base, "likelihood": "9", "disposition": "open"}, "t", "vp")
        with self.assertRaisesRegex(tm.ModelError, "Describe the scenario"):
            tm.set_threat(rec, "TB-1.spoof_link", {**base, "scenario": "  ", "disposition": "open"}, "t", "vp")
        with self.assertRaisesRegex(tm.ModelError, "not on the model"):
            tm.set_threat(rec, "TB-9.nope", base, "t", "vp")

    def test_accept_needs_the_approver_for_the_rating_and_a_future_expiry(self):
        rec = fictional()
        fields = {"scenario": "Residual copy in the vendor's backups", "likelihood": "4", "impact": "4",
                  "disposition": "accept", "mitigations": "", "rating_basis": "Backups rotate in 30 days",
                  "accepted_until": (date.today() + timedelta(days=60)).isoformat()}
        with self.assertRaisesRegex(tm.ModelError, "VP or the CISO"):
            tm.set_threat(rec, "TB-7.residual_copies", fields, "dir@example.com", "director")
        with self.assertRaisesRegex(tm.ModelError, "approver"):
            tm.set_threat(rec, "TB-7.residual_copies", fields, "nobody@example.com", "")
        with self.assertRaisesRegex(tm.ModelError, "past|future"):
            tm.set_threat(rec, "TB-7.residual_copies", {**fields, "accepted_until": "2020-01-01"}, "vp@example.com", "vp")
        with self.assertRaisesRegex(tm.ModelError, "at most"):
            tm.set_threat(rec, "TB-7.residual_copies", {**fields, "accepted_until": (date.today() + timedelta(days=900)).isoformat()},
                          "vp@example.com", "vp")
        t = tm.set_threat(rec, "TB-7.residual_copies", fields, "vp@example.com", "vp")
        self.assertEqual((t["disposition"], t["accepted_by"], t["status"]), ("accept", "vp@example.com", "decided"))

    def test_review_is_blocked_until_every_threat_is_decided(self):
        rec = fictional()
        with self.assertRaisesRegex(tm.ModelError, "still open"):
            tm.review(rec, "t")
        decide_all(rec)
        store = tm.review(rec, "t", "first review")
        self.assertEqual(store["version"], 1)
        self.assertEqual(len(store["history"]), 1)
        self.assertEqual(store["history"][0]["note"], "first review")
        self.assertEqual(tm.build(rec)["version"], 1)
        self.assertEqual(tm.status(rec)["state"], "current")

    def test_change_after_review_needs_review_and_says_what_changed(self):
        rec = fictional()
        decide_all(rec)
        tm.review(rec, "t")
        self.assertEqual(tm.status(rec)["state"], "current", "no change, nothing to review")
        rec["factsheet"]["hosting"] = "US (Virginia)"
        rec["factsheet"]["subprocessors"] = "Example Host Ltd; Second Analytics Inc"
        info = tm.status(rec)
        self.assertEqual(info["state"], "needs_review")
        self.assertIn("Hosting changed", info["changes"])
        self.assertIn("Sub-processors changed", info["changes"])
        decide_all(rec)  # new or changed threats must be decided again
        tm.review(rec, "t", "hosting moved to US")
        self.assertEqual(rec["threat_model"]["version"], 2)
        self.assertEqual(len(rec["threat_model"]["history"]), 2)
        self.assertEqual(tm.status(rec)["state"], "current")

    def test_new_connected_app_is_a_change(self):
        rec = fictional()
        decide_all(rec)
        tm.review(rec, "t")
        rec["live_access"] = [{"id": "app1", "display_name": "Gong", "app_id": "g", "scopes": ["Calendars.Read"],
                               "kind": "oauth_app", "status": "active", "source": "manual",
                               "last_seen": "2026-10-01", "first_seen": "2026-10-01", "owner": ""}]
        self.assertIn("Connected apps changed (1 added, 0 removed)", tm.status(rec)["changes"])


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.rec = fictional()
        tm.set_threat(self.rec, "TB-1.spoof_link", {"scenario": "Fake (look-alike) page \\ with <tags> & symbols",
                                                    "likelihood": "4", "impact": "4", "disposition": "mitigate",
                                                    "mitigations": "Block unknown domains\nAlert on new intake links"},
                      "t", "vp")
        model = tm.build(self.rec)
        self.blocks = te.blocks(self.rec, model, model["status"], "Fictional Notes Co")

    def test_docx_is_a_valid_package_with_real_tables(self):
        data = te.docx_bytes(self.blocks)
        z = zipfile.ZipFile(io.BytesIO(data))
        self.assertEqual(z.testzip(), None)
        for name in ("[Content_Types].xml", "_rels/.rels", "word/document.xml", "word/styles.xml",
                     "word/_rels/document.xml.rels", "word/footer1.xml"):
            ET.fromstring(z.read(name))  # every part is well-formed XML
        root = ET.fromstring(z.read("word/document.xml"))
        self.assertGreaterEqual(len(root.findall(".//%stbl" % W)), 8)
        text = "".join(root.itertext())
        for heading in ("1. Document control", "2. Scope summary", "3. Proposed target design", "4. System inventory",
                        "5. Data flow", "6. Trust boundaries", "7. Threat table", "8. Open questions", "9. Sign-off"):
            self.assertIn(heading, text)
        self.assertIn("Fictional Notes Co", text)
        self.assertIn("look-alike", text)
        self.assertIn("<tags> & symbols", text, "markup in content is escaped, not interpreted")
        self.assertIn("Block unknown domains", text)

    def test_pdf_has_a_consistent_xref_and_page_count(self):
        data = te.pdf_bytes(self.blocks, "Threat model: Fictional Notes Co")
        self.assertTrue(data.startswith(b"%PDF-1.4"))
        self.assertTrue(data.rstrip().endswith(b"%%EOF"))
        xref_at = int(re.search(rb"startxref\n(\d+)\n", data).group(1))
        self.assertTrue(data[xref_at:].startswith(b"xref"))
        offsets = re.findall(rb"(\d{10}) 00000 n", data[xref_at:])
        for i, off in enumerate(offsets, start=1):
            self.assertTrue(data[int(off):].startswith(b"%d 0 obj" % i), "object %d offset is wrong" % i)
        pages = int(re.search(rb"/Count (\d+)", data).group(1))
        self.assertEqual(len(re.findall(rb"/Type /Page /Parent", data)), pages)

    def test_pdf_paginates_long_tables_and_repeats_header(self):
        rows = [["TB-%d.row%d" % (i % 7 + 1, i), "A long scenario sentence that keeps going " * 4, "Medium (3x3)",
                 "Mitigate", "- one\n- two"] for i in range(90)]
        blocks = [("title", "Long"), ("table", {"head": ["ID", "Scenario", "Rating", "Disposition", "Mitigations"],
                                               "widths": [1, 3, 1, 1, 2], "rows": rows})]
        data = te.pdf_bytes(blocks, "Long")
        pages = int(re.search(rb"/Count (\d+)", data).group(1))
        self.assertGreater(pages, 2)
        self.assertIn(("Page 2 of %d" % pages).encode(), data)
        self.assertGreaterEqual(data.count(b"Scenario"), pages, "header row repeats on each page")

    def test_pdf_accepts_non_ascii_text_without_crashing(self):
        blocks = [("p", "Café – “quoted” ✓ emoji \U0001F600 and (parens) \\ backslash")]
        data = te.pdf_bytes(blocks, "Unicode – title")
        self.assertTrue(data.startswith(b"%PDF"))

    def test_undecided_model_still_exports(self):
        rec = fictional()
        model = tm.build(rec)
        blocks = te.blocks(rec, model, model["status"], "Fictional Notes Co")
        self.assertIn("Not signed. The model has not been reviewed.", "".join(str(b[1]) for b in blocks))
        te.docx_bytes(blocks)
        te.pdf_bytes(blocks)


class DiagramTests(unittest.TestCase):
    def _svg_root(self, rec):
        import threat_diagram as td
        d = td.layout(rec)
        return d, ET.fromstring(td.svg(d))

    def test_every_vendor_gets_flows_and_boundaries(self):
        d, root = self._svg_root(fictional())
        text = " ".join(t.text or "" for t in root.iter("{http://www.w3.org/2000/svg}text"))
        for i in range(1, 8):
            self.assertIn("F-%d" % i, text)
            self.assertIn("TB-%d" % i, text)
        self.assertIn("Example Model Co", text)
        self.assertEqual(root.get("role"), "img")

    def test_unconfirmed_boundaries_are_red_dashed(self):
        import threat_diagram as td
        d = td.layout(fictional(factsheet={"ai_used": "no", "gaps": []}))
        red = [e for e in d["prims"] if e["k"] == "line" and e["color"] == td.UNCONFIRMED]
        self.assertTrue(red and all(e["dash"] for e in red))
        legend = " ".join(e["s"] for e in d["prims"] if e["k"] == "text")
        self.assertIn("Not confirmed yet", legend)

    def test_answering_a_boundary_question_confirms_it(self):
        import threat_diagram as td
        rec = fictional()
        q = next(q for q in tm.build(rec)["questions"] if q["relates_to"] == ["TB-7"])
        exit_flow = lambda: next(e for e in td.layout(rec)["prims"] if e["k"] == "line" and e["pts"][-1] == (990, 548))
        self.assertTrue(exit_flow()["dash"])
        tm.set_question(rec, q["id"], "Deletion certificate within 30 days, backups expire at 35", "Vendor", "t")
        self.assertEqual({b["id"]: b["status"] for b in tm.build(rec)["boundaries"]}["TB-7"], "known")
        self.assertFalse(exit_flow()["dash"])

    def test_long_lists_collapse_into_more(self):
        import threat_diagram as td
        rec = fictional()
        rec["live_access"] = [{"id": "a%d" % i, "display_name": "App %d" % i, "app_id": "x", "scopes": ["User.Read"],
                               "kind": "oauth_app", "status": "active", "source": "manual", "last_seen": "2026-10-01",
                               "first_seen": "", "owner": ""} for i in range(9)]
        rec["factsheet"]["subprocessors"] = "; ".join("Processor %d" % i for i in range(8))
        d = td.layout(rec)
        texts = [e["s"] for e in d["prims"] if e["k"] == "text"]
        self.assertIn("+ 6 more", texts)
        self.assertTrue(any(t.startswith("+ ") and t.endswith("more") and t != "+ 6 more" for t in texts))
        ys = [e["y"] + e["h"] for e in d["prims"] if e["k"] == "rect"]
        self.assertLessEqual(max(ys), td.H, "nothing is drawn off the canvas")

    def test_names_are_escaped_in_svg(self):
        _d, root = self._svg_root(fictional(vendor="<script>alert(1)</script> & Co"))
        self.assertIsNone(root.find(".//{http://www.w3.org/2000/svg}script"))

    def test_png_fallback_is_a_png(self):
        import threat_diagram as td
        data = td.png_fallback(td.layout(fictional()))
        self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_word_export_embeds_the_diagram_on_a_landscape_page(self):
        rec = fictional()
        model = tm.build(rec)
        data = te.docx_bytes(te.blocks(rec, model, model["status"], "Fictional Notes Co"))
        z = zipfile.ZipFile(io.BytesIO(data))
        self.assertIn("word/media/diagram.svg", z.namelist())
        self.assertIn("word/media/diagram.png", z.namelist())
        doc = z.read("word/document.xml").decode()
        ET.fromstring(doc)
        self.assertIn("svgBlip", doc)
        self.assertIn('w:orient="landscape"', doc)
        ET.fromstring(z.read("word/media/diagram.svg"))

    def test_pdf_export_has_a_landscape_diagram_page(self):
        rec = fictional()
        model = tm.build(rec)
        data = te.pdf_bytes(te.blocks(rec, model, model["status"], "Fictional Notes Co"), "T")
        self.assertIn(b"/MediaBox [0 0 842 595]", data)
        xref_at = int(re.search(rb"startxref\n(\d+)\n", data).group(1))
        for i, off in enumerate(re.findall(rb"(\d{10}) 00000 n", data[xref_at:]), start=1):
            self.assertTrue(data[int(off):].startswith(b"%d 0 obj" % i))


class RouteTests(ServerCase):
    SLUG = "Route_Notes_Co"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        save_vendor(fictional(vendor="Route Notes Co", slug=cls.SLUG))
        risk_store.set_approver("local-analyst", "vp", "test")

    def _raw(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", path)
        r = c.getresponse()
        data = r.read()
        headers = {k.lower(): v for k, v in r.getheaders()}
        c.close()
        return r.status, data, headers

    def test_threat_tab_is_on_the_vendor_record(self):
        s, body, _h = self.c.get("/vendor/" + self.SLUG)
        self.assertEqual(s, 200)
        self.assertIn('data-tab="threat"', body)
        self.assertIn('data-panel="threat"', body)
        self.assertIn("TB-1.spoof_link", body, "the model is shown on first load, with no generate step")

    def test_diagram_is_on_the_tab_and_downloadable(self):
        s, body, _h = self.c.get("/vendor/" + self.SLUG)
        self.assertIn('class="tm-figure"><svg', body)
        s, data, h = self._raw("/threat/%s/diagram.svg" % self.SLUG)
        self.assertEqual(s, 200)
        self.assertEqual(h["content-type"], "image/svg+xml")
        ET.fromstring(data)

    def test_threat_page_redirects_to_the_tab(self):
        s, _b, h = self.c.get("/threat/" + self.SLUG)
        self.assertEqual(s, 303)
        self.assertEqual(h["location"], "/vendor/%s#threat" % self.SLUG)

    def test_full_flow_decide_review_export(self):
        page = "/vendor/" + self.SLUG
        s, body, _h = self.c.post("/threat/%s/threat" % self.SLUG, {"tid": "TB-1.spoof_link", "scenario": "Fake intake page",
                                  "likelihood": "4", "impact": "4", "disposition": "mitigate", "mitigations": ""}, page=page)
        self.assertEqual(s, 400)
        self.assertIn("Mitigate needs", body)

        s, _b, h = self.c.post("/threat/%s/threat" % self.SLUG, {"tid": "TB-1.spoof_link", "scenario": "Fake intake page",
                               "likelihood": "4", "impact": "4", "disposition": "mitigate",
                               "mitigations": "Block unknown domains"}, page=page)
        self.assertEqual(s, 303)
        self.assertEqual(h["location"], "/vendor/%s#threat" % self.SLUG)

        qid = tm.build(load_vendor(self.SLUG))["questions"][0]["id"]
        s, _b, _h = self.c.post("/threat/%s/question" % self.SLUG, {"qid": qid, "answer": "Vendor confirmed EU only",
                                                                  "owner": "Vendor CISO"}, page=page)
        self.assertEqual(s, 303)
        self.assertEqual(tm.build(load_vendor(self.SLUG))["questions"][0]["answer"], "Vendor confirmed EU only")

        s, body, _h = self.c.post("/threat/%s/review" % self.SLUG, {"note": ""}, page=page)
        self.assertEqual(s, 400)
        self.assertIn("still open", body)

        for t in tm.build(load_vendor(self.SLUG))["threats"]:
            if t["decided"]:
                continue
            s, _b, _h = self.c.post("/threat/%s/threat" % self.SLUG, {"tid": t["id"], "scenario": "Reviewed " + t["id"],
                                    "likelihood": "1", "impact": "1", "disposition": "transfer", "mitigations": ""}, page=page)
            self.assertEqual(s, 303, t["id"])

        s, _b, _h = self.c.post("/threat/%s/review" % self.SLUG, {"note": "Ready for the file"}, page=page)
        self.assertEqual(s, 303)
        s, body, _h = self.c.get(page)
        self.assertIn(">Reviewed</span>", body)

        s, data, h = self._raw("/threat/%s/export.docx" % self.SLUG)
        self.assertEqual(s, 200)
        self.assertTrue(data.startswith(b"PK"))
        self.assertIn("threat-model-%s-v1.docx" % self.SLUG, h["content-disposition"])
        s, data, h = self._raw("/threat/%s/export.pdf" % self.SLUG)
        self.assertEqual(s, 200)
        self.assertTrue(data.startswith(b"%PDF-1.4"))

        actions = [e["action"] for e in audit.for_slug(self.SLUG)]
        for a in ("threat_decided", "threat_question_answered", "threat_model_reviewed", "threat_model_exported"):
            self.assertIn(a, actions)

    def test_changing_the_record_changes_the_tab_without_a_refresh(self):
        from records import update_vendor
        update_vendor(self.SLUG, lambda r: (r["factsheet"].update({"hosting": "US (Virginia)"}), r)[1])
        s, body, _h = self.c.get("/vendor/" + self.SLUG)
        self.assertIn("US (Virginia)", body, "the tab reads the record as it is now")

    def test_post_without_csrf_is_refused(self):
        s, _b, _h = self.c.post("/threat/%s/review" % self.SLUG, {}, csrf=False)
        self.assertEqual(s, 403)

    def test_unknown_vendor_and_bad_action(self):
        s, _b, _h = self.c.get("/threat/No_Such_Vendor")
        self.assertEqual(s, 404)
        s, _b, _h = self.c.get("/threat/%s/unknown" % self.SLUG)
        self.assertEqual(s, 404)


if __name__ == "__main__":
    unittest.main()
