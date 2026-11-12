"""AI questionnaire: website research, model output validation, analyst approval, vendor answers.

No network and no model calls: the model and the web are replaced with fakes.
"""
from __future__ import annotations

import re
import unittest
from urllib.parse import urlencode

from test_app import ServerCase  # sets up the throwaway data folder first

import ai_questionnaire  # noqa: E402
import llm  # noqa: E402
import tokens  # noqa: E402
import vendor_research as vr  # noqa: E402
from records import load_vendor  # noqa: E402

PAGES = {
    "https://acme.example/security": (
        "<html><head><title>Acme Security</title><script>steal()</script></head><body>"
        "<h1>Security at Acme</h1><p>" + "We encrypt data at rest with AES-256. " * 20 + "</p>"
        '<a href="/trust/subprocessors">Subprocessors</a> <a href="/careers">Careers</a> '
        '<a href="https://evil.example/security">Elsewhere</a> <a href="/docs/security-whitepaper.pdf">Whitepaper</a>'
        "</body></html>"),
    "https://acme.example/trust/subprocessors": (
        "<html><head><title>Subprocessors</title></head><body><p>" + "AWS us-east-1 hosts all customer data. " * 20 + "</p></body></html>"),
}
PAGE_URLS = set(PAGES)

MODEL_REPLY = {
    "profile": {
        "summary": "Acme is a <b>SaaS</b> tool.", "data_flow": "Browser to Acme API to AWS.", "published_material": "adequate",
        "areas": {"encryption": {"status": "covered", "notes": "AES-256 at rest.", "sources": ["https://acme.example/security", "https://forged.example/x"]},
                  "made_up_area": {"status": "covered"}},
        "product_notes": ["Indexes customer repositories."],
    },
    "questions": [
        {"area": "vuln", "text": "When was your last penetration test, and by which firm?", "why": "Not published.", "priority": "high", "feeds": "pentest_current"},
        {"area": "retention", "text": "Can indexed code be deleted, and what stops working if it is?", "why": "Deletion impact unclear.", "priority": "high", "feeds": ""},
        {"area": "not_an_area", "text": "<script>alert(1)</script> Who can read our data?", "why": "x", "priority": "urgent", "feeds": "exception"},
        {"area": "vuln", "text": "When was your last penetration test, and by which firm?", "why": "duplicate"},
        {"area": "ai", "text": "short"},
    ],
}


def fake_fetch(url):
    if url not in PAGES:
        raise vr.ResearchError("HTTP 404")
    return url, PAGES[url]


class ResearchTests(unittest.TestCase):
    def test_internal_addresses_are_refused(self):
        for bad in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://10.1.2.3/", "http://[::1]/",
                    "http://192.168.0.1/", "https://example.com:8443/", "file:///etc/passwd", "ftp://example.com/",
                    "https://user:pw@example.com/"):
            with self.assertRaises(vr.ResearchError, msg=bad):
                vr.public_url(bad)

    def test_page_text_skips_scripts(self):
        title, text, links = vr.parse(PAGES["https://acme.example/security"])
        self.assertEqual(title, "Acme Security")
        self.assertIn("AES-256", text)
        self.assertNotIn("steal()", text)
        self.assertIn("/trust/subprocessors", links)

    def test_site_of(self):
        self.assertEqual(vr.site_of("docs.cursor.com"), "cursor.com")
        self.assertEqual(vr.site_of("www.example.co.uk"), "example.co.uk")

    def test_crawl_stays_on_site_and_follows_security_links(self):
        saved = (vr.fetch, vr.public_url)
        vr.fetch, vr.public_url = fake_fetch, (lambda u: u)
        try:
            r = vr.research("https://acme.example/security")
        finally:
            vr.fetch, vr.public_url = saved
        urls = [p["url"] for p in r["pages"]]
        self.assertEqual(urls, ["https://acme.example/security", "https://acme.example/trust/subprocessors"])
        self.assertEqual(r["documents"], ["https://acme.example/docs/security-whitepaper.pdf"])


class CleaningTests(unittest.TestCase):
    def test_model_output_is_forced_into_shape(self):
        profile, qs = ai_questionnaire.clean_result(MODEL_REPLY, PAGE_URLS)
        self.assertEqual(profile["areas"]["encryption"]["sources"], ["https://acme.example/security"], "forged source dropped")
        self.assertNotIn("made_up_area", profile["areas"])
        self.assertEqual(len(qs), 4, "duplicate and too-short questions dropped; the required integrations question added")
        self.assertEqual((qs[-1]["feeds"], qs[-1]["source"]), ("integrations", "required"))
        odd = qs[2]
        self.assertEqual((odd["area"], odd["priority"], odd["feeds"]), ("governance", "medium", ""))
        self.assertEqual(qs[0]["feeds"], "pentest_current")

    def test_form_cannot_forge_feeds_or_why(self):
        _p, qs = ai_questionnaire.clean_result(MODEL_REPLY, PAGE_URLS)
        fields = {"n": "3",
                  "q0_id": qs[0]["id"], "q0_keep": "on", "q0_text": "Edited: last pentest date and firm?", "q0_area": "vuln",
                  "q1_id": qs[1]["id"], "q1_text": "dropped because unticked", "q1_area": "retention",
                  "q2_id": "q_deadbeef", "q2_keep": "on", "q2_text": "Injected row claiming to feed a rule", "q2_area": "ai",
                  "new0_text": "Do you support customer-managed keys?", "new0_area": "encryption"}
        out = ai_questionnaire.questions_from_form(fields, qs)
        self.assertEqual([q["text"][:7] for q in out], ["Edited:", "Injecte", "Do you ", "List ev"],
                         "the required integrations question comes back if it was not kept")
        self.assertEqual(out[0]["feeds"], "pentest_current", "stored feeds kept")
        self.assertEqual((out[1]["feeds"], out[1]["source"]), ("", "analyst"), "unknown id cannot claim a rule field")
        self.assertEqual(out[2]["source"], "analyst")


class _SyncThread:
    def __init__(self, target, args=(), daemon=None):
        self.target, self.args = target, args

    def start(self):
        self.target(*self.args)


class AiFlowTests(ServerCase):
    def setUp(self):
        self.saved = (llm.configured, llm.chat_json, vr.research, vr.public_url, ai_questionnaire.threading.Thread)
        llm.configured = lambda: True
        llm.chat_json = lambda system, user, **kw: MODEL_REPLY
        vr.research = lambda start, website="": {"fetched_at": "2026-09-29T00:00:00+00:00", "start": start, "documents": [], "errors": [],
                                                 "pages": [{"url": u, "title": "t", "text": "x" * 300} for u in PAGES]}
        vr.public_url = lambda u: u if u.startswith("https://acme.example") else (_ for _ in ()).throw(vr.ResearchError("internal"))
        ai_questionnaire.threading.Thread = _SyncThread

    def tearDown(self):
        llm.configured, llm.chat_json, vr.research, vr.public_url, ai_questionnaire.threading.Thread = self.saved

    def test_draft_approve_answer(self):
        self.make_vendor("Acme AI Co", website="https://acme.example")
        slug = "Acme_AI_Co"
        s, page, _h = self.c.post("/ai/draft", {"slug": slug, "source_url": "http://169.254.169.254/"})
        self.assertEqual(s, 400)
        self.assertIn("internal", page)

        s, _b, _h = self.c.post("/ai/draft", {"slug": slug, "source_url": "https://acme.example/security", "context": "Our monorepo"})
        self.assertEqual(s, 303)
        _s, page, _h = self.c.get("/ai/" + slug)
        self.assertIn("Indexes customer repositories.", page)
        self.assertIn("&lt;b&gt;SaaS&lt;/b&gt;", page)
        self.assertIn("&lt;script&gt;alert(1)", page)
        self.assertNotIn("<script>alert(1)", page)

        draft = load_vendor(slug)["ai_q"]["draft"]
        form = {"slug": slug, "n": str(len(draft)), "do": "approve", "new0_text": "Where is indexed code stored?", "new0_area": "dataflow"}
        for i, q in enumerate(draft):
            form.update({"q%d_id" % i: q["id"], "q%d_text" % i: q["text"], "q%d_area" % i: q["area"]})
            if "alert" not in q["text"]:
                form["q%d_keep" % i] = "on"
        s, _b, h = self.c.post("/ai/questions", form, page="/ai/" + slug)
        self.assertEqual(s, 303)
        token = h["location"].rsplit("/", 1)[1]
        self.assertEqual(tokens.lookup(token)["kind"], "ai")
        approved = load_vendor(slug)["ai_q"]["approved"]
        self.assertEqual(len(approved), 4, "three kept or added, plus the required integrations question")
        self.assertEqual(sum(1 for q in approved if q["feeds"] == "integrations"), 1)

        _s, portal, _h = self.c.get("/q/" + token)
        self.assertIn("When was your last penetration test", portal)
        self.assertIn("Where is indexed code stored?", portal)
        self.assertNotIn("alert(1)", portal, "question the analyst removed is not sent")

        pen = next(q for q in approved if q["feeds"] == "pentest_current")
        body = urlencode({pen["id"]: "Executive summary only, no findings attached", "sneaky_field": "x"})
        s, _b, _h = self.c.req("POST", "/q/" + token, body, {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(s, 200)
        rec = load_vendor(slug)
        self.assertIn(pen["id"], rec["ai_answers"])
        self.assertNotIn("sneaky_field", rec["ai_answers"])
        self.assertIn("pentest_exec_only", {f["id"] for f in rec["followups"]}, "fixed rule still fires on AI answers")
        _s, page, _h = self.c.get("/vendor/" + slug)
        self.assertTrue(re.search(r"When was your last penetration test.*Executive summary only", page, re.S))

    def test_no_model_configured(self):
        llm.configured = lambda: False
        self.make_vendor("No Model Co")
        s, page, _h = self.c.post("/ai/draft", {"slug": "No_Model_Co", "source_url": ""})
        self.assertEqual(s, 400)
        self.assertIn("No model is configured", page)


HVAC_REPLY = {
    "profile": {"engagement": "On-site HVAC contractor with remote access to building controllers.", "published_material": "none",
                "summary": "No published security material.", "areas": {}},
    "questions": [
        {"area": "accounts", "kind": "answer", "text": "Will your technicians use named accounts, a temporary account, or a shared login?", "priority": "high"},
        {"area": "systems_access", "kind": "answer", "text": "Which hosts or controllers will you connect to, and with what remote tool?", "priority": "high"},
        {"area": "governance", "kind": "document", "doc_type": "Certificate of insurance", "if_missing": "high",
         "text": "Please upload your current certificate of insurance.", "feeds": "soc2"},
        {"area": "personnel", "kind": "document", "doc_type": "Background check policy", "if_missing": "low",
         "text": "Please upload your technician background check policy."},
        {"area": "devices", "kind": "document", "doc_type": "Network diagram", "if_missing": "medium",
         "text": "Please upload a diagram of how your equipment connects to our network."},
    ],
}


def _multipart(fields: dict, files: dict):
    b = "AIBOUNDARY"
    body = b"".join(('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (b, k, v)).encode() for k, v in fields.items())
    for name, (fname, data) in files.items():
        body += ('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n'
                 % (b, name, fname)).encode() + data + b"\r\n"
    return body + ("--%s--\r\n" % b).encode(), {"Content-Type": "multipart/form-data; boundary=" + b}


class DocumentFlowTests(AiFlowTests):
    def setUp(self):
        super().setUp()
        llm.chat_json = lambda system, user, **kw: HVAC_REPLY

    def test_draft_approve_answer(self):  # inherited flow is covered in AiFlowTests
        pass

    def test_no_model_configured(self):
        pass

    def test_documents_flag_by_severity_and_no_soc2_flag(self):
        self.make_vendor("Cool Air HVAC")
        slug = "Cool_Air_HVAC"
        self.assertEqual(self.c.post("/ai/draft", {"slug": slug, "source_url": ""})[0], 303)
        draft = load_vendor(slug)["ai_q"]["draft"]
        insurance = next(q for q in draft if q["doc_type"] == "Certificate of insurance")
        self.assertEqual((insurance["kind"], insurance["if_missing"], insurance["feeds"]), ("document", "high", ""),
                         "a document request never feeds a text rule")
        form = {"slug": slug, "n": str(len(draft)), "do": "approve"}
        for i, q in enumerate(draft):
            form.update({"q%d_id" % i: q["id"], "q%d_text" % i: q["text"], "q%d_area" % i: q["area"], "q%d_keep" % i: "on",
                         "q%d_if_missing" % i: q["if_missing"] or "medium"})
        s, _b, h = self.c.post("/ai/questions", form, page="/ai/" + slug)
        token = h["location"].rsplit("/", 1)[1]
        approved = {q["doc_type"] or q["area"]: q for q in load_vendor(slug)["ai_q"]["approved"]}

        _s, portal, _h = self.c.get("/q/" + token)
        self.assertIn('enctype="multipart/form-data"', portal)
        self.assertIn("We do not have this document", portal)

        bg, net = approved["Background check policy"], approved["Network diagram"]
        body, headers = _multipart(
            {approved["accounts"]["id"]: "One shared login for all technicians", bg["id"] + "__none": "yes", bg["id"]: "We do not run checks"},
            {"file_" + insurance["id"]: ("insurance.pdf", b"%PDF-1.4 certificate"), "file_" + net["id"]: ("diagram.pdf", b"not a pdf")})
        s, received, _h = self.c.req("POST", "/q/" + token, body, headers)
        self.assertEqual(s, 200)
        self.assertIn("were not accepted", received)

        rec = load_vendor(slug)
        docs = rec["ai_docs"]
        self.assertEqual(docs[insurance["id"]]["status"], "provided")
        self.assertEqual(docs[bg["id"]]["status"], "not_available")
        self.assertEqual(docs[net["id"]]["status"], "missing")
        self.assertTrue(any(f.get("question_id") == insurance["id"] and f["uploaded_by"] == "vendor:" + slug for f in rec["evidence_files"]))
        flags = {f["id"]: f for f in rec["followups"]}
        self.assertNotIn("doc_" + insurance["id"], flags)
        self.assertEqual(flags["doc_" + bg["id"]]["severity"], "low")
        self.assertIn("cannot provide", flags["doc_" + bg["id"]]["title"])
        self.assertEqual(flags["doc_" + net["id"]]["severity"], "medium")
        self.assertNotIn("soc2_missing", flags, "the AI did not ask an HVAC contractor for a SOC 2")
        self.assertNotIn("pentest_missing", flags)

        # Resubmitting without the file keeps the earlier upload.
        body, headers = _multipart({approved["accounts"]["id"]: "Named accounts from now on"}, {})
        self.c.req("POST", "/q/" + token, body, headers)
        self.assertEqual(load_vendor(slug)["ai_docs"][insurance["id"]]["status"], "provided")


class LlmTests(unittest.TestCase):
    def test_parse_json_tolerates_fences_and_chatter(self):
        self.assertEqual(llm.parse_json('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(llm.parse_json('Here you go: {"a": 2} hope it helps'), {"a": 2})
        with self.assertRaises(llm.LLMError):
            llm.parse_json("no json here")


if __name__ == "__main__":
    unittest.main()
