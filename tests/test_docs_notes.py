"""Analyst notes and the document repository.

Runs with the other tests:  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import re
import sqlite3
import unittest
from datetime import date, timedelta

from test_app import ServerCase  # sets up the throwaway data folder first

import config  # noqa: E402
import documents  # noqa: E402
import notes_store  # noqa: E402
from records import load_vendor  # noqa: E402

TODAY = date.today()
PDF = b"%PDF-1.4\n% test file\n"


def _upload(csrf, slug, filename=b"report.pdf", data=PDF, **fields):
    b = "DOCBOUNDARY"
    parts = {"_csrf": csrf, "slug": slug, **fields}
    body = b"".join(('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (b, k, v)).encode() for k, v in parts.items())
    body += ('--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\nContent-Type: application/pdf\r\n\r\n'
             % (b, filename.decode())).encode() + data + ("\r\n--%s--\r\n" % b).encode()
    return body, {"Content-Type": "multipart/form-data; boundary=" + b}


class DocumentLogicTests(unittest.TestCase):
    def test_unreviewed_is_never_green(self):
        f = {"kind": "soc2_type2", "valid_until": (TODAY + timedelta(days=200)).isoformat()}
        self.assertEqual(documents.status(f)[0], "unreviewed")
        f["reviewed_by"] = "ana@example.com"
        self.assertEqual(documents.status(f)[:3:2], ("reviewed", "green"))

    def test_expired_beats_reviewed(self):
        f = {"kind": "pentest", "valid_until": (TODAY - timedelta(days=1)).isoformat(), "reviewed_by": "ana"}
        self.assertEqual(documents.status(f)[0], "expired")

    def test_soc_report_goes_stale_a_year_after_its_period(self):
        f = {"kind": "soc2_type2", "period_end": (TODAY - timedelta(days=400)).isoformat(), "reviewed_by": "ana"}
        self.assertEqual(documents.status(f)[0], "expired")
        f["kind"] = "contract"  # contracts do not age out by period
        self.assertEqual(documents.status(f)[0], "reviewed")

    def test_clock_only_moves_forward(self):
        later = (TODAY + timedelta(days=300)).isoformat()
        rec = {"soc2_expires": (TODAY + timedelta(days=30)).isoformat()}
        self.assertEqual(documents.clock_update(rec, {"kind": "soc2_type2", "valid_until": later}), ("soc2_expires", later))
        rec["soc2_expires"] = (TODAY + timedelta(days=400)).isoformat()
        self.assertIsNone(documents.clock_update(rec, {"kind": "soc2_type2", "valid_until": later}))
        self.assertIsNone(documents.clock_update({}, {"kind": "insurance", "valid_until": later}))

    def test_bad_dates_are_dropped(self):
        m = documents.clean_meta({"period_end": "2026-13-40", "valid_until": "next year", "description": "  a   b "})
        self.assertEqual((m["period_end"], m["valid_until"], m["description"]), ("", "", "a b"))

    def test_unknown_type_becomes_other(self):
        self.assertEqual(documents.valid_kind("<script>"), "other")
        self.assertEqual(documents.label("soc2"), "SOC 2 / ISO")  # legacy uploads still read


class NoteStoreTests(unittest.TestCase):
    def test_notes_cannot_be_edited_or_deleted(self):
        nid = notes_store.add("Store_Co", "general", "first", "ana@example.com")
        con = sqlite3.connect(str(config.RISK_DB_PATH))
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute("UPDATE vendor_notes SET body = 'changed' WHERE id = ?", (nid,))
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute("DELETE FROM vendor_notes WHERE id = ?", (nid,))
        finally:
            con.close()

    def test_correction_must_be_on_same_vendor(self):
        nid = notes_store.add("Vendor_A", "general", "about A", "ana")
        with self.assertRaises(notes_store.NoteError):
            notes_store.add("Vendor_B", "general", "sneaky", "ana", corrects=nid)

    def test_empty_and_oversized_notes_refused(self):
        with self.assertRaises(notes_store.NoteError):
            notes_store.add("Vendor_A", "general", "   ", "ana")
        with self.assertRaises(notes_store.NoteError):
            notes_store.add("Vendor_A", "general", "x" * (notes_store.BODY_MAX + 1), "ana")

    def test_unknown_kind_becomes_general(self):
        nid = notes_store.add("Vendor_K", "evil'kind", "hello", "ana")
        self.assertEqual(next(n for n in notes_store.for_vendor("Vendor_K") if n["id"] == nid)["kind"], "general")


class NotesAndDocumentsHttpTests(ServerCase):
    def test_add_and_correct_a_note(self):
        self.make_vendor("Notes Co")
        s, _b, h = self.c.post("/note", {"slug": "Notes_Co", "kind": "finding", "body": "MFA not enforced for <b>admins</b>"})
        self.assertEqual(s, 303)
        self.assertIn("#notes", h["location"])
        _s, page, _h = self.c.get("/vendor/Notes_Co")
        self.assertIn("MFA not enforced for &lt;b&gt;admins&lt;/b&gt;", page)
        nid = notes_store.for_vendor("Notes_Co")[0]["id"]
        s, _b, _h = self.c.post("/note", {"slug": "Notes_Co", "kind": "finding", "body": "MFA enforced, confirmed on call", "corrects": str(nid)})
        self.assertEqual(s, 303)
        _s, page, _h = self.c.get("/vendor/Notes_Co")
        self.assertIn("corrected by #", page)
        self.assertIn("corrects #%d" % nid, page)

    def test_note_needs_csrf(self):
        self.make_vendor("Csrf Note Co")
        s, _b, _h = self.c.post("/note", {"slug": "Csrf_Note_Co", "body": "x"}, csrf=False)
        self.assertEqual(s, 403)

    def test_empty_note_shows_error(self):
        self.make_vendor("Empty Note Co")
        s, page, _h = self.c.post("/note", {"slug": "Empty_Note_Co", "body": "  "})
        self.assertEqual(s, 400)
        self.assertIn("Write something", page)

    def test_upload_moves_clock_and_review_is_recorded(self):
        self.make_vendor("Docs Co")
        until = (TODAY + timedelta(days=330)).isoformat()
        body, hdr = _upload(self.c.csrf(), "Docs_Co", kind="soc2_type2", valid_until=until,
                            period_end=(TODAY - timedelta(days=35)).isoformat(), description="FY26 Type II", back="vendor")
        s, _b, h = self.c.req("POST", "/evidence", body, hdr)
        self.assertEqual(s, 303)
        self.assertIn("/vendor/Docs_Co#documents", h["location"])
        rec = load_vendor("Docs_Co")
        f = rec["evidence_files"][-1]
        self.assertEqual((f["kind"], f["valid_until"], f["description"], f["reviewed_by"]), ("soc2_type2", until, "FY26 Type II", ""))
        self.assertEqual(rec["soc2_expires"], until)
        _s, page, _h = self.c.get("/vendor/Docs_Co")
        self.assertIn("Not reviewed", page)

        s, _b, _h = self.c.post("/document/review", {"slug": "Docs_Co", "doc_id": f["id"], "note": "No exceptions; CUEC 4 is ours"})
        self.assertEqual(s, 303)
        f = load_vendor("Docs_Co")["evidence_files"][-1]
        self.assertTrue(f["reviewed_by"] and f["reviewed_at"])
        review = notes_store.for_doc("Docs_Co", f["id"])
        self.assertEqual(len(review), 1)
        self.assertEqual(review[0]["kind"], "doc_review")

    def test_review_of_unknown_document_is_404(self):
        self.make_vendor("Ghost Doc Co")
        s, _b, _h = self.c.post("/document/review", {"slug": "Ghost_Doc_Co", "doc_id": "nope"})
        self.assertEqual(s, 404)

    def test_wrong_magic_bytes_rejected(self):
        self.make_vendor("Fake Pdf Co")
        body, hdr = _upload(self.c.csrf(), "Fake_Pdf_Co", data=b"MZ\x90\x00 not a pdf", kind="pentest")
        s, page, _h = self.c.req("POST", "/evidence", body, hdr)
        self.assertEqual(s, 400)
        self.assertIn("do not match", page)
        self.assertFalse(load_vendor("Fake_Pdf_Co").get("evidence_files"))

    def test_library_lists_and_filters(self):
        self.make_vendor("Library Co")
        body, hdr = _upload(self.c.csrf(), "Library_Co", filename=b"insurance.pdf", kind="insurance")
        self.c.req("POST", "/evidence", body, hdr)
        _s, page, _h = self.c.get("/documents")
        self.assertIn("insurance.pdf", page)
        _s, page, _h = self.c.get("/documents?type=pentest&q=library")
        self.assertNotIn("insurance.pdf", page)
        _s, page, _h = self.c.get("/documents?status=unreviewed&q=library")
        self.assertIn("insurance.pdf", page)
        _s, page, _h = self.c.get("/documents?q=%3Cscript%3E")
        self.assertNotIn("<script>", page)

    def test_vendor_portal_upload_gets_a_real_type(self):
        self.assertEqual(documents.guess_kind("SOC 2 Type I report"), "soc2_type1")
        self.assertEqual(documents.guess_kind("Most recent penetration test"), "pentest")


if __name__ == "__main__":
    unittest.main()
