"""Per-request caching (memo.py) and the one-pass indexes that keep big portfolios fast."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_app import ServerCase  # noqa: E402  (sets up the throwaway data folder first)

import access_store  # noqa: E402
import control_objectives as co  # noqa: E402
import integrations as ig  # noqa: E402
import memo  # noqa: E402
import records  # noqa: E402


def _vendor(slug, **extra):
    records.save_vendor({"vendor": slug.replace("_", " "), "slug": slug, "stage": "active", **extra}, replace=True)


class MemoTests(unittest.TestCase):
    def tearDown(self):
        for s in ("Memo_A", "Memo_B", "Memo_C"):
            records.delete_vendor(s)

    def test_no_caching_outside_a_request(self):
        calls = []
        memo.cached("k", lambda: calls.append(1))
        memo.cached("k", lambda: calls.append(1))
        self.assertEqual(len(calls), 2)

    def test_reused_within_a_request_and_dropped_after(self):
        calls = []
        with memo.request():
            memo.cached("k", lambda: calls.append(1) or "v")
            self.assertEqual(memo.cached("k", lambda: calls.append(1) or "v"), "v")
        self.assertEqual(len(calls), 1)
        with memo.request():
            memo.cached("k", lambda: calls.append(1) or "v")
        self.assertEqual(len(calls), 2)

    def test_a_write_inside_the_request_is_seen_straight_away(self):
        _vendor("Memo_A")
        with memo.request():
            before = {r["slug"] for r in records.list_vendors()}
            _vendor("Memo_B")
            after = {r["slug"] for r in records.list_vendors()}
            records.delete_vendor("Memo_A")
            gone = {r["slug"] for r in records.list_vendors()}
        self.assertNotIn("Memo_B", before)
        self.assertIn("Memo_B", after)
        self.assertNotIn("Memo_A", gone)

    def test_overview_computed_once_per_request(self):
        with mock.patch.object(ig, "_overview", wraps=ig._overview) as spy, memo.request():
            ig.overview()
            ig.overview()
            co.matrix()
        self.assertEqual(spy.call_count, 1)

    def test_observed_scopes_are_indexed_not_rescanned(self):
        _vendor("Memo_C")
        rec = records.load_vendor("Memo_C")
        access_store.replace_rows(rec, [access_store.normalize_row({"display_name": "Memo app", "app_id": "memo-app",
                                                                     "scopes": ["Mail.Read", "Mail.Send"], "status": "active"})])
        records.save_vendor(rec)
        row = ig.normalize({"name": "Memo int", "source": "Memo_C", "target": "you", "mechanism": "oauth_app",
                            "app_id": "memo-app", "scopes": [{"name": "Mail.Read", "grant": "delegated"}], "status": "active"})
        vendors = ig._vendors()
        index = ig.observed_index(vendors)
        self.assertEqual(index["memo-app"], {"Mail.Read", "Mail.Send"})
        self.assertEqual(ig.findings(row, vendors), ig.findings(row, vendors, observed=index))
        self.assertIn("scope_drift", [f[0] for f in ig.findings(row, vendors, observed=index)])
        with mock.patch.object(access_store, "rows", wraps=access_store.rows) as spy:
            for _ in range(20):
                ig.findings(row, vendors, observed=index)
        self.assertEqual(spy.call_count, 0)


class MemoServerTests(ServerCase):
    def test_save_then_render_in_one_request_shows_the_save(self):
        # environment setup writes, then renders the page from the same request
        s, page, _h = self.c.post("/environment/setup", {"idp": "Okta", "collab": "Google Workspace"}, page="/environment")
        self.assertEqual(s, 200)
        self.assertIn("Saved. 2 systems", page)
        self.assertIn("Okta", page)


if __name__ == "__main__":
    unittest.main()
