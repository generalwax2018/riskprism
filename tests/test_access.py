import unittest

import access_flags
import access_store


class AccessStoreTests(unittest.TestCase):
    def test_drops_empty_name(self):
        self.assertIsNone(access_store.normalize_row({"scopes": ["Mail.Send"]}))

    def test_keeps_known_shape(self):
        row = access_store.normalize_row({
            "display_name": "Slack", "kind": "oauth_app", "source": "demo",
            "scopes": "chat:write users:read", "status": "active",
        })
        self.assertEqual(row["display_name"], "Slack")
        self.assertEqual(row["scopes"], ["chat:write", "users:read"])

    def test_replace_dedupes(self):
        rec = access_store.replace_rows({}, [
            {"display_name": "A", "id": "1"},
            {"display_name": "A-again", "id": "1"},
        ])
        self.assertEqual(len(rec["live_access"]), 1)


class AccessFlagTests(unittest.TestCase):
    def test_blind_authorized(self):
        flags = access_flags.findings({"authorization": "authorized", "live_access": []})
        self.assertTrue(any(c == "access_blind" for c, _, _ in flags))

    def test_access_after_offboard(self):
        flags = access_flags.findings({
            "stage": "offboarded",
            "live_access": [{"display_name": "Slack", "status": "active"}],
        })
        self.assertTrue(any(c == "access_after_offboard" for c, _, _ in flags))

    def test_offboard_clean_is_silent(self):
        flags = access_flags.findings({"stage": "offboarded", "live_access": []})
        self.assertEqual(flags, [])

    def test_write_scope(self):
        flags = access_flags.findings({
            "authorization": "trial_only",
            "live_access": [{
                "display_name": "Mystery AI",
                "status": "active",
                "scopes": ["Mail.Send"],
            }],
        })
        self.assertTrue(any(c == "access_write_scope" for c, _, _ in flags))


class AccessPanelTests(unittest.TestCase):
    def test_panel_lists_rows_and_escapes(self):
        import views
        html = views._access_html({
            "authorization": "trial_only",
            "live_access": [{"display_name": "<b>Evil</b> AI", "status": "active", "scopes": ["Mail.Send"]}],
        })
        self.assertIn("&lt;b&gt;Evil&lt;/b&gt; AI", html)
        self.assertNotIn("<b>Evil</b>", html)
        self.assertIn("write-class scopes", html)

    def test_panel_empty_says_blind_spot(self):
        import views
        html = views._access_html({"authorization": "authorized", "live_access": []})
        self.assertIn("blind spot", html)


if __name__ == "__main__":
    unittest.main()
