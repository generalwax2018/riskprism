"""Declared versus observed scopes on the vendor Integrations tab."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_app import ServerCase  # noqa: E402  (sets up the throwaway data folder first)

import access_store  # noqa: E402
import environment as env  # noqa: E402
import integrations as ig  # noqa: E402
import integrations_demo  # noqa: E402
import shadow  # noqa: E402
from records import delete_vendor, load_vendor, save_vendor  # noqa: E402

DEMO = tuple(v["slug"] for v in integrations_demo.VENDORS)


def setUpModule():
    integrations_demo.run()


def tearDownModule():
    for slug in DEMO:
        delete_vendor(slug)
    for p in (ig.PATH, env.PATH, shadow.PATH):
        if p.exists():
            p.unlink()


class DriftTests(ServerCase):
    def test_match_missing_and_undeclared(self):
        d = {p["name"]: p for p in ig.drift("ServiceNow")["pairs"]}
        spoke = d["ServiceNow Entra ID spoke (IntegrationHub)"]
        self.assertEqual((spoke["observed_only"], spoke["declared_only"]), ([], []))
        intune = d["Service Graph connector for Microsoft Intune"]
        self.assertEqual(intune["declared_only"], ["DeviceManagementApps.Read.All"])
        self.assertFalse(d["ServiceNow notifications in Microsoft Teams"]["observed_known"])
        fn = ig.drift("Fieldnote_AI")
        self.assertEqual(fn["pairs"][0]["observed_only"], ["Files.Read.All"])
        self.assertEqual(fn["drifting"], 1)

    def test_unrecorded_live_app(self):
        rec = load_vendor("Workday")
        access_store.replace_rows(rec, [access_store.normalize_row({"display_name": "Workday Reports Bot", "app_id": "wd-bot-1",
                                                                     "scopes": ["Mail.Send"], "status": "active", "source": "entra"})])
        save_vendor(rec)
        d = ig.drift("Workday")
        self.assertEqual([u["app_id"] for u in d["unrecorded"]], ["wd-bot-1"])
        _s, page, _h = self.c.get("/vendor/Workday")
        self.assertIn("Declared vs observed", page)
        self.assertIn("not recorded", page)
        _s, page, _h = self.c.get("/vendor/Fieldnote_AI")
        self.assertIn('dr-scope bad mono">Files.Read.All', page)


if __name__ == "__main__":
    unittest.main()
