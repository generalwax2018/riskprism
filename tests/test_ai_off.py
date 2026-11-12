"""ENTROPY_AI=off: no AI controls, no model calls, no vendor website fetches, everything else still works."""
from __future__ import annotations

import os
import unittest
from unittest import mock

from test_app import ServerCase  # sets up the throwaway data folder first

import config  # noqa: E402
import llm  # noqa: E402
import vendor_research as vr  # noqa: E402


class AiOffTests(ServerCase):
    def setUp(self):
        self.patch = mock.patch.object(config, "AI_ENABLED", False)
        self.patch.start()
        self.env = mock.patch.dict(os.environ, {"LLM_BASE_URL": "https://api.example/v1", "LLM_API_KEY": "k"})
        self.env.start()

    def tearDown(self):
        self.patch.stop()
        self.env.stop()

    def test_model_layer_refuses_even_when_configured(self):
        self.assertFalse(llm.configured())
        self.assertIn("off", llm.describe())
        with mock.patch("urllib.request.urlopen") as net:
            with self.assertRaises(llm.LLMError):
                llm.chat("s", "u")
            net.assert_not_called()

    def test_website_research_refuses(self):
        with self.assertRaises(vr.ResearchError):
            vr.fetch("https://acme.example/security")
        with self.assertRaises(vr.ResearchError):
            vr.research("https://acme.example/security")

    def test_ai_controls_hidden_and_routes_refused(self):
        self.make_vendor("No AI Co")
        s, page, _h = self.c.get("/vendor/No_AI_Co")
        self.assertEqual(s, 200)
        self.assertNotIn('href="/ai/No_AI_Co"', page)
        self.assertNotIn("Ask AI for a date", page)
        self.assertIn("AI: off (enforced)", page)
        s, page, _h = self.c.get("/ai/No_AI_Co")
        self.assertEqual(s, 403)
        for path in ("/ai/draft", "/ai/questions", "/accept/suggest"):
            s, _b, _h = self.c.post(path, {"slug": "No_AI_Co", "source_url": "https://acme.example/"})
            self.assertEqual(s, 403, path)
        # the manual workflow is untouched
        for path in ("/", "/integrations", "/controls", "/environment", "/threat/No_AI_Co/export.pdf"):
            s, _b, _h = self.c.get(path)
            self.assertIn(s, (200, 303), path)

    def test_startup_rejects_unknown_value(self):
        with mock.patch.dict(os.environ, {"ENTROPY_AI": "maybe"}):
            self.assertTrue(any("ENTROPY_AI" in p for p in config.check_startup()))


class AiOnTests(ServerCase):
    def test_button_shows_when_enabled(self):
        self.make_vendor("With AI Co")
        _s, page, _h = self.c.get("/vendor/With_AI_Co")
        self.assertIn('href="/ai/With_AI_Co"', page)
        self.assertNotIn("AI: off (enforced)", page)


if __name__ == "__main__":
    unittest.main()
