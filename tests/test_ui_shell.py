"""The page shell: glass toolbar and grouped sidebar, light and dark, nothing loaded from outside."""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_app import ServerCase  # noqa: E402  (sets up the throwaway data folder first)

ROOT = Path(__file__).resolve().parent.parent
CSS = (ROOT / "static" / "app.css").read_text(encoding="utf-8")


class StylesheetTests(unittest.TestCase):
    def test_follows_system_light_and_dark(self):
        self.assertIn("@media (prefers-color-scheme: dark)", CSS)
        self.assertIn("color-scheme: light", CSS)
        self.assertIn("color-scheme: dark", CSS)

    def test_loads_nothing_from_outside(self):
        self.assertNotIn("@import", CSS)
        self.assertNotRegex(CSS, r"url\(\s*['\"]?(https?:)?//")

    def test_readable_without_backdrop_blur(self):
        self.assertIn("@supports not ((backdrop-filter: blur(1px))", CSS)

    def test_braces_balance(self):
        self.assertEqual(CSS.count("{"), CSS.count("}"))


class ShellTests(ServerCase):
    def test_every_view_marks_itself_once(self):
        for path, label in (("/", "Portfolio"), ("/executive", "Executive"), ("/findings", "Findings"), ("/alerts", "Renewals"),
                            ("/risk", "Risk acceptance"), ("/controls", "Control objectives"), ("/environment", "Your environment"),
                            ("/integrations", "Integrations"), ("/shadow", "Shadow IT"), ("/documents", "Documents"),
                            ("/policy", "Policy"), ("/report", "Report a tool"), ("/import", "Import CSV")):
            s, page, _h = self.c.get(path)
            self.assertEqual(s, 200, path)
            on = re.findall(r'<a class="on" href="([^"]*)">', page)
            self.assertEqual(len(on), 1, (path, on))
            self.assertIn(label, page)
            self.assertIn('class="topbar"', page)
            self.assertIn('class="rail"', page)
            self.assertIn('<meta name="color-scheme" content="light dark">', page)

    def test_no_outside_requests_in_pages(self):
        _s, page, _h = self.c.get("/")
        for tag in re.findall(r"<(?:link|script|img)\b[^>]*>", page):
            self.assertNotRegex(tag, r"(src|href)=\"(https?:)?//", tag)


class PublicRepoTests(unittest.TestCase):
    def test_research_user_agent_names_this_server_only(self):
        import config
        import vendor_research
        saved = config.BASE_URL
        try:
            config.BASE_URL = ""
            self.assertNotIn("http", vendor_research.user_agent())
            config.BASE_URL = "https://grc.example.org"
            self.assertIn("+https://grc.example.org", vendor_research.user_agent())
        finally:
            config.BASE_URL = saved

    def test_license_and_notices_ship(self):
        self.assertIn("MIT License", (ROOT / "LICENSE").read_text(encoding="utf-8"))
        self.assertIn("qrcodegen.py", (ROOT / "THIRD_PARTY.md").read_text(encoding="utf-8"))
        self.assertIn("Project Nayuki", (ROOT / "qrcodegen.py").read_text(encoding="utf-8"))

    def test_no_personal_paths_in_docs(self):
        for path in [ROOT / "README.md", ROOT / "SECURITY.md", *sorted((ROOT / "docs").glob("*.md"))]:
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"C:\\Users\\[A-Za-z]", path.name)
            self.assertNotIn("entropysecurity-tprm", text, path.name)  # the repo is github.com/generalwax2018/riskprism

    def test_doc_links_resolve(self):
        pages = [ROOT / "README.md", ROOT / "SECURITY.md", ROOT / "CONTRIBUTING.md", *sorted((ROOT / "docs").glob("*.md"))]
        for page in pages:
            for target in re.findall(r"\]\(([^)#\s]+)", page.read_text(encoding="utf-8")):
                if re.match(r"[a-z]+:", target):
                    continue
                self.assertTrue((page.parent / target).exists(), "%s links to missing %s" % (page.name, target))

    def test_readme_states_requirements_and_install(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for heading in ("## Requirements", "## Install and run", "### Try it on your laptop", "### Run with Docker",
                        "### Run on a server for your team"):
            self.assertIn(heading, readme)
        self.assertIn("Python 3.10 or newer", readme)
        workflow = ROOT / ".github" / "workflows" / "test.yml"
        if workflow.exists():  # CI tests the oldest version the README promises
            self.assertIn('"3.10"', workflow.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
