"""Clean-install pilot: start the real server as a separate process on an empty data folder and walk the
main flows end to end, the way a new customer would. Catches anything that only works because an earlier
test left data behind, and any traceback the handlers swallow into the server log.
"""
from __future__ import annotations

import http.client
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parent.parent


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Pilot:
    def __init__(self, **env):
        self.data = tempfile.mkdtemp(prefix="rp-pilot-")
        self.port = _free_port()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("ENTROPY_", "LLM_", "XAI_"))}
        self.env.update({"ENTROPY_DATA_DIR": self.data, "ENTROPY_PORT": str(self.port), "ENTROPY_HOST": "127.0.0.1",
                         "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1", **env})
        self.log = open(Path(self.data) / "server.log", "w+")
        self.proc = subprocess.Popen([sys.executable, "serve.py"], cwd=str(ROOT), env=self.env, stdout=self.log, stderr=subprocess.STDOUT)
        self.cookie = ""
        for _ in range(100):
            try:
                if self.get("/healthz")[0] == 200:
                    return
            except OSError:
                time.sleep(0.1)
        self.stop()
        raise RuntimeError("server did not start: " + self.output())

    def output(self) -> str:
        self.log.flush()
        self.log.seek(0)
        return self.log.read()

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()
        shutil.rmtree(self.data, ignore_errors=True)

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Cookie": self.cookie} if self.cookie else {}
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        for sc in r.msg.get_all("Set-Cookie") or []:
            if sc.startswith("es_session="):
                self.cookie = sc.split(";", 1)[0]
        out = (r.status, data, {k.lower(): v for k, v in r.getheaders()})
        c.close()
        return out

    def get(self, path):
        return self.req("GET", path)

    def text(self, path):
        s, b, _h = self.get(path)
        return s, b.decode("utf-8", "replace")

    def csrf(self, page="/intake"):
        return re.search(r'name="_csrf" value="([^"]+)"', self.text(page)[1]).group(1)

    def post(self, path, fields, page="/intake"):
        return self.req("POST", path, urlencode({**fields, "_csrf": self.csrf(page)}), {"Content-Type": "application/x-www-form-urlencoded"})

    def upload(self, path, fields, fname, content, page="/intake"):
        b = "PILOTBOUNDARY"
        parts = ['--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (b, k, v)
                 for k, v in {**fields, "_csrf": self.csrf(page)}.items()]
        body = "".join(parts).encode() + ('--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
                                          'Content-Type: text/csv\r\n\r\n' % (b, fname)).encode() + content.encode() + ("\r\n--%s--\r\n" % b).encode()
        return self.req("POST", path, body, {"Content-Type": "multipart/form-data; boundary=" + b})


class CleanInstallTests(unittest.TestCase):
    def assertClean(self, p: Pilot):
        out = p.output()
        self.assertNotIn("Traceback", out)
        self.assertNotIn("failed:", out)

    def test_first_day_without_login(self):
        p = Pilot(ENTROPY_AUTH="none")
        try:
            # empty install: every page renders with no data at all
            for path in ("/", "/executive", "/findings", "/alerts", "/risk", "/integrations", "/environment", "/controls",
                         "/shadow", "/documents", "/policy", "/report", "/import", "/intake", "/findings.csv", "/admin/data",
                         "/admin/data/export.zip", "/admin/data/audit.csv",
                         "/integrations/catalog.json", "/executive/board.pdf"):
                s, _b, _h = p.get(path)
                self.assertEqual(s, 200, path)
            # describe the environment
            s, b, _h = p.post("/environment/setup", {"idp": "Microsoft Entra ID", "collab": "Microsoft 365", "itsm": "ServiceNow"},
                              page="/environment")
            self.assertEqual(s, 200)
            self.assertIn(b"3 systems", b)
            # onboard a vendor and send the questionnaire
            s, _b, h = p.post("/intake", {"vendor": "Pilot Vendor", "website": "https://pilot.example", "data": "customer email",
                                          "connects": "yes", "category": "crm"})
            self.assertEqual(s, 303)
            token = h["location"].rsplit("/", 1)[1]
            s, form = p.text("/q/" + token)
            self.assertEqual(s, 200)
            self.assertIn("int_connect", form)
            s, _b, _h = p.req("POST", "/q/" + token, urlencode({"int_connect": "yes", "int_list": "Reads our Microsoft 365 mail",
                                                                  "int_permissions": "Mail.Read (delegated)", "int_admin": "no",
                                                                  "hosting": "Azure"}),
                              {"Content-Type": "application/x-www-form-urlencoded"})
            self.assertEqual(s, 200)
            s, page = p.text("/vendor/Pilot_Vendor")
            self.assertEqual(s, 200)
            for tab in ("Integrations", "Controls", "Threat model"):
                self.assertIn(tab, page)
            # integration from the answers, then the vendor's exports
            self.assertEqual(p.post("/integrations/draft", {"slug": "Pilot_Vendor"})[0], 303)
            for path, ctype in (("/threat/Pilot_Vendor/export.pdf", "application/pdf"), ("/threat/Pilot_Vendor/export.docx", "officedocument"),
                                ("/threat/Pilot_Vendor/diagram.svg", "svg")):
                s, b, h = p.get(path)
                self.assertEqual(s, 200, path)
                self.assertIn(ctype, h["content-type"], path)
                self.assertGreater(len(b), 500, path)
            # shadow IT from an identity-provider export
            apps = "displayName,appId,scopes,lastSignIn\nPilot Vendor,pv-1,Mail.Read,2026-10-01\nRandom Notes,rn-9,Files.ReadWrite.All,2026-10-02\n"
            s, _b, _h = p.upload("/shadow/apps", {"source": "entra"}, "apps.csv", apps, page="/shadow")
            self.assertEqual(s, 200)
            s, page = p.text("/findings")
            self.assertIn("Random Notes", page)
            s, csv_ = p.text("/findings.csv")
            self.assertTrue(csv_.startswith("Key,Summary"))
            # sample data still loads on a populated install, and everything still renders
            self.assertEqual(p.post("/integrations/seed", {}, page="/integrations")[0], 303)
            for path in ("/", "/executive", "/findings", "/integrations", "/controls", "/environment", "/shadow",
                         "/vendor/ServiceNow", "/vendor/Fieldnote_AI", "/executive/board.pdf"):
                self.assertEqual(p.get(path)[0], 200, path)
            self.assertIn("RiskPrism", p.output())
            self.assertIn("Backups:", p.output())
            # end of a pilot: remove the sample data, export, then delete everything
            s, b, _h = p.post("/admin/data/sample", {}, page="/admin/data")
            self.assertIn(b"Sample data removed", b)
            self.assertEqual(p.get("/vendor/ServiceNow")[0], 404)  # the sample vendor record is gone
            self.assertEqual(p.get("/admin/data/export.zip")[0], 200)
            s, b, _h = p.post("/admin/data/delete", {"confirm": "DELETE ALL DATA", "backups": "1"}, page="/admin/data")
            self.assertIn(b"All data deleted", b)
            for path in ("/", "/executive", "/findings", "/integrations", "/controls", "/environment"):
                self.assertEqual(p.get(path)[0], 200, path)
            self.assertClean(p)
        finally:
            p.stop()

    def test_ai_off_install(self):
        p = Pilot(ENTROPY_AUTH="none", ENTROPY_AI="off", LLM_BASE_URL="https://api.example/v1", LLM_API_KEY="k")
        try:
            self.assertIn("AI: off", p.output())
            p.post("/intake", {"vendor": "Manual Co"})
            s, page = p.text("/vendor/Manual_Co")
            self.assertNotIn("/ai/Manual_Co", page)
            self.assertEqual(p.get("/ai/Manual_Co")[0], 403)
            self.assertClean(p)
        finally:
            p.stop()

    def test_accounts_install_first_admin(self):
        p = Pilot(ENTROPY_AUTH="accounts")
        try:
            self.assertEqual(p.get("/")[0], 303)  # sign-in required
            out = subprocess.run([sys.executable, "accounts.py", "invite", "admin@pilot.example", "--admin", "--name", "Pilot Admin"],
                                 cwd=str(ROOT), env=p.env, capture_output=True, text=True, timeout=30)
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            link = re.search(r"/setup/(\S+)", out.stdout).group(1)
            s, page = p.text("/setup/" + link)
            self.assertEqual(s, 200)
            self.assertIn("admin@pilot.example", page)
            # the authenticator secret is not stored in the clear
            db = (Path(p.data) / "riskprism.db").read_bytes()
            secret = re.search(r'<p class="mono key">([A-Z2-7 ]+)</p>', page).group(1).replace(" ", "")
            self.assertNotIn(secret.encode(), db)
            self.assertClean(p)
        finally:
            p.stop()

    def test_bad_config_refuses_to_start(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("ENTROPY_")}
        env.update({"ENTROPY_DATA_DIR": tempfile.mkdtemp(), "ENTROPY_AUTH": "none", "ENTROPY_OIDC_ISSUER": "https://idp.example",
                    "ENTROPY_OIDC_CLIENT_ID": "x", "ENTROPY_PORT": str(_free_port())})
        r = subprocess.run([sys.executable, "serve.py"], cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 2)
        self.assertIn("ENTROPY_AUTH=accounts", r.stderr)


if __name__ == "__main__":
    unittest.main()
