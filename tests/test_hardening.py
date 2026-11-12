"""Hardening from the open-source security review: client address, DNS rebinding, model transport, file modes."""
from __future__ import annotations

import os
import socket
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_app  # noqa: E402,F401  (sets up the throwaway data folder first)

import auth  # noqa: E402
import config  # noqa: E402
import llm  # noqa: E402
import serve  # noqa: E402
import vendor_research as vr  # noqa: E402


class ClientAddressTests(unittest.TestCase):
    def test_direct_client_cannot_choose_its_address(self):
        self.assertEqual(serve.client_ip("8.8.8.8", "1.2.3.4"), "8.8.8.8")

    def test_proxy_on_this_machine_supplies_the_last_hop(self):
        self.assertEqual(serve.client_ip("127.0.0.1", "6.6.6.6, 198.51.100.7"), "198.51.100.7")
        self.assertEqual(serve.client_ip("10.0.0.4", "198.51.100.7:51234"), "198.51.100.7")
        self.assertEqual(serve.client_ip("::1", "[2001:db8::5]:443"), "2001:db8::5")

    def test_garbage_header_falls_back_to_the_peer(self):
        self.assertEqual(serve.client_ip("127.0.0.1", "not-an-ip"), "127.0.0.1")
        self.assertEqual(serve.client_ip("127.0.0.1", ""), "127.0.0.1")

    def test_failed_sign_in_memory_is_bounded(self):
        saved = dict(auth._failures)
        try:
            auth._failures.clear()
            auth._failures.update({"192.0.2.%d" % i: [0.0] for i in range(10001)})
            auth.record_failure("198.51.100.1")
            self.assertLess(len(auth._failures), 10)
        finally:
            auth._failures.clear()
            auth._failures.update(saved)


class RebindingTests(unittest.TestCase):
    def answers(self, ip):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]

    def test_private_answer_at_connect_time_is_refused(self):
        with mock.patch.object(vr, "_proxy_endpoints", return_value=set()), \
                mock.patch.object(vr.socket, "getaddrinfo", return_value=self.answers("169.254.169.254")), \
                mock.patch.object(vr.socket, "socket") as sock:
            with self.assertRaises(vr.ResearchError):
                vr._guarded_connection(("vendor.example", 443), 5)
            sock.assert_not_called()  # never even opened a socket

    def test_public_answer_connects_to_that_address(self):
        fake = mock.MagicMock()
        with mock.patch.object(vr, "_proxy_endpoints", return_value=set()), \
                mock.patch.object(vr.socket, "getaddrinfo", return_value=self.answers("93.184.215.14")), \
                mock.patch.object(vr.socket, "socket", return_value=fake):
            self.assertIs(vr._guarded_connection(("vendor.example", 443), 5), fake)
        fake.connect.assert_called_once_with(("93.184.215.14", 443))

    def test_only_the_proxy_itself_is_exempt(self):
        with mock.patch.object(vr, "_proxy_endpoints", return_value={("127.0.0.1", 3128)}), \
                mock.patch.object(vr.socket, "getaddrinfo", return_value=self.answers("127.0.0.1")), \
                mock.patch.object(vr.socket, "create_connection") as direct:
            vr._guarded_connection(("127.0.0.1", 3128), 5)
            direct.assert_called_once()
            with self.assertRaises(vr.ResearchError):  # same host, the vendor's port: a rebinding attempt
                vr._guarded_connection(("127.0.0.1", 443), 5)

    def test_opener_uses_the_guarded_connections(self):
        kinds = {type(h).__name__ for h in vr._OPENER.handlers}
        self.assertIn("_GuardedHTTP", kinds)
        self.assertIn("_GuardedHTTPS", kinds)
        self.assertIs(vr._GuardedHTTPConnection("vendor.example")._create_connection, vr._guarded_connection)
        self.assertIs(vr._GuardedHTTPSConnection("vendor.example")._create_connection, vr._guarded_connection)

    def test_end_to_end_a_local_address_is_never_fetched(self):
        import http.server
        import threading
        import urllib.request
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            op = urllib.request.build_opener(urllib.request.ProxyHandler({}), vr._GuardedHTTP, vr._GuardedHTTPS)
            with self.assertRaises(vr.ResearchError):
                op.open("http://127.0.0.1:%d/" % srv.server_address[1], timeout=5)
        finally:
            srv.shutdown()
            srv.server_close()


class ModelTransportTests(unittest.TestCase):
    def test_https_or_this_machine_only(self):
        self.assertEqual(llm.transport_problem("https://api.example/v1"), "")
        self.assertEqual(llm.transport_problem("http://127.0.0.1:11434/v1"), "")
        self.assertEqual(llm.transport_problem("http://localhost:1234/v1"), "")
        self.assertIn("https://", llm.transport_problem("http://models.internal.example/v1"))
        self.assertIn("https://", llm.transport_problem("ftp://x.example"))

    def test_chat_refuses_plain_http_to_another_host(self):
        env = {"LLM_BASE_URL": "http://models.internal.example/v1", "LLM_API_KEY": "k"}
        with mock.patch.dict(os.environ, env), mock.patch.object(config, "AI_ENABLED", True), \
                mock.patch.object(llm.urllib.request, "urlopen") as op:
            with self.assertRaises(llm.LLMError):
                llm.chat("s", "u")
            op.assert_not_called()

    def test_startup_refuses_it_too(self):
        with mock.patch.dict(os.environ, {"LLM_BASE_URL": "http://models.internal.example/v1"}), \
                mock.patch.object(config, "AI_ENABLED", True):
            self.assertTrue(any("LLM_BASE_URL" in p for p in config.check_startup()))


class SignOutTests(unittest.TestCase):
    def test_sign_out_ends_every_session(self):
        import accounts
        tok = accounts.invite("signout@example.com", "Sign Out")
        u = accounts.by_invite(tok)
        before = accounts.session_value(accounts.get(u["id"]), auth._sig, 3600)
        self.assertIsNone(accounts.session_user(before, auth._sig))  # still invited, not active
        with accounts._db(write=True) as con:
            con.execute("UPDATE users SET status = 'active' WHERE id = ?", (u["id"],))
        live = accounts.session_value(accounts.get(u["id"]), auth._sig, 3600)
        self.assertEqual(accounts.session_user(live, auth._sig)["id"], u["id"])
        accounts.end_sessions(u["id"])
        self.assertIsNone(accounts.session_user(live, auth._sig))


class FileModeTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_server_sets_a_private_umask(self):
        src = (Path(serve.__file__)).read_text(encoding="utf-8")
        self.assertIn("os.umask(0o077)", src)
        old = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as d:
                p = Path(d) / "x.json"
                p.write_text("{}")
                self.assertEqual(stat.S_IMODE(p.stat().st_mode) & 0o077, 0)
        finally:
            os.umask(old)


if __name__ == "__main__":
    unittest.main()
