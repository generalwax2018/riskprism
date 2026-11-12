"""Authenticator secrets are encrypted at rest and older plaintext rows are converted."""
from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_app import Client  # noqa: E402,F401  (sets up the throwaway data folder first)

import accounts  # noqa: E402
import config  # noqa: E402


class TotpAtRestTests(unittest.TestCase):
    def test_round_trip_and_tamper(self):
        s = accounts.new_totp_secret()
        sealed = accounts.seal(s)
        self.assertTrue(sealed.startswith("enc1:"))
        self.assertNotIn(s, sealed)
        self.assertNotEqual(sealed, accounts.seal(s))  # fresh nonce each time
        self.assertEqual(accounts.unseal(sealed), s)
        i = 40  # inside the ciphertext
        flipped = sealed[:i] + ("A" if sealed[i] != "A" else "B") + sealed[i + 1:]
        self.assertEqual(accounts.unseal(flipped), "")
        with mock.patch.object(config, "SECRET", b"another-server"):
            self.assertEqual(accounts.unseal(sealed), "")

    def test_database_holds_only_ciphertext(self):
        email = "atrest@example.com"
        if not accounts.by_email(email):
            accounts.invite(email, "At Rest", by="test")
        u = accounts.by_email(email)
        self.assertRegex(u["totp_secret"], r"^[A-Z2-7]{32}$")
        con = sqlite3.connect(str(config.RISK_DB_PATH))
        raw = con.execute("SELECT totp_secret FROM users WHERE email = ?", (email,)).fetchone()[0]
        con.close()
        self.assertTrue(raw.startswith("enc1:"))
        self.assertNotIn(u["totp_secret"], raw)
        self.assertEqual(next(x for x in accounts.list_users() if x["email"] == email)["totp_secret"], "")

    def test_plaintext_rows_are_converted(self):
        email = "legacy@example.com"
        if not accounts.by_email(email):
            accounts.invite(email, "Legacy", by="test")
        plain = accounts.new_totp_secret()
        con = sqlite3.connect(str(config.RISK_DB_PATH))
        with con:
            con.execute("UPDATE users SET totp_secret = ? WHERE email = ?", (plain, email))
        self.assertEqual(accounts.by_email(email)["totp_secret"], plain)  # still readable before conversion
        accounts._ready.clear()  # next open converts, as on the first start after upgrading
        self.assertEqual(accounts.by_email(email)["totp_secret"], plain)
        raw = con.execute("SELECT totp_secret FROM users WHERE email = ?", (email,)).fetchone()[0]
        con.close()
        self.assertTrue(raw.startswith("enc1:"))


if __name__ == "__main__":
    unittest.main()
