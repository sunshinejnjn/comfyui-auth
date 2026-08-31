import tempfile
import unittest
from pathlib import Path

from auth_core import (
    LDAPConfigError,
    SessionSigner,
    UserConfigError,
    load_ldap_config,
    load_users,
    password_sha256,
    verify_credentials,
)


class UserConfigTests(unittest.TestCase):
    def write_config(self, contents: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "users.conf"
        path.write_text(contents, encoding="utf-8")
        return path

    def test_loads_multiple_users_and_comments(self):
        alice = password_sha256("alice password")
        bob = password_sha256("bob password")
        users = load_users(self.write_config(f"# users\nalice = {alice}\n\n bob={bob}\n"))
        self.assertEqual(users, {"alice": alice, "bob": bob})

    def test_rejects_bad_hash_duplicate_and_empty_file(self):
        cases = ["alice = nope\n", f"alice={'0' * 64}\nalice={'1' * 64}\n", "# empty\n"]
        for contents in cases:
            with self.subTest(contents=contents), self.assertRaises(UserConfigError):
                load_users(self.write_config(contents))

    def test_verifies_credentials(self):
        users = {"alice": password_sha256("correct horse")}
        self.assertTrue(verify_credentials(users, "alice", "correct horse"))
        self.assertFalse(verify_credentials(users, "alice", "wrong"))
        self.assertFalse(verify_credentials(users, "unknown", "correct horse"))


class SessionTests(unittest.TestCase):
    def test_round_trip_tampering_expiry_and_removed_user(self):
        signer = SessionSigner(b"x" * 32, max_age_seconds=100)
        token = signer.create("alice", now=1_000)
        self.assertEqual(signer.verify(token, {"alice": "hash"}, now=1_050), "alice")
        self.assertIsNone(signer.verify(token + "x", {"alice": "hash"}, now=1_050))
        self.assertIsNone(signer.verify(token, {"alice": "hash"}, now=1_101))
        self.assertIsNone(signer.verify(token, {}, now=1_050))


class LDAPConfigTests(unittest.TestCase):
    def write_config(self, contents: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "ldap.conf"
        path.write_text(contents, encoding="utf-8")
        return path

    def test_loads_domain_and_case_insensitive_whitelist(self):
        config = load_ldap_config(
            self.write_config(
                "LDAP_SERVER = ldap://ldap.example.com:389\n"
                "SEARCH_BASE = OU=People, DC=Example, DC=COM\n"
                "WHITELIST = Alice, bob\n"
            )
        )
        self.assertEqual(config.domain, "example.com")
        self.assertEqual(config.identity("ALICE@EXAMPLE.COM"), ("alice", "alice@example.com"))
        self.assertTrue(config.is_whitelisted("ALICE"))
        self.assertIsNone(config.identity("alice@other.example"))

    def test_rejects_missing_fields_invalid_base_and_upn_in_whitelist(self):
        cases = [
            "LDAP_SERVER=ldap.example.com\nSEARCH_BASE=OU=People\nWHITELIST=alice\n",
            "LDAP_SERVER=ldap.example.com\nSEARCH_BASE=DC=example,DC=com\n",
            "LDAP_SERVER=ldap.example.com\nSEARCH_BASE=DC=example,DC=com\nWHITELIST=alice@example.com\n",
        ]
        for contents in cases:
            with self.subTest(contents=contents), self.assertRaises(LDAPConfigError):
                load_ldap_config(self.write_config(contents))


if __name__ == "__main__":
    unittest.main()
