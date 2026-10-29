import unittest
from datetime import datetime, timezone

from permission_lint import lint_manifest, summarize, parse_ts, main

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)


def sane():
    """Synthetic email-assistant manifest with tight grants."""
    return {
        "agent": "email-assistant",
        "grants": [
            {"action": "gmail.read", "scope": "read",
             "paths": ["mailbox:inbox"], "domains": ["mail.google.com"],
             "expires_at": "2026-12-31T00:00:00Z"},
            {"action": "gmail.send", "scope": "write",
             "paths": ["mailbox:outbox"], "domains": ["mail.google.com"],
             "expires_at": "2026-12-31T00:00:00Z",
             "delegatable": False},
            {"action": "calendar.read", "scope": "read",
             "paths": ["calendar:primary"], "domains": ["googleapis.com"],
             "expires_at": "2026-11-30T00:00:00Z"},
        ],
    }


def rules(findings):
    return [f["rule"] for f in findings]


def errors(findings):
    return [f for f in findings if f["severity"] == "error"]


class TestSaneManifest(unittest.TestCase):
    def test_sane_manifest_passes(self):
        findings = lint_manifest(sane(), now=NOW)
        self.assertEqual(errors(findings), [], findings)

    def test_sane_summary_ok(self):
        self.assertTrue(summarize(lint_manifest(sane(), now=NOW))["ok"])


class TestShapeValidation(unittest.TestCase):
    def test_non_object_manifest(self):
        self.assertIn("invalid-manifest", rules(lint_manifest([1], now=NOW)))

    def test_missing_grants_list(self):
        self.assertIn("invalid-manifest", rules(lint_manifest({}, now=NOW)))

    def test_grant_missing_action_and_scope(self):
        findings = lint_manifest({"grants": [{}]}, now=NOW)
        self.assertGreaterEqual(rules(findings).count("invalid-grant"), 2)

    def test_unknown_scope(self):
        doc = sane(); doc["grants"][0]["scope"] = "admin"
        self.assertIn("invalid-grant", rules(lint_manifest(doc, now=NOW)))

    def test_bad_expires_at(self):
        doc = sane(); doc["grants"][0]["expires_at"] = "next friday"
        self.assertIn("invalid-grant", rules(lint_manifest(doc, now=NOW)))


class TestWarnings(unittest.TestCase):
    def test_wildcard_action_warns(self):
        doc = sane(); doc["grants"][0]["action"] = "*"
        findings = lint_manifest(doc, now=NOW)
        self.assertIn("wildcard-action", rules(findings))
        self.assertEqual(errors(findings), [], findings)

    def test_network_any_warns(self):
        doc = sane(); doc["grants"].append(
            {"action": "http.get", "scope": "network", "domains": ["*"],
             "expires_at": "2026-12-31T00:00:00Z"})
        findings = lint_manifest(doc, now=NOW)
        self.assertIn("network-any", rules(findings))
        self.assertEqual(errors(findings), [], findings)

    def test_standing_write_warns(self):
        doc = sane(); del doc["grants"][1]["expires_at"]
        self.assertIn("standing-write", rules(lint_manifest(doc, now=NOW)))

    def test_expired_grant_warns(self):
        doc = sane(); doc["grants"][0]["expires_at"] = "2026-01-01T00:00:00Z"
        self.assertIn("expired-grant", rules(lint_manifest(doc, now=NOW)))

    def test_unlimited_delegation_warns(self):
        doc = sane(); doc["grants"][0]["delegatable"] = True
        self.assertIn("delegation-unlimited", rules(lint_manifest(doc, now=NOW)))

    def test_duplicate_grant_info(self):
        doc = sane(); doc["grants"].append(dict(doc["grants"][0]))
        findings = lint_manifest(doc, now=NOW)
        self.assertIn("duplicate-grant", rules(findings))
        self.assertEqual(errors(findings), [], findings)


class TestErrorConjunctions(unittest.TestCase):
    def test_write_without_paths_is_error(self):
        doc = sane(); del doc["grants"][1]["paths"]
        findings = lint_manifest(doc, now=NOW)
        self.assertIn("unrestricted-write", rules(findings))
        self.assertTrue(errors(findings))

    def test_write_wildcard_path_is_error(self):
        doc = sane(); doc["grants"][1]["paths"] = ["*"]
        self.assertIn("unrestricted-write", rules(lint_manifest(doc, now=NOW)))

    def test_read_without_paths_is_not_unrestricted_write(self):
        doc = sane(); del doc["grants"][0]["paths"]
        findings = lint_manifest(doc, now=NOW)
        self.assertNotIn("unrestricted-write", rules(findings))

    def test_exfil_conjunction(self):
        doc = sane()
        doc["grants"].append({"action": "fs.read", "scope": "read",
                              "paths": ["~/.env", "~/secrets/api_key.txt"],
                              "expires_at": "2026-12-31T00:00:00Z"})
        doc["grants"].append({"action": "http.post", "scope": "network",
                              "domains": ["*"],
                              "expires_at": "2026-12-31T00:00:00Z"})
        findings = lint_manifest(doc, now=NOW)
        self.assertIn("exfil-conjunction", rules(findings))
        self.assertTrue(errors(findings))
        self.assertIn("sensitive-read", rules(findings))  # info also present

    def test_sensitive_read_alone_is_not_error(self):
        doc = sane()
        doc["grants"].append({"action": "fs.read", "scope": "read",
                              "paths": ["~/.env"],
                              "expires_at": "2026-12-31T00:00:00Z"})
        findings = lint_manifest(doc, now=NOW)
        self.assertIn("sensitive-read", rules(findings))
        self.assertNotIn("exfil-conjunction", rules(findings))
        self.assertEqual(errors(findings), [], findings)


class TestHelpers(unittest.TestCase):
    def test_parse_ts(self):
        self.assertEqual(parse_ts("2026-10-29T12:00:00Z"), NOW)
        self.assertIsNone(parse_ts("junk"))
        self.assertIsNone(parse_ts(None))


class TestCLI(unittest.TestCase):
    def test_exit_codes(self):
        import json, os, tempfile
        with tempfile.TemporaryDirectory() as td:
            good = os.path.join(td, "good.json")
            bad = os.path.join(td, "bad.json")
            with open(good, "w") as fh: json.dump(sane(), fh)
            broken = sane(); del broken["grants"][1]["paths"]
            with open(bad, "w") as fh: json.dump(broken, fh)
            self.assertEqual(main([good, "--json", "--now",
                                   "2026-10-29T12:00:00Z"]), 0)
            self.assertEqual(main([bad, "--now", "2026-10-29T12:00:00Z"]), 1)
            self.assertEqual(main([os.path.join(td, "nope")]), 2)
            self.assertEqual(main([good, "--now", "junk"]), 2)


if __name__ == "__main__":
    unittest.main()
