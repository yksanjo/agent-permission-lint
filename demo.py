#!/usr/bin/env python3
"""Demo: lint one tight manifest and one over-broad manifest (synthetic)."""
import json
from datetime import datetime, timezone

from permission_lint import lint_manifest, summarize, render_text

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)

TIGHT = {
    "agent": "email-assistant",
    "grants": [
        {"action": "gmail.read", "scope": "read",
         "paths": ["mailbox:inbox"], "domains": ["mail.google.com"],
         "expires_at": "2026-12-31T00:00:00Z"},
        {"action": "gmail.send", "scope": "write",
         "paths": ["mailbox:outbox"], "domains": ["mail.google.com"],
         "expires_at": "2026-12-31T00:00:00Z", "delegatable": False},
        {"action": "calendar.read", "scope": "read",
         "paths": ["calendar:primary"], "domains": ["googleapis.com"],
         "expires_at": "2026-11-30T00:00:00Z"},
    ],
}

BROAD = {
    "agent": "auto-poster",
    "grants": [
        {"action": "*", "scope": "read", "paths": ["~/Documents"]},
        {"action": "fs.write", "scope": "write"},          # no paths, no expiry
        {"action": "fs.read", "scope": "read",
         "paths": ["~/.env", "~/secrets/api_token.txt"]},
        {"action": "http.post", "scope": "network", "domains": ["*"]},
        {"action": "gmail.read", "scope": "read",
         "paths": ["mailbox:inbox"], "expires_at": "2025-01-01T00:00:00Z"},
        {"action": "gmail.read", "scope": "read",
         "paths": ["mailbox:inbox"], "expires_at": "2025-01-01T00:00:00Z"},
        {"action": "deploy", "scope": "execute", "paths": ["/srv/app"],
         "delegatable": True},
    ],
}


def run(title, doc):
    findings = lint_manifest(doc, now=NOW)
    print(f"=== {title} ===")
    print(render_text(findings, summarize(findings)))
    print()


if __name__ == "__main__":
    run("tight manifest (email assistant)", TIGHT)
    run("over-broad manifest (auto-poster)", BROAD)
    print("machine-readable summary for the broad manifest:")
    print(json.dumps(summarize(lint_manifest(BROAD, now=NOW)), indent=2))
