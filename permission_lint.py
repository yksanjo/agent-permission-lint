#!/usr/bin/env python3
"""agent-permission-lint: audit an agent's permission manifest for over-breadth.

A permission manifest lists what an agent is allowed to do: which actions,
with what scope (read/write/execute/network), over which paths and domains,
until when. This tool audits the manifest itself - not the agent's actions -
and flags grants that are broader than a reviewer would usually accept.

Severity design: a single broad pattern is a warning (broad grants are often
deliberate); only conjunctions that form a concrete risk shape escalate to
errors - write/execute with no path restriction, and the exfiltration shape
(read of secret-looking paths plus unrestricted network egress).

Offline, static, review signals only. It audits the grant document; it does
not gate actions at runtime - pair it with a preflight gate for that.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

ERROR = "error"
WARN = "warning"
INFO = "info"

VALID_SCOPES = {"read", "write", "execute", "network"}
WRITE_SCOPES = {"write", "execute"}
SENSITIVE_GLOBS = (".env", "secret", "credential", "id_rsa", ".pem",
                   "private_key", "token", "password")


def parse_ts(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _finding(rule, severity, path, message):
    return {"rule": rule, "severity": severity, "path": path, "message": message}


def _is_sensitive(path: str) -> bool:
    low = path.lower()
    return any(g in low for g in SENSITIVE_GLOBS)


def _unrestricted_paths(grant) -> bool:
    paths = grant.get("paths")
    if not paths:
        return True  # no path restriction at all
    return any(p.strip() in {"*", "/", "/*", "~", "/**"} for p in paths
               if isinstance(p, str))


def _unrestricted_domains(grant) -> bool:
    domains = grant.get("domains")
    if not domains:
        return True
    return any(d.strip() in {"*", "0.0.0.0/0", "any"} for d in domains
               if isinstance(d, str))


def lint_manifest(doc, now: datetime | None = None) -> list:
    findings: list[dict] = []
    clock = now or datetime.now(timezone.utc)

    if not isinstance(doc, dict):
        return [_finding("invalid-manifest", ERROR, "$", "manifest must be a JSON object")]
    grants = doc.get("grants")
    if not isinstance(grants, list):
        return [_finding("invalid-manifest", ERROR, "$.grants",
                         "manifest needs a grants list")]

    reads_sensitive = False
    network_any = False
    seen: dict[tuple, int] = {}

    for i, g in enumerate(grants):
        path = f"$.grants[{i}]"
        if not isinstance(g, dict):
            findings.append(_finding("invalid-grant", ERROR, path,
                                     "grant must be an object"))
            continue

        action = g.get("action")
        scope = g.get("scope")
        if not isinstance(action, str) or not action.strip():
            findings.append(_finding("invalid-grant", ERROR, f"{path}.action",
                                     "grant needs an action pattern"))
            action = ""
        if scope not in VALID_SCOPES:
            findings.append(_finding(
                "invalid-grant", ERROR, f"{path}.scope",
                f"scope must be one of {sorted(VALID_SCOPES)}"))
            scope = ""

        # single-pattern breadth -> warnings
        if action.strip() in {"*", "*.*"}:
            findings.append(_finding(
                "wildcard-action", WARN, f"{path}.action",
                "grant covers every action; narrow it to what the agent does"))
        if scope == "network" and _unrestricted_domains(g):
            findings.append(_finding(
                "network-any", WARN, f"{path}.domains",
                "network grant reaches any domain"))
            network_any = True
        if scope in WRITE_SCOPES and not g.get("expires_at"):
            findings.append(_finding(
                "standing-write", WARN, path,
                f"{scope} grant has no expiry; standing {scope} access "
                "outlives the reason it was granted"))
        if g.get("delegatable") is True and "max_depth" not in g:
            findings.append(_finding(
                "delegation-unlimited", WARN, path,
                "grant can be re-delegated with no depth limit"))

        # conjunction shapes -> errors
        if scope in WRITE_SCOPES and _unrestricted_paths(g):
            findings.append(_finding(
                "unrestricted-write", ERROR, path,
                f"{scope} grant has no path restriction; the agent can {scope} "
                "anywhere it can reach"))
        if scope == "read":
            for p in g.get("paths") or []:
                if isinstance(p, str) and _is_sensitive(p):
                    reads_sensitive = True
                    findings.append(_finding(
                        "sensitive-read", INFO, f"{path}.paths",
                        f'read of secret-looking path "{p}"; fine if the agent '
                        "needs it, dangerous if paired with open egress"))

        # freshness
        expires = parse_ts(g.get("expires_at"))
        if g.get("expires_at") and expires is None:
            findings.append(_finding(
                "invalid-grant", ERROR, f"{path}.expires_at",
                "expires_at is not a parseable ISO-8601 timestamp"))
        if expires is not None and expires < clock:
            findings.append(_finding(
                "expired-grant", WARN, f"{path}.expires_at",
                "grant expired; renew deliberately or remove it"))

        # duplicates
        key = (action.strip(), scope,
               tuple(sorted(str(p) for p in (g.get("paths") or []))),
               tuple(sorted(str(d) for d in (g.get("domains") or []))))
        if key in seen:
            findings.append(_finding(
                "duplicate-grant", INFO, path,
                f"duplicates grants[{seen[key]}]; merge them"))
        else:
            seen[key] = i

    if reads_sensitive and network_any:
        findings.append(_finding(
            "exfil-conjunction", ERROR, "$",
            "manifest combines read access to secret-looking paths with "
            "unrestricted network egress; that is the exfiltration shape"))

    order = {ERROR: 0, WARN: 1, INFO: 2}
    findings.sort(key=lambda f: (order[f["severity"]], f["rule"], f["path"]))
    return findings


def summarize(findings: list) -> dict:
    out = {"errors": 0, "warnings": 0, "infos": 0}
    for f in findings:
        out[{ERROR: "errors", WARN: "warnings", INFO: "infos"}[f["severity"]]] += 1
    out["ok"] = out["errors"] == 0
    return out


def render_text(findings: list, summary: dict) -> str:
    lines = [f"agent-permission-lint: {summary['errors']} error(s), "
             f"{summary['warnings']} warning(s), {summary['infos']} info"]
    for f in findings:
        lines.append(f"[{f['severity']}] {f['rule']} at {f['path']}: {f['message']}")
    if not findings:
        lines.append("no findings: grants are scoped, expiring, and non-overlapping")
    return "\n".join(lines)


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit an agent permission manifest for over-breadth.")
    parser.add_argument("manifest", help="manifest JSON file, or - for stdin")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--now", default=None,
                        help="reference time for expiry checks (ISO-8601)")
    args = parser.parse_args(argv)

    try:
        raw = sys.stdin.read() if args.manifest == "-" \
            else open(args.manifest, encoding="utf-8").read()
        doc = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    now = parse_ts(args.now) if args.now else None
    if args.now and now is None:
        print("error: --now is not a parseable ISO-8601 timestamp", file=sys.stderr)
        return 2

    findings = lint_manifest(doc, now=now)
    summary = summarize(findings)
    if args.json:
        print(json.dumps({"ok": summary["ok"], "summary": summary,
                          "findings": findings}, indent=2))
    else:
        print(render_text(findings, summary))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
