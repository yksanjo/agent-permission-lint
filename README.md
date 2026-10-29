# agent-permission-lint

Audit an agent's permission manifest for over-broad grants before you hand
them out.

Agent permission files drift toward "allow everything" one reasonable
request at a time: a wildcard here, a no-expiry write there, a network grant
somebody added for a demo. `agent-permission-lint` reads the manifest itself
- not the agent's actions - and flags the shapes a reviewer should reject or
justify.

Severity is deliberate: **a single broad pattern is a warning**, because
broad grants are often intentional. Only conjunctions that form a concrete
risk shape escalate to errors - `write`/`execute` with no path restriction,
and the exfiltration shape (read access to secret-looking paths combined
with unrestricted network egress).

Exit codes: `0` no errors, `1` any error, `2` usage/input problems.

## Requirements

Python 3.10+. Standard library only - no dependencies, no network.

## Usage

```
python3 permission_lint.py manifest.json
python3 permission_lint.py manifest.json --json
python3 permission_lint.py manifest.json --now 2026-10-29T12:00:00Z
```

Run the demo and tests:

```
python3 demo.py
python3 -m unittest test_permission_lint
```

## Manifest convention

```json
{
  "agent": "email-assistant",
  "grants": [
    {
      "action": "gmail.send",
      "scope": "write",
      "paths": ["mailbox:outbox"],
      "domains": ["mail.google.com"],
      "expires_at": "2026-12-31T00:00:00Z",
      "delegatable": false
    }
  ]
}
```

`scope` is one of `read`, `write`, `execute`, `network`. `paths` and
`domains` restrict where the grant applies; omitting them means
unrestricted. This is a documented convention for this linter, not an
industry standard.

## Rules

| rule | severity | what it catches |
|------|----------|-----------------|
| `invalid-manifest` / `invalid-grant` | error | malformed manifest, unknown scope, bad timestamp |
| `unrestricted-write` | error | `write`/`execute` with no path restriction |
| `exfil-conjunction` | error | secret-looking read paths + unrestricted network egress |
| `wildcard-action` | warning | grant covers every action |
| `network-any` | warning | network grant reaches any domain |
| `standing-write` | warning | `write`/`execute` grant with no expiry |
| `expired-grant` | warning | expiry in the past (checked against `--now`) |
| `delegation-unlimited` | warning | re-delegation allowed with no depth limit |
| `sensitive-read` | info | read of secret-looking path (fine alone, dangerous with open egress) |
| `duplicate-grant` | info | two identical grants |

## Limits

- **It audits the grant document, not behavior.** A tight manifest says
  nothing about whether the agent honors it, and a broad manifest may be
  exactly what its owner intended. This is a review signal, not a control.
- **It does not gate actions.** Pair it with a preflight policy gate
  (for example `action-boundary`) for runtime enforcement.
- **Heuristics, not proof.** The secret-path list and wildcard shapes are
  conventions; a clean result does not establish that a manifest is safe,
  and findings can be false positives for deliberate setups.
- **No evaluation of grant interactions beyond the documented conjunctions.**
  Two individually fine grants can still combine badly in ways this tool
  does not model.
- All demo and test data is synthetic.

## License

MIT - see [LICENSE](LICENSE).
