# Hook and evidence coverage

Source: `receiptd.cli.PRETOOLUSE_MATCHER` and
`receiptd/hooks/claude_code_gate.py` on this branch. Existing installations can
retain older matcher configurations; inspect the installed settings.

| Tool | Current init matcher | Candidate controls |
| --- | --- | --- |
| Bash | Hooked | Static command rules; recognized destinations; budgets |
| Write, Edit, MultiEdit | Hooked | Persistence/self-protection paths; scope roots; call budget |
| Read | Hooked | Candidate sensitive-path rules; scope roots; call budget |
| mcp__.* | Hooked | Payload rules/call budget; host/path-scoped opaque calls deny |
| WebFetch, Grep, Glob, LS, other unmatched tools | Outside matcher | Outside receiptd's hooks |

Read is included by the current installer, contrary to the older README scope
line. The packaged default lacks the candidate's sensitive-read rules. Installing
the matcher alone does not activate those rules. Existing hook installations
must be inspected rather than assumed to match the current installer.

| Failure | Hook status | Receipt behavior |
| --- | --- | --- |
| Missing policy | 2 | POLICY_MISSING deny if storage/signing work |
| Unreadable policy | 2 | POLICY_UNREADABLE deny if storage/signing work |
| Invalid policy | 2 | POLICY_INVALID deny if storage/signing work |
| Signing unavailable | 2 | Attempts an unsigned deny receipt |
| Ledger lock, append or anchor error; full storage | 2 | A complete receipt may be absent |
| Invalid/missing requested scope or unreadable scope state | 2 | Scope error deny if storage/signing work |

`tests/test_gate_execution_boundary.py` injects PermissionError/ENOSPC and
lock/anchor failures on otherwise allowed and denied payloads. A cooperating
caller writes an inert marker only on exit 0. Denials leave the marker absent;
the allow control writes it. Phase 3 also exercises this callback boundary using
the installed hook as a subprocess. No payload command is executed.

These tests demonstrate that a caller honoring the hook status does not invoke
its callback on denial. They do not establish that every agent integration
honors status 2, nor that a malicious caller cannot bypass the hook. No live
Claude Code execution is claimed by these tests.
