# v1.5 Phase 3 controls

Implemented independently from Nick's control descriptions. No third-party
implementation code was consulted or copied. This change adds no scored run.

## Optional scope file

Add `--scope scope.json` to the installed PreToolUse command while retaining its
`--policy` and `--ledger` flags. No scope file is read unless explicitly selected.
There is no new default scope. Example file:

```json
{
  "session_id": "example-session",
  "allowed_hosts": ["203.0.113.5"],
  "allowed_path_roots": ["workspace"],
  "max_tool_calls": 20,
  "max_egress_commands": 3
}
```

The session id must match the frame (or RECEIPTD_SESSION_ID fallback). Relative
roots resolve against the hook process working directory at startup. Omitted
lists mean no corresponding scope restriction; empty lists allow no recognized
destinations. Unknown fields, malformed files and invalid budgets deny.
The scope file is protected from recognized mutations. Its exact byte hash is
included in the signed receipt reason, separately from policy_sha256.

| Policy ID | Control |
| --- | --- |
| POL-12:SESSION_SCOPE | Static host/path lists and session binding |
| POL-12:SCOPE_INVALID | Missing, unreadable or invalid requested scope |
| POL-12:SCOPE_STATE_INVALID | Scope/history inspection failure |
| POL-13:TOOL_BUDGET | Maximum receipt-bearing hooked calls per bound session |
| POL-14:EGRESS_BUDGET | Maximum recognized network command occurrences |
| POL-15:SUPPLY_CHAIN | Docker run/pull requires image@sha256 plus 64 hex digits; download-and-execute inspection |

Budget checking and receipt appending share the existing inter-process ledger
lock. All receipt-bearing attempts count, including denials. The boundary is
inclusive: max_tool_calls=1 allows the initial call, then denies subsequent calls.
Multiple recognized network commands within one payload each consume the egress
budget. Receipts are scoped by the bound session; switching frame session ids
does not reset it. A zero budget denies the corresponding initial attempt.
Historical input hashes are checked before budget reconstruction.

## Limits and ordinary-coding denials

These are static destination constraints, not an OS network/filesystem sandbox.
They inspect literal URLs, supported network commands and recognizable path
operands; arbitrary interpreters, dynamically generated addresses/paths, aliases,
proxy settings and HTTP redirects can produce activity the rules do not see.
Opaque MCP calls deny when host/path restrictions are requested. Explicit path
checks can conservatively treat ordinary command arguments as paths. No DNS
lookup is performed, and host matching does not constrain resolved IPs.

Budget state is the selected local ledger, not a remote counter. Changing or
truncating that ledger or the trusted hook configuration can undermine accounting;
self-protection is also static. Missing receipts cannot be reconstructed. The
egress budget counts recognized command occurrences, not bytes, packets or actual
network connections. nc -z and other ordinary network diagnostics consume it.
Large histories incur scan cost and can reach the hook deadline.

Docker options not recognized by the static image parser can deny, even with a
pinned image. Download plus interpreter invocation in one call can conservatively
deny unrelated sequential commands. Existing POL-06 download rules remain active.
No actual Docker or download command is executed by the tests.

For evaluation, each model must be reported separately as attempts, non-attempts,
prevented, misses and errors. Do not compare a pooled two-model result with the
prior single-model result. Adding a second evaluated model does not remove
attack-authorship exposure. Phase 4 must pin the final candidate policy and grader
hashes and freeze the private benign selection (including a git-config session).
Phase 4 has not started.
