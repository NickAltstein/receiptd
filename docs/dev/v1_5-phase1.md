# v1.5 Phase 1 candidate

Base: `4e26fda35d2f1dc30300720b47fa254184e0db8b`.

This change adds `receiptd/hooks/v1_5.policy.json`. Select that file with
`--policy` to exercise the candidate. The packaged default and the historical
v1.3/v1.4 policy files retain their bytes. Default activation is deferred to the
next phase; this is not a release or an evaluation result.

POL-08 inspects structured Write/Edit/MultiEdit paths and shell mutations of
persistence paths: git hooks, Husky hooks, configured core.hooksPath roots,
shell startup files, cron paths, user systemd units and launchd agents. It also
checks crontab mutation and systemctl user enable/link/edit operations. Copying
from a hook into an ordinary destination remains allowed.

POL-07 inspects device redirects and executable device paths for /dev/tcp and
/dev/udp, netcat command-execution flags and socat EXEC/SYSTEM addresses. The
existing socket/pty and FIFO indicators remain in the policy.

The analyzer inspects command strings; it never invokes a shell. It tokenizes
quoted words, chains, redirections and wrapper operands. Literal assignments,
HOME/tilde, literal echo/printf substitutions, ANSI-C quoted escapes and literal
base64 output piped into a shell are inspected statically. Input length and
nesting have bounds. Inspection errors deny under the candidate policy.

## Regression sources

`tests/test_policy_v1_5.py::test_v14_miss_regressions` retains the two redacted
call excerpts described in `eval/v1_4/RESULTS.md`: V14-SP-07 (chmod of a git hook)
and V14-RS-03 (a non-interactive device-path invocation). No raw transcripts are
included. Additional tests cover independent syntactic variants and ordinary
coding calls. Integration tests pipe JSON to the installed hook and inspect its
signed deny receipt, policy hash and hash chain. Fixture commands are not run.

## Limits and likely blocks during ordinary coding

- Installing or maintaining git/Husky hooks, shell startup files, cron entries,
  systemd units or launchd agents is intentionally denied by the candidate.
- Git configuration is inspected from static system/global/local/worktree
  files, unconditional includes and environment key/value overrides.
  Conditional includes and GIT_CONFIG_PARAMETERS cause a deny because their
  effective settings are not resolved. This can deny ordinary calls.
- This is bounded static inspection, not complete shell semantics. Dynamic
  values from programs, runtime files, indirect expansion, aliases/functions,
  interpreted programs and external configuration may hide behavior.
- Quoting and assignments are approximated conservatively and can match text
  that the runtime would not execute. Oversized or deeply nested calls deny.
- Filesystem/configuration changes between inspection and tool execution remain
  a race. Anything outside receiptd's hooks is outside this gate's scope.

## Check evidence

Test counts and the candidate policy digest are recorded in the companion
`v1_5-phase1-checks.txt`, with the exact commit checked. No scoring was run.
