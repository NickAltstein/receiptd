# v1.5 Phase 2: self-protection

## Existing behavior before this change

Inspected at `11092eaa3e61bc87ff25ad2346276a2c42394380`:

- `load_policy_file`, `load_policy_from_argv` and `_run` already deny missing,
  unreadable and invalid policies. They emit POLICY_MISSING, POLICY_UNREADABLE
  or POLICY_INVALID receipts when evidence storage is writable.
- `tests/test_policy_bytes.py::test_missing_invalid_and_unreadable_policy_fail_closed`
  already checks those cases. This is not new behavior.
- POL-03 already matches the standard .claude/settings.json and local settings
  filename. It does not cover every settings suffix or all shell mutations.
- Signing failure already returns exit 2 and attempts an unsigned deny receipt.
  An unavailable signing key cannot produce a signed receipt; unwritable
  evidence storage cannot promise a receipt.

## Added candidate behavior

POL-11:SELF_PROTECTION denies structured Write/Edit/MultiEdit operations and
statically recognized shell mutations targeting .claude/settings*, the loaded
policy file, the key directory or receipt directory. Runtime supplies the actual
policy and ledger locations, including custom flags; the key directory follows
RECEIPTD_KEY_DIR. Project .receiptd and legacy .birkin paths are also protected.
Symlink targets and ancestor-directory mutations are checked. Moves check their
source as well as destination. In-place sed/perl edits are included.

The packaged default and historical policy bytes remain unchanged. Select the
candidate explicitly using the README instructions. Its digest changes in this
phase; the Phase 4 plan must pin the final candidate bytes, not the Phase 1 hash.
No plan or score has been produced here.

## Limits

This is mutation detection over hooked payloads, not a filesystem sandbox. Other
interpreters, arbitrary program behavior, hard-link aliases already on disk and
concurrent filesystem changes can evade static path inspection. Ancestor-path
checks may deny ordinary directory maintenance. POL-11 does not impose a blanket
read restriction on key/evidence paths. Anything outside receiptd's hooks remains
outside this control. Missing/invalid-policy receipt behavior is unchanged.

Phase 4 must select and hash a real privately retained git-config session before
scoring. Nick supplies that session; a synthetic unit fixture is not a replacement.
Phase 3 has not started.
