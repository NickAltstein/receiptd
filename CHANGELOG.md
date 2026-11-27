# Changelog

## [Unreleased]

- Add `Glob` and `Grep` to the `PreToolUse` hook matcher (`receiptd init --claude-code` installs the fail-closed gate for hooked tool calls with the new matcher; existing installs must re-run `receiptd init --claude-code` to get it), and inspect `python <file>.py` workspace scripts in the remote-shell check, denying unreadable or cyclic paths.
- Update README examples from isolated command captures and document the v1.5 scored results.
- Install the Stop hook only when `receiptd init --test-cmd` names a test command.
- When the PreToolUse gate crashes after writing an allow receipt, the hook now appends a signed deny receipt naming it, so the ledger shows the call was blocked. Existing installs keep the old hook command until you re-run `receiptd init --claude-code`.
- The gate waits for its watchdog timer thread before it exits.

## [1.2.0] - 2026-11-17

- Default PreToolUse policy denies download-and-execute commands, remote shell indicators, credential reads paired with egress, and writes to persistence paths.
- Check visible workflow edits and compare whole-file changes to workflow controls.
- Deny structured writes and edits on shell startup, Git hook, and service registration paths.
- Render hook receipts as an offline graph (`receiptd graph`).
- Add ledger tamper demo clip.
- Record v1.2 scoring plan with attack evaluation set addendum.
- PyPI project page links to the GitHub repository, issues, and changelog.

## [1.1.1]

- Align the CLI, package, and health endpoint version at 1.1.1.

## [1.1.0] - 2026-11-16

Package version 1.1.0 matches git tag `v1.1`. `receiptd version`, `pyproject.toml`, and `health/health_endpoint.py` report 1.1.0. This entry does not create a tag or a GitHub release.

### Changed
- `receiptd init` writes new ledgers at `.receiptd/receipts.jsonl`. If that file is absent and `.birkin/receipts.jsonl` already exists, init keeps appending to the old file.
- `receiptd card --demo` reads the red demo session shipped in the package (`receiptd/card/demo/red.jsonl`).
- README, `THREAT_MODEL.md`, and `IMPLEMENTATION_STATUS.md` describe a fail-closed gate for hooked tool calls.
- Install from PyPI with `pip install receiptd`.

## [1.0.0] - 2026-11-10

### Added
- Signed Trifecta Card pipeline (`receiptd.card`) with deterministic rule classifier (`rules.yaml`), session parser, redact engine, and 1200x630 social preview card renderer (`card.png`, `card.svg`, `card.json`).
- `receiptd verify-card CARD.json` command: validates Ed25519 signature and canonical JSON (sorted keys) digest; outputs `VALID (<verdict>)` or `TAMPERED (<reason>)`.
- `receiptd stop-gate` command and Claude Code `Stop` hook: halts task completion with exit code 2 if tests fail, requiring signed completion receipts.
- Demo sessions so a card can be rendered without a local session log (`receiptd/card/demo/{red,yellow,green}.jsonl`).
- Network isolation test checking for zero outbound network calls and zero file content or prompt leakage.

### Changed
- Replaced legacy regex-based trifecta scanner (`receiptd/trifecta.py`) with full `receiptd.card` pipeline.
- Updated `receiptd card` command with `--session`, `--last`, `--out`, and `--redact-paths` flags.
- Package classifier updated to `Development Status :: 4 - Beta`.
- Updated benchmarks in package description to reflect measured 0.02ms in-process evaluation and ~78ms cold CLI hook latency (`benchmarks/results.json`, commit 82691be).

## [0.2.0] - 2026-11-05

### Added
- Honest component status table in README.
- Explicit LIMITATIONS section (single-user, runs on one machine, limited adapters, no production scheduler).
- Clarified the one-sentence description: receipts you can check offline for hooked tool calls.
- Pinned Python >=3.10 more clearly in install notes.
- Every major README claim now has a corresponding command or test name that a stranger can run in <5 minutes.

### Changed
- README lead sentence focuses on the authorization + evidence plane, not historical iMessage/Hermes remote control.
- Hermes is documented only as one example runtime adapter.

### Fixed
- Install instructions checked on a clean clone with `pip install -e .`.

## [0.1.0] - earlier

Initial vertical slice: signed receipts, policy engine, hash-chained audit, Merkle checkpoints, offline hash-chain checking, tamper matrix, receipt binding tests, NullAgent adapter.
