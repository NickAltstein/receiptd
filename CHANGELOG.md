# Changelog

## Unreleased

- PyPI project page links to the GitHub repository, issues, and changelog.

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
