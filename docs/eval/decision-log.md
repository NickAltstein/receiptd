# v1.2 Evaluation Pre-Run Decision Log

Recorded prior to executing the `--live` 40-case `dcode` evaluation.

## 2026-11-19T19:53-05:00 (2026-11-20T00:53Z)

### Scored Commit & Artifact Pins
- **Scored code commit:** `8cd7e924a8b1ddb4c3fff1165b3ded8cfea3dcd9` (`main`, merge of PR `#35`; runtime code under `receiptd/` and `scripts/eval_v1_2/` is unchanged from `8cd7e92`).
- **Pinned hashes (unchanged from `839711fdec4e62b551c04d5a13cc5e231b962fcf`):**
  - `docs/eval/v1.2-scoring-plan.md`: `5def5c9e6f128ca421aae8b55866b44a49f80db03a118cb17535508c1babc511`
  - `docs/eval/v1.2-attack-manifest.json`: `24b6ae4c7118a2fe36ce3a5ea7546e2b16a5b786a53aad1dc39a7719a4465f44`
  - `docs/eval/benign-sessions-manifest.json`: `d117e52b6237ef1b898ab8b38144aa97943316ce8b558104f3cf7352e2b6378c`
  - `receiptd/hooks/default_pretooluse.policy.json`: `8f5901d2a1c88c88bdb0d7d9598050b2a6b9cfa289de5a2851e76a764d163986`

### Open PR Decisions Before Scoring
- **PR `#37` (`fix/verify-pubkey-path`):** Identified before scoring; **not merged**. Checked `scripts/eval_v1_2/audit.py` (lines 81–82, 155): `audit_ledger` passes `pubkey_pem = get_public_key_pem(key_dir=key_dir)` as inline PEM text rather than a filesystem path, so the `--pubkey` path-loading bug cannot affect the `--live` scored path. Leaving `#37` unmerged and leaving `docs/eval/v1.2-scoring-plan.md` untouched preserves `EXPECTED_PLAN_SHA256` (`5def5c9e...`).
- **PR `#36` (`feat/v1.3-adaptive-retry`):** Held unmerged until after the `v1.2.0` 40-case evaluation completes because it modifies `receiptd/hooks/default_pretooluse.policy.json`.
- **PR `#30` (`docs/clarify-trifecta-card`):** Confirmed its `README.md` clarification already landed on `main`; closed as superseded.

### Bitcoin Block Attestations (`docs/eval/attestations/*.ots`)
Upgraded all three `.ots` proofs (`v1.2-scoring-plan.md.ots`, `v1.2-attack-manifest.json.ots`, `benign-sessions-manifest.json.ots`) in place prior to `--live` (`.bak` backups retained locally outside git):
- Block `976330` (`00000000000000000000f5b756b188f9835e3f54b063a94c1277d8a3612a659c`): `2026-11-17T22:07:28+00:00`
- Block `976331` (`00000000000000000000730796276316aee44a63aa6dba06e2f0eab4ca56b17a`): `2026-11-17T22:09:09+00:00`
- Block `976355` (`00000000000000000001fd72820ab9a274d55c01b785be1c67c37c5dbd6648e6`): `2026-11-18T00:59:03+00:00`

## 2026-11-23T14:10-05:00 (2026-11-23T19:10Z)

### Loopback Preflight Protocol Amendment: SIP-Protected `com.apple.rapportd`
- With AirPlay Receiver and Handoff disabled (`ControlCenter` cleared), `com.apple.rapportd` (`pid=989`) remained listening on `*:60310` (IPv4/IPv6).
- `launchctl bootout gui/$(id -u)/com.apple.rapportd` failed with `Boot-out failed: 150: Operation not permitted while System Integrity Protection is engaged`.
- Rather than loosening the default loopback allowlist silently, `scripts/eval_v1_2/sandbox.py` adds an explicit opt-in flag `--allow-system-rapportd` (`allow_system_rapportd=False` by default) that permits only `rapportd` when passed and logs `"allow_system_rapportd": true` alongside the full listener list in `loopback_preflight.json`.
