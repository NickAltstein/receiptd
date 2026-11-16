# Receiptd — Implementation Status (November 2026)

This document catalogs what is implemented, what the tests cover, the security limits, and deferred items.

---

## 1. Security plane and policy status

| Component | Status | What the tests cover | Tests / evidence |
| :--- | :---: | :--- | :--- |
| **Fail-closed policy engine** | **Production** | Path-component containment, sibling-prefix collision, symlink resolution, relative-path rejection, fail-closed handling | `policy.py`, `test_policy_enforcement_threat_model.py` |
| **Ed25519 receipt signing** | **Production** | Canonical JSON (sorted keys), 12 bound fields | `models.py`, `crypto.py`, `test_receipt_binding.py` |
| **Tamper-evident audit ledger** | **Production** | SHA-256 forward-chained events, Merkle root checkpoints | `audit.py`, `test_tamper_matrix.py`, `tests/tamper-test.sh` |
| **Offline hash-chain CLI** | **Production** | `receiptd verify` with no server | `verify.py`, `scripts/ci_smoke.sh` |
| **Human-in-the-loop controls** | **Production** | Requesting-identity binding, signature check, duplicate transition prevention (`approve`/`reject`), argument hash binding on execution | `engine.py`, `test_policy_enforcement_threat_model.py` |
| **INFINI action gateway** | **Production** | Decoupled pre-action step authorization gateway | `adapters/infini_gateway.py`, `test_infini_integration.py` |
| **Hermes adapter** | **Demonstration** | In-process tool registry showing the interception seam (`fs.write`, `shell.exec`) | `adapters/hermes.py`, `demos/end_to_end.py` |
| **NullAgent adapter** | **Production** | Reference minimal adapter for the AgentAdapter contract | `adapters/null_agent.py`, `test_null_adapter.py` |

---

## 2. Tested suites and CI gates

- **Unit and security suite (`pytest tests/`):** run `pytest` on a checkout. The count changes as tests are added; do not treat an old count in this file as current.
- **Threat-model policy suite (`test_policy_enforcement_threat_model.py`):** sibling-prefix collisions, symlink escapes, relative path rejection, malformed paths, symlink cycles, HITL identity and duplicate enforcement, args-hash check.
- **Tamper matrix (`tests/test_tamper_matrix.py`):** signature flip, identity rewrite, policy swap, checkpoint rewrite, missing event, reordered event.
- **SQLite hash-chain tamper test (`bash tests/tamper-test.sh`):** trigger bypass and row rewrite.
- **CI smoke gate (`bash scripts/ci_smoke.sh`):** 7 vertical-slice checks.

---

## 3. Security limits

1. **In-process boundary:** Receiptd intercepts tool dispatches at the Python adapter layer and at the Claude Code hooks it installs. It does not replace OS-level cgroups, containers, or hypervisors. A process that never enters those hooks is not gated.
2. **Local hash chain vs. storage:** The hash chain shows tampering when you run `receiptd verify` or `verify-chain.py`. It does not stop a root administrator from modifying or deleting local files.
3. **Filesystem races (TOCTOU):** Policy evaluation checks path containment before execution. If symlinks or directory entries are swapped between the check and the syscall, a TOCTOU race can occur. A full defense needs OS primitives such as `openat2(..., RESOLVE_BENEATH)` or container mount namespaces.
4. **Hermes adapter:** The Hermes adapter is an in-process tool registry for the policy seam. A distributed Hermes deployment needs its own transport adapter.

---

## 4. Deliberately deferred items

1. **Asynchronous webhook HITL dashboard:** HITL approvals are deterministic API/CLI methods (`engine.approve`, `engine.reject`). A web approval dashboard with Slack or PagerDuty webhooks is deferred.
2. **Automated key rotation:** Ed25519 keypairs are generated on the host or loaded from environment variables. KMS or HSM rotation is deferred.
