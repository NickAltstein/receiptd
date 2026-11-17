"""Direct hook invocation and separated ledger/receipt audit helpers."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from receiptd.crypto import canonical_json, canonical_json_subset, get_public_key_pem, sha256_hex, verify_ed25519
from receiptd.ledger import GENESIS_HASH, SIGNABLE_RECEIPT_FIELDS

from .manifest_checks import EXPECTED_POLICY_SHA256


@dataclass(frozen=True)
class HookCallResult:
    """Raw subprocess result from invoking receiptd PreToolUse hook."""

    exit_code: int
    stdout: str
    stderr: str


def run_hook_direct(
    payload: dict[str, Any],
    *,
    receiptd_python: Path,
    policy_path: Path,
    ledger_path: Path,
    key_dir: Path,
    timeout_seconds: float = 30.0,
) -> HookCallResult:
    """Invoke receiptd.hooks.claude_code_gate directly on JSON stdin without wrapper shell."""
    env = dict(os.environ)
    env["RECEIPTD_KEY_DIR"] = str(key_dir)
    env.pop("RECEIPTD_SIGNING_KEY", None)
    env.pop("BIRKIN_SIGNING_KEY", None)
    proc = subprocess.run(
        [
            str(receiptd_python),
            "-m",
            "receiptd.hooks.claude_code_gate",
            "--policy",
            str(policy_path),
            "--ledger",
            str(ledger_path),
        ],
        input=json.dumps(payload),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    return HookCallResult(
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def _run_receiptd_verify(
    *,
    receiptd_python: Path,
    ledger_path: Path,
    key_dir: Path,
    pubkey_pem: str | None,
    allow_unanchored: bool,
) -> tuple[int, str]:
    cmd = [
        str(receiptd_python),
        "-m",
        "receiptd.cli",
        "verify",
        "--ledger",
        str(ledger_path),
    ]
    if pubkey_pem:
        cmd.extend(["--pubkey", pubkey_pem])
    if allow_unanchored:
        cmd.append("--allow-unanchored")
    env = dict(os.environ)
    env["RECEIPTD_KEY_DIR"] = str(key_dir)
    proc = subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _classify_anchor_status(rc: int, output: str) -> str:
    if rc == 0:
        return "checked_pass"
    lowered = output.lower()
    if "missing signed ledger anchor" in lowered or "anchor state file" in lowered:
        return "missing"
    if "unsigned" in lowered:
        return "unsigned"
    if "invalid ed25519 signature" in lowered:
        return "invalid_signature"
    return "truncation_mismatch"


def audit_ledger(
    ledger_path: Path,
    *,
    receiptd_python: Path,
    key_dir: Path,
    expected_policy_sha256: str = EXPECTED_POLICY_SHA256,
) -> dict[str, Any]:
    """Audit ledger entries across policy hash, signature/chain, local anchor, and checkpoints."""
    if not ledger_path.is_file():
        return {
            "ledger_exists": False,
            "receipt_count": 0,
            "checkpoint_count": 0,
            "receipts": [],
            "policy_hash_ok": False,
            "policy_hash_mismatches": ["ledger_missing"],
            "signature_and_chain_ok": False,
            "unsigned_count": 0,
            "invalid_sig_count": 0,
            "chain_break_count": 0,
            "local_anchor_status": "missing",
            "checkpoint_status": "none_emitted_below_interval",
            "verify_unanchored_exit_code": None,
            "verify_unanchored_output": "",
            "verify_anchored_exit_code": None,
            "verify_anchored_output": "",
        }

    raw_lines = [ln for ln in ledger_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    entries: list[dict[str, Any]] = []
    parse_errors = 0
    for ln in raw_lines:
        try:
            obj = json.loads(ln)
            if isinstance(obj, dict):
                entries.append(obj)
            else:
                parse_errors += 1
        except json.JSONDecodeError:
            parse_errors += 1

    receipts = [e for e in entries if e.get("type") != "checkpoint"]
    checkpoints = [e for e in entries if e.get("type") == "checkpoint"]

    try:
        pubkey_pem = get_public_key_pem(key_dir=key_dir)
    except Exception:
        pubkey_pem = None

    policy_mismatches: list[str] = []
    unsigned_count = 0
    invalid_sig_count = 0
    chain_break_count = parse_errors

    expected_prev = GENESIS_HASH
    for idx, rec in enumerate(receipts, 1):
        rec_seq = rec.get("seq")
        if rec_seq != idx:
            chain_break_count += 1
        stored_prev = rec.get("prev_hash") or rec.get("prev_receipt_hash") or ""
        if stored_prev != expected_prev:
            chain_break_count += 1

        stored_hash = rec.get("hash") or rec.get("receipt_sha256") or ""
        rec_copy = {k: v for k, v in rec.items() if k not in ("hash", "receipt_sha256")}
        recomputed = sha256_hex(canonical_json(rec_copy))
        if not stored_hash or recomputed != stored_hash:
            chain_break_count += 1

        expected_prev = stored_hash or recomputed

        pol_hash = rec.get("policy_sha256")
        if pol_hash != expected_policy_sha256:
            policy_mismatches.append(f"seq={rec_seq}:got={pol_hash}")

        sig = rec.get("sig")
        if bool(rec.get("signing_error", False)) or not sig:
            unsigned_count += 1
        elif not pubkey_pem:
            invalid_sig_count += 1
        else:
            signable = canonical_json_subset(rec, SIGNABLE_RECEIPT_FIELDS)
            if not verify_ed25519(pubkey_pem, sig, signable):
                invalid_sig_count += 1

    unanchored_rc, unanchored_out = _run_receiptd_verify(
        receiptd_python=receiptd_python,
        ledger_path=ledger_path,
        key_dir=key_dir,
        pubkey_pem=pubkey_pem,
        allow_unanchored=True,
    )
    anchored_rc, anchored_out = _run_receiptd_verify(
        receiptd_python=receiptd_python,
        ledger_path=ledger_path,
        key_dir=key_dir,
        pubkey_pem=pubkey_pem,
        allow_unanchored=False,
    )

    sig_chain_ok = (
        len(receipts) > 0
        and parse_errors == 0
        and chain_break_count == 0
        and unsigned_count == 0
        and invalid_sig_count == 0
        and unanchored_rc == 0
    )

    anchor_status = _classify_anchor_status(anchored_rc, anchored_out) if len(receipts) > 0 else "missing"

    if len(checkpoints) == 0:
        cp_status = "none_emitted_below_interval"
    elif unanchored_rc == 0:
        cp_status = "checked_pass"
    else:
        cp_status = "failed"

    return {
        "ledger_exists": True,
        "receipt_count": len(receipts),
        "checkpoint_count": len(checkpoints),
        "receipts": receipts,
        "policy_hash_ok": len(receipts) > 0 and len(policy_mismatches) == 0,
        "policy_hash_mismatches": policy_mismatches,
        "signature_and_chain_ok": sig_chain_ok,
        "unsigned_count": unsigned_count,
        "invalid_sig_count": invalid_sig_count,
        "chain_break_count": chain_break_count,
        "local_anchor_status": anchor_status,
        "checkpoint_status": cp_status,
        "verify_unanchored_exit_code": unanchored_rc,
        "verify_unanchored_output": unanchored_out,
        "verify_anchored_exit_code": anchored_rc,
        "verify_anchored_output": anchored_out,
    }


def evaluate_single_receipt_evidence(
    receipt: dict[str, Any] | None,
    ledger_audit: dict[str, Any],
    *,
    expected_decision: str,
    expected_policy_sha256: str = EXPECTED_POLICY_SHA256,
) -> dict[str, Any]:
    """Build separated evidence dictionary for one hooked call."""
    if receipt is None:
        return {
            "receipt_present": False,
            "policy_hash_ok": False,
            "signature_and_chain_ok": False,
            "local_anchor_status": ledger_audit.get("local_anchor_status", "missing"),
            "checkpoint_status": ledger_audit.get("checkpoint_status", "none_emitted_below_interval"),
            "evidence_status": "evidence_failure_missing_receipt",
            "failure_reason": "no matching receipt found in ledger",
            "verify_unanchored_output": ledger_audit.get("verify_unanchored_output", ""),
            "verify_anchored_output": ledger_audit.get("verify_anchored_output", ""),
        }

    is_unsigned = bool(receipt.get("signing_error", False)) or not receipt.get("sig")
    pol_ok = receipt.get("policy_sha256") == expected_policy_sha256
    sig_chain_ok = bool(ledger_audit.get("signature_and_chain_ok", False))
    decision_matches = receipt.get("decision") == expected_decision

    if is_unsigned:
        status = "evidence_failure_unsigned_receipt"
        reason = "receipt unsigned or signing_error=True"
    elif not pol_ok:
        status = "evidence_failure_policy_hash_mismatch"
        reason = f"receipt policy_sha256={receipt.get('policy_sha256')!r} != {expected_policy_sha256!r}"
    elif not sig_chain_ok:
        if ledger_audit.get("invalid_sig_count", 0) > 0:
            status = "evidence_failure_invalid_signature"
            reason = "Ed25519 signature check failed"
        else:
            status = "evidence_failure_broken_hash_chain"
            reason = "ledger hash chain or tamper audit failed"
    elif not decision_matches:
        status = "evidence_failure_decision_mismatch"
        reason = f"receipt decision={receipt.get('decision')!r} != {expected_decision!r}"
    else:
        status = "valid_signed_deny" if expected_decision == "deny" else "valid_signed_allow"
        reason = ""

    return {
        "receipt_present": True,
        "policy_hash_ok": pol_ok,
        "signature_and_chain_ok": sig_chain_ok and pol_ok and not is_unsigned,
        "local_anchor_status": ledger_audit.get("local_anchor_status", "missing"),
        "checkpoint_status": ledger_audit.get("checkpoint_status", "none_emitted_below_interval"),
        "evidence_status": status,
        "failure_reason": reason,
        "verify_unanchored_output": ledger_audit.get("verify_unanchored_output", ""),
        "verify_anchored_output": ledger_audit.get("verify_anchored_output", ""),
    }
