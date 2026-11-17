"""Benign Claude Code session replay and descriptive historical denial reporting."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from receiptd.card.parser import parse_session_file

from .audit import audit_ledger, run_hook_direct
from .manifest_checks import EXPECTED_POLICY_SHA256, PinMismatchError

ELIGIBLE_TOOL_RE = re.compile(r"^(Bash|Write|Edit|MultiEdit|mcp__.*)$")


def _index_session_files(sessions_root: Path) -> dict[str, Path]:
    """Map transcript filename -> path beneath sessions_root without reading Beacon/mcpvenom."""
    found: dict[str, Path] = {}
    if not sessions_root.exists():
        return found
    for path in sorted(sessions_root.rglob("*.jsonl")):
        found[path.name] = path
    return found


def _extract_raw_tool_calls(transcript_path: Path) -> list[dict[str, Any]]:
    """Extract ordered tool_use payloads from one Claude Code transcript without keeping text."""
    calls: list[dict[str, Any]] = []
    for raw_line in transcript_path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip():
            continue
        record = json.loads(raw_line)
        if record.get("type") != "assistant":
            continue
        message = record.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            name = str(block.get("name") or "unknown")
            inp = block.get("input")
            calls.append(
                {
                    "tool_name": name,
                    "tool_input": inp if isinstance(inp, dict) else {},
                }
            )
    return calls


def one_sided_95_binomial_upper_bound(k_denied: int, n_trials: int) -> float | None:
    """Compute exact Clopper-Pearson one-sided 95% upper bound for zero denials cleanly."""
    if n_trials <= 0:
        return None
    if k_denied == 0:
        return round(1.0 - (0.05 ** (1.0 / n_trials)), 6)
    return None


def replay_benign_manifest(
    *,
    benign_manifest: dict[str, Any],
    sessions_root: Path,
    receiptd_python: Path,
    policy_path: Path,
    ledger_path: Path,
    key_dir: Path,
    adjudication: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay frozen historical session calls and report descriptive outcomes unless adjudicated."""
    file_index = _index_session_files(sessions_root)
    unique_sessions = benign_manifest.get("unique_sessions", [])

    total_files_checked = 0
    total_calls_observed = 0
    eligible_calls_replayed = 0
    eligible_sessions_with_calls = 0

    calls_denied = 0
    calls_allowed = 0
    calls_unexpected_exit = 0
    sessions_with_denial: set[str] = set()
    denied_summaries: list[dict[str, Any]] = []

    for sess in unique_sessions:
        sess_id = str(sess["session_id"])
        file_names = list(sess.get("file_names", []))
        file_hashes = list(sess.get("file_sha256s", []))
        if len(file_names) != len(file_hashes):
            raise PinMismatchError(f"Mismatched file_names/file_sha256s for session {sess_id}")

        sess_eligible = 0
        for fname, expected_hash in zip(file_names, file_hashes):
            path = file_index.get(fname)
            if path is None or not path.is_file():
                raise PinMismatchError(f"Frozen transcript file missing under {sessions_root}: {fname}")
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                raise PinMismatchError(
                    f"Frozen transcript hash mismatch for {fname}: expected {expected_hash}, got {actual_hash}"
                )
            total_files_checked += 1

            parsed = parse_session_file(path)
            raw_calls = _extract_raw_tool_calls(path)
            if len(parsed.calls) != len(raw_calls):
                raise PinMismatchError(
                    f"Parsed call count ({len(parsed.calls)}) != raw tool_use count ({len(raw_calls)}) in {fname}"
                )
            total_calls_observed += len(raw_calls)

            for call in raw_calls:
                tname = call["tool_name"]
                if not ELIGIBLE_TOOL_RE.match(tname):
                    continue
                eligible_calls_replayed += 1
                sess_eligible += 1
                payload = {
                    "session_id": sess_id,
                    "tool_name": tname,
                    "tool_input": call["tool_input"],
                }
                hook_res = run_hook_direct(
                    payload,
                    receiptd_python=receiptd_python,
                    policy_path=policy_path,
                    ledger_path=ledger_path,
                    key_dir=key_dir,
                )
                if hook_res.exit_code == 2:
                    calls_denied += 1
                    sessions_with_denial.add(sess_id)
                    denied_summaries.append(
                        {
                            "session_id": sess_id,
                            "tool_name": tname,
                            "stderr": hook_res.stderr.strip()[:300],
                        }
                    )
                elif hook_res.exit_code == 0:
                    calls_allowed += 1
                else:
                    calls_unexpected_exit += 1

        if sess_eligible > 0:
            eligible_sessions_with_calls += 1

    if total_files_checked != benign_manifest["transcript_file_count"]:
        raise PinMismatchError("Replayed transcript file count mismatch")
    if total_calls_observed != benign_manifest["total_tool_calls"]:
        raise PinMismatchError("Replayed total tool call count mismatch")
    if eligible_calls_replayed != benign_manifest["eligible_hooked_calls"]:
        raise PinMismatchError("Replayed eligible hooked call count mismatch")
    if eligible_sessions_with_calls != benign_manifest["sessions_with_eligible_hooked_calls"]:
        raise PinMismatchError("Replayed eligible session count mismatch")

    ledger_audit = audit_ledger(
        ledger_path,
        receiptd_python=receiptd_python,
        key_dir=key_dir,
        expected_policy_sha256=EXPECTED_POLICY_SHA256,
    )

    return summarize_benign_outcomes(
        transcript_files=total_files_checked,
        unique_sessions=len(unique_sessions),
        eligible_sessions=eligible_sessions_with_calls,
        total_calls=total_calls_observed,
        eligible_calls=eligible_calls_replayed,
        historical_calls_denied=calls_denied,
        historical_calls_allowed=calls_allowed,
        unexpected_exits=calls_unexpected_exit,
        historical_sessions_with_denial=len(sessions_with_denial),
        denied_summaries=denied_summaries,
        ledger_audit=ledger_audit,
        adjudication=adjudication,
    )


def summarize_benign_outcomes(
    *,
    transcript_files: int,
    unique_sessions: int,
    eligible_sessions: int,
    total_calls: int,
    eligible_calls: int,
    historical_calls_denied: int,
    historical_calls_allowed: int,
    unexpected_exits: int,
    historical_sessions_with_denial: int,
    denied_summaries: list[dict[str, Any]],
    ledger_audit: dict[str, Any],
    adjudication: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Format benign replay metrics descriptively unless pre-gate adjudication is provided."""
    adjudicated_flag = bool(adjudication and adjudication.get("frozen_before_gate") is True)
    report: dict[str, Any] = {
        "transcript_file_count": transcript_files,
        "unique_session_count": unique_sessions,
        "eligible_session_count": eligible_sessions,
        "total_tool_calls": total_calls,
        "eligible_hooked_calls": eligible_calls,
        "historical_eligible_calls_denied": historical_calls_denied,
        "historical_eligible_calls_allowed": historical_calls_allowed,
        "historical_calls_unexpected_exit": unexpected_exits,
        "historical_eligible_sessions_with_denial": historical_sessions_with_denial,
        "denied_call_summaries": denied_summaries,
        "adjudicated_expected_outcomes": adjudicated_flag,
        "reporting_mode": "adjudicated_false_blocks" if adjudicated_flag else "descriptive_historical_denials",
        "ledger_audit": {
            "policy_hash_ok": ledger_audit.get("policy_hash_ok"),
            "signature_and_chain_ok": ledger_audit.get("signature_and_chain_ok"),
            "local_anchor_status": ledger_audit.get("local_anchor_status"),
            "checkpoint_status": ledger_audit.get("checkpoint_status"),
            "receipt_count": ledger_audit.get("receipt_count"),
            "checkpoint_count": ledger_audit.get("checkpoint_count"),
        },
        "false_block_rate_sessions": None,
        "session_one_sided_95_upper_bound": None,
    }

    if adjudicated_flag and adjudication is not None:
        expected_allow_sessions = int(adjudication.get("expected_allow_session_count", 0))
        false_block_sessions = int(adjudication.get("false_block_session_count", 0))
        if expected_allow_sessions > 0:
            report["false_block_rate_sessions"] = (
                f"{false_block_sessions}/{expected_allow_sessions}"
            )
            report["session_one_sided_95_upper_bound"] = one_sided_95_binomial_upper_bound(
                false_block_sessions, expected_allow_sessions
            )
    return report
