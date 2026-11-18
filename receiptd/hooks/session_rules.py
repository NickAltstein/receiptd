"""Stateful per-session ledger rules for receiptd v1.3.

All window durations and count thresholds in this module are defaults, not tuned values.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..crypto import sha256_hex
from .normalize import extract_normalized_paths, normalize_tool_input

# Default bounds, not tuned values.
DEFAULT_ADAPTIVE_RETRY_WINDOW_SECONDS = 60

RULE_ADAPTIVE_RETRY = "RULE-01:ADAPTIVE_RETRY"
RULE_ADAPTIVE_RETRY_ESCALATION = "RULE-01:ADAPTIVE_RETRY_ESCALATION"
RULE_SESSION_DENIED = "RULE-01:SESSION_DENIED"

RECEIPT_TYPE_ADAPTIVE_RETRY = "adaptive_retry"
RECEIPT_TYPE_ADAPTIVE_RETRY_ESCALATION = "adaptive_retry_escalation"
RECEIPT_TYPE_SESSION_DENIED = "session_denied"

_PROTECTED_PATH_PATTERNS = (
    re.compile(r"(?:^|/)\.env(?:\.[^/\s]*)?$"),
    re.compile(r"(?:^|/)\.aws/(?:credentials|config)$"),
    re.compile(r"(?:^|/)\.ssh/(?:id_[^/\s]+|authorized_keys|config|known_hosts)$"),
    re.compile(r"(?:^|/)\.(?:netrc|npmrc|pypirc)$"),
    re.compile(r"(?:^|/)\.kube/config$"),
    re.compile(r"(?:^|/)\.claude/settings(?:\.local)?\.json$"),
    re.compile(r"(?:^|/)\.github/workflows/[^/\s]+\.ya?ml$"),
    re.compile(r"(?:^|/)\.(?:bashrc|zshrc|profile|bash_profile)$"),
    re.compile(r"(?:^|/)\.git/hooks/"),
    re.compile(r"(?:^|/)library/launchagents/"),
    re.compile(r"(?:^|/)launchdaemons/"),
    re.compile(r"(?:^|/)\.config/systemd/user/"),
    re.compile(r"^/etc/(?:passwd|shadow|sudoers)$"),
    re.compile(r"(?:^|/)credentials(?:\.[^/\s]+)?$"),
)


def is_protected_path(path: str) -> bool:
    """Return True if a normalized path refers to a protected secret or persistence target."""
    if not isinstance(path, str) or not path:
        return False
    lowered = path.lower().rstrip("/")
    return any(pattern.search(lowered) for pattern in _PROTECTED_PATH_PATTERNS)


def protected_path_hashes_for_call(tool_name: str, tool_input: Any) -> list[str]:
    """Return sorted unique SHA-256 digests of normalized protected paths in tool_input."""
    hashes: list[str] = []
    for norm_path in extract_normalized_paths(tool_name, tool_input):
        if is_protected_path(norm_path):
            digest = sha256_hex(norm_path.encode("utf-8"))
            if digest not in hashes:
                hashes.append(digest)
    return hashes


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def resolve_adaptive_retry_window(
    policy_window: int | None = None,
    environ: dict[str, str] | None = None,
) -> int:
    env = os.environ if environ is None else environ
    raw_env = env.get("RECEIPTD_ADAPTIVE_RETRY_WINDOW_SECONDS")
    if raw_env is not None:
        try:
            parsed = int(raw_env)
            if parsed > 0:
                return parsed
        except ValueError:
            pass
    if isinstance(policy_window, int) and policy_window > 0:
        return policy_window
    return DEFAULT_ADAPTIVE_RETRY_WINDOW_SECONDS


def read_session_receipts(ledger_path: Path | str, session_id: str) -> list[dict[str, Any]]:
    """Read receipt records (excluding checkpoints) belonging to session_id."""
    path = Path(ledger_path)
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return []
    for line in content.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict) or obj.get("type") == "checkpoint":
            continue
        if str(obj.get("session_id", "")) == session_id:
            rows.append(obj)
    return rows


def _row_norm_hash(row: dict[str, Any]) -> str | None:
    existing = row.get("normalized_args_sha256")
    if isinstance(existing, str) and existing:
        return existing
    tool_name = str(row.get("tool") or row.get("tool_name") or "")
    tool_input = row.get("tool_input")
    if isinstance(tool_input, dict) and tool_name:
        _, _, digest = normalize_tool_input(tool_name, tool_input)
        return digest
    return None


def _row_protected_hashes(row: dict[str, Any]) -> set[str]:
    existing = row.get("protected_path_hashes")
    if isinstance(existing, list):
        return {str(item) for item in existing if isinstance(item, str) and item}
    tool_name = str(row.get("tool") or row.get("tool_name") or "")
    tool_input = row.get("tool_input")
    if isinstance(tool_input, dict) and tool_name:
        return set(protected_path_hashes_for_call(tool_name, tool_input))
    return set()


@dataclass(frozen=True)
class AdaptiveRetryVerdict:
    kind: str  # "none" | "adaptive_retry" | "adaptive_retry_escalation" | "session_denied"
    rule_id: str | None
    reason: str | None
    prior_denied_receipt_hash: str | None
    prior_denied_args_sha256: str | None
    origin_denied_ts: str | None


def evaluate_adaptive_retry(
    session_receipts: list[dict[str, Any]],
    *,
    tool_name: str,
    normalized_args_sha256: str,
    protected_path_hashes: list[str],
    now: datetime,
    window_seconds: int = DEFAULT_ADAPTIVE_RETRY_WINDOW_SECONDS,
) -> AdaptiveRetryVerdict:
    """Evaluate Rule 1 (adaptive retry after deny and session denial on 2nd retry within W)."""
    for row in session_receipts:
        if (
            row.get("session_denied") is True
            or row.get("receipt_type") in (RECEIPT_TYPE_ADAPTIVE_RETRY_ESCALATION, RECEIPT_TYPE_SESSION_DENIED)
            or RULE_ADAPTIVE_RETRY_ESCALATION in (row.get("rule_ids") or [])
            or RULE_SESSION_DENIED in (row.get("rule_ids") or [])
        ):
            return AdaptiveRetryVerdict(
                kind=RECEIPT_TYPE_SESSION_DENIED,
                rule_id=RULE_SESSION_DENIED,
                reason="session denied",
                prior_denied_receipt_hash=str(row.get("hash") or row.get("receipt_sha256") or "") or None,
                prior_denied_args_sha256=str(row.get("normalized_args_sha256") or "") or None,
                origin_denied_ts=str(row.get("origin_denied_ts") or row.get("ts") or "") or None,
            )

    cutoff = now - timedelta(seconds=window_seconds)
    current_path_set = set(protected_path_hashes)

    matching_denies: list[dict[str, Any]] = []
    for row in session_receipts:
        if row.get("decision") != "deny":
            continue
        row_tool = str(row.get("tool") or row.get("tool_name") or "")
        if row_tool != tool_name:
            continue
        row_ts = parse_timestamp(row.get("ts"))
        if row_ts is None or row_ts < cutoff or row_ts > now:
            continue
        row_norm = _row_norm_hash(row)
        row_paths = _row_protected_hashes(row)
        same_norm_args = row_norm is not None and row_norm == normalized_args_sha256
        same_protected_path = bool(current_path_set and (row_paths & current_path_set))
        if same_norm_args or same_protected_path:
            matching_denies.append(row)

    if not matching_denies:
        return AdaptiveRetryVerdict("none", None, None, None, None, None)

    prior_retry = next(
        (row for row in reversed(matching_denies) if row.get("receipt_type") == RECEIPT_TYPE_ADAPTIVE_RETRY),
        None,
    )
    if prior_retry is not None:
        origin_ts = parse_timestamp(prior_retry.get("origin_denied_ts") or prior_retry.get("ts"))
        if origin_ts is not None and origin_ts >= cutoff:
            return AdaptiveRetryVerdict(
                kind=RECEIPT_TYPE_ADAPTIVE_RETRY_ESCALATION,
                rule_id=RULE_ADAPTIVE_RETRY_ESCALATION,
                reason=f"session denied: matched rule {RULE_ADAPTIVE_RETRY_ESCALATION}",
                prior_denied_receipt_hash=str(
                    prior_retry.get("prior_denied_receipt_hash")
                    or prior_retry.get("hash")
                    or ""
                )
                or None,
                prior_denied_args_sha256=str(
                    prior_retry.get("prior_denied_args_sha256")
                    or prior_retry.get("normalized_args_sha256")
                    or ""
                )
                or None,
                origin_denied_ts=origin_ts.isoformat(),
            )

    anchor = matching_denies[0]
    return AdaptiveRetryVerdict(
        kind=RECEIPT_TYPE_ADAPTIVE_RETRY,
        rule_id=RULE_ADAPTIVE_RETRY,
        reason=f"matched rule {RULE_ADAPTIVE_RETRY}",
        prior_denied_receipt_hash=str(anchor.get("hash") or anchor.get("receipt_sha256") or "") or None,
        prior_denied_args_sha256=str(anchor.get("normalized_args_sha256") or _row_norm_hash(anchor) or "") or None,
        origin_denied_ts=str(anchor.get("ts") or "") or None,
    )
