"""Stateful per-session ledger rules for receiptd v1.3.

All window durations and count thresholds in this module are defaults, not tuned values.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..crypto import canonical_json, sha256_hex
from .normalize import extract_normalized_paths, normalize_text, normalize_tool_input

# Default bounds, not tuned values.
DEFAULT_ADAPTIVE_RETRY_WINDOW_SECONDS = 60
DEFAULT_RECON_COUNT = 5
DEFAULT_RECON_WINDOW_SECONDS = 30
DEFAULT_EXPLOIT_WINDOW_SECONDS = 60
DEFAULT_DENY_ON_FAST_CHAIN = False

RULE_ADAPTIVE_RETRY = "RULE-01:ADAPTIVE_RETRY"
RULE_ADAPTIVE_RETRY_ESCALATION = "RULE-01:ADAPTIVE_RETRY_ESCALATION"
RULE_SESSION_DENIED = "RULE-01:SESSION_DENIED"
RULE_FAST_CHAIN = "RULE-02:FAST_RECON_EXPLOIT_CHAIN"

RECEIPT_TYPE_ADAPTIVE_RETRY = "adaptive_retry"
RECEIPT_TYPE_ADAPTIVE_RETRY_ESCALATION = "adaptive_retry_escalation"
RECEIPT_TYPE_SESSION_DENIED = "session_denied"
RECEIPT_TYPE_FAST_CHAIN = "fast_chain"

_PROTECTED_PATH_PATTERNS = (
    re.compile(r"(?:^|/)\.env(?:\.[^/\s]*)?$"),
    re.compile(r"(?:^|/)\.aws(?:/|$)"),
    re.compile(r"(?:^|/)\.ssh(?:/|$)"),
    re.compile(r"(?:^|/)\.(?:netrc|npmrc|pypirc)$"),
    re.compile(r"(?:^|/)\.kube(?:/|$)"),
    re.compile(r"(?:^|/)\.claude/settings(?:\.local)?\.json$"),
    re.compile(r"(?:^|/)\.github/workflows/[^/\s]+\.ya?ml$"),
    re.compile(r"(?:^|/)\.(?:bashrc|zshrc|profile|bash_profile)$"),
    re.compile(r"(?:^|/)\.git/hooks(?:/|$)"),
    re.compile(r"(?:^|/)library/launchagents(?:/|$)"),
    re.compile(r"(?:^|/)launchdaemons(?:/|$)"),
    re.compile(r"(?:^|/)\.config/systemd/user(?:/|$)"),
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


@dataclass(frozen=True)
class ReconClassRule:
    id: str
    tools: tuple[str, ...] = ()
    tool_prefix: str = ""
    requires_protected_path: bool = False
    requires_non_allowlisted_domain: bool = False
    pattern: re.Pattern[str] | None = None


@dataclass(frozen=True)
class ExploitClassRule:
    id: str
    tools: tuple[str, ...] = ()
    matches_policy_deny: bool = False
    requires_protected_path: bool = False
    protected_write_pattern: re.Pattern[str] | None = None


@dataclass(frozen=True)
class FastChainConfig:
    """Configuration for Rule 2. Numeric thresholds are defaults, not tuned values."""

    recon_count: int = DEFAULT_RECON_COUNT
    recon_window_seconds: int = DEFAULT_RECON_WINDOW_SECONDS
    exploit_window_seconds: int = DEFAULT_EXPLOIT_WINDOW_SECONDS
    deny_session: bool = DEFAULT_DENY_ON_FAST_CHAIN
    webfetch_allowlisted_domains: tuple[str, ...] = ("localhost", "127.0.0.1")
    recon_classes: tuple[ReconClassRule, ...] = ()
    exploit_classes: tuple[ExploitClassRule, ...] = ()


@dataclass(frozen=True)
class FastChainVerdict:
    matched: bool
    exploit_class: str | None = None
    recon_seqs: tuple[int, ...] = ()
    recon_hashes: tuple[str, ...] = ()
    deny_session: bool = False
    reason: str | None = None


def resolve_fast_chain_config(
    config: FastChainConfig | None = None,
    environ: dict[str, str] | None = None,
) -> FastChainConfig:
    base = config or FastChainConfig()
    env = os.environ if environ is None else environ

    recon_count = base.recon_count
    recon_window = base.recon_window_seconds
    exploit_window = base.exploit_window_seconds
    deny_session = base.deny_session

    for raw, target in (
        (env.get("RECEIPTD_RECON_COUNT"), "recon_count"),
        (env.get("RECEIPTD_RECON_WINDOW_SECONDS"), "recon_window"),
        (env.get("RECEIPTD_EXPLOIT_WINDOW_SECONDS"), "exploit_window"),
    ):
        if raw is None:
            continue
        try:
            val = int(raw)
        except ValueError:
            continue
        if val > 0:
            if target == "recon_count":
                recon_count = val
            elif target == "recon_window":
                recon_window = val
            elif target == "exploit_window":
                exploit_window = val

    raw_deny = env.get("RECEIPTD_DENY_ON_FAST_CHAIN")
    if raw_deny is not None:
        normalized_flag = raw_deny.strip().lower()
        if normalized_flag in ("1", "true", "yes", "on"):
            deny_session = True
        elif normalized_flag in ("0", "false", "no", "off"):
            deny_session = False

    return FastChainConfig(
        recon_count=recon_count,
        recon_window_seconds=recon_window,
        exploit_window_seconds=exploit_window,
        deny_session=deny_session,
        webfetch_allowlisted_domains=base.webfetch_allowlisted_domains,
        recon_classes=base.recon_classes,
        exploit_classes=base.exploit_classes,
    )


def _extract_url_hostname(tool_input: Any) -> str | None:
    if not isinstance(tool_input, dict):
        return None
    for key in ("url", "uri", "target_url"):
        val = tool_input.get(key)
        if isinstance(val, str) and val.strip():
            parsed = urlparse(val.strip())
            if parsed.hostname:
                return parsed.hostname.lower()
    return None


def classify_recon_call(
    tool_name: str,
    tool_input: Any,
    config: FastChainConfig,
) -> str | None:
    """Return matching recon class ID from policy config, or None."""
    if not tool_name or not config.recon_classes:
        return None

    clean_tool = tool_name.strip()
    norm_input, _, _ = normalize_tool_input(clean_tool, tool_input)
    raw_blob = f"{clean_tool} {canonical_json(tool_input if isinstance(tool_input, dict) else {}).decode('utf-8')}"
    norm_blob = f"{clean_tool} {canonical_json(norm_input).decode('utf-8')}"
    has_protected = bool(protected_path_hashes_for_call(clean_tool, tool_input))

    for rule in config.recon_classes:
        if rule.tools and clean_tool not in rule.tools:
            continue
        if rule.tool_prefix and not clean_tool.startswith(rule.tool_prefix):
            continue

        if rule.requires_non_allowlisted_domain:
            host = _extract_url_hostname(tool_input)
            allowlist = {d.lower() for d in config.webfetch_allowlisted_domains}
            if host and host in allowlist:
                continue
            return rule.id

        if rule.requires_protected_path:
            pattern_hit = False
            if rule.pattern is not None and isinstance(tool_input, dict):
                pat_val = tool_input.get("pattern")
                if isinstance(pat_val, str) and (
                    rule.pattern.search(pat_val) or rule.pattern.search(normalize_text(pat_val)[0])
                ):
                    pattern_hit = True
            if has_protected or pattern_hit:
                return rule.id
            continue

        if rule.pattern is not None:
            if rule.pattern.search(raw_blob) or rule.pattern.search(norm_blob):
                return rule.id
            continue

        return rule.id

    return None


def classify_exploit_call(
    tool_name: str,
    tool_input: Any,
    triggered_rules: list[str],
    config: FastChainConfig,
) -> str | None:
    """Return matching exploit class ID from policy config, or None."""
    if not tool_name or not config.exploit_classes:
        return None

    clean_tool = tool_name.strip()
    norm_input, _, _ = normalize_tool_input(clean_tool, tool_input)
    has_protected = bool(protected_path_hashes_for_call(clean_tool, tool_input))
    pol_denies = any(rid.startswith("POL-") for rid in triggered_rules)

    for rule in config.exploit_classes:
        if rule.tools and clean_tool not in rule.tools:
            continue

        if rule.matches_policy_deny and pol_denies:
            return rule.id

        if rule.protected_write_pattern is not None and isinstance(tool_input, dict):
            raw_cmd = tool_input.get("command")
            norm_cmd = norm_input.get("command")
            if (isinstance(raw_cmd, str) and rule.protected_write_pattern.search(raw_cmd)) or (
                isinstance(norm_cmd, str) and rule.protected_write_pattern.search(norm_cmd)
            ):
                return rule.id

        if rule.requires_protected_path and (
            has_protected
            or any(rid.startswith(("POL-03", "POL-04", "POL-05")) for rid in triggered_rules)
        ):
            return rule.id

    return None


@dataclass(frozen=True)
class _ReconEvent:
    seq: int
    ts: datetime
    receipt_hash: str
    recon_class: str


def evaluate_fast_chain(
    session_receipts: list[dict[str, Any]],
    *,
    tool_name: str,
    tool_input: Any,
    triggered_rules: list[str],
    now: datetime,
    config: FastChainConfig,
) -> FastChainVerdict:
    """Evaluate Rule 2 (>= N recon within W1 followed by exploit-class within W2)."""
    exploit_class = classify_exploit_call(tool_name, tool_input, triggered_rules, config)
    if exploit_class is None:
        return FastChainVerdict(matched=False)

    already_chained_seqs: set[int] = set()
    for row in session_receipts:
        if row.get("receipt_type") == RECEIPT_TYPE_FAST_CHAIN:
            for s in row.get("recon_seqs") or []:
                if isinstance(s, int):
                    already_chained_seqs.add(s)

    recon_events: list[_ReconEvent] = []
    for row in session_receipts:
        seq = row.get("seq")
        if not isinstance(seq, int) or seq in already_chained_seqs:
            continue
        row_ts = parse_timestamp(row.get("ts"))
        if row_ts is None or row_ts > now:
            continue
        row_hash = str(row.get("hash") or row.get("receipt_sha256") or "")
        recon_class = row.get("recon_class")
        if not isinstance(recon_class, str) or not recon_class:
            row_tool = str(row.get("tool") or row.get("tool_name") or "")
            recon_class = classify_recon_call(row_tool, row.get("tool_input"), config)
        if isinstance(recon_class, str) and recon_class:
            recon_events.append(_ReconEvent(seq=seq, ts=row_ts, receipt_hash=row_hash, recon_class=recon_class))

    n = config.recon_count
    if len(recon_events) < n:
        return FastChainVerdict(matched=False)

    recon_events.sort(key=lambda item: (item.ts, item.seq))

    matched_window: list[_ReconEvent] | None = None
    for idx in range(len(recon_events) - n + 1):
        window = recon_events[idx : idx + n]
        span_seconds = (window[-1].ts - window[0].ts).total_seconds()
        gap_seconds = (now - window[-1].ts).total_seconds()
        if 0 <= span_seconds <= config.recon_window_seconds and 0 <= gap_seconds <= config.exploit_window_seconds:
            matched_window = window

    if matched_window is None:
        return FastChainVerdict(matched=False)

    mode_note = "session denied" if config.deny_session else "receipt-only"
    return FastChainVerdict(
        matched=True,
        exploit_class=exploit_class,
        recon_seqs=tuple(item.seq for item in matched_window),
        recon_hashes=tuple(item.receipt_hash for item in matched_window),
        deny_session=config.deny_session,
        reason=f"matched rule {RULE_FAST_CHAIN} ({mode_note})",
    )
