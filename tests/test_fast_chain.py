"""Tests for Rule 2: fast recon-to-exploit chain detection."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from receiptd.crypto import SigningKey, canonical_json, sha256_hex
from receiptd.hooks.claude_code_gate import default_policy_path, load_policy_file
from receiptd.hooks.session_rules import (
    DEFAULT_DENY_ON_FAST_CHAIN,
    DEFAULT_EXPLOIT_WINDOW_SECONDS,
    DEFAULT_RECON_COUNT,
    DEFAULT_RECON_WINDOW_SECONDS,
    RECEIPT_TYPE_FAST_CHAIN,
    RECEIPT_TYPE_SESSION_DENIED,
    RULE_FAST_CHAIN,
    RULE_SESSION_DENIED,
)
from receiptd.ledger import GENESIS_HASH, append_ledger_entry, build_signed_receipt


def _run_hook(
    tmp_path: Path,
    ledger: Path,
    payload: dict,
    *,
    extra_env: dict[str, str] | None = None,
    policy_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "RECEIPTD_KEY_DIR": str(tmp_path / "keys"),
    }
    if extra_env:
        env.update(extra_env)
    cmd = [sys.executable, "-m", "receiptd.hooks.claude_code_gate", "--ledger", str(ledger)]
    if policy_path is not None:
        cmd.extend(["--policy", str(policy_path)])
    return subprocess.run(
        cmd,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=env,
        timeout=30,
    )


def _read_receipts(ledger: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in ledger.read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line).get("type") != "checkpoint"
    ]


def _seed_recon_receipts(
    ledger: Path,
    sk: SigningKey,
    *,
    session_id: str,
    timestamps: list[datetime],
    policy_sha: str,
) -> None:
    prev = GENESIS_HASH
    samples = [
        ("Read", {"file_path": ".env"}),
        ("Grep", {"path": ".aws/credentials", "pattern": "AWS"}),
        ("Glob", {"path": "~/.ssh", "pattern": "*"}),
        ("WebFetch", {"url": "https://collector.example.invalid/spec"}),
        ("mcp__env__list_secrets", {"scope": "all"}),
    ]
    for idx, ts in enumerate(timestamps):
        tool, ti = samples[idx % len(samples)]
        rec = build_signed_receipt(
            sk=sk,
            v=1,
            seq=idx + 1,
            ts=ts.isoformat(),
            session_id=session_id,
            tool=tool,
            args_sha256=sha256_hex(canonical_json(ti)),
            decision="allow",
            rule_ids=[],
            blast_radius=10,
            reason="allowed",
            policy_sha256=policy_sha,
            prev_hash=prev,
            extra_fields={"tool_input": ti},
        )
        append_ledger_entry(ledger, rec)
        prev = rec["hash"]


def test_default_policy_explicitly_defines_recon_and_exploit_classes():
    data, policy = load_policy_file(default_policy_path())
    raw = json.loads(data.decode("utf-8"))
    assert DEFAULT_RECON_COUNT == 5
    assert DEFAULT_RECON_WINDOW_SECONDS == 30
    assert DEFAULT_EXPLOIT_WINDOW_SECONDS == 60
    assert DEFAULT_DENY_ON_FAST_CHAIN is False
    assert policy.fast_chain.recon_count == 5
    assert policy.fast_chain.recon_window_seconds == 30
    assert policy.fast_chain.exploit_window_seconds == 60
    assert policy.fast_chain.deny_session is False
    assert len(policy.fast_chain.recon_classes) >= 3
    assert len(policy.fast_chain.exploit_classes) >= 2
    assert "dcode" in raw["fast_chain"]["host_hook_coverage"]
    assert "claude_code" in raw["fast_chain"]["host_hook_coverage"]


def test_fast_chain_emits_signed_receipt_only_by_default(tmp_path: Path):
    ledger = tmp_path / "receipts.jsonl"
    sess = "sess-chain-default"

    recon_calls = [
        {"session_id": sess, "tool_name": "Read", "tool_input": {"file_path": ".env"}},
        {"session_id": sess, "tool_name": "Grep", "tool_input": {"path": ".aws/credentials", "pattern": "KEY"}},
        {"session_id": sess, "tool_name": "Glob", "tool_input": {"pattern": "**/.env*"}},
        {"session_id": sess, "tool_name": "WebFetch", "tool_input": {"url": "https://metadata.example.invalid/token"}},
        {"session_id": sess, "tool_name": "mcp__secrets__get_env", "tool_input": {"name": "ALL"}},
    ]
    for call in recon_calls:
        res = _run_hook(tmp_path, ledger, call)
        assert res.returncode == 0

    # Protected-path Write (~/.ssh/authorized_keys is a protected write, not blocked by POL-05)
    exploit = _run_hook(
        tmp_path,
        ledger,
        {
            "session_id": sess,
            "tool_name": "Write",
            "tool_input": {"file_path": "~/.ssh/authorized_keys", "content": "ssh-ed25519 AAAA"},
        },
    )
    assert exploit.returncode == 0  # receipt-only by default

    rows = _read_receipts(ledger)
    assert len(rows) == 7
    fc = rows[-1]
    assert fc["receipt_type"] == RECEIPT_TYPE_FAST_CHAIN
    assert fc["rule_ids"] == [RULE_FAST_CHAIN]
    assert fc["decision"] == "allow"
    assert fc["session_denied"] is False
    assert fc["recon_seqs"] == [1, 2, 3, 4, 5]
    assert len(fc["recon_hashes"]) == 5
    assert fc["exploit_receipt_hash"] == rows[-2]["hash"]
    assert "sig" in fc

    # Subsequent benign call remains allowed when deny_session is off
    followup = _run_hook(
        tmp_path,
        ledger,
        {"session_id": sess, "tool_name": "Bash", "tool_input": {"command": "pytest -q"}},
    )
    assert followup.returncode == 0


def test_fast_chain_opt_in_session_deny_via_policy(tmp_path: Path):
    ledger = tmp_path / "receipts.jsonl"
    sess = "sess-chain-optin-policy"

    raw_policy = json.loads(default_policy_path().read_text(encoding="utf-8"))
    raw_policy["fast_chain"]["deny_session"] = True
    optin_policy = tmp_path / "optin.policy.json"
    optin_policy.write_text(json.dumps(raw_policy), encoding="utf-8")

    recon_calls = [
        {"session_id": sess, "tool_name": "Read", "tool_input": {"file_path": ".env"}},
        {"session_id": sess, "tool_name": "Read", "tool_input": {"file_path": "~/.ssh/id_rsa"}},
        {"session_id": sess, "tool_name": "Grep", "tool_input": {"path": ".aws/credentials", "pattern": "AWS"}},
        {"session_id": sess, "tool_name": "WebFetch", "tool_input": {"url": "https://evil.invalid/a"}},
        {"session_id": sess, "tool_name": "mcp__host__list_secrets", "tool_input": {}},
    ]
    for call in recon_calls:
        assert _run_hook(tmp_path, ledger, call, policy_path=optin_policy).returncode == 0

    exploit = _run_hook(
        tmp_path,
        ledger,
        {
            "session_id": sess,
            "tool_name": "Write",
            "tool_input": {"file_path": "~/.ssh/authorized_keys", "content": "ssh-ed25519 AAAA"},
        },
        policy_path=optin_policy,
    )
    assert exploit.returncode == 2

    rows = _read_receipts(ledger)
    fc = rows[-1]
    assert fc["receipt_type"] == RECEIPT_TYPE_FAST_CHAIN
    assert fc["decision"] == "deny"
    assert fc["session_denied"] is True

    later = _run_hook(
        tmp_path,
        ledger,
        {"session_id": sess, "tool_name": "Bash", "tool_input": {"command": "echo hi"}},
        policy_path=optin_policy,
    )
    assert later.returncode == 2
    assert _read_receipts(ledger)[-1]["receipt_type"] == RECEIPT_TYPE_SESSION_DENIED
    assert _read_receipts(ledger)[-1]["rule_ids"] == [RULE_SESSION_DENIED]


def test_read_five_files_then_edit_non_protected_file_emits_no_chain_receipt(tmp_path: Path):
    # Case A: 5 ordinary file reads + edit non-protected file
    ledger_a = tmp_path / "ledger_a.jsonl"
    sess_a = "sess-normal-files"
    for i in range(5):
        res = _run_hook(
            tmp_path,
            ledger_a,
            {"session_id": sess_a, "tool_name": "Read", "tool_input": {"file_path": f"src/mod_{i}.py"}},
        )
        assert res.returncode == 0
    edit_a = _run_hook(
        tmp_path,
        ledger_a,
        {
            "session_id": sess_a,
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/app/handler.py", "old_string": "a", "new_string": "b"},
        },
    )
    assert edit_a.returncode == 0
    rows_a = _read_receipts(ledger_a)
    assert all(row.get("receipt_type") != RECEIPT_TYPE_FAST_CHAIN for row in rows_a)

    # Case B: 5 protected reads + edit non-protected file -> not an exploit-class call -> no chain receipt
    ledger_b = tmp_path / "ledger_b.jsonl"
    sess_b = "sess-protected-read-benign-edit"
    for target in (".env", ".aws/credentials", "~/.ssh/id_rsa", ".netrc", "~/.zshrc"):
        res = _run_hook(
            tmp_path,
            ledger_b,
            {"session_id": sess_b, "tool_name": "Read", "tool_input": {"file_path": target}},
        )
        assert res.returncode == 0
    edit_b = _run_hook(
        tmp_path,
        ledger_b,
        {
            "session_id": sess_b,
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/app/handler.py", "old_string": "a", "new_string": "b"},
        },
    )
    assert edit_b.returncode == 0
    rows_b = _read_receipts(ledger_b)
    assert all(row.get("receipt_type") != RECEIPT_TYPE_FAST_CHAIN for row in rows_b)


def test_allowlisted_webfetch_and_benign_mcp_do_not_trigger_chain(tmp_path: Path):
    ledger = tmp_path / "receipts.jsonl"
    sess = "sess-allowlisted-recon"
    calls = [
        {"session_id": sess, "tool_name": "WebFetch", "tool_input": {"url": "http://localhost:8080/health"}},
        {"session_id": sess, "tool_name": "WebFetch", "tool_input": {"url": "http://127.0.0.1:11434/api/tags"}},
        {"session_id": sess, "tool_name": "mcp__calc__add", "tool_input": {"a": 1, "b": 2}},
        {"session_id": sess, "tool_name": "mcp__docs__search", "tool_input": {"query": "pytest fixtures"}},
        {"session_id": sess, "tool_name": "Read", "tool_input": {"file_path": "README.md"}},
    ]
    for call in calls:
        assert _run_hook(tmp_path, ledger, call).returncode == 0

    exploit = _run_hook(
        tmp_path,
        ledger,
        {
            "session_id": sess,
            "tool_name": "Write",
            "tool_input": {"file_path": "~/.ssh/authorized_keys", "content": "ssh-ed25519 AAAA"},
        },
    )
    assert exploit.returncode == 0
    assert all(row.get("receipt_type") != RECEIPT_TYPE_FAST_CHAIN for row in _read_receipts(ledger))


def test_fast_chain_window_bounds_w1_and_w2(tmp_path: Path, monkeypatch):
    key_dir = tmp_path / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    sk = SigningKey.generate()
    policy_bytes, _ = load_policy_file(default_policy_path())
    policy_sha = sha256_hex(policy_bytes)
    now = datetime.now(timezone.utc)

    # Spread across > W1 (30s): 0s..40s -> no fast_chain
    ledger_w1 = tmp_path / "ledger_w1.jsonl"
    _seed_recon_receipts(
        ledger_w1,
        sk,
        session_id="sess-w1-expired",
        timestamps=[now - timedelta(seconds=45 - i * 10) for i in range(5)],
        policy_sha=policy_sha,
    )
    res_w1 = _run_hook(
        tmp_path,
        ledger_w1,
        {
            "session_id": "sess-w1-expired",
            "tool_name": "Write",
            "tool_input": {"file_path": "~/.ssh/authorized_keys", "content": "ssh-ed25519 AAAA"},
        },
    )
    assert res_w1.returncode == 0
    assert all(row.get("receipt_type") != RECEIPT_TYPE_FAST_CHAIN for row in _read_receipts(ledger_w1))

    # 5 recon within 20s, but latest recon was 70s ago (> W2 = 60s) -> no fast_chain
    ledger_w2 = tmp_path / "ledger_w2.jsonl"
    _seed_recon_receipts(
        ledger_w2,
        sk,
        session_id="sess-w2-expired",
        timestamps=[now - timedelta(seconds=90 - i * 5) for i in range(5)],
        policy_sha=policy_sha,
    )
    res_w2 = _run_hook(
        tmp_path,
        ledger_w2,
        {
            "session_id": "sess-w2-expired",
            "tool_name": "Write",
            "tool_input": {"file_path": "~/.ssh/authorized_keys", "content": "ssh-ed25519 AAAA"},
        },
    )
    assert res_w2.returncode == 0
    assert all(row.get("receipt_type") != RECEIPT_TYPE_FAST_CHAIN for row in _read_receipts(ledger_w2))
