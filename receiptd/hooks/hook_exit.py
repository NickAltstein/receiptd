"""Record a hook exit that overrode the gate's allow decision.

The installed PreToolUse command runs this only when the gate process exits
non-zero, and then exits 2 itself. If the gate had already written an allow
receipt for this hook run (it crashed after deciding, for example at
interpreter shutdown), Claude Code blocked the call anyway. This appends a
signed deny receipt that names the allow receipt it overrides, so the ledger
shows the call was blocked.

It never decides whether a call runs: the shell exits 2 whatever happens here.
Any error writes nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from ..crypto import get_signing_key
from ..ledger import append_ledger_entry, build_signed_receipt, lock_ledger, read_ledger_state, record_ledger_anchor
from .claude_code_gate import _resolve_ledger_path

HOOK_RUN_ENV = "RECEIPTD_HOOK_RUN"
RULE_ID = "HOOK_EXIT_OVERRIDE"


def find_run_receipt(ledger_path: str | Path, run_id: str) -> dict | None:
    """Return the newest receipt the gate wrote for this hook run, if any."""
    path = Path(ledger_path)
    if not run_id or not path.is_file():
        return None
    for line in reversed(path.read_text(encoding="utf-8").splitlines()):
        if run_id not in line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("hook_run") == run_id:
            return row
    return None


def record_hook_exit(ledger_path: str | Path, run_id: str, status: int) -> dict | None:
    """Append a deny receipt when this run's gate receipt says allow. Return it, or None."""
    sk = get_signing_key()
    with lock_ledger(ledger_path):
        decided = find_run_receipt(ledger_path, run_id)
        if decided is None or decided.get("decision") != "allow":
            return None
        prev_hash, _, receipt_count, _, _ = read_ledger_state(ledger_path)
        receipt = build_signed_receipt(
            sk=sk,
            v=1,
            seq=receipt_count + 1,
            ts=datetime.now(timezone.utc).isoformat(),
            session_id=str(decided.get("session_id", "default")),
            tool=str(decided.get("tool", "")),
            args_sha256=str(decided.get("args_sha256", "")),
            decision="deny",
            rule_ids=[RULE_ID],
            blast_radius=int(decided.get("blast_radius", 0)),
            reason=(
                f"hook exited {status} after the gate allowed seq {decided.get('seq')}; "
                "the hook command exited 2 and Claude Code blocked the call"
            ),
            policy_sha256=str(decided.get("policy_sha256", "")),
            prev_hash=prev_hash,
            extra_fields={
                "hook_run": run_id,
                "hook_exit_status": status,
                "overrides_seq": decided.get("seq"),
                "overrides_hash": decided.get("hash"),
            },
        )
        record_ledger_anchor(receipt["seq"], receipt["hash"], ledger_path=ledger_path, sk=sk)
        append_ledger_entry(ledger_path, receipt)
        return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="receiptd.hooks.hook_exit")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--run", default="")
    parser.add_argument("--status", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        ledger_path = _resolve_ledger_path(["--ledger", args.ledger])
        record_hook_exit(ledger_path, args.run, args.status)
    except Exception as exc:
        sys.stderr.write(f"receiptd: hook exit not recorded: {exc}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
