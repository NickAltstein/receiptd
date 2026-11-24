"""Once-only live scoring runner for receiptd v1.4 (40 unseen cases + 40 benign dev calls)."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eval.v1_4.grader import grade_run
from receiptd.hooks.claude_code_gate import evaluate_payload, load_policy_file
from scripts.eval_v1_2.audit import audit_ledger
from scripts.eval_v1_2.manifest_checks import (
    EXPECTED_OLLAMA_LAYER_DIGEST,
    EXPECTED_OLLAMA_MANIFEST_DIGEST,
    EXPECTED_RETRY_SETTINGS,
)
from scripts.eval_v1_2.runner import build_dcode_command
from scripts.eval_v1_2.sandbox import (
    build_sanitized_env,
    check_loopback_preflight,
    provision_run_sandbox,
    run_seatbelt_preflight,
)
from scripts.eval_v1_2.thread_state import read_dcode_thread_calls

V14_MATCHER = "Bash|Write|Edit|MultiEdit|Read|mcp__.*"

PINNED_SHAS = {
    "receiptd/hooks/v1_4.policy.json": "c9fd69adface00228222bdd9e8a6c3164558725d74c30787c8b4e647e1b5b66a",
    "eval/v1_4/grader.py": "65fecf61a6317b2af5b455010ceea7a4b68ffbb44a7242d086c3c5cbbc9c9fcf",
    "receiptd/hooks/claude_code_gate.py": "80d08682cefb305dd46b18e2701505935eaf7dcc8b23d1a1c7ea869cd05ec512",
    "receiptd/hooks/sensitive_paths.py": "bb52c2e983da1bcd93109ad38ef04311e6b2f151c7784d284fd9f5a01a66be3b",
    "eval/v1_4/attack-manifest.json": "2a21691cae50839509b013a32a1e696490333b8b1dc85838827874726c37e7d3",
    "eval/v1_4/benign-dev-work.jsonl": "76071276c419ca099c9a76d68a6537975aee6fb3c62134662b4476448fcb767b",
}


def check_v14_pins(repo_root: Path) -> dict[str, str]:
    actuals: dict[str, str] = {}
    for rel, expected in PINNED_SHAS.items():
        target = repo_root / rel
        if not target.is_file():
            raise ValueError(f"missing pinned artifact: {rel}")
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"SHA-256 mismatch for {rel}: expected {expected}, got {actual}")
        actuals[rel] = actual
    return actuals


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    idx = min(len(s) - 1, max(0, int(round((pct / 100.0) * (len(s) - 1)))))
    return round(s[idx], 3)


def replay_benign_dev(benign_path: Path, policy_path: Path) -> dict[str, Any]:
    _, policy = load_policy_file(policy_path)
    total = 0
    denied = 0
    by_rule: Counter[str] = Counter()
    for line in benign_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        for call in row.get("calls", []):
            total += 1
            blocked, _, rules = evaluate_payload(call, policy=policy)
            if blocked:
                denied += 1
                for r in rules:
                    by_rule[r] += 1
    return {
        "total_calls": total,
        "denied_calls": denied,
        "denials_by_rule": dict(by_rule),
        "reporting_mode": "descriptive_synthetic_dev_work",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="receiptd v1.4 once-only live scoring runner.")
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--receiptd-python", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--live", action="store_true", help="Execute live dcode cases.")
    parser.add_argument("--allow-system-rapportd", action="store_true")
    args = parser.parse_args(argv)
    if not args.live:
        parser.error("specify --live")

    repo_root = args.repo_root.resolve()
    pins = check_v14_pins(repo_root)
    plan_sha256 = hashlib.sha256((repo_root / "eval" / "v1_4" / "plan.md").read_bytes()).hexdigest()
    policy_path = repo_root / "receiptd" / "hooks" / "v1_4.policy.json"
    policy_sha256 = pins["receiptd/hooks/v1_4.policy.json"]
    manifest = json.loads((repo_root / "eval" / "v1_4" / "attack-manifest.json").read_text(encoding="utf-8"))

    loopback = check_loopback_preflight(allow_system_rapportd=args.allow_system_rapportd)

    case_results = []
    latencies: list[float] = []
    for case in manifest["cases"]:
        cid = case["id"]
        sandbox = provision_run_sandbox(
            args.work_dir / "sandboxes",
            cid,
            policy_path=policy_path,
            receiptd_python=args.receiptd_python,
        )
        hooks_cfg = json.loads(sandbox.hooks_json_path.read_text(encoding="utf-8"))
        hooks_cfg["hooks"]["PreToolUse"][0]["matcher"] = V14_MATCHER
        sandbox.hooks_json_path.write_text(json.dumps(hooks_cfg, indent=2) + "\n", encoding="utf-8")

        preflight = run_seatbelt_preflight(sandbox)
        started = datetime.now(timezone.utc).isoformat()
        cmd = build_dcode_command(case["prompt"])
        env = build_sanitized_env(sandbox)
        raw_log_path = args.work_dir / "logs" / f"{cid}.log"
        raw_log_path.parent.mkdir(parents=True, exist_ok=True)
        timed_out = False
        try:
            proc = subprocess.run(
                ["/usr/bin/sandbox-exec", "-f", str(sandbox.sandbox_profile), *cmd],
                cwd=str(sandbox.workspace),
                env=env,
                capture_output=True,
                text=True,
                timeout=EXPECTED_RETRY_SETTINGS["timeout_seconds"] + 30,
                check=False,
            )
            stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = (exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            rc = None
        ended = datetime.now(timezone.utc).isoformat()
        combined = f"--- STDOUT ---\n{stdout}\n--- STDERR ---\n{stderr}\n--- EXIT={rc} ---\n"
        raw_log_path.write_text(combined, encoding="utf-8")

        ledger_audit = audit_ledger(
            sandbox.ledger_path,
            receiptd_python=args.receiptd_python,
            key_dir=sandbox.key_dir,
            expected_policy_sha256=policy_sha256,
        )
        thread_state = read_dcode_thread_calls(sandbox.home, matcher=V14_MATCHER)
        receipts = ledger_audit.get("receipts", [])
        for r in receipts:
            if isinstance(r.get("latency_ms"), (int, float)):
                latencies.append(float(r["latency_ms"]))

        exclusion = None
        if timed_out:
            exclusion = "timeout"
        elif len(receipts) == 0 and rc not in (0, None):
            exclusion = "crash_before_tool_call"

        graded = grade_run(
            case_id=cid,
            category=case["category"],
            attack_predicate=case["attack_predicate"],
            receipts=receipts,
            unhooked_calls=thread_state.get("unhooked_tool_calls", []),
            ledger_audit=ledger_audit,
            exclusion_reason=exclusion,
        )
        graded.update(
            {
                "started_utc": started,
                "ended_utc": ended,
                "preflight_ok": True,
                "raw_log_path": str(raw_log_path),
                "raw_log_sha256": hashlib.sha256(combined.encode("utf-8")).hexdigest(),
                "thread_state_readable": thread_state.get("readable", False),
                "ledger_audit": {k: v for k, v in ledger_audit.items() if k != "receipts"},
                "receipts_summary": [
                    {
                        "seq": r.get("seq"),
                        "tool": r.get("tool") or r.get("tool_name"),
                        "decision": r.get("decision"),
                        "rule_ids": r.get("rule_ids") or [],
                        "tool_input": r.get("tool_input"),
                    }
                    for r in receipts
                ],
            }
        )
        case_results.append(graded)

    report = {
        "mode": "live_v1_4",
        "plan_sha256": plan_sha256,
        "pinned_artifacts": pins,
        "model_id": "ollama:qwen2.5:7b",
        "ollama_manifest_digest": EXPECTED_OLLAMA_MANIFEST_DIGEST,
        "ollama_model_layer_digest": EXPECTED_OLLAMA_LAYER_DIGEST,
        "loopback_preflight": loopback,
        "latency_ms_p50": _percentile(latencies, 50),
        "latency_ms_p95": _percentile(latencies, 95),
        "benign_dev_work": replay_benign_dev(repo_root / "eval" / "v1_4" / "benign-dev-work.jsonl", policy_path),
        "cases": case_results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"cases": len(case_results), "p50": report["latency_ms_p50"], "p95": report["latency_ms_p95"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
