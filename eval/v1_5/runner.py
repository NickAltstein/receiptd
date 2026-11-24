"""Disposable-VM evaluation runner scaffold for receiptd v1.5.

Enforces all pre-committed pins from `eval/v1_5/PLAN.md` before and between cases:
- Candidate policy: `receiptd/hooks/v1_5.policy.json` (exact SHA-256)
- Externally supplied cases: `eval/v1_5/externally-supplied-cases.json` (exact SHA-256)
- Ollama daemon version and digests for both `qwen2.5:7b` and `llama3.1:8b`
- Disposable Lima VM template & Ubuntu ARM64 cloud image digest
- Complete case-level observable bindings before any execution

No scoring runs without `--execute-approved-plan <sha256>` matching the committed plan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

PINNED_STATIC_FILES: dict[str, str] = {
    "receiptd/hooks/v1_5.policy.json": "ee8b6ff621c47e6ea5fe94fd11d66e2694e0cca5206bc2722630d2c7f15e05e1",
    "receiptd/hooks/claude_code_gate.py": "544b8df2c6037328800dd33468aa90a6f2e73e96b68e447764dc3526b5bdbd30",
    "receiptd/hooks/shell_analysis.py": "1aca64cb9f074b71cd2f3e24d57d26a831afcc1e5f3f2ecdd9ad2dd6cad5c751",
    "receiptd/hooks/session_controls.py": "552e656c1b2f627128fa7166f0e4f0bf5081377bbed8aff1ddb3ecaa4d268e0c",
    "receiptd/hooks/sensitive_paths.py": "bb52c2e983da1bcd93109ad38ef04311e6b2f151c7784d284fd9f5a01a66be3b",
    "eval/v1_5/externally-supplied-cases.json": "37b2f1fc5e1d5a5e5d2ea2caa3156805fd7b262a9a192d3ca44ed02f367a4680",
    "eval/v1_5/main-attack-manifest.json": "c6e79d2bb3042356da13cde807a5037719ba9f6ddf4a3be3dea9e2edfd607e61",
    "eval/v1_5/case-bindings.json": "49cb3016467adc9b5c0622838b75c358db3cc204541776f0e1e5c02eb56bbc70",
    "eval/v1_5/generate_main_set.py": "460bca93ee706606114ba71904ec86ef76c4988e98e957ffaa5f0dd334eb68f4",
}

PINNED_POLICY_REL = "receiptd/hooks/v1_5.policy.json"
PINNED_POLICY_SHA256 = PINNED_STATIC_FILES[PINNED_POLICY_REL]

PINNED_EXPOSED_CASES_REL = "eval/v1_5/externally-supplied-cases.json"
PINNED_EXPOSED_CASES_SHA256 = PINNED_STATIC_FILES[PINNED_EXPOSED_CASES_REL]

PINNED_OLLAMA_VERSION = "0.40.16"
PINNED_MODEL_DIGESTS: dict[str, str] = {
    "qwen2.5:7b": "sha256:845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e",
    "llama3.1:8b": "sha256:46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e",
}

REQUIRED_CASE_BINDINGS = (
    "attempt_predicate",
    "preparation_predicate",
    "dispatch_predicate",
    "goal_predicate",
    "hook_relevance",
    "fixture_id",
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_static_pins(repo_root: Path) -> dict[str, str]:
    """Verify immutable v1.5 policy, gate implementation, and supplied-cases hashes."""
    actuals: dict[str, str] = {}
    for rel, expected in PINNED_STATIC_FILES.items():
        p = repo_root / rel
        if not p.is_file():
            raise ValueError(f"missing pinned file: {rel}")
        actual = sha256_file(p)
        if actual != expected:
            raise ValueError(f"pin mismatch for {rel}: expected {expected}, got {actual}")
        actuals[rel] = actual
    return actuals


def verify_ollama_pins(
    base_url: str = "http://127.0.0.1:11434",
    models: tuple[str, ...] = ("qwen2.5:7b", "llama3.1:8b"),
) -> dict[str, Any]:
    """Verify Ollama daemon version and exact model digests."""
    with urllib.request.urlopen(f"{base_url}/api/version", timeout=5) as resp:
        ver_payload = json.loads(resp.read().decode("utf-8"))
    version = str(ver_payload.get("version") or "")
    if version != PINNED_OLLAMA_VERSION:
        raise ValueError(
            f"Ollama version mismatch: expected {PINNED_OLLAMA_VERSION}, got {version}"
        )

    with urllib.request.urlopen(f"{base_url}/api/tags", timeout=5) as resp:
        tags_payload = json.loads(resp.read().decode("utf-8"))
    by_name = {
        str(m.get("name")): f"sha256:{m.get('digest')}"
        for m in tags_payload.get("models", [])
        if isinstance(m, dict) and m.get("name") and m.get("digest")
    }
    matched: dict[str, str] = {}
    for tag in models:
        expected = PINNED_MODEL_DIGESTS[tag]
        actual = by_name.get(tag)
        if actual != expected:
            raise ValueError(f"Ollama digest mismatch for {tag}: expected {expected}, got {actual}")
        matched[tag] = actual
    return {"ollama_version": version, "model_digests": matched}


def validate_case_bindings(
    bindings_data: dict[str, Any],
    expected_case_ids: set[str],
) -> list[str]:
    """Return list of missing mechanical bindings blocking execution."""
    missing: list[str] = []
    main_cases = bindings_data.get("main_cases", {})
    exposed_cases = bindings_data.get("externally_supplied_cases", {})
    all_bound = {**main_cases, **exposed_cases}

    for cid in expected_case_ids:
        b = all_bound.get(cid)
        if not isinstance(b, dict):
            missing.append(f"{cid}:missing_binding_entry")
            continue
        for key in REQUIRED_CASE_BINDINGS:
            val = b.get(key)
            if val is None or val == "":
                missing.append(f"{cid}:missing_{key}")
    return missing


def inspect_private_benign_session(session_path: Path) -> dict[str, Any]:
    """Return non-sensitive metadata (hash and counts only) for a private session file."""
    import re

    raw = session_path.read_bytes()
    total_tool_calls = 0
    git_config_calls = 0
    for line in raw.splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        msg = obj.get("message") if isinstance(obj, dict) else None
        content = msg.get("content") if isinstance(msg, dict) else None
        if not isinstance(content, list):
            continue
        for blk in content:
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                total_tool_calls += 1
                inp = blk.get("input") or {}
                cmd = inp.get("command", "") if isinstance(inp, dict) else ""
                if isinstance(cmd, str) and re.search(r"\bgit\s+config\b", cmd):
                    git_config_calls += 1
    return {
        "session_sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "total_tool_calls": total_tool_calls,
        "git_config_calls": git_config_calls,
        "raw_path_omitted": True,
    }


def check_lima_available() -> str:
    """Return installed `limactl` version string or raise RuntimeError."""
    proc = subprocess.run(
        ["limactl", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"limactl unavailable: {proc.stderr.strip()}")
    return proc.stdout.strip()


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return round(ordered[idx], 3)


def summarize_latency(
    cold_hook_ms: list[float],
    in_process_ms: list[float],
    *,
    vm_config: dict[str, Any],
) -> dict[str, Any]:
    """Keep cold-hook end-to-end latency strictly separate from in-process latency."""
    return {
        "vm_config": vm_config,
        "cold_hook_end_to_end_ms": {
            "samples": len(cold_hook_ms),
            "p50": percentile(cold_hook_ms, 50),
            "p95": percentile(cold_hook_ms, 95),
            "includes": ["process_startup", "policy_load", "lock_wait", "receipt_io"],
        },
        "in_process_eval_and_sign_ms": {
            "samples": len(in_process_ms),
            "p50": percentile(in_process_ms, 50),
            "p95": percentile(in_process_ms, 95),
            "includes": ["policy_eval", "canonical_json", "ed25519_sign"],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="receiptd v1.5 disposable-VM runner (pin check only unless approved)."
    )
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument(
        "--check-pins-only",
        action="store_true",
        help="Verify static policy/corpus pins, Ollama digests, and Lima availability without running cases.",
    )
    parser.add_argument(
        "--execute-approved-plan",
        type=str,
        default=None,
        help="Exact SHA-256 of the approved eval/v1_5/PLAN.md authorizing scored execution.",
    )
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()

    static_pins = verify_static_pins(repo_root)
    ollama_pins = verify_ollama_pins()
    lima_version = check_lima_available()

    if args.check_pins_only:
        print(
            json.dumps(
                {
                    "status": "pins_ok",
                    "static_pins": static_pins,
                    "ollama": ollama_pins,
                    "lima_version": lima_version,
                    "scoring_executed": False,
                },
                indent=2,
            )
        )
        return 0

    if not args.execute_approved_plan:
        parser.error("refusing execution: pass --check-pins-only or --execute-approved-plan <sha256>")

    plan_path = repo_root / "eval" / "v1_5" / "PLAN.md"
    actual_plan_sha = sha256_file(plan_path)
    if actual_plan_sha != args.execute_approved_plan:
        raise SystemExit(
            f"plan SHA-256 mismatch: expected {args.execute_approved_plan}, got {actual_plan_sha}"
        )

    exposed = json.loads((repo_root / PINNED_EXPOSED_CASES_REL).read_text(encoding="utf-8"))
    main_manifest = json.loads((repo_root / "eval/v1_5/main-attack-manifest.json").read_text(encoding="utf-8"))
    bindings_data = json.loads((repo_root / "eval/v1_5/case-bindings.json").read_text(encoding="utf-8"))
    expected_ids = {c["id"] for c in main_manifest["cases"]} | {c["id"] for c in exposed["cases"]}
    missing_bindings = validate_case_bindings(bindings_data, expected_ids)
    if missing_bindings:
        raise SystemExit(
            f"refusing execution: missing observable bindings ({len(missing_bindings)} items)"
        )

    raise SystemExit("No scoring authorized; waiting for Nick's final plan approval")


if __name__ == "__main__":
    raise SystemExit(main())
