"""Plan, manifest, model, and policy pin checks for the v1.2.0 evaluation runner."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EXPECTED_PLAN_COMMIT = "839711fdec4e62b551c04d5a13cc5e231b962fcf"
EXPECTED_PLAN_SHA256 = "5def5c9e6f128ca421aae8b55866b44a49f80db03a118cb17535508c1babc511"
EXPECTED_MANIFEST_SHA256 = "24b6ae4c7118a2fe36ce3a5ea7546e2b16a5b786a53aad1dc39a7719a4465f44"
EXPECTED_BENIGN_MANIFEST_SHA256 = "d117e52b6237ef1b898ab8b38144aa97943316ce8b558104f3cf7352e2b6378c"
EXPECTED_POLICY_SHA256 = "8f5901d2a1c88c88bdb0d7d9598050b2a6b9cfa289de5a2851e76a764d163986"

EXPECTED_HARNESS_PACKAGE = "deepagents-code"
EXPECTED_HARNESS_VERSION = "0.2.9"
EXPECTED_RECEIPTD_VERSION = "1.2.0"

EXPECTED_MODEL_ID = "ollama:qwen2.5:7b"
EXPECTED_OLLAMA_TAG = "qwen2.5:7b"
EXPECTED_OLLAMA_MANIFEST_DIGEST = (
    "sha256:845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e"
)
EXPECTED_OLLAMA_LAYER_DIGEST = (
    "sha256:2bada8a7450677000f678be90653b85d364de7db25eb5ea54136ada5f3933730"
)
EXPECTED_MODEL_PARAMS: dict[str, Any] = {
    "temperature": 0.0,
    "seed": 42,
    "num_ctx": 16384,
    "keep_alive": "30m",
    "base_url": "http://localhost:11434",
}
EXPECTED_RETRY_SETTINGS: dict[str, int] = {
    "max_retries": 3,
    "max_turns": 8,
    "timeout_seconds": 300,
}
EXPECTED_HOOK_TIMEOUT_SECONDS = 30
EXPECTED_CATEGORIES = {
    "download_and_execute": 10,
    "reverse_shell": 10,
    "credential_egress": 10,
    "persistence": 10,
}
ALLOWED_EXCLUSIONS = frozenset(
    {
        "http_400_tool_schema",
        "http_429_after_3_retries",
        "crash_before_first_tool_call",
    }
)


class PinMismatchError(RuntimeError):
    """Raised when plan, manifest, model, or policy pins do not match 839711f."""


@dataclass(frozen=True)
class CheckedArtifacts:
    """Checked hashes and loaded manifests for an evaluation run."""

    repo_root: Path
    plan_path: Path
    plan_sha256: str
    attack_manifest_path: Path
    attack_manifest_sha256: str
    attack_manifest: dict[str, Any]
    benign_manifest_path: Path
    benign_manifest_sha256: str
    benign_manifest: dict[str, Any]
    policy_path: Path
    policy_sha256: str


def sha256_file(path: Path) -> str:
    """Return lowercase SHA-256 hex digest of exact file bytes."""
    if not path.is_file():
        raise PinMismatchError(f"Missing required artifact file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_runtime_pins(
    *,
    model_id: str,
    model_params: dict[str, Any],
    retry_settings: dict[str, int],
    policy_path: Path,
    ollama_manifest_path: Path | None = None,
    dcode_bin: str | None = None,
) -> dict[str, str]:
    """Check model, runtime, policy, and Ollama digest pins before execution."""
    if model_id != EXPECTED_MODEL_ID:
        raise PinMismatchError(
            f"Model ID mismatch: expected {EXPECTED_MODEL_ID!r}, got {model_id!r}"
        )
    if model_params != EXPECTED_MODEL_PARAMS:
        raise PinMismatchError(
            f"Model params mismatch: expected {EXPECTED_MODEL_PARAMS!r}, got {model_params!r}"
        )
    if retry_settings != EXPECTED_RETRY_SETTINGS:
        raise PinMismatchError(
            f"Retry settings mismatch: expected {EXPECTED_RETRY_SETTINGS!r}, got {retry_settings!r}"
        )

    policy_sha = sha256_file(policy_path)
    if policy_sha != EXPECTED_POLICY_SHA256:
        raise PinMismatchError(
            f"Policy SHA-256 mismatch for {policy_path}: expected {EXPECTED_POLICY_SHA256}, got {policy_sha}"
        )

    result: dict[str, str] = {
        "model_id": model_id,
        "ollama_manifest_digest": EXPECTED_OLLAMA_MANIFEST_DIGEST,
        "ollama_model_layer_digest": EXPECTED_OLLAMA_LAYER_DIGEST,
        "policy_sha256": policy_sha,
    }

    if ollama_manifest_path is not None:
        if not ollama_manifest_path.is_file():
            raise PinMismatchError(f"Missing Ollama manifest file: {ollama_manifest_path}")
        raw_manifest = json.loads(ollama_manifest_path.read_text(encoding="utf-8"))
        layers = raw_manifest.get("layers", [])
        digests = {
            layer.get("mediaType"): layer.get("digest")
            for layer in layers
            if isinstance(layer, dict)
        }
        model_layer = digests.get("application/vnd.ollama.image.model")
        manifest_digest = digests.get("application/vnd.docker.distribution.manifest.v2+json")
        if model_layer != EXPECTED_OLLAMA_LAYER_DIGEST:
            raise PinMismatchError(
                f"Ollama model layer digest mismatch: expected {EXPECTED_OLLAMA_LAYER_DIGEST}, got {model_layer}"
            )
        if manifest_digest != EXPECTED_OLLAMA_MANIFEST_DIGEST:
            raise PinMismatchError(
                f"Ollama manifest digest mismatch: expected {EXPECTED_OLLAMA_MANIFEST_DIGEST}, got {manifest_digest}"
            )

    if dcode_bin is not None:
        proc = subprocess.run(
            [dcode_bin, "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or EXPECTED_HARNESS_VERSION not in proc.stdout:
            raise PinMismatchError(
                f"Expected {EXPECTED_HARNESS_PACKAGE} {EXPECTED_HARNESS_VERSION}; got rc={proc.returncode} out={proc.stdout!r}"
            )
        result["dcode_version"] = proc.stdout.strip().splitlines()[0]

    return result


def load_and_check_artifacts(
    repo_root: Path,
    *,
    policy_path: Path | None = None,
) -> CheckedArtifacts:
    """Load plan, attack manifest, benign manifest, and policy and enforce all committed hashes."""
    plan_path = repo_root / "docs" / "eval" / "v1.2-scoring-plan.md"
    attack_manifest_path = repo_root / "docs" / "eval" / "v1.2-attack-manifest.json"
    benign_manifest_path = repo_root / "docs" / "eval" / "benign-sessions-manifest.json"
    resolved_policy = policy_path or (
        repo_root / "receiptd" / "hooks" / "default_pretooluse.policy.json"
    )

    plan_sha = sha256_file(plan_path)
    if plan_sha != EXPECTED_PLAN_SHA256:
        raise PinMismatchError(
            f"Scoring plan SHA-256 mismatch: expected {EXPECTED_PLAN_SHA256}, got {plan_sha}"
        )

    attack_sha = sha256_file(attack_manifest_path)
    if attack_sha != EXPECTED_MANIFEST_SHA256:
        raise PinMismatchError(
            f"Attack manifest SHA-256 mismatch: expected {EXPECTED_MANIFEST_SHA256}, got {attack_sha}"
        )

    benign_sha = sha256_file(benign_manifest_path)
    if benign_sha != EXPECTED_BENIGN_MANIFEST_SHA256:
        raise PinMismatchError(
            f"Benign manifest SHA-256 mismatch: expected {EXPECTED_BENIGN_MANIFEST_SHA256}, got {benign_sha}"
        )

    policy_sha = sha256_file(resolved_policy)
    if policy_sha != EXPECTED_POLICY_SHA256:
        raise PinMismatchError(
            f"Policy SHA-256 mismatch: expected {EXPECTED_POLICY_SHA256}, got {policy_sha}"
        )

    attack_manifest = json.loads(attack_manifest_path.read_text(encoding="utf-8"))
    _validate_attack_manifest_contents(attack_manifest)

    benign_manifest = json.loads(benign_manifest_path.read_text(encoding="utf-8"))
    _validate_benign_manifest_contents(benign_manifest)

    return CheckedArtifacts(
        repo_root=repo_root,
        plan_path=plan_path,
        plan_sha256=plan_sha,
        attack_manifest_path=attack_manifest_path,
        attack_manifest_sha256=attack_sha,
        attack_manifest=attack_manifest,
        benign_manifest_path=benign_manifest_path,
        benign_manifest_sha256=benign_sha,
        benign_manifest=benign_manifest,
        policy_path=resolved_policy,
        policy_sha256=policy_sha,
    )


def _validate_attack_manifest_contents(manifest: dict[str, Any]) -> None:
    if manifest.get("expected_policy_sha256") != EXPECTED_POLICY_SHA256:
        raise PinMismatchError("Attack manifest expected_policy_sha256 differs from pinned v1.2.0 policy")

    harness = manifest.get("harness", {})
    if harness.get("version") != EXPECTED_HARNESS_VERSION:
        raise PinMismatchError(f"Harness version mismatch: {harness.get('version')!r}")
    if harness.get("model_id") != EXPECTED_MODEL_ID:
        raise PinMismatchError(f"Manifest model_id mismatch: {harness.get('model_id')!r}")
    if harness.get("ollama_manifest_digest") != EXPECTED_OLLAMA_MANIFEST_DIGEST:
        raise PinMismatchError("Manifest ollama_manifest_digest mismatch")
    if harness.get("ollama_model_layer_digest") != EXPECTED_OLLAMA_LAYER_DIGEST:
        raise PinMismatchError("Manifest ollama_model_layer_digest mismatch")
    if harness.get("model_params") != EXPECTED_MODEL_PARAMS:
        raise PinMismatchError("Manifest model_params mismatch")
    if harness.get("retry_settings") != EXPECTED_RETRY_SETTINGS:
        raise PinMismatchError("Manifest retry_settings mismatch")

    cases = manifest.get("cases", [])
    if not isinstance(cases, list) or len(cases) != 40:
        raise PinMismatchError(f"Expected exactly 40 cases in manifest, found {len(cases)}")
    counts: dict[str, int] = {}
    seen_ids: set[str] = set()
    for case in cases:
        cid = case.get("id")
        cat = case.get("category")
        if not cid or cid in seen_ids:
            raise PinMismatchError(f"Duplicate or empty case id: {cid!r}")
        seen_ids.add(cid)
        counts[cat] = counts.get(cat, 0) + 1
    if counts != EXPECTED_CATEGORIES:
        raise PinMismatchError(f"Category count mismatch: expected {EXPECTED_CATEGORIES}, got {counts}")


def _validate_benign_manifest_contents(manifest: dict[str, Any]) -> None:
    expected_counts = {
        "transcript_file_count": 19,
        "unique_session_count": 18,
        "sessions_with_tool_calls": 3,
        "sessions_with_eligible_hooked_calls": 3,
        "total_tool_calls": 986,
        "eligible_hooked_calls": 888,
    }
    for key, val in expected_counts.items():
        if manifest.get(key) != val:
            raise PinMismatchError(f"Benign manifest {key} mismatch: expected {val}, got {manifest.get(key)!r}")
