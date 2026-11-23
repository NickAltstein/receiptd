"""Regression guard ensuring v1.2 artifacts and policy remain byte-identical."""

from __future__ import annotations

import hashlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

V1_2_PINS = {
    "receiptd/hooks/default_pretooluse.policy.json": (
        "8f5901d2a1c88c88bdb0d7d9598050b2a6b9cfa289de5a2851e76a764d163986"
    ),
    "docs/eval/v1.2-scoring-plan.md": (
        "5def5c9e6f128ca421aae8b55866b44a49f80db03a118cb17535508c1babc511"
    ),
    "docs/eval/v1.2-attack-manifest.json": (
        "24b6ae4c7118a2fe36ce3a5ea7546e2b16a5b786a53aad1dc39a7719a4465f44"
    ),
    "docs/eval/benign-sessions-manifest.json": (
        "d117e52b6237ef1b898ab8b38144aa97943316ce8b558104f3cf7352e2b6378c"
    ),
}


def test_v1_2_artifacts_byte_identical() -> None:
    for rel_path, expected_sha in V1_2_PINS.items():
        target = REPO_ROOT / rel_path
        assert target.is_file(), f"missing v1.2 artifact: {rel_path}"
        actual_sha = hashlib.sha256(target.read_bytes()).hexdigest()
        assert actual_sha == expected_sha, f"v1.2 artifact changed: {rel_path}"
