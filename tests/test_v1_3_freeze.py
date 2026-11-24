"""Regression guard ensuring v1.3 artifacts and policy remain byte-identical."""

from __future__ import annotations

import hashlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

V1_3_PINS = {
    "receiptd/hooks/v1_3.policy.json": (
        "49a22a549d8e8f474120b881f148250421b53c37e86742676bab066766a8c179"
    ),
    "eval/v1_3/plan.md": (
        "3d8d4525266a959a9923eaf382051d7f27d0fb23c51d01a4ebfb866d0f43097f"
    ),
    "eval/v1_3/benign-dev-work.jsonl": (
        "5e9627dbec3ec9dc922ad88753d13edf1dd593b0f11e8cb78bc3f9941da40fad"
    ),
}


def test_v1_3_artifacts_byte_identical() -> None:
    for rel_path, expected_sha in V1_3_PINS.items():
        target = REPO_ROOT / rel_path
        assert target.is_file(), f"missing v1.3 artifact: {rel_path}"
        actual_sha = hashlib.sha256(target.read_bytes()).hexdigest()
        assert actual_sha == expected_sha, f"v1.3 artifact changed: {rel_path}"
