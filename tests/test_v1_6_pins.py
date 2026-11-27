"""Pre-score pin verification tests for receiptd v1.6."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from eval.v1_6.runner import HOOK_MATCHER, main as runner_main, sha256_file, validate_case_bindings, verify_artifact_pins
from receiptd.cli import PRETOOLUSE_MATCHER

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_v16_pins_match_repo_files() -> None:
    pins_path = REPO_ROOT / "eval/v1_6/PINS.json"
    pins = json.loads(pins_path.read_text(encoding="utf-8"))
    assert pins["scoring_authorized"] is False
    assert pins["status"] == "pending_approval"
    assert pins["gate_implementation"]["pretooluse_matcher"] == PRETOOLUSE_MATCHER
    assert pins["eval_implementation"]["runner_hook_matcher"] == HOOK_MATCHER
    assert PRETOOLUSE_MATCHER == HOOK_MATCHER

    actuals = verify_artifact_pins(REPO_ROOT)
    assert len(actuals) == len(pins["all_artifact_sha256"])


def test_v16_runner_aborts_on_tampered_or_missing_pin(tmp_path: Path) -> None:
    pins_src = REPO_ROOT / "eval/v1_6/PINS.json"
    pins = json.loads(pins_src.read_text(encoding="utf-8"))

    for rel in pins["all_artifact_sha256"]:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / rel, dst)
    (tmp_path / "eval/v1_6/PINS.json").write_text(pins_src.read_text(encoding="utf-8"), encoding="utf-8")

    # Clean copy verifies
    verify_artifact_pins(tmp_path)

    # Tampered pinned file aborts before any model call
    policy_copy = tmp_path / "receiptd/hooks/v1_6.policy.json"
    policy_copy.write_text(policy_copy.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="pin mismatch"):
        verify_artifact_pins(tmp_path)
    with pytest.raises(ValueError, match="pin mismatch"):
        runner_main(["--repo-root", str(tmp_path)])

    # Restore, then delete a pinned file -> aborts
    shutil.copy2(REPO_ROOT / "receiptd/hooks/v1_6.policy.json", policy_copy)
    (tmp_path / "eval/v1_6/grader.py").unlink()
    with pytest.raises(ValueError, match="missing pinned file"):
        verify_artifact_pins(tmp_path)

    # Restore, then replace a pin with TODO -> aborts
    shutil.copy2(REPO_ROOT / "eval/v1_6/grader.py", tmp_path / "eval/v1_6/grader.py")
    bad_pins = json.loads((tmp_path / "eval/v1_6/PINS.json").read_text(encoding="utf-8"))
    bad_pins["all_artifact_sha256"]["eval/v1_6/grader.py"] = "TODO"
    (tmp_path / "eval/v1_6/PINS.json").write_text(json.dumps(bad_pins), encoding="utf-8")
    with pytest.raises(ValueError, match="unresolved pin"):
        verify_artifact_pins(tmp_path)


def test_v16_case_bindings_cover_regression_and_heldout_ids() -> None:
    bindings = json.loads((REPO_ROOT / "eval/v1_6/case-bindings.json").read_text(encoding="utf-8"))
    main_manifest = json.loads((REPO_ROOT / "eval/v1_5/main-attack-manifest.json").read_text(encoding="utf-8"))
    exposed_manifest = json.loads((REPO_ROOT / "eval/v1_5/externally-supplied-cases.json").read_text(encoding="utf-8"))
    heldout_manifest = json.loads((REPO_ROOT / "eval/v1_6/heldout-hash-manifest.json").read_text(encoding="utf-8"))

    expected_ids = (
        {c["id"] for c in main_manifest["cases"]}
        | {c["id"] for c in exposed_manifest["cases"]}
        | {c["id"] for c in heldout_manifest["cases"]}
    )
    assert len(expected_ids) == 98
    missing = validate_case_bindings(bindings, expected_ids)
    assert missing == []
    assert sha256_file(REPO_ROOT / "eval/v1_6/heldout-hash-manifest.json") == (
        "284e5e913d1cb49c48439ed2a57e5dcc8b7021550263044bb5b2b1751ffb72f8"
    )
