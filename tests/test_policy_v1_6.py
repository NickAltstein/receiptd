"""v1.6 gate policy tests: static fixtures only, never execute attack commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from receiptd.hooks.claude_code_gate import evaluate_payload, load_policy_file
from receiptd.hooks.sensitive_paths import SENSITIVE_PATH_CORE

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "receiptd/hooks/v1_6.policy.json"


def _eval(tool_name: str, tool_input: dict, *, cwd: Path | None = None, scope=None):
    _, policy = load_policy_file(POLICY)
    payload = {"tool_name": tool_name, "tool_input": tool_input}
    if cwd is not None:
        payload["cwd"] = str(cwd)
    return evaluate_payload(payload, policy, scope=scope) if scope is not None else evaluate_payload(payload, policy)


# --- Item 1: Sensitive-path pattern (POL-09 / POL-10) ---

def test_v16_sensitive_path_single_source_of_truth() -> None:
    raw = json.loads(POLICY.read_text(encoding="utf-8"))
    by_id = {r["id"]: r["pattern"] for r in raw["rules"]}
    assert SENSITIVE_PATH_CORE in by_id["POL-09:SENSITIVE_READ"]
    assert SENSITIVE_PATH_CORE in by_id["POL-10:SENSITIVE_BASH_READ"]


@pytest.mark.parametrize("path", [
    "/etc/ssl/private/server.crt",
    "/etc/ssl/private/server.key",
    "certs/app.key",
    "/tmp/tls/service.key",
    "certs/private/dev.crt",
    "private/ca.crt",
])
def test_v16_item1_read_sensitive_keys_and_private_certs_denied(path: str) -> None:
    blocked, _, rules = _eval("Read", {"file_path": path})
    assert blocked and "POL-09:SENSITIVE_READ" in rules


@pytest.mark.parametrize("command", [
    "cat /etc/ssl/private/server.crt",
    "base64 /etc/ssl/private/server.key",
    "head -n 5 certs/app.key",
    "cat certs/private/dev.crt",
    "cat < /etc/ssl/private/server.crt",
])
def test_v16_item1_bash_sensitive_keys_and_private_certs_denied(command: str) -> None:
    blocked, _, rules = _eval("Bash", {"command": command})
    assert blocked and "POL-10:SENSITIVE_BASH_READ" in rules


@pytest.mark.parametrize("tool,tool_input", [
    ("Read", {"file_path": "/etc/ssl/certs/ca-certificates.crt"}),
    ("Read", {"file_path": "certs/public/server.crt"}),
    ("Read", {"file_path": ".env.example"}),
    ("Bash", {"command": "cat certs/public/server.crt"}),
    ("Bash", {"command": "cat .env.example"}),
])
def test_v16_item1_benign_public_crt_and_env_example_allowed(tool: str, tool_input: dict) -> None:
    blocked, _, _ = _eval(tool, tool_input)
    assert not blocked
