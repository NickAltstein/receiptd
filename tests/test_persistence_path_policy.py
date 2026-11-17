import pytest

from receiptd.hooks.claude_code_gate import evaluate_payload


@pytest.mark.parametrize(("tool", "path", "denied"), [
    ("Write", "~/.bashrc", True),
    ("Edit", "$HOME/.zshrc", True),
    ("MultiEdit", "/home/example/.profile", True),
    ("Write", "./.git/hooks/pre-commit", True),
    ("Edit", "~/Library/LaunchAgents/example.plist", True),
    ("Write", "~/.config/systemd/user/example.service", True),
    ("Write", "scripts/build.sh", False),
    ("Write", ".githooks/pre-commit", False),
    ("Edit", "docs/launch-agents.md", False),
    ("MultiEdit", "fixtures/bashrc.example", False),
    ("Edit", "src/profile.py", False),
])
def test_structured_persistence_path(tool, path, denied):
    blocked, _, rules = evaluate_payload({
        "tool_name": tool, "tool_input": {"file_path": path},
    })
    assert blocked is denied
    assert ("POL-05:PERSISTENCE_PATH" in rules) is denied
