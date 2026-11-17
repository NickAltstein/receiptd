import json

import pytest

from receiptd.hooks.claude_code_gate import evaluate_payload


@pytest.mark.parametrize(("command", "denied"), [
    ('echo fixture >> ~/.bashrc', True),
    ('printf fixture >> "$HOME/.zshrc"', True),
    ('printf fixture >> ~/.profile', True),
    ('printf fixture | crontab -', True),
    ('cp x .git/hooks/pre-commit', True),
    ('systemctl --user enable fixture.service', True),
    ('echo fixture >> scripts/build.sh', False),
    ('cp x .githooks/pre-commit', False),
    ('crontab -l', False),
    ('systemctl --user status fixture.service', False),
    ('cat ~/.bashrc', False),
    ('cp .git/hooks/pre-commit /tmp/hook-copy', False),
])
def test_shell_policy(command, denied):
    payload = json.loads(json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}))
    blocked, _, rules = evaluate_payload(payload)
    assert blocked is denied
    assert ("POL-08:SHELL_PERSISTENCE" in rules) is denied
