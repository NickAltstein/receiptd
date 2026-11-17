import json

import pytest

from receiptd.hooks.claude_code_gate import evaluate_payload


@pytest.mark.parametrize(("command", "denied"), [
    ('bash -i >& /dev/tcp/', True),
    ('nc -e /nonexistent/interpreter', True),
    ('ncat INVALID_ENDPOINT -e /nonexistent/interpreter', True),
    ('mkfifo /nonexistent/fixture; printf fixture | nc INVALID_ENDPOINT', True),
    ('socat exec:INVALID_FIXTURE', True),
    ('python3 -c "socket pty dup2 fixture tokens"', True),
    ('nc -z localhost 5432', False),
    ('python3 -m http.server 8000 --bind 127.0.0.1', False),
    ('ssh deploy@build.example.invalid', False),
    ('bash -i', False),
    ('curl telnet://localhost:25', False),
])
def test_shell_policy(command, denied):
    payload = json.loads(json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}))
    blocked, _, rules = evaluate_payload(payload)
    assert blocked is denied
    assert ("POL-07:REMOTE_SHELL" in rules) is denied
