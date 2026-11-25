"""Self-protection fixtures are payloads; their commands are never executed."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from receiptd.hooks.claude_code_gate import evaluate_payload, load_policy_file
from receiptd.cli import _verify_ledger_file
from receiptd.crypto import get_public_key_pem

POLICY = Path(__file__).resolve().parents[1] / 'receiptd/hooks/v1_5.policy.json'


@pytest.mark.parametrize('tool', ['Write', 'Edit', 'MultiEdit'])
@pytest.mark.parametrize('path', ['.claude/settings.json', '.claude/settings.local.json', '.claude/settings.extra', 'policy.json', 'keys/key.pem', 'evidence/receipts.jsonl'])
def test_structured_mutations(tmp_path, monkeypatch, tool, path):
    monkeypatch.setenv('RECEIPTD_KEY_DIR', str(tmp_path / 'keys'))
    _, policy = load_policy_file(POLICY)
    blocked, _, rules = evaluate_payload({'cwd': str(tmp_path), 'tool_name': tool, 'tool_input': {'file_path': path}}, policy, protected_paths=(tmp_path / 'policy.json', tmp_path / 'evidence'))
    assert blocked and 'POL-11:SELF_PROTECTION' in rules


@pytest.mark.parametrize('command', [
    'echo fixture > .claude/settings.extra',
    'cp fixture policy.json', 'mv fixture evidence/receipts.jsonl',
    'chmod 600 keys/key.pem', 'chown user evidence/receipts.jsonl',
    'ln -sf fixture policy.json', 'tee policy.json',
    'rm evidence/receipts.jsonl',
    'bash -c \'echo fixture > policy.json\'',
])
def test_shell_mutations(tmp_path, monkeypatch, command):
    monkeypatch.setenv('RECEIPTD_KEY_DIR', str(tmp_path / 'keys'))
    _, policy = load_policy_file(POLICY)
    blocked, _, rules = evaluate_payload({'cwd': str(tmp_path), 'tool_name': 'Bash', 'tool_input': {'command': command}}, policy, protected_paths=(tmp_path / 'policy.json', tmp_path / 'evidence'))
    assert blocked and 'POL-11:SELF_PROTECTION' in rules


@pytest.mark.parametrize('command', ['pytest -q', 'cat policy.json', 'git config --get core.hooksPath', 'echo fixture > docs/policy.json'])
def test_non_mutations_allowed(tmp_path, monkeypatch, command):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('RECEIPTD_KEY_DIR', str(tmp_path / 'keys'))
    monkeypatch.setenv('GIT_CONFIG_NOSYSTEM', '1')
    _, policy = load_policy_file(POLICY)
    assert not evaluate_payload({'cwd': str(tmp_path), 'tool_name': 'Bash', 'tool_input': {'command': command}}, policy, protected_paths=(tmp_path / 'policy.json', tmp_path / 'evidence'))[0]


def invoke(tmp_path, policy, payload):
    ledger = tmp_path / 'evidence/receipts.jsonl'
    keys = tmp_path / 'keys'
    env = {**os.environ, 'HOME': str(tmp_path), 'RECEIPTD_KEY_DIR': str(keys)}
    env.pop('RECEIPTD_SIGNING_KEY', None)
    env.pop('BIRKIN_SIGNING_KEY', None)
    proc = subprocess.run([sys.executable, '-m', 'receiptd.hooks.claude_code_gate', '--policy', str(policy), '--ledger', str(ledger)], input=json.dumps(payload), capture_output=True, text=True, cwd=tmp_path, env=env, timeout=15)
    receipt = json.loads(ledger.read_text().splitlines()[0])
    assert proc.returncode == 2
    assert receipt['decision'] == 'deny'
    assert _verify_ledger_file(ledger, pubkey=get_public_key_pem(keys), allow_unanchored=True)
    return receipt


@pytest.mark.parametrize('target', ['policy.json', 'keys/key.pem', 'evidence/receipts.jsonl', '.claude/settings.extra'])
def test_hook_runtime_paths(tmp_path, target):
    policy = tmp_path / 'policy.json'
    policy.write_bytes(POLICY.read_bytes())
    receipt = invoke(tmp_path, policy, {'tool_name': 'Write', 'tool_input': {'file_path': str(tmp_path / target), 'content': 'fixture'}})
    assert 'POL-11:SELF_PROTECTION' in receipt['rule_ids']
    assert receipt['policy_sha256'] == hashlib.sha256(policy.read_bytes()).hexdigest()


@pytest.mark.parametrize('kind', ['missing', 'unreadable', 'invalid'])
@pytest.mark.parametrize('tool', ['Bash', 'Write'])
def test_policy_failure_receipts(tmp_path, kind, tool):
    policy = tmp_path / 'policy.json'
    if kind == 'unreadable':
        policy.mkdir()  # Reading a directory as policy bytes raises OSError.
    elif kind == 'invalid':
        policy.write_text('{')
    receipt = invoke(tmp_path, policy, {'tool_name': tool, 'tool_input': {'command': 'echo fixture', 'file_path': 'ordinary.txt'}})
    assert receipt['rule_ids'] == ['POLICY_' + kind.upper()]
    assert receipt['reason'] == 'receiptd: policy ' + kind


@pytest.mark.parametrize('command', ['sed -i s/a/b/ policy.json', 'perl -pi -e s/a/b/ policy.json', 'mv .claude config-backup', 'chmod 777 evidence'])
def test_editors_and_directory_mutations(tmp_path, command):
    _, policy = load_policy_file(POLICY)
    blocked, _, rules = evaluate_payload({'cwd': str(tmp_path), 'tool_name': 'Bash', 'tool_input': {'command': command}}, policy, protected_paths=(tmp_path / 'policy.json', tmp_path / 'evidence'))
    assert blocked and 'POL-11:SELF_PROTECTION' in rules


def test_symlink_alias(tmp_path):
    target = tmp_path / 'policy.json'
    target.write_text('fixture')
    (tmp_path / 'alias').symlink_to(target)
    _, policy = load_policy_file(POLICY)
    blocked, _, rules = evaluate_payload({'cwd': str(tmp_path), 'tool_name': 'Write', 'tool_input': {'file_path': 'alias'}}, policy, protected_paths=(target,))
    assert blocked and 'POL-11:SELF_PROTECTION' in rules


def test_permission_error_writes_deny_receipt(tmp_path, monkeypatch):
    import io
    from receiptd.hooks import claude_code_gate as gate
    policy = tmp_path / 'policy.json'
    policy.write_bytes(POLICY.read_bytes())
    ledger = tmp_path / 'evidence/receipts.jsonl'
    original = Path.read_bytes
    def read_bytes(path):
        if path == policy:
            raise PermissionError('fixture permission denial')
        return original(path)
    monkeypatch.setattr(Path, 'read_bytes', read_bytes)
    monkeypatch.setenv('RECEIPTD_KEY_DIR', str(tmp_path / 'keys'))
    monkeypatch.setattr(sys, 'argv', ['gate', '--policy', str(policy), '--ledger', str(ledger)])
    monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps({'tool_name': 'Bash', 'tool_input': {'command': 'echo fixture'}})))
    assert gate.main() == 2
    receipt = json.loads(ledger.read_text().splitlines()[0])
    assert receipt['rule_ids'] == ['POLICY_UNREADABLE']
    assert receipt['decision'] == 'deny'
