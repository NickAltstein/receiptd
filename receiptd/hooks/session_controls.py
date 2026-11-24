"""Optional local session controls, implemented without third-party code."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from .shell_analysis import command_views, _expand

NETWORK = {'curl', 'wget', 'fetch', 'nc', 'ncat', 'netcat', 'ssh', 'scp', 'rsync'}


@dataclass(frozen=True)
class SessionScope:
    session_id: str
    hosts: frozenset[str] | None
    roots: tuple[Path, ...] | None
    max_calls: int | None
    max_egress: int | None
    sha256: str


def load_scope(path: Path, cwd: Path) -> SessionScope:
    raw = path.read_bytes()
    if len(raw) > 65536:
        raise ValueError('scope exceeds input limit')
    data = json.loads(raw)
    permitted = {'session_id', 'allowed_hosts', 'allowed_path_roots', 'max_tool_calls', 'max_egress_commands'}
    if not isinstance(data, dict) or set(data) - permitted:
        raise ValueError('scope fields are invalid')
    session = data.get('session_id')
    if not isinstance(session, str) or not session.strip():
        raise ValueError('scope needs a session_id')
    for name in ('max_tool_calls', 'max_egress_commands'):
        value = data.get(name)
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError('scope budget is invalid')
    for name in ('allowed_hosts', 'allowed_path_roots'):
        value = data.get(name)
        if name in data and (not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value)):
            raise ValueError('scope allow-list is invalid')
    hosts = None if 'allowed_hosts' not in data else frozenset(h.lower() for h in data['allowed_hosts'])
    roots = None if 'allowed_path_roots' not in data else tuple((cwd / Path(v)).resolve() for v in data['allowed_path_roots'])
    return SessionScope(session, hosts, roots, data.get('max_tool_calls'), data.get('max_egress_commands'), hashlib.sha256(raw).hexdigest())


def network_commands(command: str) -> list[list[str]]:
    return [words for words in command_views(command) if words and Path(words[0]).name in NETWORK]


def egress_count(payload: dict) -> int:
    args = payload.get('tool_input', {})
    command = args.get('command') if payload.get('tool_name') == 'Bash' else None
    return len(network_commands(command)) if isinstance(command, str) else 0


def supply_chain_match(command: str) -> bool:
    views = command_views(command)
    # Conservative same-call treatment includes download followed by execution.
    if any(w and Path(w[0]).name in {'curl', 'wget', 'fetch'} for w in views) and any(w and Path(w[0]).name in {'sh', 'bash', 'zsh', 'dash', 'python', 'python3', 'node'} for w in views):
        return True
    for words in views:
        if not words or Path(words[0]).name != 'docker':
            continue
        args = words[1:]
        if args[:1] in (['image'], ['container']):
            args = args[1:]
        if args and args[0].startswith('-') and any(a in {'run', 'pull'} for a in args):
            return True
        if not args or args[0] not in {'run', 'pull'}:
            continue
        args = args[1:]
        consumes = {'--name', '--env', '-e', '--env-file', '--volume', '-v', '--mount', '--network', '--user', '-u', '--workdir', '-w', '--entrypoint', '--platform', '-p', '--publish', '--label', '-l'}
        while args and args[0].startswith('-'):
            option = args.pop(0)
            if option == '--':
                break
            if option in consumes:
                if not args:
                    return True
                args.pop(0)
            elif option not in {'--rm', '-i', '-t', '-it', '-d', '--detach', '--quiet', '-q'} and '=' not in option:
                return True
        if not args or not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', args[0]):
            return True
    return False


def scope_rules(scope: SessionScope, payload: dict, ledger: Path) -> list[str]:
    rules = []
    if str(payload.get('session_id') or os.environ.get('RECEIPTD_SESSION_ID', 'default')) != scope.session_id:
        return ['POL-12:SESSION_SCOPE']
    args = payload.get('tool_input', {})
    command = args.get('command') if payload.get('tool_name') == 'Bash' else None
    views = command_views(command) if isinstance(command, str) else []
    if payload.get('tool_name', '').startswith('mcp__') and (scope.hosts is not None or scope.roots is not None):
        rules.append('POL-12:SESSION_SCOPE')  # Opaque MCP tool semantics.
    if scope.hosts is not None:
        for words in views:
            if not words or Path(words[0]).name not in NETWORK:
                continue
            hosts = set()
            for word in words[1:]:
                if '://' in word:
                    host = urlsplit(word).hostname
                    if host:
                        hosts.add(host.lower())
                elif re.fullmatch(r'(?:[^@\s]+@)?[A-Za-z0-9.-]+:.*', word):
                    hosts.add(word.split('@')[-1].split(':')[0].lower())
            if not hosts and Path(words[0]).name in {'nc', 'ncat', 'netcat', 'ssh'}:
                operands = [w for w in words[1:] if not w.startswith('-')]
                if operands:
                    hosts.add(operands[0].split('@')[-1].lower())
            if not hosts or not hosts <= scope.hosts:
                rules.append('POL-12:SESSION_SCOPE')
    if scope.roots is not None:
        paths = []
        if payload.get('tool_name') in {'Write', 'Edit', 'MultiEdit', 'Read'}:
            value = args.get('file_path')
            if not isinstance(value, str):
                rules.append('POL-12:SESSION_SCOPE')
            else:
                paths.append(value)
        for words in views:
            file_command = bool(words) and Path(words[0]).name in {'cd', 'cat', 'head', 'tail', 'tee', 'cp', 'mv', 'ln', 'chmod', 'chown', 'touch', 'rm', 'mkdir', 'install', 'truncate', 'sed', 'perl'}
            for i, word in enumerate(words[1:], 1):
                if i > 0 and (re.fullmatch(r'[<>]+&?|&>>?', words[i - 1]) or words[i - 1] in {'-o', '--output', '-O'}):
                    paths.append(word)
                if file_command and not word.startswith('-') and not word.isdigit() and not re.fullmatch(r'[<>]+&?', word):
                    paths.append(word)
                if '://' not in word and (word.startswith(('/', './', '../', '~/', '$HOME/', '${HOME}/')) or '/' in word and not word.startswith('-')):
                    paths.append(word)
        cwd = Path(payload.get('cwd') or Path.cwd())
        for value in paths:
            expanded = _expand(value, {'HOME': os.environ.get('HOME', '/home/user')})
            target = (cwd / expanded).resolve()
            if not any(target == root or root in target.parents for root in scope.roots):
                rules.append('POL-12:SESSION_SCOPE')
    calls = egress = 0
    if (scope.max_calls is not None or scope.max_egress is not None) and ledger.exists():
        for line in ledger.read_text().splitlines():
            row = json.loads(line)
            if row.get('type') == 'checkpoint' or row.get('session_id') != scope.session_id:
                continue
            calls += 1
            stored = row.get('tool_input')
            if not isinstance(stored, dict):
                raise ValueError('budget history lacks tool input')
            from ..crypto import canonical_json
            if hashlib.sha256(canonical_json(stored)).hexdigest() != row.get('args_sha256'):
                raise ValueError('budget history input hash mismatch')
            egress += egress_count({'tool_name': row.get('tool'), 'tool_input': stored})
    if scope.max_calls is not None and calls + 1 > scope.max_calls:
        rules.append('POL-13:TOOL_BUDGET')
    if scope.max_egress is not None and egress + egress_count(payload) > scope.max_egress:
        rules.append('POL-14:EGRESS_BUDGET')
    return list(dict.fromkeys(rules))
