"""Install-time fail-closed tests for the Claude Code hook command.

Claude Code blocks a PreToolUse hook only on exit 2. A bare ``python3 -m
receiptd.hooks.claude_code_gate`` exits 1 when that ``python3`` cannot import
receiptd (venv, pipx), and the tool call runs. Init must record the
interpreter that has receiptd and refuse to report success unless the
installed command exits 2 on a known-bad call.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from receiptd.cli import (
    INIT_PROBE_PAYLOAD,
    app,
    hook_shell_command,
    pretooluse_hook_command,
)
from receiptd.hooks.claude_code_gate import (
    coerce_hook_status,
    hook_status_from_exception,
    main as gate_main,
)
from receiptd.hooks.claude_code_stop_gate import main as stop_main

REPO_ROOT = Path(__file__).resolve().parent.parent
runner = CliRunner()


def test_coerce_hook_status_only_allows_zero():
    assert coerce_hook_status(0) == 0
    assert coerce_hook_status(2) == 2
    assert coerce_hook_status(1) == 2
    assert coerce_hook_status(127) == 2


def test_system_exit_1_becomes_2():
    assert hook_status_from_exception(SystemExit(1)) == 2
    assert hook_status_from_exception(SystemExit(0)) == 0
    assert hook_status_from_exception(SystemExit(2)) == 2
    assert hook_status_from_exception(RuntimeError("boom")) == 2


def test_gate_main_coerces_unexpected_status(monkeypatch):
    monkeypatch.setattr(
        "receiptd.hooks.claude_code_gate.resolve_deadline_ms",
        lambda environ=None: 60_000,
    )
    monkeypatch.setattr("receiptd.hooks.claude_code_gate._run", lambda: 1)
    assert gate_main() == 2


def test_gate_main_exception_returns_2(monkeypatch):
    monkeypatch.setattr(
        "receiptd.hooks.claude_code_gate.resolve_deadline_ms",
        lambda environ=None: 60_000,
    )

    def boom():
        raise RuntimeError("gate blew up")

    monkeypatch.setattr("receiptd.hooks.claude_code_gate._run", boom)
    assert gate_main() == 2


def test_stop_main_exception_returns_2(monkeypatch):
    def boom():
        raise RuntimeError("stop blew up")

    monkeypatch.setattr("receiptd.hooks.claude_code_stop_gate._main_args", boom)
    assert stop_main() == 2


def test_shell_wrapper_turns_import_failure_into_exit_2():
    missing = hook_shell_command(sys.executable, ["-m", "receiptd.hooks.does_not_exist"])
    denied = subprocess.run(missing, shell=True, capture_output=True, text=True, timeout=30)
    assert denied.returncode == 2

    allowed = hook_shell_command(sys.executable, ["-c", "import sys; sys.exit(0)"])
    ok = subprocess.run(allowed, shell=True, capture_output=True, text=True, timeout=30)
    assert ok.returncode == 0

    absent = hook_shell_command("/nonexistent/receiptd-python", ["-m", "receiptd"])
    missing_bin = subprocess.run(absent, shell=True, capture_output=True, text=True, timeout=30)
    assert missing_bin.returncode == 2


def test_init_command_uses_this_interpreter():
    command = pretooluse_hook_command(".birkin/pretooluse.policy.json")
    assert command.startswith(sys.executable) or command.startswith(f"'{sys.executable}'")
    assert "receiptd.hooks.claude_code_gate" in command
    assert command.endswith("|| exit 2")
    assert not command.startswith("python3 ")


def test_init_refuses_when_probe_does_not_exit_2(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def fake_probe(policy_path, ledger_path=".birkin/receipts.jsonl", cwd=None):
        return subprocess.CompletedProcess(
            args=["python3"],
            returncode=1,
            stdout="",
            stderr="No module named receiptd",
        )

    monkeypatch.setattr("receiptd.cli.probe_installed_hook", fake_probe)
    result = runner.invoke(app, ["init", "--claude-code"])
    assert result.exit_code == 2
    assert "refused" in result.stderr.lower() or "refused" in result.output.lower()
    assert not (tmp_path / ".claude" / "settings.json").exists()
    assert "initialization complete" not in result.output.lower()


def test_init_refuses_exit_2_without_deny_receipt(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def fake_probe(policy_path, ledger_path=".birkin/receipts.jsonl", cwd=None):
        return subprocess.CompletedProcess(args=["python3"], returncode=2, stdout="", stderr="")

    monkeypatch.setattr("receiptd.cli.probe_installed_hook", fake_probe)
    result = runner.invoke(app, ["init", "--claude-code"])
    assert result.exit_code == 2
    assert not (tmp_path / ".claude" / "settings.json").exists()


def test_init_probe_blocks_known_bad_call(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(tmp_path / "keys"))
    result = runner.invoke(app, ["init", "--claude-code"])
    assert result.exit_code == 0, result.output
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    gate = settings["hooks"]["PreToolUse"][0]["hooks"][0]
    assert gate["command"] == pretooluse_hook_command(".birkin/pretooluse.policy.json")
    assert gate["onFailure"] == "block"
    ledger = tmp_path / ".birkin" / "receipts.jsonl"
    lines = [json.loads(line) for line in ledger.read_text().splitlines() if line.strip()]
    assert lines[0]["decision"] == "deny"
    assert lines[0]["session_id"] == INIT_PROBE_PAYLOAD["session_id"]


def _write_stub_python3(directory: Path) -> None:
    directory.mkdir(parents=True)
    stub = directory / "python3"
    stub.write_text(
        "#!/bin/sh\n"
        "echo 'stub python3 cannot import receiptd' >&2\n"
        "exit 1\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)


def test_isolated_venv_install_blocks_known_bad_call(tmp_path):
    """pip-install into a fresh venv, then run the hook with a PATH python3 that exits 1."""
    venv = tmp_path / "venv"
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=120)
    pip = venv / "bin" / "pip"
    venv_python = venv / "bin" / "python"
    subprocess.run(
        [str(pip), "install", "--disable-pip-version-check", str(REPO_ROOT)],
        check=True,
        timeout=300,
    )

    stub_bin = tmp_path / "stub-bin"
    _write_stub_python3(stub_bin)
    env = os.environ.copy()
    env["PATH"] = str(stub_bin) + os.pathsep + env.get("PATH", "")
    env["HOME"] = str(home)
    env["RECEIPTD_KEY_DIR"] = str(tmp_path / "keys")
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    env.pop("RECEIPTD_SIGNING_KEY", None)
    env.pop("BIRKIN_SIGNING_KEY", None)

    bare = subprocess.run(
        ["python3", "-c", "import receiptd"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert bare.returncode == 1

    init = subprocess.run(
        [str(venv_python), "-m", "receiptd", "init", "--claude-code"],
        capture_output=True,
        text=True,
        cwd=project,
        env=env,
        timeout=60,
    )
    assert init.returncode == 0, init.stderr
    settings = json.loads((project / ".claude" / "settings.json").read_text())
    command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert str(venv_python) in command
    assert "|| exit 2" in command
    assert not command.startswith("python3 ")

    before = 0
    ledger = project / ".birkin" / "receipts.jsonl"
    if ledger.is_file():
        before = sum(1 for line in ledger.read_text().splitlines() if line.strip())
    probe = subprocess.run(
        command,
        input=json.dumps(INIT_PROBE_PAYLOAD),
        capture_output=True,
        text=True,
        shell=True,
        cwd=project,
        env=env,
        timeout=60,
    )
    assert probe.returncode == 2, probe.stderr
    lines = [json.loads(line) for line in ledger.read_text().splitlines() if line.strip()]
    assert len(lines) > before
    assert lines[-1]["decision"] == "deny"
    assert lines[-1]["session_id"] == INIT_PROBE_PAYLOAD["session_id"]
    assert "stub python3" not in probe.stderr
