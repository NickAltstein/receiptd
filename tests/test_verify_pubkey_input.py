"""Tests for `--pubkey` accepting both filesystem paths and inline key material."""
from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from typer.testing import CliRunner

from receiptd.cli import app
from receiptd.crypto import SigningKey, sha256_hex
from receiptd.ledger import GENESIS_HASH, append_ledger_entry, build_signed_receipt

REPO_ROOT = Path(__file__).resolve().parent.parent
STANDALONE = REPO_ROOT / "tools" / "verify_standalone.py"
runner = CliRunner()


def _create_signed_ledger(tmp_path: Path, *, name: str = "receipts.jsonl") -> tuple[Path, SigningKey, Path]:
    sk = SigningKey.generate()
    ledger = tmp_path / name
    rec = build_signed_receipt(
        sk=sk,
        v=1,
        seq=1,
        ts="2026-11-17T12:00:00+00:00",
        session_id="pubkey-test",
        tool="Bash",
        args_sha256=sha256_hex(b"{}"),
        decision="allow",
        rule_ids=[],
        blast_radius=10,
        reason="allowed",
        policy_sha256="0" * 64,
        prev_hash=GENESIS_HASH,
    )
    append_ledger_entry(ledger, rec)
    pub_file = tmp_path / "signer.pub.pem"
    pub_file.write_bytes(sk.public_pem_bytes)
    return ledger, sk, pub_file


def _run_standalone(ledger: Path, pubkey: str | None, key_dir: Path, *, env_pubkey: str | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(STANDALONE), "--ledger", str(ledger), "--key-dir", str(key_dir), "--allow-unanchored"]
    if pubkey is not None:
        cmd.extend(["--pubkey", pubkey])
    env = os.environ.copy()
    env["RECEIPTD_KEY_DIR"] = str(key_dir)
    env.pop("RECEIPTD_SIGNING_KEY", None)
    env.pop("BIRKIN_SIGNING_KEY", None)
    if env_pubkey is None:
        env.pop("RECEIPTD_PUBLIC_KEY", None)
    else:
        env["RECEIPTD_PUBLIC_KEY"] = env_pubkey
    return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)


def test_verify_accepts_pubkey_filename_and_pem_contents(tmp_path: Path, monkeypatch):
    key_dir = tmp_path / "empty_keys"
    key_dir.mkdir()
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    monkeypatch.delenv("RECEIPTD_PUBLIC_KEY", raising=False)

    ledger, sk, pub_file = _create_signed_ledger(tmp_path)
    pem_text = sk.public_pem_bytes.decode("ascii")
    raw_b64 = base64.b64encode(
        sk.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")

    # 1. File path to public PEM
    res_file = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", str(pub_file), "--allow-unanchored"])
    assert res_file.exit_code == 0, res_file.output
    assert "AUTHENTIC" in res_file.output
    st_file = _run_standalone(ledger, str(pub_file), key_dir)
    assert st_file.returncode == 0, st_file.stderr
    assert "AUTHENTIC" in st_file.stdout

    # 2. Inline PEM contents
    res_pem = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", pem_text, "--allow-unanchored"])
    assert res_pem.exit_code == 0, res_pem.output
    assert "AUTHENTIC" in res_pem.output
    st_pem = _run_standalone(ledger, pem_text, key_dir)
    assert st_pem.returncode == 0, st_pem.stderr
    assert "AUTHENTIC" in st_pem.stdout

    # 3. Raw 32-byte Base64 public key
    res_b64 = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", raw_b64, "--allow-unanchored"])
    assert res_b64.exit_code == 0, res_b64.output
    st_b64 = _run_standalone(ledger, raw_b64, key_dir)
    assert st_b64.returncode == 0, st_b64.stderr


def test_verify_pubkey_file_wrong_key_fails_closed(tmp_path: Path, monkeypatch):
    key_dir = tmp_path / "empty_keys"
    key_dir.mkdir()
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    monkeypatch.delenv("RECEIPTD_PUBLIC_KEY", raising=False)

    ledger, _, _ = _create_signed_ledger(tmp_path)
    wrong_sk = SigningKey.generate()
    wrong_file = tmp_path / "wrong.pub.pem"
    wrong_file.write_bytes(wrong_sk.public_pem_bytes)

    res = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", str(wrong_file), "--allow-unanchored"])
    assert res.exit_code == 2
    assert "TAMPER DETECTED" in res.output

    st = _run_standalone(ledger, str(wrong_file), key_dir)
    assert st.returncode == 2
    assert "TAMPER DETECTED" in st.stdout


def test_verify_missing_directory_and_empty_pubkey_paths_fail_closed(tmp_path: Path, monkeypatch):
    key_dir = tmp_path / "empty_keys"
    key_dir.mkdir()
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    monkeypatch.delenv("RECEIPTD_PUBLIC_KEY", raising=False)

    ledger, _, _ = _create_signed_ledger(tmp_path)
    missing = tmp_path / "does_not_exist.pub.pem"
    empty_file = tmp_path / "empty.pub.pem"
    empty_file.write_text("", encoding="utf-8")

    for bad in (missing, tmp_path, empty_file):
        res = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", str(bad), "--allow-unanchored"])
        assert res.exit_code == 2
        st = _run_standalone(ledger, str(bad), key_dir)
        assert st.returncode == 2


def test_verify_supports_tilde_and_env_pubkey_path(tmp_path: Path, monkeypatch):
    key_dir = tmp_path / "empty_keys"
    key_dir.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))

    ledger, sk, pub_file = _create_signed_ledger(tmp_path)

    # Tilde path via --pubkey
    res_tilde = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", f"~/{pub_file.name}", "--allow-unanchored"])
    assert res_tilde.exit_code == 0, res_tilde.output

    # Env var pointing to PEM file path
    monkeypatch.setenv("RECEIPTD_PUBLIC_KEY", str(pub_file))
    res_env_file = runner.invoke(app, ["verify", "--ledger", str(ledger), "--allow-unanchored"])
    assert res_env_file.exit_code == 0, res_env_file.output
    st_env_file = _run_standalone(ledger, None, key_dir, env_pubkey=str(pub_file))
    assert st_env_file.returncode == 0, st_env_file.stderr

    # Env var holding inline PEM contents
    monkeypatch.setenv("RECEIPTD_PUBLIC_KEY", sk.public_pem_bytes.decode("ascii"))
    res_env_pem = runner.invoke(app, ["verify", "--ledger", str(ledger), "--allow-unanchored"])
    assert res_env_pem.exit_code == 0, res_env_pem.output
