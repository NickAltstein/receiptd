import pytest


@pytest.fixture(autouse=True)
def isolate_receipt_signing_keys(monkeypatch, tmp_path):
    """Keep default signing and ledger state inside each test directory."""
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(tmp_path / "receiptd-keys"))
