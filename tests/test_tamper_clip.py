import os
from pathlib import Path
import subprocess
import sys


def test_clip_denies_allows_and_detects_tampering():
    root = Path(__file__).resolve().parents[1]
    env = {
        **os.environ,
        "CLIP_FAST": "1",
        "PATH": os.pathsep.join((str(Path(sys.executable).parent), os.environ["PATH"])),
        "PYTHONPATH": str(root),
    }
    result = subprocess.run(
        ["bash", str(root / "demos" / "clip.sh")],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    output = result.stdout
    assert output.index("Hook exit 2") < output.index("Hook exit 0")
    assert '"decision": "deny"' in output
    assert '"decision": "allow"' in output
    assert "Signatures and hash chain checked (exit 0)." in output
    assert output.rstrip().endswith("TAMPER DETECTED (exit 2).")
