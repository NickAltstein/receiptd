import os
import re
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def pages(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    target = tmp_path_factory.mktemp("graph")
    env = {
        **os.environ,
        "PATH": os.pathsep.join((str(Path(sys.executable).parent), os.environ["PATH"])),
        "PYTHONPATH": str(root),
    }
    subprocess.run(["bash", str(root / "demos" / "graph-demo.sh"), str(target)],
                   check=True, env=env, timeout=30)
    return [(target / name).read_text() for name in ("graph.html", "graph-tampered.html")]


def test_graph_pass_and_counts(pages):
    assert "5 receipts · 3 allowed · 2 denied" in pages[0]
    assert "Signatures and hash chain checked: <strong>pass</strong>" in pages[0]


def test_graph_marks_the_break_and_later_receipts(pages):
    broken = pages[1]
    assert "fail at receipt 3" in broken
    assert re.search(r'id="receipt-3"[^>]*>[^<]*.*?chain broken here', broken, re.S)
    for i in (4, 5):
        node = broken.split(f'id="receipt-{i}"', 1)[1].split("</li>", 1)[0]
        assert "unverifiable after break" in node


def test_graph_omits_arguments_by_default(pages):
    for page in pages:
        assert "fixture-private-command" not in page
        assert "fixture-private-path.txt" not in page
        assert ".claude/settings.json" not in page
        assert "pytest -q" not in page
        assert "Arguments hash" in page


def test_graph_has_no_external_assets(pages):
    for page in pages:
        assert not re.search(r'''(?:src|href)\s*=\s*["']https?://''', page, re.I)
        assert "default-src 'none'" in page


def test_graph_includes_arguments_only_when_requested():
    import json

    from receiptd.graph import render_graph

    snapshot = json.dumps({"tool_input": {"command": "<example>"}})
    assert "&lt;example&gt;" not in render_graph(snapshot, True, None, False)
    page = render_graph(snapshot, True, None, True)
    assert "&lt;example&gt;" in page
    assert "Check before sharing" in page
