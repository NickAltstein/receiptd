import pytest

from receiptd.hooks.claude_code_gate import evaluate_payload


@pytest.mark.parametrize(("before", "after", "denied"), [
    ("run: pytest", "run: pytest -q", True),
    ("- uses: actions/checkout@v4", "- uses: actions/checkout@v5", True),
    ("permissions:\n  contents: read", "permissions:\n  contents: write", True),
    ('"run": pytest', "", True),
    ("", "run: |\n  pytest", True),
    ("# run: pytest", "# run: pytest -q", False),
    ("# Build procedure", "# Test procedure", False),
    ("name: Test", "name: Python tests", False),
    ("run: pytest\n# Test", "run: pytest\n# Run tests", False),
    ("description: Old text", "description: New text", False),
])
def test_workflow_edit_policy(before, after, denied):
    blocked, _, rules = evaluate_payload({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": ".github/workflows/ci.yml",
            "old_string": before,
            "new_string": after,
        },
    })
    assert blocked is denied
    assert ("POL-04:WORKFLOW_PROTECTED_KEYS" in rules) is denied


@pytest.mark.parametrize(("original", "replacement", "denied"), [
    ("steps:\n  - run: pytest\n", "# Comment\nsteps:\n  - run: pytest\n", False),
    ("name: Tests\nrun: 'pytest'\n", 'name: Test suite\nrun: "pytest"\n', False),
    ("run: pytest\n", "run: pytest -q\n", True),
    ("permissions:\n  contents: read\n", "name: Tests\n", True),
    (None, "name: Tests\n", True),
    ("run: pytest\nrun: echo\n", "run: pytest\n", True),
])
def test_workflow_write_compares_protected_values(tmp_path, original, replacement, denied):
    path = tmp_path / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True)
    if original is not None:
        path.write_text(original, encoding="utf-8")
    blocked, _, rules = evaluate_payload({
        "tool_name": "Write",
        "tool_input": {"file_path": str(path), "content": replacement},
    })
    assert blocked is denied
    assert ("POL-04:WORKFLOW_PROTECTED_KEYS" in rules) is denied
