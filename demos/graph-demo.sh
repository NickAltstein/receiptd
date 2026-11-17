#!/usr/bin/env bash
set -euo pipefail

output="$(cd "${1:-.}" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"
export HOME="$work" RECEIPTD_KEY_DIR="$work/keys"
unset RECEIPTD_PUBLIC_KEY
receiptd init --claude-code >init.log 2>&1 || { cat init.log >&2; exit 1; }
hook="$(python3 -c 'import json; print(json.load(open(".claude/settings.json"))["hooks"]["PreToolUse"][0]["hooks"][0]["command"])')"

submit() {
  local status=0
  printf '%s\n' "$2" | bash -c "$hook" || status=$?
  [[ "$status" == "$1" ]]
}

# The init probe is the first denial in the ledger. These four calls add
# three allows and one denial. The hook receives JSON and executes no tool.
submit 0 '{"session_id":"graph-demo","tool_name":"Bash","tool_input":{"command":"printf fixture-private-command"}}'
submit 2 '{"session_id":"graph-demo","tool_name":"Write","tool_input":{"file_path":".claude/settings.json","content":"{}"}}'
submit 0 '{"session_id":"graph-demo","tool_name":"Write","tool_input":{"file_path":"fixture-private-path.txt","content":"demo"}}'
submit 0 '{"session_id":"graph-demo","tool_name":"Bash","tool_input":{"command":"pytest -q"}}'
receiptd graph --out "$output/graph.html"

python3 - <<'PY'
import json
import re
from pathlib import Path

ledger = Path(".receiptd/receipts.jsonl")
lines = ledger.read_bytes().splitlines(keepends=True)
index = next(i for i, line in enumerate(lines) if json.loads(line).get("seq") == 3)
lines[index], changes = re.subn(rb'("tool"\s*:\s*")W(?=rite")', rb'\g<1>w', lines[index], count=1)
assert changes == 1
ledger.write_bytes(b"".join(lines))
PY

status=0
receiptd graph --out "$output/graph-tampered.html" || status=$?
[[ "$status" == 2 ]]
