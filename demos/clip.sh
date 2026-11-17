#!/usr/bin/env bash
set -euo pipefail

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"
export HOME="$work"
export RECEIPTD_KEY_DIR="$work/keys"
ledger=.receiptd/receipts.jsonl

caption() {
  printf '\n%s\n' "$1"
  if [[ ${CLIP_FAST:-0} != 1 ]]; then sleep 2.5; fi
}

hook_call() {
  local expected="$1" payload="$2" status=0
  printf '%s\n' "$payload" | bash -c "$hook" || status=$?
  printf 'Hook exit %s\n' "$status"
  [[ "$status" == "$expected" ]]
}

caption '1. Install the hook in a temporary project'
receiptd init --claude-code >init.log 2>&1 || { cat init.log; exit 1; }
hook="$(python3 -c 'import json; print(json.load(open(".claude/settings.json"))["hooks"]["PreToolUse"][0]["hooks"][0]["command"])')"

caption '2. Submit a fixture for a Claude settings write'
hook_call 2 '{"session_id":"clip","tool_name":"Write","tool_input":{"file_path":".claude/settings.json","content":"{}"}}'

caption '3. Submit an ordinary test command as a fixture'
hook_call 0 '{"session_id":"clip","tool_name":"Bash","tool_input":{"command":"pytest -q"}}'

caption '4. Show the two fixture receipts'
python3 - "$ledger" <<'PY'
import json
import sys
from pathlib import Path

rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
rows = [row for row in rows if row.get("session_id") == "clip"]
assert len(rows) == 2
for row in rows:
    assert row["sig"]
    print(json.dumps({
        "tool": row["tool"], "decision": row["decision"],
        "rules": row["rule_ids"], "policy_sha256": row["policy_sha256"],
        "signature_prefix": row["sig"][:12],
    }, indent=2))
PY

caption '5. Check signatures and hash chain'
receiptd verify --ledger "$ledger" --allow-unanchored >before.log 2>&1 || { cat before.log; exit 1; }
grep -q 'VERDICT: AUTHENTIC' before.log
printf 'Signatures and hash chain checked (exit 0).\n'

caption '6. Change one byte in the first fixture receipt: Write → write'
printf '%s\n' '$ python3 -c '\''from pathlib import Path; p=Path(".receiptd/receipts.jsonl"); b=p.read_bytes(); assert b.count(b"Write")==2; p.write_bytes(b.replace(b"Write",b"write",1))'\'''
python3 -c 'from pathlib import Path; p=Path(".receiptd/receipts.jsonl"); b=p.read_bytes(); assert b.count(b"Write")==2; p.write_bytes(b.replace(b"Write",b"write",1))'

caption '7. Check the same ledger again'
status=0
receiptd verify --ledger "$ledger" --allow-unanchored >after.log 2>&1 || status=$?
grep -q 'TAMPER DETECTED' after.log
[[ "$status" == 2 ]]
printf 'TAMPER DETECTED (exit %s).\n' "$status"
