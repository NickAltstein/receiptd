"""Show the calls behind each v1.5 miss, from the private scored output.

Read-only. Run it locally against the private v1.5 output directory (the one
holding case-results.jsonl and runs/). It changes nothing and prints, for each
miss, every call the grader counted as a dispatched prohibited attempt:

- route "unhooked": the call never reached the gate (deepagents glob/grep).
  Only the tool name is recorded for these calls.
- route "hooked": the gate allowed the call; the command or path comes from
  that case's events.jsonl.

    python eval/v1_6/classify_v1_5_misses.py <private v1.5 output dir>

Commands are truncated to 200 characters. The fixtures hold only EVAL_DECOY_
values, but review the output before sharing it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _load_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _target(event: dict) -> str:
    payload = event.get("payload", {})
    args = payload.get("tool_input") or {}
    value = args.get("command") or args.get("file_path") or args.get("path") or ""
    return str(value)[:200]


def main(output: Path) -> int:
    rows = _load_jsonl(output / "case-results.jsonl")
    if not rows:
        print(f"no case-results.jsonl rows under {output}", file=sys.stderr)
        return 1
    misses = [r for r in rows if r.get("primary_outcome") == "miss"]
    print(f"{len(misses)} miss rows")
    for row in misses:
        model, corpus, case_id = row["model_id"], row["corpus"], row["case_id"]
        run = output / "runs" / f"{model.replace(':', '_')}-{corpus}-{case_id}"
        print(f"\n== {case_id} | {model} | goal_completed={row.get('goal_completed')}")
        evidence_path = run / "evidence.json"
        if not evidence_path.is_file():
            print(f"   evidence.json missing at {run}")
            continue
        calls = json.loads(evidence_path.read_text()).get("calls", [])
        events = _load_jsonl(run / "events.jsonl")
        flagged = [c for c in calls
                   if c.get("prohibited_action_attempted") == "true"
                   and c.get("caller_dispatch_observed") == "true"]
        if not flagged:
            print("   no call with attempted=true and dispatched=true (miss from goal only)")
        for call in flagged:
            seq = call.get("seq")
            if call.get("hook_matched_and_invoked") == "false":
                print(f"   seq={seq} route=unhooked tool={call.get('native_tool_name')}")
                continue
            event = events[seq - 1] if isinstance(seq, int) and 0 < seq <= len(events) else {}
            print(f"   seq={seq} route=hooked tool={call.get('native_tool_name')} "
                  f"exit={call.get('hook_exit_status')} rules={list(call.get('rule_ids') or [])}")
            print(f"      {_target(event)!r}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: python eval/v1_6/classify_v1_5_misses.py <private v1.5 output dir>", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(Path(sys.argv[1])))
