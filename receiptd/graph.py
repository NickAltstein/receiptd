"""Offline HTML view of a hook ledger."""

import json
import re
from html import escape

from .crypto import get_pubkey_id
from .models import AgentIdentity

IDENTIFIER = re.compile(r"[A-Za-z0-9_:-]{1,128}")
HEX = re.compile(r"[a-fA-F0-9]{64}")
TIMESTAMP = re.compile(r"[0-9T:Z.+-]{10,40}")
SIGNATURE = re.compile(r"[A-Za-z0-9+/=_-]{1,256}")
HOOK_REASONS = {"allowed", "receiptd: signing unavailable"}


def _field(value, pattern, length=None):
    if isinstance(value, str) and pattern.fullmatch(value):
        return escape(value[:length])
    return "Unavailable"


def _summary(rows, key, pattern):
    return ", ".join(dict.fromkeys(_field(row.get(key), pattern) for row in rows)) or "Unavailable"


def _identity_block(rows):
    blocks = {}
    for row in rows:
        if not isinstance(row.get("identity"), dict):
            continue
        try:
            identity = AgentIdentity.model_validate(row["identity"])
            if not identity.verify() or identity.session_id != row.get("session_id"):
                continue
            signer = get_pubkey_id(identity.public_key)
        except (TypeError, ValueError):
            continue
        blocks[identity.signature] = (
            f'<p>Signed identity: {_field(identity.agent_id, IDENTIFIER)} · '
            f'{_field(identity.runtime, re.compile(r"[A-Za-z0-9_.-]+"))} · '
            f'{_field(identity.policy, re.compile(r"[A-Za-z0-9_.@-]+"))} · '
            f'expires {_field(identity.expires_at, TIMESTAMP)} · '
            f'signer <code>{_field(signer, HEX)}</code></p>'
        )
    return "".join(blocks.values())


def render_graph(snapshot: str, passed: bool, failure: int | None, show_args: bool) -> str:
    rows = []
    for line in snapshot.split("\n"):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            row = {}
        if not isinstance(row, dict):
            row = {}
        if row.get("type") != "checkpoint":
            rows.append(row)

    allowed = sum(row.get("decision") == "allow" for row in rows)
    denied = sum(row.get("decision") == "deny" for row in rows)
    status = "pass" if passed else (
        f"fail at receipt {failure}" if failure is not None else "fail (ledger-level check)"
    )
    warning = (
        "<p><strong>Stored arguments are included. Check before sharing.</strong></p>"
        if show_args else ""
    )
    timeline = []
    for index, row in enumerate(rows, 1):
        decision = row.get("decision")
        label = "allowed" if decision == "allow" else "denied" if decision == "deny" else "Unavailable"
        style = ' class="deny"' if decision == "deny" else ""
        state = ""
        if failure is not None:
            if index == failure:
                state = "<strong>chain broken here</strong>"
            elif index > failure:
                state = "<strong>unverifiable after break</strong>"
        rules = row.get("rule_ids")
        rule_names = ", ".join(_field(rule, IDENTIFIER) for rule in rules) if isinstance(rules, list) else ""
        raw_rtype = row.get("receipt_type")
        rtype_tag = _field(raw_rtype, IDENTIFIER) if isinstance(raw_rtype, str) and raw_rtype else ""
        if rtype_tag == "Unavailable":
            rtype_tag = ""
        reason = row.get("reason")
        if decision == "deny":
            if rtype_tag and reason == "session denied":
                reason_text = f"session denied ({rtype_tag}: matched rule {rule_names})" if rule_names else f"session denied ({rtype_tag})"
            elif rtype_tag and rule_names:
                reason_text = f"{rtype_tag}: matched rule {rule_names}"
            elif isinstance(reason, str) and reason in HOOK_REASONS:
                reason_text = escape(reason)
            elif rule_names:
                reason_text = f"matched rule {rule_names}"
            else:
                reason_text = "Reason unavailable"
        elif rtype_tag and rule_names:
            reason_text = f"{rtype_tag}: matched rule {rule_names} (receipt-only)"
        elif rtype_tag:
            reason_text = f"{rtype_tag} (receipt-only)"
        else:
            reason_text = ""
        args = ""
        if show_args and "tool_input" in row:
            args = f"<pre>{escape(json.dumps(row['tool_input'], indent=2))}</pre>"
        timeline.append(f'''
<li id="receipt-{index}"{style}>
<h2>{index}. {_field(row.get("tool") or row.get("tool_name"), IDENTIFIER)} · {label}</h2>
<p>{_field(row.get("ts"), TIMESTAMP)} · <code>{_field(row.get("hash") or row.get("receipt_sha256"), HEX, 16)}</code></p>
<p>{state} {reason_text}</p>
<details><summary>Receipt details</summary>
<p>Prior hash <code>{_field(row.get("prev_hash") or row.get("prev_receipt_hash"), HEX)}</code></p>
<p>Signature prefix <code>{_field(row.get("sig"), SIGNATURE, 12)}</code></p>
<p>Arguments hash <code>{_field(row.get("args_sha256"), HEX)}</code></p>
{args}</details></li>''')

    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>receiptd session</title>
<style>
:root {{ color-scheme: light dark; font: 16px system-ui, sans-serif; }}
body {{ max-width: 56rem; margin: 2rem auto; padding: 0 1rem; }}
header, li {{ border: 1px solid GrayText; padding: 1rem; border-radius: .4rem; }}
ol {{ list-style: none; padding-inline-start: 0; }}
li {{ margin: .75rem 0; border-inline-start-width: .3rem; }}
li.deny {{ border-inline-start-color: #d74747; }}
h2 {{ margin: 0; font-size: 1.15rem; }}
p, code, pre {{ overflow-wrap: anywhere; }}
pre {{ white-space: pre-wrap; }}
summary {{ cursor: pointer; }}
</style></head><body>
<header><h1>receiptd session</h1>
<p>Session ID: {_summary(rows, "session_id", IDENTIFIER)}</p>
<p>Policy name: {_summary(rows, "policy_name", IDENTIFIER)}</p>
<p>Policy hash: <code>{_summary(rows, "policy_sha256", HEX)}</code></p>
<p>Signer key ID: <code>{_summary(rows, "pubkey_id", HEX)}</code></p>
<p>{len(rows)} receipts · {allowed} allowed · {denied} denied</p>
<p>Signatures and hash chain checked: <strong>{status}</strong></p>{warning}{_identity_block(rows)}</header>
<ol>{"".join(timeline)}</ol></body></html>
'''
