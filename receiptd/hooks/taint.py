"""Stateful taint ratchet for the PreToolUse gate. Opt-in per policy file.

A policy that omits ``taint`` never reaches ``decide``: the gate writes the same
receipts and exits the same way it did before this module existed. With
``taint`` present, the gate reads the receipts already in the ledger, rebuilds
the labels raised earlier in the same ``session_id``, and denies a call that
matches a sink rule while one of that rule's labels is active. The outcome is
written into the signed part of the receipt the gate appends.

Mechanism, in order, for one call:

1. Read the ledger under the gate's file lock. Every record must parse, chain,
   hash and sign correctly, and the signed anchor in the key directory must
   match the ledger. This is ``ledger.check_ledger``, the same function
   ``receiptd verify`` uses. Any failure denies the call and nothing is
   written: no receipt, no anchor. The ledger stays as it is on disk, so the
   damage stays visible and every later call is denied the same way, until an
   operator repairs or rotates the ledger.
2. Fold this session's receipts in file order. A receipt's signed
   ``taint_labels_active`` must equal the labels seen so far plus its own
   ``taint_added``. Nothing removes a label. A receipt that breaks this is
   handled like a failed check in step 1.
3. Match the current call against ``sources``. Labels it raises count as
   active for the rest of this evaluation.
4. Match against ``sinks``. A sink denies when one of its labels is active.
5. A denied call raised nothing: the hook exits 2, so the tool did not run and
   nothing it fetched reached the model. Only an allowed call writes
   ``taint_added``.

Limits this module accepts rather than solves. It sees calls that reach the
hook and assumes the host honors exit 2. It matches the shape of a call (tool
name and arguments), never the content a tool returns. The ledger and the key
directory are ordinary files: an actor who can rewrite both together is outside
what a same-user hook can resist. See docs/taint-ratchet.md.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..crypto import Ed25519PublicKey, canonical_json
from ..ledger import LedgerIntegrityError, check_ledger

# What the gate prints on stderr when the ledger fails its checks. No rule id
# is written anywhere: a failed check produces no receipt.
LEDGER_INTEGRITY_ERROR = "LEDGER_INTEGRITY_ERROR"

TAINT_SCOPES = (
    "payload",
    "shell_command",
    "read_path",
    "write_path",
    "read_path_outside_workspace",
)
_RULE_KEYS = {"id", "labels", "tool", "scope", "pattern", "ignore_case"}
_LABEL = re.compile(r"[a-z][a-z0-9_]{0,63}")
TAINT_FIELDS = ("taint_labels_active", "taint_added", "taint_denied_rule", "source_receipt_hash")


class TaintLedgerError(Exception):
    """The ledger cannot support a taint decision.

    The gate denies the call and writes nothing to the ledger. The message is
    the sentence `receiptd verify` prints for the same damage.
    """


@dataclass(frozen=True)
class TaintRule:
    id: str
    labels: tuple[str, ...]
    scope: str
    tools: tuple[str, ...] | None
    pattern: re.Pattern[str] | None


@dataclass(frozen=True)
class TaintPolicy:
    sources: tuple[TaintRule, ...]
    sinks: tuple[TaintRule, ...]


@dataclass(frozen=True)
class TaintState:
    """Labels active in a session, and the receipt that first raised each."""

    labels: tuple[str, ...]
    sources: dict[str, str]


@dataclass(frozen=True)
class TaintOutcome:
    """What the ratchet decided about one call.

    ``rule_ids`` are appended to the receipt's ``rule_ids`` and deny the call.
    ``fields`` go into the signed part of the receipt. ``note`` explains a
    taint deny and is empty otherwise. There is no outcome for a call the
    ledger could not support: `decide` raises for that instead.
    """

    rule_ids: tuple[str, ...]
    fields: dict[str, Any]
    note: str


def _fields(active: tuple[str, ...], added: tuple[str, ...], denied_rule: str, source_hash: str) -> dict[str, Any]:
    return {
        "taint_labels_active": list(active),
        "taint_added": list(added),
        "taint_denied_rule": denied_rule,
        "source_receipt_hash": source_hash,
    }


# --------------------------------------------------------------------------- #
# Policy schema
# --------------------------------------------------------------------------- #
def _parse_rule(raw: Any, kind: str, index: int, seen: dict[str, str]) -> TaintRule:
    where = f"taint {kind}[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{where} must be an object")
    unknown = set(raw) - _RULE_KEYS
    if unknown:
        raise ValueError(f"{where} has unknown keys: {sorted(unknown)}")
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValueError(f"{where} id must be a non-empty string")
    if rule_id in seen:
        raise ValueError(f"{where} id {rule_id!r} is already used")
    seen[rule_id] = kind

    raw_labels = raw.get("labels")
    if not isinstance(raw_labels, list) or not raw_labels:
        raise ValueError(f"{where} labels must be a non-empty list")
    labels: list[str] = []
    for label in raw_labels:
        if not isinstance(label, str) or not _LABEL.fullmatch(label):
            raise ValueError(f"{where} label {label!r} must match {_LABEL.pattern}")
        if label not in labels:
            labels.append(label)
    if len(labels) != len(raw_labels):
        raise ValueError(f"{where} labels has duplicates")

    tools: tuple[str, ...] | None = None
    if "tool" in raw:
        raw_tools = raw["tool"]
        names = [raw_tools] if isinstance(raw_tools, str) else raw_tools
        if not isinstance(names, list) or not names or any(not isinstance(n, str) or not n for n in names):
            raise ValueError(f"{where} tool must be a tool name or a non-empty list of names")
        tools = tuple(names)

    scope = raw.get("scope", "payload")
    if scope not in TAINT_SCOPES:
        raise ValueError(f"{where} has an unknown scope")

    pattern: re.Pattern[str] | None = None
    if scope == "read_path_outside_workspace":
        if "pattern" in raw:
            raise ValueError(f"{where} read_path_outside_workspace takes no pattern")
    else:
        text = raw.get("pattern")
        if not isinstance(text, str):
            raise ValueError(f"{where} pattern must be a string")
        ignore_case = raw.get("ignore_case", False)
        if not isinstance(ignore_case, bool):
            raise ValueError(f"{where} ignore_case must be a boolean")
        try:
            pattern = re.compile(text, re.IGNORECASE if ignore_case else 0)
        except re.error as exc:
            raise ValueError(f"{where} pattern is not a valid regex") from exc
    return TaintRule(id=rule_id, labels=tuple(labels), scope=scope, tools=tools, pattern=pattern)


def parse_taint(raw: Any) -> TaintPolicy:
    """Parse the optional ``taint`` object of a PreToolUse policy. Raises ValueError."""
    if not isinstance(raw, dict):
        raise ValueError("taint must be an object")
    unknown = set(raw) - {"sources", "sinks"}
    if unknown:
        raise ValueError(f"taint has unknown keys: {sorted(unknown)}")
    seen: dict[str, str] = {}
    lists: dict[str, tuple[TaintRule, ...]] = {}
    for kind in ("sources", "sinks"):
        items = raw.get(kind, [])
        if not isinstance(items, list):
            raise ValueError(f"taint {kind} must be a list")
        lists[kind] = tuple(_parse_rule(item, kind, i, seen) for i, item in enumerate(items))
    raisable = {label for rule in lists["sources"] for label in rule.labels}
    for rule in lists["sinks"]:
        dead = [label for label in rule.labels if label not in raisable]
        if dead:
            # A sink label no source raises never denies: almost certainly a typo.
            raise ValueError(f"taint sink {rule.id!r} names labels no source raises: {dead}")
    return TaintPolicy(sources=lists["sources"], sinks=lists["sinks"])


# --------------------------------------------------------------------------- #
# Matching one call
# --------------------------------------------------------------------------- #
def _normalize_paths(rule: TaintRule, tool_name: str, tool_input: dict) -> list[str]:
    """Normalized file_path of a call, or none when the rule's tool filter fails."""
    from .claude_code_gate import _normalize_path

    if rule.tools and tool_name not in rule.tools:
        return []
    path = tool_input.get("file_path")
    return [_normalize_path(path)] if isinstance(path, str) and path else []


def rule_matches(rule: TaintRule, payload: dict) -> bool:
    """Match one rule against the call. A failed inspection counts as a match."""
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_name, str) or not isinstance(tool_input, dict):
        return False
    if rule.tools and tool_name not in rule.tools:
        return False
    pattern = rule.pattern

    if rule.scope == "payload" and pattern is not None:
        return pattern.search(f"{tool_name} {canonical_json(tool_input).decode('utf-8')}") is not None

    if rule.scope in ("read_path", "write_path") and pattern is not None:
        return any(pattern.search(path) for path in _normalize_paths(rule, tool_name, tool_input))

    if rule.scope == "read_path_outside_workspace":
        path = tool_input.get("file_path")
        if tool_name != "Read" or not isinstance(path, str) or not path:
            return False
        try:
            cwd = payload.get("cwd")
            workspace = Path(cwd) if isinstance(cwd, str) and cwd else Path.cwd()
            target = (workspace / Path(_normalize_paths(rule, tool_name, tool_input)[0])).resolve()
            root = workspace.resolve()
        except (OSError, RuntimeError, ValueError, IndexError):
            # A path that cannot be resolved is treated as outside the workspace.
            return True
        return not (target == root or root in target.parents)

    if rule.scope == "shell_command" and pattern is not None:
        if tool_name != "Bash":
            return False
        command = tool_input.get("command")
        if not isinstance(command, str):
            return False
        from .claude_code_gate import normalize_shell_command
        from .shell_analysis import command_views

        if pattern.search(command) is not None or pattern.search(normalize_shell_command(command)) is not None:
            return True
        # Also test each command of a chain, including commands behind shells
        # and wrappers that command_views exposes.
        try:
            views = [" ".join(words) for words in command_views(command)]
        except (ValueError, RuntimeError):
            return True
        return any(pattern.search(view) is not None for view in views)

    return False


def matching_sources(taint: TaintPolicy, payload: dict) -> list[TaintRule]:
    return [rule for rule in taint.sources if rule_matches(rule, payload)]


def triggering_sink(taint: TaintPolicy, payload: dict, active: tuple[str, ...]) -> tuple[TaintRule, str] | None:
    """First sink rule, in policy order, that matches with one of its labels active."""
    for rule in taint.sinks:
        if rule_matches(rule, payload):
            for label in rule.labels:
                if label in active:
                    return rule, label
    return None


# --------------------------------------------------------------------------- #
# Rebuilding state from the ledger
# --------------------------------------------------------------------------- #
def rebuild(receipts: list[tuple[str, dict]], session_id: str) -> TaintState:
    """Fold this session's receipts. Raise TaintLedgerError when a label disappears."""
    labels: set[str] = set()
    sources: dict[str, str] = {}
    for receipt_hash, entry in receipts:
        if entry.get("session_id") != session_id:
            continue
        if not any(field in entry for field in TAINT_FIELDS):
            # Written without taint fields: an older policy, the Stop hook, or
            # a gate that could not load its signing key. It raised nothing.
            continue
        seq = entry.get("seq")
        active, added = entry.get("taint_labels_active"), entry.get("taint_added")
        shape = (
            isinstance(active, list) and isinstance(added, list)
            and all(isinstance(label, str) for label in active + added)
            and isinstance(entry.get("taint_denied_rule"), str)
            and isinstance(entry.get("source_receipt_hash"), str)
        )
        if not shape:
            raise TaintLedgerError(f"receipt taint fields are malformed at sequence #{seq}")
        if sorted(active) != sorted(labels | set(added)):
            raise TaintLedgerError(f"receipt taint state is not monotonic at sequence #{seq}")
        labels = set(active)
        for label in added:
            sources.setdefault(label, receipt_hash)
    return TaintState(labels=tuple(sorted(labels)), sources=sources)


def load_session_taint(ledger_path: str | Path, session_id: str, public_key: Ed25519PublicKey) -> TaintState:
    """Read the ledger, check it end to end, and return this session's labels.

    Raises TaintLedgerError for anything that leaves the session's labels
    unknown: an unreadable file, a record that does not parse, a chain, hash,
    signature, checkpoint or anchor failure, or a receipt whose taint state
    contradicts the receipts before it. The ledger checks are
    ``ledger.check_ledger``, the same function ``receiptd verify`` uses, so the
    gate and the offline check read a ledger alike. A ledger that does not
    exist yet and has no anchor is a fresh install and yields an empty state.
    """
    path = Path(ledger_path)
    try:
        source: str = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        # No ledger file. That is a fresh install only if no anchor names this
        # ledger; the anchor check below is what tells the two apart.
        source = ""
    except (OSError, UnicodeDecodeError) as exc:
        raise TaintLedgerError(f"ledger unreadable ({type(exc).__name__})") from exc
    try:
        checked = check_ledger(source, path, public_key)
    except LedgerIntegrityError as exc:
        raise TaintLedgerError(exc.reason) from None
    return rebuild(list(checked.receipts), session_id)


# --------------------------------------------------------------------------- #
# Deciding one call
# --------------------------------------------------------------------------- #
def decide(
    taint: TaintPolicy,
    ledger_path: str | Path,
    session_id: str,
    payload: dict,
    public_key: Ed25519PublicKey,
    *,
    already_denied: bool,
) -> TaintOutcome:
    """Apply the ratchet to one call.

    Raises TaintLedgerError when the ledger cannot establish the session's
    labels. The caller denies the call and writes nothing: no receipt, no
    anchor. Appending to a ledger that failed its checks would re-point the
    anchor at the new last line, and a cut-off tail would pass every check
    one call later. A damaged ledger stays as it is until an operator looks
    at it.
    """
    state = load_session_taint(ledger_path, session_id, public_key)

    raised = matching_sources(taint, payload)
    # Sources are evaluated before sinks, so a call that is both is denied.
    fresh = tuple(sorted({label for rule in raised for label in rule.labels} - set(state.labels)))
    hit = triggering_sink(taint, payload, tuple(sorted(set(state.labels) | set(fresh))))
    if hit is None:
        # A call the base rules already denied did not run and raised nothing,
        # so its receipt names the labels the session had, not the ones this
        # call matched. The next call carries the same labels.
        active = tuple(sorted(set(state.labels) | (set() if already_denied else set(fresh))))
        return TaintOutcome((), _fields(active, () if already_denied else fresh, "", ""), "")

    rule, label = hit
    if label in fresh:
        source_hash = ""
        note = f"taint label {label} is raised by this same call"
        rule_ids = (rule.id,) + tuple(r.id for r in raised if label in r.labels)
    else:
        source_hash = state.sources[label]
        note = f"taint label {label} is active since receipt {source_hash}"
        rule_ids = (rule.id,)
    return TaintOutcome(rule_ids, _fields(state.labels, (), rule.id, source_hash), note)
