"""Shared deterministic lexical normalizer for receiptd hook policy evaluation and rules.

All size caps and limits in this module are defaults, not tuned values.
"""
from __future__ import annotations

import base64
import os
import posixpath
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from ..crypto import canonical_json, sha256_hex

# Default bounds, not tuned values.
DEFAULT_MAX_BASE64_INPUT_BYTES = 4096
DEFAULT_MAX_BASE64_OUTPUT_BYTES = 4096

_UNSET = object()

_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_B64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{8,}={0,2})(?![A-Za-z0-9+/=_-])")
_HOME_VAR_RE = re.compile(r"\$\{?home\}?", re.IGNORECASE)
_TILDE_RE = re.compile(r"(?:(?<=^)|(?<=[\s=:|;&]))~(?=$|[\s/|;&:])")
_MULTI_SLASH_RE = re.compile(r"(?<!:)//+")
_PATH_TOKEN_RE = re.compile(r"(?:https?://\S+|[^\s|;&<>()'\"]+)")

PATH_INPUT_KEYS = frozenset(
    {"file_path", "path", "target_file", "notebook_path", "directory", "target_path", "cwd"}
)


def _resolve_home(home: Any) -> str | None:
    if home is _UNSET:
        env_home = os.environ.get("HOME", "").strip()
        candidate = env_home
    elif isinstance(home, str):
        candidate = home.strip()
    elif isinstance(home, Path):
        candidate = str(home).strip()
    else:
        return None
    if not candidate:
        return None
    normalized = candidate.replace("\\", "/")
    normalized = _MULTI_SLASH_RE.sub("/", normalized).rstrip("/")
    return normalized or "/"


def _is_printable_text(data: bytes) -> str | None:
    if not data or b"\x00" in data:
        return None
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in decoded if ch in ("\t", "\n", "\r") or 32 <= ord(ch) < 127 or ord(ch) > 159)
    if printable != len(decoded):
        return None
    return decoded


def _decode_one_level_base64(
    text: str,
    *,
    max_input_bytes: int = DEFAULT_MAX_BASE64_INPUT_BYTES,
    max_output_bytes: int = DEFAULT_MAX_BASE64_OUTPUT_BYTES,
) -> tuple[str, bool, bool]:
    """Decode printable one-level base64 candidate tokens up to configured size caps."""
    decoded_any = False
    capped_any = False

    def _replace(match: re.Match[str]) -> str:
        nonlocal decoded_any, capped_any
        token = match.group(1)
        if len(token.encode("utf-8")) > max_input_bytes:
            capped_any = True
            return token
        if len(token) % 4 != 0 or token.islower() or token.isdigit():
            return token
        try:
            if "-" in token or "_" in token:
                raw = base64.urlsafe_b64decode(token.encode("ascii"))
            else:
                raw = base64.b64decode(token.encode("ascii"), validate=True)
        except Exception:
            return token
        if len(raw) > max_output_bytes:
            capped_any = True
            return token
        decoded = _is_printable_text(raw)
        if decoded is None:
            return token
        decoded_any = True
        return decoded

    return _B64_TOKEN_RE.sub(_replace, text), decoded_any, capped_any


def _canonicalize_path_segment(token: str) -> str:
    if "://" in token:
        scheme, rest = token.split("://", 1)
        if "/" in rest:
            host, path_part = rest.split("/", 1)
            norm_path = posixpath.normpath("/" + path_part)
            return f"{scheme}://{host}{norm_path}"
        return f"{scheme}://{rest}"
    if "/" not in token and token not in (".", ".."):
        return token
    if "=" in token and not token.startswith("/") and "://" not in token:
        key, sep, val = token.partition("=")
        if "/" in val:
            return f"{key}{sep}{_canonicalize_path_segment(val)}"
    had_trailing_slash = len(token) > 1 and token.endswith("/")
    norm = posixpath.normpath(token)
    if norm == "." and token.startswith("./"):
        return "."
    if had_trailing_slash and not norm.endswith("/"):
        norm += "/"
    return norm


def _canonicalize_paths_in_text(text: str) -> str:
    return _PATH_TOKEN_RE.sub(lambda m: _canonicalize_path_segment(m.group(0)), text)


def normalize_text(
    text: str,
    *,
    home: Any = _UNSET,
    max_base64_bytes: int = DEFAULT_MAX_BASE64_INPUT_BYTES,
    max_decoded_bytes: int = DEFAULT_MAX_BASE64_OUTPUT_BYTES,
) -> tuple[str, list[str]]:
    """Deterministically normalize shell/command text and return (normalized_text, trace)."""
    if not isinstance(text, str):
        return "", []

    trace: list[str] = []
    current = text

    if _PERCENT_RE.search(current):
        decoded = unquote(current)
        if decoded != current:
            current = decoded
            trace.append("url_decode")

    b64_out, b64_decoded, b64_capped = _decode_one_level_base64(
        current,
        max_input_bytes=max_base64_bytes,
        max_output_bytes=max_decoded_bytes,
    )
    if b64_capped:
        trace.append("base64_size_cap")
    if b64_decoded and b64_out != current:
        current = b64_out
        trace.append("base64_decode")

    no_quotes = current.replace("'", "").replace('"', "")
    if no_quotes != current:
        current = no_quotes
        trace.append("strip_shell_quoting")

    no_backslashes = current.replace("\\", "")
    if no_backslashes != current:
        current = no_backslashes
        trace.append("strip_backslashes")

    collapsed = re.sub(r"[^\S\n]+", " ", current)
    collapsed = re.sub(r" *\n *", "\n", collapsed).strip()
    if collapsed != current:
        current = collapsed
        trace.append("collapse_whitespace")

    folded = current.lower()
    if folded != current:
        current = folded
        trace.append("case_fold")

    resolved_home = _resolve_home(home)
    if resolved_home is not None:
        home_lower = resolved_home.lower()
        expanded = _HOME_VAR_RE.sub(home_lower, current)
        expanded = _TILDE_RE.sub(home_lower, expanded)
        if expanded != current:
            current = expanded
            trace.append("expand_home")

    canon = _canonicalize_paths_in_text(current)
    if canon != current:
        current = canon
        trace.append("canonicalize_paths")

    return current, trace


def normalize_path(
    path: str,
    *,
    home: Any = _UNSET,
    max_base64_bytes: int = DEFAULT_MAX_BASE64_INPUT_BYTES,
    max_decoded_bytes: int = DEFAULT_MAX_BASE64_OUTPUT_BYTES,
) -> tuple[str, list[str]]:
    """Deterministically normalize a file path and return (normalized_path, trace)."""
    if not isinstance(path, str):
        return "", []

    trace: list[str] = []
    current = path.strip()
    if current != path:
        trace.append("collapse_whitespace")

    if _PERCENT_RE.search(current):
        decoded = unquote(current)
        if decoded != current:
            current = decoded
            trace.append("url_decode")

    b64_out, b64_decoded, b64_capped = _decode_one_level_base64(
        current,
        max_input_bytes=max_base64_bytes,
        max_output_bytes=max_decoded_bytes,
    )
    if b64_capped:
        trace.append("base64_size_cap")
    if b64_decoded and b64_out != current:
        current = b64_out
        trace.append("base64_decode")

    no_quotes = current.replace("'", "").replace('"', "")
    if no_quotes != current:
        current = no_quotes
        trace.append("strip_shell_quoting")

    sep_fixed = current.replace("\\", "/")
    if sep_fixed != current:
        current = sep_fixed
        trace.append("canonicalize_separators")

    collapsed = re.sub(r"[^\S\n]+", " ", current)
    collapsed = re.sub(r" *\n *", "\n", collapsed).strip()
    if collapsed != current:
        current = collapsed
        trace.append("collapse_whitespace")

    folded = current.lower()
    if folded != current:
        current = folded
        trace.append("case_fold")

    resolved_home = _resolve_home(home)
    if resolved_home is not None:
        home_lower = resolved_home.lower()
        expanded = _HOME_VAR_RE.sub(home_lower, current)
        expanded = _TILDE_RE.sub(home_lower, expanded)
        if expanded != current:
            current = expanded
            trace.append("expand_home")

    canon = _canonicalize_path_segment(current)
    if canon != current:
        current = canon
        trace.append("canonicalize_paths")

    return current, trace


def normalize_tool_input(
    tool_name: str,
    tool_input: Any,
    *,
    home: Any = _UNSET,
    max_base64_bytes: int = DEFAULT_MAX_BASE64_INPUT_BYTES,
) -> tuple[dict[str, Any], list[str], str]:
    """Normalize string values inside tool_input.

    Returns (normalized_dict, trace, normalized_args_sha256).
    """
    if not isinstance(tool_input, dict):
        empty: dict[str, Any] = {}
        return empty, [], sha256_hex(canonical_json(empty))

    trace: list[str] = []

    def _seen_extend(steps: list[str]) -> None:
        for step in steps:
            if step not in trace:
                trace.append(step)

    def _walk(value: Any, key_hint: str = "") -> Any:
        if isinstance(value, str):
            if key_hint in PATH_INPUT_KEYS:
                norm_val, steps = normalize_path(value, home=home, max_base64_bytes=max_base64_bytes)
            else:
                norm_val, steps = normalize_text(value, home=home, max_base64_bytes=max_base64_bytes)
            _seen_extend(steps)
            return norm_val
        if isinstance(value, dict):
            return {str(k): _walk(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [_walk(item, key_hint) for item in value]
        return value

    normalized = {str(k): _walk(v, str(k)) for k, v in tool_input.items()}
    norm_hash = sha256_hex(canonical_json(normalized))
    return normalized, trace, norm_hash


def extract_normalized_paths(
    tool_name: str,
    tool_input: Any,
    *,
    home: Any = _UNSET,
) -> list[str]:
    """Extract normalized candidate file/target paths from tool_input."""
    if not isinstance(tool_input, dict):
        return []

    found: list[str] = []

    def _add(candidate: str) -> None:
        if candidate and candidate not in found:
            found.append(candidate)

    for key in ("file_path", "path", "target_file", "notebook_path", "target_path"):
        val = tool_input.get(key)
        if isinstance(val, str) and val.strip():
            norm_p, _ = normalize_path(val, home=home)
            _add(norm_p)

    if tool_name == "Bash":
        cmd = tool_input.get("command")
        if isinstance(cmd, str) and cmd.strip():
            norm_cmd, _ = normalize_text(cmd, home=home)
            # Strip URL schemes before tokenizing embedded path expressions such as open(.env) or @.env.
            scrubbed = re.sub(r"https?://\S+", " ", norm_cmd)
            for token in re.findall(r"[A-Za-z0-9_./~$:-]+", scrubbed):
                cleaned = token.strip(":")
                if not cleaned or cleaned.startswith("-"):
                    continue
                if "/" in cleaned or cleaned.startswith(".") or cleaned.startswith("~") or any(
                    name in cleaned for name in (".env", "credentials", "id_rsa", "id_ed25519", "settings.json")
                ):
                    _add(cleaned)

    return found


_SHELL_SEGMENT_RE = re.compile(r"(?:\n+|;|\|\||&&|\|)")
_SHELL_PIPELINE_RE = re.compile(r"(?:\n+|;|\|\||&&)")


def split_shell_lines(command: str) -> list[str]:
    """Split a Bash command into non-empty lines while preserving line boundaries."""
    if not isinstance(command, str) or not command.strip():
        return []
    return [line.strip() for line in command.splitlines() if line.strip()]


def split_shell_pipelines(command: str) -> list[str]:
    """Split a Bash command on newline, ;, &&, and ||, keeping piped sequences together."""
    if not isinstance(command, str) or not command.strip():
        return []
    return [pipe.strip() for pipe in _SHELL_PIPELINE_RE.split(command) if pipe.strip()]


def split_shell_segments(command: str) -> list[str]:
    """Split a Bash command into atomic segments on newline, ;, &&, ||, and |."""
    if not isinstance(command, str) or not command.strip():
        return []
    return [seg.strip() for seg in _SHELL_SEGMENT_RE.split(command) if seg.strip()]
