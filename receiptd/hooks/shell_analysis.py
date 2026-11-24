"""Bounded static shell inspection. No subprocesses or shell evaluation."""
from __future__ import annotations

import base64
import configparser
import os
from pathlib import Path
import re
import shlex

MAX_TEXT = 65536
MAX_DEPTH = 8
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
BREAKS = {";", "&&", "||", "|", "&", "(", ")"}
MUTATORS = {"chmod", "chown", "ln", "cp", "mv", "install", "tee", "touch", "truncate", "mkdir", "rm", "sed", "perl"}


def _tokens(text: str) -> list[str]:
    # Preserve command-boundary newlines. Quoted newlines stay inside their
    # quoted token and are revisited only when passed to a shell.
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|()<>\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = "#"
    words = list(lexer)
    result = []
    for word in words:
        if re.fullmatch(r"[;&|()\n]+", word):
            result.extend(re.findall(r"&&|\|\||[;|&()]", word.replace("\n", ";")))
        else:
            result.append(word)
    return result


def _literal_output(text: str) -> str | None:
    """Resolve only literal echo/printf output, never arbitrary substitutions."""
    try:
        words = _tokens(text)
    except ValueError:
        return None
    if not words or any(w in BREAKS or re.fullmatch(r"[<>]+", w) for w in words):
        return None
    if any(re.search(r"[$`\\]", w) for w in words):
        return None
    if words[0] == "echo":
        args = words[1:]
        return " ".join(args[1:] if args[:1] == ["-n"] else args)
    if words[0] == "printf" and len(words) >= 2:
        if words[1] in ("%s", "%s\\n"):
            return "".join(words[2:])
        if len(words) == 2 and "%" not in words[1]:
            return words[1]
    return None


def _ansi_quotes(text: str) -> str:
    def unquote(match):
        body = match[1]
        escapes = {"a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
        def decode(escape):
            value = escape[1]
            if value.startswith("x"):
                return chr(int(value[1:], 16))
            if value[0] in "01234567":
                return chr(int(value, 8))
            return escapes.get(value, value)
        body = re.sub(r"\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|[abefnrtv\\'\"])", decode, body)
        return shlex.quote(body)
    return re.sub(r"\$'((?:\\.|[^'\\])*)'", unquote, text)


def _substitutions(text: str) -> str:
    # Resolve only non-nested literal producers. Other bodies remain visible to
    # recursive inspection; this intentionally does not emulate a shell runtime.
    for _ in range(MAX_DEPTH):
        before = text
        def replace(match):
            value = _literal_output(match.group(1))
            return value if value is not None else match.group(0)
        text = re.sub(r"\$\(([^()]*)\)", replace, text)
        text = re.sub(r"`([^`]*)`", replace, text)
        if text == before:
            break
    return text


def _expand(word: str, variables: dict[str, str]) -> str:
    word = re.sub(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))",
                  lambda m: variables.get(m[1] or m[2], m[0]), word)
    if word == "~" or word.startswith("~/"):
        word = variables["HOME"] + word[1:]
    return word


def _unwrap(words: list[str]) -> list[str]:
    """Expose command operands behind common wrappers without running them."""
    words = list(words)
    while words:
        name = Path(words[0]).name
        if re.fullmatch(r"[A-Za-z_]\w*=.*", words[0], re.S):
            words = words[1:]
            continue
        if name not in {"env", "nohup", "sudo", "timeout", "xargs", "command", "exec", "eval"}:
            break
        words = words[1:]
        if name in {"exec", "eval", "command", "nohup"}:
            while words and words[0].startswith("-"):
                words = words[1:]
            continue
        # Options consuming a separate argument; other options are flags.
        consumes = {
            "env": {"-u", "--unset", "-C", "--chdir"},
            "sudo": {"-u", "--user", "-g", "--group", "-h", "-p", "-C", "-T", "-R", "-D"},
            "timeout": {"-s", "--signal", "-k", "--kill-after"},
            "xargs": {"-n", "-I", "-d", "-s", "-a", "-P", "-L", "-E", "--max-args", "--replace"},
        }.get(name, set())
        while words and words[0].startswith("-"):
            opt = words.pop(0)
            if opt == "--":
                break
            if opt in consumes and words:
                words.pop(0)
        if name == "timeout" and words:
            words.pop(0)  # duration
    return words


def command_views(command: str) -> list[list[str]]:
    """Return bounded token views of chains, nested shells and decoded literals."""
    if len(command) > MAX_TEXT:
        raise ValueError("command exceeds static inspection limit")
    result: list[list[str]] = []
    seen: set[str] = set()
    variables = {"HOME": os.environ.get("HOME", "/home/user")}

    def visit(text: str, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise ValueError("shell nesting exceeds static inspection limit")
        if text in seen:
            return
        seen.add(text)
        text = _substitutions(_ansi_quotes(text))
        words = _tokens(text)
        segments: list[list[str]] = [[]]
        for word in words:
            if word in BREAKS:
                segments.append([])
            else:
                segments[-1].append(word)
        for index, segment in enumerate(segments):
            if not segment:
                continue
            # Assignment changes are applied in chain order, not collected
            # from later statements that have not run yet.
            for word in segment:
                match = re.fullmatch(r"([A-Za-z_]\w*)=(.*)", word, re.S)
                if match:
                    value = _expand(match[2], variables)
                    if not re.search(r"[$`()]", value):
                        variables[match[1]] = value
            segment = [_expand(w, variables) for w in segment]
            result.append(segment)
            exposed = _unwrap(segment)
            if exposed != segment and exposed:
                result.append(exposed)
            if not exposed:
                continue
            name = Path(exposed[0]).name
            if name in SHELLS:
                for i, arg in enumerate(exposed[1:], 1):
                    if arg.startswith("-") and "c" in arg and i + 1 < len(exposed):
                        visit(exposed[i + 1], depth + 1)
                        break
            if Path(segment[0]).name in {"eval", "exec"}:
                visit(" ".join(exposed), depth + 1)
            if name == "base64" and any(a in {"-d", "--decode", "-D"} for a in exposed[1:]):
                if index > 0 and index + 1 < len(segments):
                    consumer = _unwrap(segments[index + 1])
                    if consumer and Path(consumer[0]).name in SHELLS:
                        encoded = _literal_output(" ".join(shlex.quote(w) for w in segments[index - 1]))
                        if encoded is not None:
                            try:
                                decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
                            except (ValueError, UnicodeError):
                                raise ValueError("cannot inspect encoded shell input") from None
                            visit(decoded, depth + 1)
        # Inspect unresolved substitution bodies for gated actions, without
        # treating their stdout as an executable value.
        for body in re.findall(r"\$\(([^()]*)\)|`([^`]*)`", text):
            visit(body[0] or body[1], depth + 1)

    visit(command, 0)
    return result


def _config_hooks(path: Path, depth: int = 0) -> str | None:
    if depth > MAX_DEPTH:
        raise ValueError("git config nesting exceeds inspection limit")
    if not path.exists():
        return None
    data = path.read_bytes()
    if len(data) > MAX_TEXT:
        raise ValueError("git config exceeds inspection limit")
    parser = configparser.RawConfigParser(strict=False)
    parser.read_string(data.decode("utf-8"))
    if any(section.lower().startswith("includeif ") for section in parser.sections()):
        raise ValueError("conditional git config requires inspection")
    value = None
    for section in parser.sections():
        if section.lower().startswith("includeif "):
            # Conditional config needs Git's full context. Refuse the call
            # rather than assume a hooks directory in an uninspected include.
            raise ValueError("conditional git config requires explicit inspection")
        if section == "include":
            include = parser.get(section, "path", fallback=None)
            if include:
                included = Path(include.strip().strip('"')).expanduser()
                found = _config_hooks(path.parent / included, depth + 1)
                if found is not None:
                    value = found
        if section == "core":
            value = parser.get(section, "hooksPath", fallback=value)
    return value


def configured_hooks_root(cwd: Path) -> Path | None:
    """Inspect static system, global, local and worktree hooksPath settings."""
    home = Path(os.environ.get("HOME", "/home/user"))
    config_paths = [Path(os.environ.get("GIT_CONFIG_SYSTEM", "/etc/gitconfig"))]
    if os.environ.get("GIT_CONFIG_NOSYSTEM"):
        config_paths = []
    if "GIT_CONFIG_GLOBAL" in os.environ:
        config_paths.append(Path(os.environ["GIT_CONFIG_GLOBAL"]))
    else:
        config_paths += [Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config"))) / "git/config", home / ".gitconfig"]
    repo_root = cwd
    for root in (cwd, *cwd.parents):
        dotgit = root / ".git"
        if not dotgit.exists():
            continue
        repo_root = root
        gitdir = dotgit
        if dotgit.is_file():
            pointer = dotgit.read_text(encoding="utf-8")
            if not pointer.startswith("gitdir: ") or len(pointer) > MAX_TEXT:
                raise ValueError("invalid git directory pointer")
            gitdir = (root / pointer[8:].strip()).resolve()
        config = gitdir / "config"
        common = gitdir / "commondir"
        if common.is_file():
            config = (gitdir / common.read_text(encoding="utf-8").strip() / "config").resolve()
        config_paths += [config, gitdir / "config.worktree"]
        break
    value = None
    for config in config_paths:
        found = _config_hooks(config)
        if found is not None:
            value = found
    # Git's environment config overrides the file layers. Values are inspected
    # but never logged; unrelated environment variables are not expanded.
    count = int(os.environ.get("GIT_CONFIG_COUNT", "0"))
    if count < 0 or count > 128:
        raise ValueError("git environment config exceeds inspection limit")
    if os.environ.get("GIT_CONFIG_PARAMETERS"):
        raise ValueError("dynamic git config parameters require inspection")
    for i in range(count):
        if os.environ.get(f"GIT_CONFIG_KEY_{i}", "").lower() == "core.hookspath":
            value = os.environ.get(f"GIT_CONFIG_VALUE_{i}")
    if value is None:
        return None
    value = value.strip().strip('"')
    path = Path(_expand(value, {"HOME": str(home)}))
    return (repo_root / path).resolve()


def persistence_path(path: str, cwd: Path, hooks_root: Path | None) -> bool:
    expanded = _expand(path, {"HOME": os.environ.get("HOME", "/home/user")})
    candidate = Path(expanded)
    absolute = Path(os.path.abspath(cwd / candidate))
    paths = {absolute.as_posix(), absolute.resolve().as_posix()}
    for value in paths:
        if re.search(r"/(?:\.git/hooks|\.husky)(?:/|$)", value):
            return True
        if re.search(r"/(?:\.bashrc|\.bash_profile|\.bash_login|\.zshrc|\.zshenv|\.zprofile|\.zlogin|\.profile|crontab)$", value):
            return True
        if re.search(r"/(?:\.config/systemd/user|etc/systemd/(?:user|system)|usr/lib/systemd/user|Library/Launch(?:Agents|Daemons)|etc/cron(?:\.d|\.daily|\.hourly|\.weekly|\.monthly))(?:/|$)", value):
            return True
    return hooks_root is not None and (absolute == hooks_root or hooks_root in absolute.parents
                                      or absolute.resolve() == hooks_root or hooks_root in absolute.resolve().parents)


def matches_remote_shell(command: str, pattern: re.Pattern[str]) -> bool:
    for words in command_views(command):
        exposed = _unwrap(words)
        if not exposed:
            continue
        name = Path(exposed[0]).name
        # Includes the v1.4 executable-path miss, and redirects of every fd.
        if re.match(r"^/dev/(?:tcp|udp)/", exposed[0]):
            return True
        for i, word in enumerate(words[:-1]):
            if re.fullmatch(r"(?:[<>]+&?|&>>?)", word) and re.match(r"^/dev/(?:tcp|udp)/", words[i + 1]):
                return True
        if name in {"nc", "ncat", "netcat"} and any(re.match(r"^-[ec](?:$|=|/)", w) or w in {"--exec", "--sh-exec"} or w.startswith(("--exec=", "--sh-exec=")) for w in exposed[1:]):
            return True
        if name == "socat" and any(re.match(r"(?:exec|system):", w, re.I) for w in exposed[1:]):
            return True
        # Preserve other pre-existing remote-shell indicators.
        if pattern.search(" ".join(words)):
            return True
    return False


def matches_persistence(command: str | None, tool: str, args: dict, cwd: Path, path_check=None) -> bool:
    hooks_root = configured_hooks_root(cwd) if path_check is None else None
    check = path_check or persistence_path
    if tool in {"Write", "Edit", "MultiEdit"}:
        path = args.get("file_path")
        return isinstance(path, str) and check(path, cwd, hooks_root)
    if command is None:
        return False
    active_cwd = cwd
    active_hooks = hooks_root
    for words in command_views(command):
        words = _unwrap(words)
        if not words:
            continue
        name = Path(words[0]).name
        if name == "cd" and len(words) == 2:
            active_cwd = (active_cwd / words[1]).resolve()
            active_hooks = configured_hooks_root(active_cwd) if path_check is None else None
            continue
        # Honor an explicit hooksPath setting in the same payload.
        joined = " ".join(words)
        setting = re.search(r"(?:-c\s+)?core\.hooksPath(?:=|\s+)([^\s]+)", joined)
        if name == "git" and setting:
            active_hooks = (active_cwd / setting[1]).resolve()
        for i, word in enumerate(words[:-1]):
            if re.fullmatch(r"(?:[<>]+&?|&>>?)", word) and ">" in word:
                if check(words[i + 1], active_cwd, active_hooks):
                    return True
        if path_check is None and name == "crontab" and not any(w in {"-l", "--list"} for w in words[1:]):
            return True
        if path_check is None and name == "systemctl" and "--user" in words and any(w in {"enable", "link", "edit", "add-wants", "add-requires"} for w in words):
            return True
        if name == "sed" and not any(w == "--in-place" or w.startswith("--in-place=") or w.startswith("-i") for w in words[1:]):
            continue
        if name == "perl" and not any(w.startswith("-") and "i" in w for w in words[1:]):
            continue
        if name not in MUTATORS:
            continue
        plain = []
        i = 1
        while i < len(words):
            if re.fullmatch(r"(?:[<>]+&?|&>>?)", words[i]):
                if plain and plain[-1].isdigit():
                    plain.pop()  # file descriptor before a redirection
                i += 2
                continue
            plain.append(words[i])
            i += 1
        operands = [w for w in plain if not w.startswith("-")]
        if name in {"cp", "mv", "ln", "install"}:
            targets = operands if name in {"mv", "ln"} else operands[-1:]
            for i, word in enumerate(words[1:], 1):
                if word in {"-t", "--target-directory"} and i + 1 < len(words):
                    targets.append(words[i + 1])
                if word.startswith("--target-directory="):
                    targets.append(word.partition("=")[2])
        else:
            targets = operands
        if any(check(p, active_cwd, active_hooks) for p in targets):
            return True
    return False


def matches_self_protection(command, tool, args, cwd, protected):
    """Deny mutations of gate configuration and evidence paths."""
    roots = tuple((cwd / path).resolve() for path in protected)
    def check(raw, active_cwd, unused):
        path = Path(_expand(raw, {"HOME": os.environ.get("HOME", "/home/user")}))
        lexical = Path(os.path.abspath(active_cwd / path))
        for candidate in (lexical, lexical.resolve()):
            if any(candidate == root or root in candidate.parents or candidate in root.parents for root in roots):
                return True
            if candidate.name == ".claude" or (candidate.parent.name == ".claude" and candidate.name.startswith("settings")):
                return True
        return False
    return matches_persistence(command, tool, args, cwd, path_check=check)
