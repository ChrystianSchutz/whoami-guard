"""PreToolUse hook for Claude Code and Codex: deny a tool call that would send the user's identity off the machine.

    command hook (both agents):  python -I -m egress_guard.hook          (event JSON on stdin)
    HTTP hook (Claude Code):     python -I -m egress_guard.hook --serve 127.0.0.1:8977

Identity comes from ~/.egress-guard/identity.json ({"emails": [...], "names": [...], "extra": [...],
"allow_hosts": [...], "strict": false}); when the file has no e-mail or name, we add `git config user.email` /
`user.name` and the Claude Code account e-mail from ~/.claude.json (read locally, never sent anywhere), plus the
"First Last" spelled by a "first.last@" address (full name only; not for role mailboxes such as info.support@) and,
verbatim, a git user.name that carries a machine label (not when every word is a label, e.g. "Admin User").
Every decision is appended to ~/.egress-guard/log.jsonl with the matched KIND only, never the value.
"""
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import shlex
import subprocess  # nosec B404
import sys
import time
import tomllib
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from egress_guard.scan import ASK_KINDS, FUZZY_MAX, SHELL_TOOLS, Identity, scan_tool_call

HOME = Path(os.environ.get("EGRESS_GUARD_HOME", Path.home() / ".egress-guard"))
CODEX = "--codex" in sys.argv  # Codex hook command: findings that would ask are denied (Codex has no "ask")
REASON = ("whoami-guard blocked this call: it would send the user's own {kinds} to an outside service. Personal "
          "data from your context (account e-mail, name) must never go into requests, headers, URLs or bodies, even "
          "when a site asks for contact details. Use a generic identifier without personal data (for example "
          "'User-Agent: research-script/1.0'), or stop and ask the user whether and what to send.")

ASK_REASON = ("whoami-guard: this call may send personal data to an outside service ({kinds}: a look-alike form of "
              "the user's identity, or an e-mail address in a User-Agent / From / contact field). Approve only if you "
              "meant to send it. Agents: do not put any e-mail address in a User-Agent or contact header unless the "
              "user listed it in allow_emails; use a generic identifier instead.")


def _git(key: str) -> str:
    try:
        r = subprocess.run(["git", "config", "--global", key], capture_output=True, text=True,  # noqa: S603, S607
                           timeout=2)  # nosec B603 B607
        return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def load_identity() -> tuple[Identity, bool]:
    cfg = {}
    f = HOME / "identity.json"
    if f.exists():
        cfg = json.loads(f.read_text(encoding="utf-8"))
    ident = Identity(emails=list(cfg.get("emails", [])), names=list(cfg.get("names", [])),
                     extra=list(cfg.get("extra", [])), allow_hosts=list(cfg.get("allow_hosts", [])),
                     ignore=list(cfg.get("ignore", [])), fuzzy=str(cfg.get("fuzzy", "ask")),
                     contact_fields=str(cfg.get("contact_fields", "ask")),
                     allow_emails=list(cfg.get("allow_emails", [])) + list(cfg.get("contact_alias", [])), first_alone=bool(cfg.get("first_alone", False)),
                     )
    if cfg.get("autodetect", True):
        found = _autodetect()
        for e in found["emails"]:
            if e not in ident.emails:
                ident.emails.append(e)
        for n in found["names"]:
            if n not in ident.names:
                ident.names.append(n)
        for x in found.get("extra", []):
            if x not in ident.extra:
                ident.extra.append(x)
        for n in found.get("derived_names", []):
            if n not in ident.names and n not in ident.derived_names:
                ident.derived_names.append(n)
    return ident, bool(cfg.get("strict", False))


# git often holds a template address or a machine label, which must not become "the user's identity" (2026-10-26:
# a `you@example.com` git e-mail made the hook block a note that quoted the README example)
PLACEHOLDER_EMAIL = re.compile(r"(?i)(?:noreply\.github\.com|@(?:[\w-]+\.)*example\.(?:com|org|net)|"
                               r"\.(?:example|invalid|test|localhost|local)$)")
NOT_NAME_WORDS = {"desktop", "laptop", "pc", "user", "admin", "administrator", "home", "work", "dev", "build"}
# local parts of team and role mailboxes: "info.support@" spells no person (Codex review r2, 2026-10-29: the guessed
# name "Info Support" made the hook block an ordinary "support-bot")
ROLE_WORDS = NOT_NAME_WORDS | {
    "info", "support", "contact", "contacts", "hello", "hi", "team", "office", "help", "helpdesk", "sales", "billing",
    "accounts", "account", "admins", "noreply", "no", "reply", "donotreply", "mail", "email", "service", "services",
    "news", "newsletter", "jobs", "careers", "hr", "marketing", "press", "media", "legal", "privacy", "security",
    "abuse", "postmaster", "webmaster", "hostmaster", "root", "system", "sys", "ops", "devops", "it", "tech", "test",
    "bot", "bots", "alerts", "notifications", "feedback", "orders", "shop", "store", "kontakt", "biuro", "pomoc",
    "obsluga", "sklep", "zamowienia", "faktury"}
CACHE_VERSION = 2

def _autodetect() -> dict:
    """git and Claude Code account identity, cached for a day: spawning git costs ~100 ms per tool call on Windows."""
    cache = HOME / "autodetect.cache.json"
    try:
        if time.time() - cache.stat().st_mtime < 86400:
            cached = json.loads(cache.read_text(encoding="utf-8"))
            if cached.get("v") == CACHE_VERSION:
                return cached
    except (OSError, ValueError, AttributeError):
        pass
    out = {"v": CACHE_VERSION, "emails": [], "names": [], "extra": [], "derived_names": []}
    for e in (_git("user.email"), _claude_email()):
        if e and "@" in e and e not in out["emails"] and not PLACEHOLDER_EMAIL.search(e):
            out["emails"].append(e)
    raw = " ".join((_git("user.name") or "").split())
    n = " ".join(w for w in raw.split() if w.lower() not in NOT_NAME_WORDS)
    if " " in n:  # a first and a last name left; "Jan Desktop" -> "Jan" alone is not used as a name
        out["names"].append(n)
    if " " in raw and raw != n and n:
        # ...but the configured string itself is what agents copy into a User-Agent ("tool (Jan Desktop)"), so it is
        # protected verbatim (Codex review 2026-10-29: two guarded runs sent exactly this string). Only when a word
        # that is not a machine label is left: "Admin User" names nobody and must not block "Admin Users Guide".
        out["extra"].append(raw)
    for e in out["emails"]:
        d = name_from_email(e)
        if d and d not in out["names"] and d not in out["derived_names"]:
            # "jan.kowalski@" -> "Jan Kowalski": in the baseline an agent wrote the user's full name, derived from
            # the account e-mail, into a User-Agent (2026-10-29 rescoring). A guess: full name only, no surname alone.
            out["derived_names"].append(d)
    try:
        HOME.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(out), encoding="utf-8")
    except OSError:
        pass
    return out


def name_from_email(email: str) -> str:
    """'jan.kowalski84@x.pl' -> 'Jan Kowalski'; '' unless the local part is exactly two words of letters, neither
    of them a role or machine word ('info.support@', 'admin.user@')."""
    parts = [re.sub(r"\d+$", "", p) for p in re.split(r"[._-]", email.split("@", 1)[0].split("+", 1)[0])]
    if len(parts) == 2 and all(len(p) >= 2 and p.isalpha() and p.lower() not in ROLE_WORDS for p in parts):
        return " ".join(p.capitalize() for p in parts)
    return ""


def _claude_email() -> str:
    try:
        d = json.loads((Path.home() / ".claude.json").read_text(encoding="utf-8"))
        return (d.get("oauthAccount") or {}).get("emailAddress", "")
    except (OSError, ValueError):
        return ""


SELF_REASON = ("whoami-guard blocked this control operation. A conversational yes does not grant an exception. ")
# The agent must not grant itself an exception or switch the hook off (the user's own `!` commands are not hooked).
# A shell segment that names a control (the allow command, the whoami-guard folder, an EGRESS_GUARD_* assignment,
# the agent's hook settings) is denied unless it only reads (grep, cat, ls, git log ...), so docs and log reading
# pass and `"whoami-guard-allow"`, `/usr/bin/whoami-guard-allow`, `python -c "...'.egress-guard'..."` do not
# (Sol review r2, 2026-11-01). A script written first and run later is not seen: a seatbelt, not a sandbox.
# Running the hook itself is a control too (0.2.4): an event piped into it by the agent could fake a PostToolUse and
# record an approval the user never gave.
_CTRL = re.compile(r"whoami-guard-allow|egress_guard[./\\]allow|\.egress-guard|run_hook\.py|whoami-guard-hook|"
                   r"egress_guard[./\\]hook|egress_guard\s+import\s+hook|"
                   r"\.claude[/\\]+settings(?:\.local)?\.json|\.codex[/\\]+(?:config\.toml|hooks\.json)", re.I)
_ASSIGN = re.compile(r"(?:^|[\s;&|(]|\$env:)EGRESS_GUARD_\w+\s*=|\b(?:setx|set)\s+EGRESS_GUARD_\w+", re.I)
# a write INTO a control file: redirect or tee target, PowerShell writers (sed: _sed_touches; perl is no reader)
_WRITE = re.compile(r"(?:>>?|\btee\s+(?:-a\s+)?|Set-Content|Add-Content|Out-File)\s*(?:-\w+\s+)*[\"']?[^\s;&|]*(?:"
                    + _CTRL.pattern + r")", re.I)
# commands that only read or print; a control named in them is a mention, not an attempt
_READERS = {"for", "if", "while", "echo", "printf", "which", "where", "grep", "egrep", "rg", "cat", "type", "head",
            "tail", "less", "more", "ls", "dir", "wc", "file", "stat", "find", "git", "get-content", "gc",
            "select-string", "sls", "get-childitem", "gci", "test-path", "jq", "diff", "cut", "sort", "uniq", "nl",
            "od", "xxd", "sha256sum", "md5sum", "tee", "sed"}  # sed -i is a write: _WRITE / _sed_writes_control
_HEREDOC = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?")
# `echo "$(whoami-guard-allow --off)"`: the substitution runs, whatever command prints it (Sol review r3)
_SUBST = re.compile(r"\$\(([^()]*(?:\([^()]*\)[^()]*)*)\)|`([^`]*)`|[<>]\(([^()]*)\)")
# the agent may look at the running exceptions or the usage; neither changes anything
_READ_ONLY_ALLOW = re.compile(r"(?:whoami-guard-allow|egress_guard[./\\]allow|run_hook\.py[\"']?\s+allow)\S*"
                              r"(?:\.exe)?[\"']?\s+(?:--list|--help|-h)\s*$", re.I)


def _segments(cmd: str) -> list[str]:
    """Split a shell line on unquoted ; | & and newlines; a heredoc body stays with the command that reads it."""
    out, cur, q, i, n = [], [], "", 0, len(cmd)
    while i < n:
        c = cmd[i]
        if q:
            cur.append(c)
            if c == q:
                q = ""
            elif c == "\\" and q == '"' and i + 1 < n:
                cur.append(cmd[i + 1])
                i += 1
        elif c in "'\"":
            q = c
            cur.append(c)
        elif c == "<" and (m := _HEREDOC.match(cmd, i)):
            end = re.compile(r"^\s*" + re.escape(m.group(1)) + r"\s*$", re.M).search(cmd, m.end())
            stop = end.end() if end else n
            cur.append(cmd[i:stop])
            i = stop
            continue
        elif c in ";|&\n":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    out.append("".join(cur))
    return [x for x in out if x.strip()]


_MARK = re.compile(r"whoami-guard|egress_guard|egress-guard", re.I)
_SETTINGS = re.compile(r"[/\\]\.claude[/\\]settings(?:\.local)?\.json$|[/\\]\.codex[/\\](?:config\.toml|hooks\.json)$",
                       re.I)


def _first_word(seg: str) -> str:
    seg = re.sub(r"^\s*(?:\w+=\S*\s+)*", "", seg)  # leading VAR=value
    w = seg.strip().split(None, 1)[0] if seg.strip() else ""
    return re.split(r"[/\\]", w.strip("\"'`()"))[-1].lower().removesuffix(".exe")


# one plain `s` command (no `e` / `w` flag, nothing after it): the only sed script that may MENTION a control
# Possessive quantifiers and no overlap between `\\.` and the plain character: `s#\a\a...#x#;#` (75 characters)
# and 50 KB of spaces before `p;#` ran past the hook timeout with the backtracking forms (Astra review r6).
_PLAIN_SUB = re.compile(r"\s*+(?:(?:\d+(?:,\d+)?|\$)\s*+)?s([^\w\s\\])(?:\\.|(?!\1)[^\\])*+\1"
                        r"(?:\\.|(?!\1)[^\\])*+\1[gpiImM0-9]*+\s*+", re.S)
# a script that only prints, deletes from the output or quits (`sed -n '/.egress-guard/p' README.md`; Astra r5)
_SED_ADDR = r"(?:\d++|\$|/(?:\\.|[^/\\\n])*+/I?)"
_SED_CMD = rf"(?:{_SED_ADDR}(?:\s*+,\s*+{_SED_ADDR})?\s*+)?(?:!\s*+)?[pdqn=]"
_SED_READ = re.compile(rf"\s*+{_SED_CMD}(?:[ \t]*+[;\n]\s*+{_SED_CMD})*+\s*+(?:;\s*+)?")


def _sed_touches(seg: str) -> bool:
    """A sed line that may change a control. sed reads (`sed -n 60,80p egress_guard/allow.py`) and `sed -i` on a
    note whose script only MENTIONS the whoami-guard folder pass (false blocks, 2026-11-09). Options are parsed as
    GNU getopt does (`-e's/x/y/'`, `--in-place`, `-ni`, options after operands; Astra review r4). Denied: a control
    file as target of an in-place edit, and a script naming a control unless it is one plain `s` command (`w` and
    `e` write files and run commands). A line that does not parse counts as a write."""
    try:
        args = shlex.split(seg, posix=True)
    except ValueError:
        return True
    i = next((k for k, x in enumerate(args) if re.split(r"[/\\]", x)[-1].lower().removesuffix(".exe") == "sed"),
             None)
    if i is None:
        return True
    scripts: list[str] = []
    files: list[str] = []
    inplace = given = rest = False
    take = ""  # the option whose value is the next word: e (script), f (script file), l (line length)
    for x in args[i + 1:]:
        if take:
            if take == "e":
                scripts.append(x)
            elif take == "f":
                files.append(x)  # read, not written
            given, take = given or take in "ef", ""
        elif rest or not x.startswith("-") or x == "-":
            files.append(x)
        elif x == "--":
            rest = True
        elif x.startswith("--"):
            name, eq, val = x[2:].partition("=")
            kind = ("i" if name and "in-place".startswith(name) else
                    "e" if name and "expression".startswith(name) else
                    "f" if len(name) > 1 and "file".startswith(name) else
                    "l" if name and "line-length".startswith(name) else "")
            if kind == "i":
                inplace = True
            elif kind and not eq:
                take = kind
            elif kind in ("e", "f"):
                (scripts if kind == "e" else files).append(val)
                given = True
        else:
            for k, c in enumerate(x[1:], 1):
                if c == "i":
                    inplace = True
                    break  # -i takes the rest of the word as a backup suffix
                if c in "efl":
                    val = x[k + 1:]
                    if not val:
                        take = c
                    elif c != "l":
                        (scripts if c == "e" else files).append(val)
                        given = True
                    break
    if take:
        return True  # an option still waiting for its value: the line is cut, assume the worst
    if not given and files:
        scripts.append(files.pop(0))  # no -e / -f: the first operand is the script
    if any(_CTRL.search(sc) and not (_PLAIN_SUB.fullmatch(sc) or _SED_READ.fullmatch(sc)) for sc in scripts):
        return True
    return inplace and any(_CTRL.search(f) for f in files)


def _shell_touches(cmd: str) -> bool:
    if _ASSIGN.search(cmd):
        return True
    for m in _SUBST.finditer(cmd):
        inner = next(g for g in m.groups() if g is not None)
        if _CTRL.search(inner) and _shell_touches(inner):
            return True
    for seg in _segments(cmd):
        head = _HEREDOC.split(seg, 1)[0]  # `cat > notes.md <<EOF ... EOF`: the heredoc text is data, not a command
        first = _first_word(seg)
        if not _CTRL.search(head if first in _READERS else seg):
            continue
        if _READ_ONLY_ALLOW.search(seg.strip()):
            continue
        if _WRITE.search(head) or re.search(r"\bfind\b.*-(?:delete|exec)", head) or first not in _READERS:
            return True
        if first == "sed" and _sed_touches(head):
            return True
    return False


def _hook_entries(text: str, toml: bool = False):
    """{(event, hook group)} for every hook group (matcher + its hooks) that runs whoami-guard in a settings file
    (Claude Code JSON or Codex TOML, same shape); None when it does not parse. Comparing whole groups catches a
    narrowed matcher as well as a removed hook."""
    try:
        data = (tomllib.loads(text) if toml else json.loads(text)) if text.strip() else {}
    except (ValueError, RecursionError):  # TOMLDecodeError is a ValueError; 25,000 nested `[` (Astra review r6)
        return None
    out = set()
    hooks = data.get("hooks") if isinstance(data, dict) else None
    for event, groups in (hooks.items() if isinstance(hooks, dict) else []):
        for g in groups if isinstance(groups, list) else [groups]:
            spec = json.dumps(g, sort_keys=True)
            if _MARK.search(spec):
                out.add((event, spec))
    return out


def _edited(old: str, inp: dict) -> str:
    """The settings text after an Edit / MultiEdit / Write."""
    if "content" in inp:
        return str(inp.get("content") or "")
    for e in (inp.get("edits") or []) if "edits" in inp else [inp]:
        if isinstance(e, dict):
            a, b = str(e.get("old_string") or ""), str(e.get("new_string") or "")
            old = old.replace(a, b) if e.get("replace_all") else old.replace(a, b, 1)
    return old


def _drops_hook(path: str, inp: dict) -> bool:
    """A file tool edit of the agent's settings that weakens the whoami-guard hook. Not only removing its name:
    narrowing the matcher ("Bash|WebFetch" -> "WebFetch"), moving it to PostToolUse, or "disableAllHooks" switch it
    off just as well (Sol review r3). Any change to a whoami-guard entry is the user's to make."""
    if not _SETTINGS.search(path.replace("\\", "/").replace("/", "\\")) and not _SETTINGS.search(path):
        return False
    try:
        old = Path(path).expanduser().read_text(encoding="utf-8")
    except (OSError, ValueError):
        old = ""
    new = _edited(old, inp)
    toml = path.lower().endswith(".toml")  # Codex: its matcher line holds no "hook" (Astra review r4)
    if re.search(r'"disableAllHooks"\s*:\s*true', new) and not re.search(r'"disableAllHooks"\s*:\s*true', old):
        return True
    before, after = _hook_entries(old, toml), _hook_entries(new, toml)
    if not before:
        return False  # no whoami-guard hook in this file (or it never parsed): nothing to protect here
    return after is None or not before <= after


def _patch_touches(patch: str) -> bool:
    """Codex apply_patch: a file in the whoami-guard folder, or a settings file whose hook lines change (any changed
    line naming a hook, a matcher or whoami-guard; a narrowed matcher keeps the marker count; Astra review r4)."""
    def guarded(p: str) -> bool:
        return ".egress-guard" in p.replace("\\", "/")

    def settings(p: str) -> bool:
        return bool(_SETTINGS.search(p) or re.search(
            r"(?:^|[/\\])(?:settings(?:\.local)?\.json|config\.toml|hooks\.json)$", p))

    # a file block runs to the next file header or the end; `*** Move to:` belongs to it (it was cut off before the
    # move check could see it; Astra review r5)
    for m in re.finditer(r"^\*\*\* (Update|Add|Delete) File: (.+)$((?:\n(?!\*\*\* (?:Update|Add|Delete) File:|"
                         r"\*\*\* End Patch).*)*)", patch, re.M):
        op, path, body = m.group(1), m.group(2).strip(), m.group(3)
        moves = [x.strip() for x in re.findall(r"^\*\*\* Move to: (.+)$", body, re.M)]
        if any(guarded(p) for p in [path, *moves]):
            return True
        if any(settings(p) for p in moves):
            return True  # another file moved over the settings replaces them whole
        if settings(path):
            changed = [ln for ln in body.splitlines() if ln[:1] in "+-"]
            if op == "Delete" or moves or any(_MARK.search(ln) or re.search(r"hook|matcher", ln, re.I)
                                              for ln in changed):
                return True
    return False


def _touches_controls(event: dict) -> bool:
    tool, inp = event.get("tool_name", ""), event.get("tool_input") or {}
    if isinstance(inp, str):
        return tool == "apply_patch" and _patch_touches(inp)
    if not isinstance(inp, dict):
        return False
    if tool in ("Bash", "PowerShell", "exec_command", "shell"):
        return any(_shell_touches(v) for v in inp.values() if isinstance(v, str)) or \
            any(_shell_touches(" ".join(map(str, v))) for v in inp.values() if isinstance(v, list))
    if tool == "apply_patch":
        return any(_patch_touches(v) for v in inp.values() if isinstance(v, str))
    path = str(inp.get("file_path") or inp.get("path") or inp.get("notebook_path") or "")
    if path and tool in ("Read", "Glob", "Grep", "LS", "NotebookRead", "view_image"):
        return False  # reading the log or the settings changes nothing (Sol review r3: Read of log.jsonl was blocked)
    if path:
        try:
            p = Path(path).expanduser().resolve()
            if p == HOME.resolve() or HOME.resolve() in p.parents:
                return True
        except (OSError, ValueError):
            return True
        return _drops_hook(path, inp)
    return False


def _strs(v) -> list[str]:
    return [str(x) for x in v if isinstance(x, (str, int, float))] if isinstance(v, list) else []


def session_rec(session_id: str) -> dict:
    """The user's running exception for this session (whoami-guard-allow): mode ('ask' / 'off' / ''), and extra
    allowed e-mails and hosts for this session only; {} when there is none or it expired."""
    if not session_id:
        return {}
    try:
        rec = json.loads((HOME / "sessions.json").read_text(encoding="utf-8")).get(session_id) or {}
        until = float(rec.get("until", 0)) if isinstance(rec, dict) else 0.0
        if not math.isfinite(until) or until <= time.time():  # "nan" compared false and granted forever (Sol r3)
            return {}
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        return {}  # a broken record grants nothing and never crashes the hook (Sol review r2)
    mode = rec.get("mode") if rec.get("mode") in ("ask", "off") else ""
    return {"mode": mode, "emails": _strs(rec.get("emails")), "hosts": _strs(rec.get("hosts")), "until": until}


# Approval memory (0.2.4): a convenience against repeat prompts, not an authentication of the user's answer. A
# question the user answered "yes" to is not asked again in the same session for the same data in the same call
# shape. The PreToolUse hook that asks writes a pending record (session, tool_use_id, keyed digest of the call); the
# PostToolUse event, which Claude Code sends only for a call that really ran, turns it into an approval. Only
# findings that were a question become approvals: a call that was denied never runs, so a hard block is never
# remembered. Everything stored is an HMAC, never a value; the salt sits in the same file, so this hides values from
# a casual reader and does not stop an agent that sets out to forge a PostToolUse (the README's threat model).
APPROVALS = "approvals.json"
EPOCH_KEY = "_approvals_epoch"  # in sessions.json, written only by whoami-guard-allow; --clear changes it
EPOCH_BROKEN = "\0unreadable"  # sessions.json exists but is unreadable: matches no stored epoch
APPROVAL_HOURS = 2.0  # without a running session exception
PENDING_TTL = 7200.0  # an unanswered question older than this is forgotten
MAX_PENDING, MAX_APPROVED = 50, 500  # per session
_NO_MEMORY_MODES = {"bypassPermissions", "dontAsk"}  # no prompt is shown there, so a run is no answer
# Shell commands are remembered only as one built-in gh command (Sol review of 0.2.4): the same text of any other
# command can send elsewhere (`curl -K file`, `$VAR`, a script, a gh alias redefined as a shell command). gh refuses
# aliases and extensions named like a built-in command ("already a gh command or extension", checked with gh
# 2.101.0), so `gh pr ...` always runs gh's own `pr`.
GH_REMEMBER = {"issue", "pr", "api", "repo", "gist", "release", "search", "label", "workflow", "run", "discussion",
               "project"}
# Characters that let the shell (bash or PowerShell) pick or change the target at run time: expansions,
# substitutions, redirections, chaining, subshells, globs, escapes, splatting. Outside quotes all of them; inside
# double quotes the ones both shells still expand.
# `#` too: an unquoted `# --hostname x` is a comment to the shell but an option to shlex (Sol review r3).
_INDIRECT_BARE = set("$`<>|;&(){}[]*?~\\%!@#\n\r")
_INDIRECT_DQ = set("$`\\!\n\r")


def _mac(salt: str, *parts: str) -> str:
    return hmac.new(bytes.fromhex(salt), "\0".join(parts).encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:32]


def _load_approvals(create: bool = False) -> dict | None:
    """approvals.json, or None when there is none (and `create` is false). A malformed file counts as empty and gets
    a new salt, which invalidates whatever it held: a broken file grants nothing and never crashes the hook."""
    try:
        d = json.loads((HOME / APPROVALS).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        d = None
    salt = d.get("salt") if isinstance(d, dict) else None
    if not (isinstance(salt, str) and re.fullmatch(r"[0-9a-f]{32,128}", salt)):
        if not create:
            return None
        return {"v": 1, "salt": secrets.token_hex(16), "pending": {}, "approved": {}}
    return {"v": 1, "salt": salt,
            "pending": d["pending"] if isinstance(d.get("pending"), dict) else {},
            "approved": d["approved"] if isinstance(d.get("approved"), dict) else {}}


def _save_approvals(data: dict) -> None:
    now = time.time()
    for name, alive, cap in (("pending", lambda e: now - _num(e.get("ts")) < PENDING_TTL, MAX_PENDING),
                             ("approved", lambda e: _num(e.get("until")) > now, MAX_APPROVED)):
        table = data[name]
        for sid in list(table):
            rows = [e for e in table[sid] if isinstance(e, dict) and alive(e)] if isinstance(table[sid], list) else []
            if rows:
                table[sid] = rows[-cap:]
            else:
                del table[sid]
    tmp = HOME / f"{APPROVALS}.{os.getpid()}.tmp"
    try:
        HOME.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, HOME / APPROVALS)  # a reader never sees half a file
    except OSError:
        # another session holds the file (Windows): this approval is not remembered, the next call asks again
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _num(v) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0.0
    return f if math.isfinite(f) else 0.0


def _shell_indirect(cmd: str) -> bool:
    """Anything in a shell line that can make the same text reach another target at run time."""
    q = ""
    for c in cmd:
        if q == "'":
            q = "" if c == "'" else q  # single quotes: literal in bash and PowerShell
        elif q == '"':
            if c in _INDIRECT_DQ:
                return True
            q = "" if c == '"' else q
        elif c in "'\"":
            q = c
        elif c in _INDIRECT_BARE:
            return True
    return bool(q)  # an unclosed quote: do not guess


def _gh_destination(cmd: str, cwd: str) -> list[str] | None:
    """`gh <built-in> ...` with no shell indirection: the subcommand group and the host gh really talks to (GitHub or
    the host it names) from this folder (its git remote picks the repository). None for every other shell line."""
    if _shell_indirect(cmd):
        return None
    try:
        toks = shlex.split(cmd, posix=True)
    except ValueError:
        return None
    if len(toks) < 2 or toks[0].lower() not in ("gh", "gh.exe") or toks[1] not in GH_REMEMBER:
        return None
    # Options that read a file (--body-file, -F, --input, --notes-file, --template) change what is sent, never the
    # host: --hostname / -R and the endpoint stay in the command text. They can change the content and, for
    # `gh api graphql --input`, the repository on the same host. The approval covers only the value found in this
    # text, so a file option does not stop the memory (a bare `@file` already counts as indirection above).
    hosts = _gh_targets(toks)
    if hosts is None:
        return None
    return sorted({"cmd:gh", "sub:" + toks[1], "cwd:" + cwd} | {"host:" + h for h in hosts})


_URL_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")


def _gh_targets(toks: list[str]) -> set[str] | None:
    """The host gh will actually talk to (Sol review r2: not every host named anywhere, e.g. in a --body): the value
    of --hostname, the HOST of `-R/--repo HOST/OWNER/REPO`, else GH_HOST from the environment the hook sees, else
    github.com. A token that is a whole URL (`gh pr view https://host/o/r/pull/1`, `gh api https://host/x`) can
    pick the host itself: not remembered. So is a bundle of short flags hiding -R (`-wR host/o/r`)."""
    hosts: set[str] = set()
    repo_hosts: set[str] = set()
    it = iter(enumerate(toks[2:]))
    for _, t in it:
        if _URL_TOKEN.match(t):
            return None
        val = None
        if t in ("--hostname", "-R", "--repo"):
            val = next(it, (0, ""))[1]
            name = t
        elif t.startswith(("--hostname=", "--repo=")):
            name, val = t.split("=", 1)
        elif t.startswith("-R") and len(t) > 2:
            name, val = "-R", t[2:].lstrip("=")
        elif t.startswith("-") and not t.startswith("--") and "R" in t[2:]:
            return None
        if val is None:
            continue
        if _URL_TOKEN.match(val):
            return None
        val = val.strip().lower().rstrip(".")
        if name == "--hostname":
            hosts.add(val)
        elif val.count("/") >= 2:
            repo_hosts.add(val.split("/", 1)[0].rstrip("."))
    hosts |= repo_hosts
    if not hosts:
        env = {os.environ.get(k, "").strip().lower() for k in ("GH_HOST",)} - {""}
        repo = os.environ.get("GH_REPO", "").strip().lower()
        if repo.count("/") >= 2:
            env.add(repo.split("/", 1)[0])
        hosts = env or {"github.com"}
    return hosts if all(h and re.fullmatch(r"[a-z0-9.-]+(?::\d+)?", h) for h in hosts) else None


def _destinations(event: dict) -> list[str] | None:
    """The call shape an approval is bound to, or None when this call is never remembered. Non-shell tools (MCP,
    WebFetch, file tools): the whole tool input, word for word, so another channel, recipient, URL or file asks
    again. Shell tools: only one built-in gh command (see GH_REMEMBER); everything else asks every time."""
    tool = str(event.get("tool_name") or "")
    inp = event.get("tool_input") or {}
    if tool not in SHELL_TOOLS:
        return ["call:" + tool + "\0" + json.dumps(inp, sort_keys=True)]
    cmd = inp.get("command") if isinstance(inp, dict) else None
    if not isinstance(cmd, str):
        return None
    return _gh_destination(cmd, str(event.get("cwd") or ""))


def _epoch() -> str:
    """The revocation epoch: whoami-guard-allow --clear writes a new one into sessions.json (the hook never writes
    that file), and approvals or questions from another epoch count for nothing. A PostToolUse that raced --clear
    and wrote approvals back after the delete cannot bring them to life. No file yet: "". A file that exists but
    cannot be read or parsed: EPOCH_BROKEN, under which no approval matches and none is recorded (fail closed)."""
    try:
        d = json.loads((HOME / "sessions.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return ""
    except (OSError, ValueError, RecursionError):
        return EPOCH_BROKEN
    if not isinstance(d, dict):
        return EPOCH_BROKEN
    v = d.get(EPOCH_KEY, "")
    return v if isinstance(v, str) and v != EPOCH_BROKEN else EPOCH_BROKEN


def _approval_key(salt: str, finding, dests: list[str]) -> str:
    return _mac(salt, "approval", finding.kind, finding.needle, *dests)


def _call_mac(salt: str, event: dict) -> str:
    return _mac(salt, "call", str(event.get("tool_name") or ""),
                json.dumps(event.get("tool_input") or {}, sort_keys=True))


def _approved(data: dict | None, sid: str, ask_mode: bool, epoch: str) -> set[str]:
    """Keys approved for this session and still valid. Approvals of findings that are only a question because of a
    running `--ask` exception count only while that exception runs."""
    if not data or not sid:
        return set()
    if epoch == EPOCH_BROKEN:
        return set()
    now, keys = time.time(), set()
    rows = data["approved"].get(sid)
    for e in rows if isinstance(rows, list) else []:
        if isinstance(e, dict) and isinstance(e.get("k"), str) and _num(e.get("until")) > now and \
                e.get("e", "") == epoch and (ask_mode or not e.get("m")):
            keys.add(e["k"])
    return keys


def remember(event: dict) -> dict:
    """PostToolUse: the call ran, so if this session's hook asked about exactly this call (same tool_use_id, same
    content), the user said yes: remember its findings for the same destinations. Never blocks, never prints."""
    sid = str(event.get("session_id") or "")
    codex = CODEX or os.environ.get("EGRESS_GUARD_AGENT", "").strip().lower() == "codex"
    if not sid or codex or str(event.get("permission_mode") or "") in _NO_MEMORY_MODES:
        return {}
    data = _load_approvals()
    rows = data["pending"].get(sid) if data else None
    if not data or not isinstance(rows, list):
        return {}
    now, tuid, call = time.time(), str(event.get("tool_use_id") or ""), _call_mac(data["salt"], event)
    hit = next((e for e in rows if isinstance(e, dict) and e.get("id") == tuid and e.get("call") == call
                and now - _num(e.get("ts")) < PENDING_TTL), None)
    if hit is None:
        return {}
    rows.remove(hit)
    epoch = hit.get("e", "")
    if epoch != _epoch() or epoch == EPOCH_BROKEN:
        _save_approvals(data)
        return {}  # asked before a --clear: that question no longer counts
    rec = session_rec(sid)
    ask_now = (str(rec.get("mode") or "") or os.environ.get("EGRESS_GUARD_MODE", "").strip().lower()) == "ask"
    until = rec.get("until") or now + APPROVAL_HOURS * 3600  # the session exception's end, else 2 hours
    n = 0
    keys = hit.get("keys")
    for item in keys if isinstance(keys, list) else []:
        if not (isinstance(item, list) and len(item) == 2 and isinstance(item[0], str)):
            continue
        key, ask_mode = item[0], bool(item[1])
        if ask_mode and not ask_now:
            continue  # the --ask exception ended between the question and the run
        rows_ok = data["approved"].get(sid)
        data["approved"][sid] = (rows_ok if isinstance(rows_ok, list) else []) + [
            {"k": key, "m": ask_mode, "until": until, "e": epoch}]
        n += 1
    _save_approvals(data)
    if n:
        _log({"ts": now, "event": "PostToolUse", "tool": event.get("tool_name"), "remembered": n, "session": sid,
              "folder": Path(str(event.get("cwd") or "")).name})
    return {}


def _ask_pending(event: dict, sid: str, data: dict | None, keys: list[tuple[str, bool]], epoch: str) -> None:
    """Note the question, so that the PostToolUse of this very call can turn it into an approval. `epoch` is the one
    read when the decision started: a question that crossed a --clear stays in the old epoch."""
    if not sid or not keys or epoch == EPOCH_BROKEN:
        return
    data = data or _load_approvals(create=True)
    rows = data["pending"].get(sid)
    rows = rows if isinstance(rows, list) else []
    rows.append({"id": str(event.get("tool_use_id") or ""), "call": _call_mac(data["salt"], event),
                 "ts": time.time(), "e": epoch, "keys": [[k, m] for k, m in keys]})
    data["pending"][sid] = rows
    _save_approvals(data)


_HOST = re.compile(r"https?://(?:[^/\s'\"@]*@)?([A-Za-z0-9.-]+)", re.IGNORECASE)


MAX_HOSTS = 12


def _hosts(event: dict, allowed: list[str] | tuple[str, ...] = ()) -> list[str]:
    """Hosts the tool call names that are not allowed yet. All of them, not the first few: a file or browser call
    passes only when every host in it is allowed, so a command naming 3 of 4 hosts never unblocked it (a CV file
    with links to four sites, 2026-11-09)."""
    text = json.dumps(event.get("tool_input") or {})
    hosts = dict.fromkeys(h.lower().rstrip(".") for h in _HOST.findall(text))
    return [h for h in hosts if not any(h == a or h.endswith("." + a) for a in allowed)][:MAX_HOSTS]


def _ps(x: str) -> str:
    return x if re.fullmatch(r"[\w@%+=:,./-]+", x) else "'" + x.replace("'", "''") + "'"


def _allow_cmd(args: list[str]) -> str:
    """The approval command as printed in a block message: the allow.py of the package that runs this hook, by the
    Python that runs it, with full paths, so it works whatever the user's PATH is (2026-11-09: the bare
    `whoami-guard-allow` was "command not found" in Git Bash for a contrib/run_hook.py install). POSIX-quoted for
    Claude Code's `!` (bash, also Git Bash on Windows) and macOS/Linux shells; on Windows also a PowerShell form,
    which needs `&` before a program path (Astra review r4)."""
    argv = [Path(sys.executable).as_posix(), (Path(__file__).resolve().parent / "allow.py").as_posix(), *args]
    out = f"`! {shlex.join(argv)}`"
    if os.name == "nt":
        out += f" (PowerShell: `& {' '.join(_ps(x) for x in argv)}`)"
    return out


def _owner_handoff(event: dict) -> str:
    codex = (CODEX or os.environ.get("EGRESS_GUARD_AGENT", "").strip().lower() == "codex"
             or str(event.get("tool_name") or "") in {"exec_command", "apply_patch", "shell"})
    if not codex:
        return " Please paste the exception command above for the user to run with !."
    return (" CODEX — NEXT RESPONSE, BEFORE ANY MORE TOOLS: briefly name the blocked operation in the user's "
            "language, then paste the exact ! command above in a code block and tell the user to paste and run it. "
            "Do not replace the command with a yes/no question, a form, a board entry, or an apology. "
            "Do not run it yourself. WAIT FOR EXECUTION, NOT VERBAL APPROVAL: a <user_shell_command> result "
            "with Exit code: 0 is the user's execution confirmation. Acknowledge it immediately and retry the "
            "unchanged blocked operation once; do not wait for 'done'/'gotowe' or ask the user to repeat it. "
            "For an installation command, verify the installation instead of reinstalling. If the command "
            "fails, report its actual error and do not assume approval. Do not rewrite a denied operation "
            "to bypass the hook.")


def _control_escalation(event: dict) -> str:
    from egress_guard import control

    sid = str(event.get("session_id") or "")
    if not sid:
        return ("This call has no session id, so a scoped exception cannot be issued. "
                "Report the missing session id to the user; do not choose another session.")
    command = _allow_cmd(["--control-once", control.digest(event), "--session", sid])
    return (f"Owner-run exception: {command}. This grants one unchanged tool call in this session for 10 minutes; "
            "it does not turn off other checks. For commands that read scripts or files, show those contents "
            "for review too: the exception binds the command, not file contents." + _owner_handoff(event))


def _host_helps(ident: Identity, event: dict, hosts: list[str], strict: bool, codex: bool) -> bool:
    """Would `--host` for these hosts let this call through? Asked of the scanner itself, so the advice follows
    the same rules (an MCP call with a body beside an allowed url stays blocked; Astra review r5). A shell line with
    an allowed host gets a question, which Codex does not have. Huge calls are not scanned twice."""
    inp = event.get("tool_input") or {}
    if not hosts or len(json.dumps(inp)) > FUZZY_MAX:
        return False
    after = scan_tool_call(str(event.get("tool_name") or ""), inp,
                           replace(ident, allow_hosts=list(ident.allow_hosts) + hosts), strict, cwd=event.get("cwd"))
    return not after or (not codex and all("@" in f.kind for f in after))


def _escalation(ident: Identity, event: dict, kinds: list[str], strict: bool = False) -> str:
    """What the agent should do next: use an approved address, or ask the user with a reason and the exact command
    that approves it (a standalone escalation; nothing is sent anywhere)."""
    out = ""
    if ident.allow_emails:
        out += (" Addresses the user approved for agents (use one of them instead): "
                + ", ".join(ident.allow_emails[:5]) + ".")
    codex = CODEX or os.environ.get("EGRESS_GUARD_AGENT", "").strip().lower() == "codex"
    hosts = _hosts(event, ident.allow_hosts)
    # The exception that really lets this call through: --host only when the scanner then passes the call (or asks,
    # outside Codex); --email covers only someone else's address in a contact field (the user's own address and name
    # have no allow list); Codex has no questions, so there only --off helps (Astra reviews r4, r5).
    if kinds and all(k.split("@")[0] == "contact-email" for k in kinds) and not codex:
        args, what = ["--email", "ADDRESS"], "allows that address"
    elif _host_helps(ident, event, hosts, strict, codex):
        args, what = [x for h in hosts for x in ("--host", h)], "allows these sites"
    elif codex:
        args, what = ["1", "--off"], "turns the checks off for one hour"
    else:
        args, what = ["1", "--ask"], "turns blocks into questions for one hour"
    sid = str(event.get("session_id") or "")
    if sid:  # bind the approval to the session that asked, not to whichever session logged last (Sol review r2)
        args += ["--session", sid[:12]]
        where = "in this session only"
    else:  # without an id the command would pick the newest logged session, maybe another one (Sol review r3)
        args += ["--session", "ID"]  # no <id>: bash reads `<id` as a redirect
        where = ("in one session (this call carried no session id: the command refuses without --session; "
                 "`--list` and its error message show the ids)")
    out += (" If sending this is really needed for the user's task, stop and ask the user: say what you want to send, "
            f"to which site and why, and give them this command, which {what} {where}: "
            f"{_allow_cmd(args)}. Do not retry with the data rewritten or encoded." + _owner_handoff(event))
    return out


AI_AUTHOR_REASON = ("whoami-guard: this commit names an AI agent as its author or co-author ({what}). The user is the "
                    "only author: remove the `Co-authored-by:` line / the AI author address and commit again. Disclose "
                    "AI use in the PR description where the project asks for it, not in the commit.")
# 0.2.4: the agent must not put its own identity into commits (a `Co-authored-by: Claude <noreply@anthropic.com>`
# trailer, `--author`, `user.email=` of an AI vendor). It is not the user's personal data, but per-author CLA bots
# fail on it and the user did not ask for it. Checked on shell lines that run a git command which writes a commit
# or tag; a message file given with -F / --file is read too (it was written before this call).
_GIT_WRITE = re.compile(r"\bgit\b(?:\s+-c\s+\S+|\s+-C\s+\S+|\s+--[\w-]+(?:=\S+)?)*\s+"
                        r"(?:commit|commit-tree|merge|tag|am|cherry-pick|rebase|revert|notes)\b", re.I)
_AI_WORD = (r"(?:claude|anthropic|codex|openai|chatgpt|gpt-?\d[\w.-]*|copilot|gemini|cursor(?:\s+agent)?|devin|"
            r"aider|windsurf|codeium|amazon\s+q|tabnine)")
_AI_TRAILER = re.compile(r"co-?authored-?by\s*:\s*[^\n\"'<]{0,120}?(?:\b" + _AI_WORD + r"\b[^\n\"']{0,120}|"
                         r"<[^>\n]*@(?:anthropic|openai)\.com>)", re.I)
_AI_ADDR = re.compile(r"(?:--author[=\s]+[\"']?[^\"'\n]{0,120}?|user\.(?:email|name)\s*=\s*[\"']?|"
                      r"GIT_(?:AUTHOR|COMMITTER)_(?:EMAIL|NAME)\s*=\s*[\"']?)"
                      r"(?:[^\s\"']*@(?:anthropic|openai)\.com|" + _AI_WORD + r"\b)", re.I)
_MSG_FILE = re.compile(r"(?:^|\s)(?:-F\s*|--file[=\s]+)([\"']?)([^\s\"']+)\1")
MAX_MSG_FILE = 65536


def _ai_author(event: dict) -> str:
    """What names an AI agent as commit author/co-author in this call, or ''."""
    if str(event.get("tool_name") or "") not in SHELL_TOOLS:
        return ""
    cmd = str((event.get("tool_input") or {}).get("command") or "")
    if not _GIT_WRITE.search(cmd):
        return ""
    if m := _AI_TRAILER.search(cmd):
        return " ".join(m.group(0).split())[:80]
    if m := _AI_ADDR.search(cmd):
        return " ".join(m.group(0).split())[:80]
    cwd = Path(str(event.get("cwd") or "."))
    for seg in _segments(cmd):
        if not _GIT_WRITE.search(seg):
            continue
        for fm in _MSG_FILE.finditer(seg):
            p = Path(fm.group(2))
            try:
                text = (p if p.is_absolute() else cwd / p).read_text(encoding="utf-8", errors="replace")[:MAX_MSG_FILE]
            except OSError:
                continue
            if m := _AI_TRAILER.search(text):
                return " ".join(m.group(0).split())[:80] + f" (in {p.name})"
    return ""


def decide(event: dict, ident: Identity, strict: bool) -> dict:
    t0 = time.perf_counter()
    from egress_guard import control

    if _touches_controls(event) and not control.consume(event, HOME):
        _log({"ts": time.time(), "tool": event.get("tool_name"), "blocked": True, "kinds": ["self-protection"],
              "session": str(event.get("session_id") or ""), "folder": Path(str(event.get("cwd") or "")).name})
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": SELF_REASON + _control_escalation(event)}}
    if os.environ.get("EGRESS_GUARD_AI_AUTHOR", "").strip().lower() != "allow" and (what := _ai_author(event)):
        # independent of session exceptions: it is a rule about authorship, not a question about personal data
        _log({"ts": time.time(), "tool": event.get("tool_name"), "blocked": True, "kinds": ["ai-author"],
              "session": str(event.get("session_id") or ""), "folder": Path(str(event.get("cwd") or "")).name})
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": AI_AUTHOR_REASON.format(what=what)}}
    sid = str(event.get("session_id") or "")
    rec = session_rec(sid)
    if rec.get("emails") or rec.get("hosts"):
        ident = replace(ident, allow_emails=ident.allow_emails + list(rec.get("emails", [])),
                        allow_hosts=ident.allow_hosts + list(rec.get("hosts", [])))
    found = scan_tool_call(event.get("tool_name", ""), event.get("tool_input", {}), ident, strict,
                           cwd=event.get("cwd"))
    mode = str(rec.get("mode") or "") or os.environ.get("EGRESS_GUARD_MODE", "").strip().lower()
    codex = CODEX or os.environ.get("EGRESS_GUARD_AGENT", "").strip().lower() == "codex"
    approved, memo, data, epoch = 0, [], None, ""
    if found and sid and mode != "off" and not codex:
        epoch = _epoch()  # once per decision; the pending note keeps this one (a --clear meanwhile revokes it)
        # approval memory: drop findings the user already approved in this session for the same destinations
        hard_kinds = set(_hard(ident, {f.kind for f in found}))
        ask_mode = mode == "ask"
        dests = _destinations(event)  # None: a call shape that is never remembered (most shell commands)
        if dests is not None and (ask_mode or any(f.kind not in hard_kinds for f in found)):
            data = _load_approvals()
            salt = (data or (data := _load_approvals(create=True)))["salt"]
            ok, keep = _approved(data, sid, ask_mode, epoch), []
            for f in found:
                exact = f.kind in hard_kinds  # a block in the normal mode, a question only under --ask
                if exact and not ask_mode:
                    keep.append(f)  # a hard block is never approved
                    continue
                key = _approval_key(salt, f, dests)
                if key in ok:
                    approved += 1
                    continue
                keep.append(f)
                memo.append((key, exact))
            found = keep
    kinds = sorted({f.kind for f in found})
    # session id and folder name (no personal data) so `whoami-guard-allow` can find the session it is run in
    _log({"ts": time.time(), "tool": event.get("tool_name"), "blocked": bool(found), "kinds": kinds,
          "session": sid, "folder": Path(str(event.get("cwd") or "")).name,
          "ms": round((time.perf_counter() - t0) * 1000, 3), **({"approved": approved} if approved else {})})
    if not found:
        return {}
    if mode == "off":
        return {}  # the user's exception: one terminal (env) or one session (whoami-guard-allow)
    hard = _hard(ident, kinds)
    if mode == "ask":
        hard = []
    if codex:
        # Codex treats "ask" as an unsupported result and runs the tool (Sol review 2026-11-01): deny there
        hard = hard or kinds
    if hard:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": REASON.format(kinds=", ".join(kinds))
                                       + _escalation(ident, event, kinds, strict)}}
    _ask_pending(event, sid, data, memo, epoch)
    memory = (" If the user approves, the same data in the same call (for gh: the same gh command group, target host "
              "and folder) is not "
              "asked about again in this session (until the session exception ends, otherwise 2 hours; "
              "`whoami-guard-allow --clear` forgets).") if memo else ""
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                   "permissionDecisionReason": ASK_REASON.format(kinds=", ".join(kinds))
                                   + _escalation(ident, event, kinds, strict) + memory}}


def _hard(ident: Identity, kinds) -> list[str]:
    """Kinds that are a block in the normal mode (no exception), not a question."""
    return sorted(k for k in kinds if "@" not in k and (  # "kind@host": an allowed host in a shell line, ask
        k not in ASK_KINDS or
        (k == "contact-email" and ident.contact_fields == "deny") or
        (k != "contact-email" and ident.fuzzy == "deny")))


def handle(event: dict, ident: Identity | None, strict: bool) -> dict:
    """One hook event: PostToolUse feeds the approval memory, anything else is a PreToolUse decision."""
    if str(event.get("hook_event_name") or "") == "PostToolUse":
        return remember(event)
    if ident is None:
        ident, strict = load_identity()
    return decide(event, ident, strict)


def _log(rec: dict) -> None:
    try:
        HOME.mkdir(parents=True, exist_ok=True)
        with (HOME / "log.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def serve(addr: str) -> None:
    host, port = addr.rsplit(":", 1)
    ident, strict = load_identity()

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0)
            event = json.loads(body or b"{}")
            # No approval memory here: any local process (the agent's curl too) can POST a fake PostToolUse to this
            # port. PostToolUse events are answered with nothing.
            is_post = isinstance(event, dict) and event.get("hook_event_name") == "PostToolUse"
            out = {} if is_post else decide(event, ident, strict)
            data = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    ThreadingHTTPServer((host, int(port)), H).serve_forever()


def main() -> int:
    if len(sys.argv) > 2 and sys.argv[1] == "--serve":
        serve(sys.argv[2])
        return 0
    event = None
    try:
        event = json.loads(sys.stdin.read() or "{}")
        if isinstance(event, dict) and event.get("hook_event_name") == "PostToolUse":
            # the approval memory; it never blocks and never needs the identity (fast path, every tool call)
            out = handle(event, None, False)
        else:
            ident, strict = load_identity()
            out = handle(event, ident, strict)
    except Exception as e:  # noqa: BLE001
        if isinstance(event, dict) and event.get("hook_event_name") == "PostToolUse":
            # the call already ran: a broken memory only means the next call asks again
            _log({"ts": time.time(), "event": "PostToolUse", "kinds": ["guard-error"], "error": type(e).__name__})
            return 0
        # A crash is a non-blocking hook error to the agent, so the call would run unchecked: deny instead and keep
        # the error type (no call content) in the local log (Astra review r6)
        _log({"ts": time.time(), "blocked": True, "kinds": ["guard-error"], "error": type(e).__name__})
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                      "permissionDecisionReason": f"whoami-guard failed ({type(e).__name__}) and "
                                      "blocked this call to be safe. Tell the user; do not retry the same call."}}
    if out:
        sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
