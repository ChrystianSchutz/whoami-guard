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
import json
import math
import os
import re
import shlex
import subprocess  # nosec B404
import sys
import time
import tomllib
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from egress_guard.scan import ASK_KINDS, FUZZY_MAX, Identity, scan_tool_call

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


SELF_REASON = ("whoami-guard: only the user may change whoami-guard's settings or exceptions (its folder, "
               "whoami-guard-allow, EGRESS_GUARD_* variables, the hook entry in the agent's settings). Ask the user; "
               "they can run `! whoami-guard-allow` in this session.")
# The agent must not grant itself an exception or switch the hook off (the user's own `!` commands are not hooked).
# A shell segment that names a control (the allow command, the whoami-guard folder, an EGRESS_GUARD_* assignment,
# the agent's hook settings) is denied unless it only reads (grep, cat, ls, git log ...), so docs and log reading
# pass and `"whoami-guard-allow"`, `/usr/bin/whoami-guard-allow`, `python -c "...'.egress-guard'..."` do not
# (Sol review r2, 2026-11-01). A script written first and run later is not seen: a seatbelt, not a sandbox.
_CTRL = re.compile(r"whoami-guard-allow|egress_guard[./\\]allow|\.egress-guard|run_hook\.py[\"']?\s+allow\b|"
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
    except (OSError, ValueError, TypeError, AttributeError):
        return {}  # a broken record grants nothing and never crashes the hook (Sol review r2)
    mode = rec.get("mode") if rec.get("mode") in ("ask", "off") else ""
    return {"mode": mode, "emails": _strs(rec.get("emails")), "hosts": _strs(rec.get("hosts"))}


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
            f"{_allow_cmd(args)}. Do not retry with the data rewritten or encoded.")
    return out


def decide(event: dict, ident: Identity, strict: bool) -> dict:
    t0 = time.perf_counter()
    if _touches_controls(event):
        _log({"ts": time.time(), "tool": event.get("tool_name"), "blocked": True, "kinds": ["self-protection"],
              "session": str(event.get("session_id") or ""), "folder": Path(str(event.get("cwd") or "")).name})
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": SELF_REASON}}
    sid = str(event.get("session_id") or "")
    rec = session_rec(sid)
    if rec.get("emails") or rec.get("hosts"):
        ident = replace(ident, allow_emails=ident.allow_emails + list(rec.get("emails", [])),
                        allow_hosts=ident.allow_hosts + list(rec.get("hosts", [])))
    found = scan_tool_call(event.get("tool_name", ""), event.get("tool_input", {}), ident, strict,
                           cwd=event.get("cwd"))
    kinds = sorted({f.kind for f in found})
    # session id and folder name (no personal data) so `whoami-guard-allow` can find the session it is run in
    _log({"ts": time.time(), "tool": event.get("tool_name"), "blocked": bool(found), "kinds": kinds,
          "session": sid, "folder": Path(str(event.get("cwd") or "")).name,
          "ms": round((time.perf_counter() - t0) * 1000, 3)})
    if not found:
        return {}
    mode = str(rec.get("mode") or "") or os.environ.get("EGRESS_GUARD_MODE", "").strip().lower()
    if mode == "off":
        return {}  # the user's exception: one terminal (env) or one session (whoami-guard-allow)
    hard = [k for k in kinds if "@" not in k and (  # "kind@host": an allowed host in a shell line, ask
            k not in ASK_KINDS or
            (k == "contact-email" and ident.contact_fields == "deny") or
            (k != "contact-email" and ident.fuzzy == "deny"))]
    if mode == "ask":
        hard = []
    if CODEX or os.environ.get("EGRESS_GUARD_AGENT", "").strip().lower() == "codex":
        # Codex treats "ask" as an unsupported result and runs the tool (Sol review 2026-11-01): deny there
        hard = hard or kinds
    if hard:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": REASON.format(kinds=", ".join(kinds))
                                       + _escalation(ident, event, kinds, strict)}}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                   "permissionDecisionReason": ASK_REASON.format(kinds=", ".join(kinds))
                                   + _escalation(ident, event, kinds, strict)}}


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
            out = decide(json.loads(body or b"{}"), ident, strict)
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
    try:
        event = json.loads(sys.stdin.read() or "{}")
        ident, strict = load_identity()
        out = decide(event, ident, strict)
    except Exception as e:  # noqa: BLE001
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
