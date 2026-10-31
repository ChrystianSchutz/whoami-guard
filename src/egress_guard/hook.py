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
import os
import re
import subprocess  # nosec B404
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from egress_guard.scan import ASK_KINDS, Identity, scan_tool_call

HOME = Path(os.environ.get("EGRESS_GUARD_HOME", Path.home() / ".egress-guard"))
REASON = ("whoami-guard blocked this call: it would send the user's own {kinds} to an outside service. Personal "
          "data from your context (account e-mail, name) must never go into requests, headers, URLs or bodies, even "
          "when a site asks for contact details. Use a generic identifier without personal data (for example "
          "'User-Agent: research-script/1.0'), or stop and ask the user whether and what to send.")

ASK_REASON = ("whoami-guard: this call may send personal data to an outside service ({kinds}: a look-alike form of "
              "the user's identity, or an e-mail address in a User-Agent / From / contact field). Approve only if you "
              "meant to send it. Agents: do not put any e-mail address in a User-Agent or contact header unless the "
              "user gave you one for that purpose (contact_alias); use a generic identifier instead.")


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
                     contact_alias=list(cfg.get("contact_alias", [])), first_alone=bool(cfg.get("first_alone", False)),
                     scan_browser=bool(cfg.get("scan_browser", False)))
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


def decide(event: dict, ident: Identity, strict: bool) -> dict:
    t0 = time.perf_counter()
    found = scan_tool_call(event.get("tool_name", ""), event.get("tool_input", {}), ident, strict,
                           cwd=event.get("cwd"))
    kinds = sorted({f.kind for f in found})
    _log({"ts": time.time(), "tool": event.get("tool_name"), "blocked": bool(found), "kinds": kinds,
          "ms": round((time.perf_counter() - t0) * 1000, 3)})
    if not found:
        return {}
    hard = [k for k in kinds if k not in ASK_KINDS or
            (k == "contact-email" and ident.contact_fields == "deny") or
            (k != "contact-email" and ident.fuzzy == "deny")]
    if hard:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": REASON.format(kinds=", ".join(kinds))}}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                   "permissionDecisionReason": ASK_REASON.format(kinds=", ".join(kinds))}}


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
    event = json.loads(sys.stdin.read() or "{}")
    ident, strict = load_identity()
    out = decide(event, ident, strict)
    if out:
        sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
