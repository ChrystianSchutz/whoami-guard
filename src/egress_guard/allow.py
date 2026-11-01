"""whoami-guard-allow: exceptions for ONE agent session, granted by the user, for a limited time.

Run it inside the agent session with the `!` prefix (Claude Code runs `!` commands as the user, outside the hooks):

    ! whoami-guard-allow                         # this session: questions instead of blocks, 2 hours
    ! whoami-guard-allow --email agent@corp.io   # this session: the agent may send this address, nothing else changes
    ! whoami-guard-allow --host sec.gov          # this session: your identity may go to sec.gov (shell: it asks)
    ! whoami-guard-allow 8 --email a@b.io --host sec.gov   # several at once, for 8 hours
    ! whoami-guard-allow 1 --off                 # this session: no checks at all for 1 hour
    ! whoami-guard-allow --list                  # running exceptions
    ! whoami-guard-allow --clear                 # end all exceptions

"This session" is the session of the last tool call the hook saw; the command prints its folder so you can check.
The agent cannot run this itself: the hook denies tool calls that name this command or the whoami-guard folder.
"""
import json
import sys
import time

from egress_guard.hook import HOME

USAGE = "usage: whoami-guard-allow [HOURS] [--email ADDR]... [--host HOST]... [--ask|--off] [--list|--clear]"


def _load() -> dict:
    try:
        d = json.loads((HOME / "sessions.json").read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _last_session() -> tuple[str, str]:
    """(session id, folder name) of the newest hook log record that has a session."""
    try:
        lines = (HOME / "log.jsonl").read_text(encoding="utf-8").splitlines()[-2000:]
    except OSError:
        return "", ""
    for line in reversed(lines):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("session"):
            return str(rec["session"]), str(rec.get("folder") or "")
    return "", ""


def _values(args: list[str], flag: str) -> list[str]:
    out = []
    for i, a in enumerate(args):
        if a == flag and i + 1 < len(args):
            out.append(args[i + 1].strip())
        elif a.startswith(flag + "="):
            out.append(a.split("=", 1)[1].strip())
    return [v for v in out if v]


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "-h" in args or "--help" in args:
        print(USAGE)
        return 0
    now = time.time()
    data = {k: v for k, v in _load().items() if isinstance(v, dict) and float(v.get("until", 0)) > now}
    if "--clear" in args:
        data = {}
        print("whoami-guard: all session exceptions ended")
    elif "--list" in args:
        for sid, v in data.items():
            print(f"{sid[:8]}...  folder={v.get('folder', '')}  mode={v.get('mode') or 'normal'}  "
                  f"emails={v.get('emails', [])}  hosts={v.get('hosts', [])}  "
                  f"{round((float(v['until']) - now) / 3600, 1)} h left")
        if not data:
            print("whoami-guard: no session exceptions")
        return 0
    else:
        sid, folder = next(((a.split("=", 1)[1], "") for a in args if a.startswith("--session=")), ("", ""))
        if not sid:
            sid, folder = _last_session()
        if not sid:
            print("whoami-guard: no session found in the hook log; nothing changed", file=sys.stderr)
            return 1
        emails, hosts = _values(args, "--email"), _values(args, "--host")
        skip = {i + 1 for i, a in enumerate(args) if a in ("--email", "--host")}
        nums = [a for i, a in enumerate(args) if i not in skip and a.replace(".", "", 1).isdigit()]
        hours = float(nums[0]) if nums else 2.0
        mode = "off" if "--off" in args else "ask" if ("--ask" in args or not (emails or hosts)) else ""
        rec = data.get(sid, {})
        rec.update(until=now + hours * 3600, folder=folder or rec.get("folder", ""))
        if mode:
            rec["mode"] = mode
        rec["emails"] = sorted(set(rec.get("emails", [])) | set(emails))
        rec["hosts"] = sorted(set(rec.get("hosts", [])) | set(hosts))
        data[sid] = rec
        print(f"whoami-guard: session {sid[:8]}... (folder {rec['folder'] or '?'}) for {hours:g} h: "
              f"mode={rec.get('mode') or 'normal'}, emails={rec['emails']}, hosts={rec['hosts']}")
    HOME.mkdir(parents=True, exist_ok=True)
    (HOME / "sessions.json").write_text(json.dumps(data, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
