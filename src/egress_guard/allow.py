"""whoami-guard-allow: exceptions for ONE agent session, granted by the user, for a limited time.

Run it inside the agent session with the `!` prefix (Claude Code runs `!` commands as the user, outside the hooks):

    ! whoami-guard-allow                         # this session: questions instead of blocks, 2 hours
    ! whoami-guard-allow --email agent@corp.io   # this session: the agent may send this address, nothing else changes
    ! whoami-guard-allow --host sec.gov          # this session: your identity may go to sec.gov (shell: it asks)
    ! whoami-guard-allow 8 --email a@b.io --host sec.gov   # several at once, for 8 hours
    ! whoami-guard-allow 1 --off                 # this session: no checks at all for 1 hour
    ! whoami-guard-allow --list                  # running exceptions
    ! whoami-guard-allow --clear                 # end all exceptions

The block message gives the exact command with `--session <id>` for the session that asked. Without --session the
command uses the session of the last tool call the hook saw, and refuses when several sessions were active in the
last 10 minutes (it lists them). It prints the folder of the session it changed.
The agent cannot run this itself: the hook denies tool calls that name this command or the whoami-guard folder.
It also runs as a file, `python <package>/egress_guard/allow.py ...`, which is what block messages print: that works
for every install type whatever the PATH is.
"""
import json
import math
import sys
import time
from pathlib import Path

if __package__ in (None, ""):  # run as a file: import the package this file belongs to, not this folder's modules
    sys.path[0] = str(Path(__file__).resolve().parent.parent)

from egress_guard.hook import HOME  # noqa: E402

USAGE = ("usage: whoami-guard-allow [HOURS] [--email ADDR]... [--host HOST]... [--ask|--off] "
         "[--session ID] [--list|--clear]")


def _until(v) -> float:
    try:
        u = float(v.get("until", 0)) if isinstance(v, dict) else 0.0
    except (TypeError, ValueError):
        return 0.0
    return u if math.isfinite(u) else 0.0  # "nan" / "inf" never count as running (Sol review r3)


def _list(v) -> list[str]:
    return [str(x) for x in v if isinstance(x, str)] if isinstance(v, list) else []


def _load() -> dict:
    """Running exceptions; malformed records are dropped instead of crashing (Sol review r2)."""
    try:
        d = json.loads((HOME / "sessions.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    now = time.time()
    return {str(k): v for k, v in d.items() if _until(v) > now} if isinstance(d, dict) else {}


def _log_lines() -> list[str]:
    try:
        return (HOME / "log.jsonl").read_text(encoding="utf-8").splitlines()[-5000:]
    except OSError:
        return []


def _sessions(lines: list[str] | None = None) -> list[tuple[str, str, float]]:
    """(session id, folder, last seen) from the hook log, newest first."""
    seen: dict[str, tuple[str, float]] = {}
    for line in reversed(_log_lines() if lines is None else lines):
        try:
            rec = json.loads(line)
            sid = str(rec.get("session") or "")
            if sid and sid not in seen:
                seen[sid] = (str(rec.get("folder") or ""), float(rec.get("ts") or 0))
        except (ValueError, TypeError, AttributeError):
            continue
    return [(k, f, t) for k, (f, t) in seen.items()]


def _blocked_without_session(lines: list[str], since: float) -> bool:
    """A call blocked in the last 10 minutes that carried no session id: the user may be answering THAT block, so
    "the newest session" can be the wrong one (Sol review r3)."""
    for line in reversed(lines):
        try:
            rec = json.loads(line)
            if float(rec.get("ts") or 0) < since:
                return False
            if rec.get("blocked") and not rec.get("session"):
                return True
        except (ValueError, TypeError, AttributeError):
            continue
    return False


def _pick_session(prefix: str) -> tuple[str, str, str]:
    """(session id, folder, error)."""
    lines = _log_lines()
    sessions = _sessions(lines)
    if prefix:
        hits = [s for s in sessions if s[0].startswith(prefix)] or \
               [(k, "", 0.0) for k in _load() if k.startswith(prefix)]
        if len(hits) != 1:
            near = "; ".join(f"{s[0][:12]} (folder {s[1] or '?'})" for s in sessions[:6]) or "none in the hook log"
            return "", "", (f"--session {prefix}: {'no' if not hits else 'more than one'} matching session; "
                            f"recent sessions: {near}")
        return hits[0][0], hits[0][1], ""
    if not sessions:
        return "", "", "no session found in the hook log"
    recent = [s for s in sessions if s[2] >= sessions[0][2] - 600]
    listing = "; ".join(f"--session {s[0][:12]} (folder {s[1] or '?'})" for s in recent[:6])
    if _blocked_without_session(lines, time.time() - 600):
        return "", "", ("a call blocked in the last 10 minutes carried no session id, so the newest session may be "
                        "the wrong one; add the session you mean: " + listing)
    if len(recent) > 1:
        return "", "", ("several agent sessions were active in the last 10 minutes; use the command from the block "
                        "message, or add one of: " + listing)
    return sessions[0][0], sessions[0][1], ""


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
    data = _load()
    if "--clear" in args:
        data = {}
        print("whoami-guard: all session exceptions ended")
    elif "--list" in args:
        for sid, v in data.items():
            print(f"{sid[:8]}...  folder={v.get('folder', '')}  mode={v.get('mode') or 'normal'}  "
                  f"emails={v.get('emails', [])}  hosts={v.get('hosts', [])}  "
                  f"{round((_until(v) - now) / 3600, 1)} h left")
        if not data:
            print("whoami-guard: no session exceptions")
        for sid, folder, ts in _sessions()[:6]:  # the ids --session takes
            print(f"session {sid[:12]}  folder={folder or '?'}  last call {round((now - ts) / 60)} min ago")
        return 0
    else:
        prefix = next((a.split("=", 1)[1] for a in args if a.startswith("--session=")), "") or \
            (_values(args, "--session") or [""])[0]
        sid, folder, err = _pick_session(prefix.strip())
        if err:
            print(f"whoami-guard: {err}; nothing changed", file=sys.stderr)
            return 1
        emails, hosts = _values(args, "--email"), _values(args, "--host")
        skip = {i + 1 for i, a in enumerate(args) if a in ("--email", "--host", "--session")}
        nums = [a for i, a in enumerate(args) if i not in skip and a.replace(".", "", 1).isdigit()]
        hours = float(nums[0]) if nums else 2.0
        mode = "off" if "--off" in args else "ask" if ("--ask" in args or not (emails or hosts)) else ""
        rec = data.get(sid, {})
        rec.update(until=now + hours * 3600, folder=folder or rec.get("folder", ""))
        if mode:
            rec["mode"] = mode
        rec["emails"] = sorted(set(_list(rec.get("emails"))) | set(emails))
        rec["hosts"] = sorted(set(_list(rec.get("hosts"))) | set(hosts))
        data[sid] = rec
        print(f"whoami-guard: session {sid[:8]}... (folder {rec['folder'] or '?'}) for {hours:g} h: "
              f"mode={rec.get('mode') or 'normal'}, emails={rec['emails']}, hosts={rec['hosts']}")
    HOME.mkdir(parents=True, exist_ok=True)
    (HOME / "sessions.json").write_text(json.dumps(data, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
