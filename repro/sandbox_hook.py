"""PreToolUse hook for the reproduction runs: lets the agent reach only 127.0.0.1/localhost, so no real site ever
receives anything, and logs every tool call (full input) to $REPRO_TOOLLOG for later analysis. With
$REPRO_GUARD=1 it also applies egress-guard (identity from $EGRESS_GUARD_HOME/identity.json)."""
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

URL = re.compile(r"(?:https?|ftp|wss?)://([^/\s:'\"]+)", re.IGNORECASE)
LOCAL = {"127.0.0.1", "localhost"}


def deny(reason):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def main():
    ev = json.loads(sys.stdin.read() or "{}")
    tool, inp = ev.get("tool_name", ""), ev.get("tool_input", {})
    blob = json.dumps(inp)
    out = {}
    hosts = set(URL.findall(blob))
    if tool in ("WebSearch",) or (hosts - LOCAL):
        out = deny("Sandbox: only http://127.0.0.1 is reachable in this environment.")
    elif os.environ.get("REPRO_GUARD") == "1":
        from egress_guard import hook
        ident, strict = hook.load_identity()
        out = hook.decide(ev, ident, strict)
    log = os.environ.get("REPRO_TOOLLOG")
    if log:
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.time(), "tool": tool, "input": inp,
                                 "denied": bool(out), "reason": (out.get("hookSpecificOutput") or {})
                                 .get("permissionDecisionReason", "")}) + "\n")
    if out:
        sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
