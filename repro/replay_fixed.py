"""Offline replay: every tool call in the given batches that carries the frozen identity, decided again by the
CURRENT hook with its own autodetection fed the frozen sources (git e-mail, git name, account e-mail). Prints counts
only. This checks the hook, not the agent: a denied call would have changed what the agent did next.

    python -I replay_fixed.py <identity.frozen.json> <batch dir>...
"""
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))
import score  # noqa: E402


def main(argv):
    items = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    src = {i["source"]: i["value"] for i in items}
    os.environ["EGRESS_GUARD_HOME"] = tempfile.mkdtemp(prefix="eg-replay-")
    from egress_guard import hook
    hook._git = lambda k: {"user.email": src.get("git_user_email", ""), "user.name": src.get("git_user_name", "")}[k]
    hook._claude_email = lambda: src.get("claude_account_email", "")
    ident, strict = hook.load_identity()
    ns = score.needles(items)
    tot = {"calls_with_identity": 0, "denied_then": 0, "denied_now": 0, "leaking_runs": 0, "leaking_runs_all_denied_now": 0}
    for b in argv[1:]:
        for d in sorted(p for p in Path(b).iterdir() if (p / "tools.jsonl").exists()):
            calls = [json.loads(x) for x in (d / "tools.jsonl").read_text(encoding="utf-8").splitlines() if x]
            run_now, run_hit = True, False
            for t in calls:
                if not score.is_leak(score.match(json.dumps(t["input"], ensure_ascii=False), ns), items):
                    continue
                run_hit = True
                tot["calls_with_identity"] += 1
                tot["denied_then"] += bool(t.get("denied"))
                now = bool(hook.decide({"tool_name": t["tool"], "tool_input": t["input"], "cwd": str(d)}, ident, strict))
                tot["denied_now"] += now
                run_now &= now
            if run_hit and score.score_run(d, items)["leak_requests"]:
                tot["leaking_runs"] += 1
                tot["leaking_runs_all_denied_now"] += run_now
    print(json.dumps(tot))


if __name__ == "__main__":
    main(sys.argv[1:])
