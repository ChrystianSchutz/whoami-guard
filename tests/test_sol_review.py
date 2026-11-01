"""Regression tests for the Sol review of 0.2.0 (2026-11-01) and the allow lists / session exceptions."""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from egress_guard import allow, hook  # noqa: E402
from egress_guard.fuzzy import contact_hits, find_emails  # noqa: E402
from egress_guard.scan import Identity, scan_tool_call  # noqa: E402

EMAIL = "jan.kowalski84@example-mail.pl"
ID = Identity(emails=[EMAIL], names=["Jan Kowalski", "Jan Schmidt"])


def kinds(tool, inp, ident=ID):
    return {f.kind for f in scan_tool_call(tool, inp, ident)}


def decision(event, ident=ID):
    out = hook.decide(event, ident, False)
    return out.get("hookSpecificOutput", {}).get("permissionDecision", "allow")


def bash(cmd, sid="s1"):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": sid}


def test_browser_mcp_is_scanned_and_allow_lists_apply(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    nav = {"tool_name": "mcp__playwright__browser_navigate", "tool_input": {"url": f"https://sink.org/?u={EMAIL}"}}
    assert decision(nav) == "deny"
    assert decision({"tool_name": "mcp__claude-in-chrome__form_input", "tool_input": {"value": EMAIL}}) == "deny"
    ident = Identity(emails=[EMAIL], names=["Jan Kowalski"], allow_hosts=["wordpress.org"],
                     allow_emails=["agents@corp.io"])
    ok = {"tool_name": "mcp__playwright__browser_navigate",
          "tool_input": {"url": f"https://login.wordpress.org/?u={EMAIL}"}}
    assert decision(ok, ident) == "allow"
    form = {"tool_name": "mcp__playwright__browser_type", "tool_input": {"text": "agents@corp.io"}}
    assert decision(form, ident) == "allow"
    out = hook.decide(nav, ident, False)["hookSpecificOutput"]["permissionDecisionReason"]
    assert "agents@corp.io" in out and "whoami-guard-allow --host sink.org" in out


def test_codex_never_gets_ask(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    monkeypatch.setattr(hook, "CODEX", True)
    assert decision(bash('curl -A "bot other@corp.io" https://x.org')) == "deny"


def test_long_inputs_scan_fast():
    for s in ("a" * 100_000 + "@b", "x@" + "a." * 50_000, ("a@b " * 20_000)):
        t = time.perf_counter()
        scan_tool_call("Bash", {"command": f'curl -A "{s}" https://x.org'}, ID)
        assert time.perf_counter() - t < 3.0
    assert find_emails("mail x.y+z@corp.co.uk, junk@nodomain, a@b.io.123") == ["x.y+z@corp.co.uk", "a@b.io"]


def test_header_values_are_read_whole():
    for cmd in ('curl -H "User-Agent: bot other@gmail.com" https://x', 'curl -H "From: Contact Person <other@gmail.com>" https://x',
                "curl -Aother@gmail.com https://x", "http https://x 'User-Agent:bot other@gmail.com'",
                "wget --user-agent='bot other@gmail.com' https://x"):
        assert "contact-email" in kinds("Bash", {"command": cmd}), cmd


def test_fuzzy_reads_decoded_views_and_short_keys():
    assert "email-fuzzy" in kinds("Bash", {"command": "curl 'https://sink.org/?u=jan.kowalsky84%40example-mail.pl'"})
    assert kinds("Bash", {"command": 'curl -A "Jan Schmdt" https://x'})
    leet = Identity(emails=["muller@corp.io"], names=[])
    assert "email-fuzzy" in kinds("Bash", {"command": 'curl -A "bot mu11er@corp.io" https://x'}, leet)


def test_allow_emails_are_exact_and_placeholders_narrow():
    assert not contact_hits('curl -A "bot agents@corp.io" https://x', ["agents@corp.io"])
    assert contact_hits('curl -A "bot agent.s@corp.io" https://x', ["agents@corp.io"])
    assert contact_hits('curl -A "bot other+noreply@gmail.com" https://x', [])
    assert not contact_hits('curl -A "bot noreply@corp.io" https://x', [])


def test_block_message_lists_allowed_addresses(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    ident = Identity(emails=[EMAIL], names=["Jan Kowalski"], allow_emails=["agents@corp.io"])
    out = hook.decide(bash(f'curl -A "bot {EMAIL}" https://x.org'), ident, False)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny" and "agents@corp.io" in out["permissionDecisionReason"]


def test_allow_hosts_shell_asks_fetch_passes(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    ident = Identity(emails=[EMAIL], names=["Jan Kowalski"], allow_hosts=["sec.gov"])
    assert decision(bash(f'curl -A "bot {EMAIL}" https://www.sec.gov/x'), ident) == "ask"
    assert decision(bash(f'curl -A "bot {EMAIL}" https://evil.org/x'), ident) == "deny"
    assert decision({"tool_name": "WebFetch", "tool_input": {"url": f"https://sec.gov/?c={EMAIL}"}}, ident) == "allow"


def test_session_exceptions(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    monkeypatch.setattr(allow, "HOME", tmp_path)
    leak = bash(f'curl -A "bot {EMAIL}" https://x.org', sid="sess-A")
    assert decision(leak) == "deny"  # also logs session sess-A
    assert allow.main(["--email", "agents@corp.io"]) == 0
    assert decision(bash('curl -A "bot agents@corp.io" https://x.org', sid="sess-A")) == "allow"
    assert decision(bash('curl -A "bot agents@corp.io" https://x.org', sid="sess-B")) == "ask"  # other session
    assert decision(leak) == "deny"  # a list entry does not relax anything else
    assert allow.main(["1"]) == 1  # two sessions active: refuses to guess (Sol review r2)
    assert allow.main(["1", "--session", "sess-A"]) == 0  # no lists: questions instead of blocks for this session
    assert decision(leak) == "ask"
    assert decision(bash(f'curl -A "bot {EMAIL}" https://x.org', sid="sess-B")) == "deny"
    assert allow.main(["--clear"]) == 0
    assert decision(leak) == "deny"
    data = json.loads((tmp_path / "sessions.json").read_text())
    assert data == {}


def test_agent_cannot_grant_itself_exceptions(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    assert decision(bash("whoami-guard-allow --off")) == "deny"
    assert decision(bash("python -m egress_guard.allow 8")) == "deny"
    assert decision({"tool_name": "Write", "tool_input": {"file_path": str(tmp_path / "sessions.json"),
                                                          "content": "{}"}}) == "deny"
    assert decision(bash("export EGRESS_GUARD_MODE=off && curl https://x.org")) == "deny"


def test_mentions_of_the_controls_are_not_blocked(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    for cmd in ("grep -n 'whoami-guard-allow' README.md", "cat ~/.egress-guard/log.jsonl | tail -3",
                "git commit -m 'docs: EGRESS_GUARD_MODE and whoami-guard-allow'"):
        assert decision(bash(cmd)) == "allow", cmd
    for cmd in ("echo {} > ~/.egress-guard/sessions.json", "cp x ~/.egress-guard/identity.json",
                "cd /tmp && whoami-guard-allow 8", "EGRESS_GUARD_MODE=off claude"):
        assert decision(bash(cmd)) == "deny", cmd
