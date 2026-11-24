"""Owner-pasted approval commands; synthetic data and isolated control files only."""
import shlex
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from egress_guard import allow, control, hook
from egress_guard.scan import Identity


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    monkeypatch.setattr(allow, "HOME", tmp_path)
    monkeypatch.setattr(hook, "CODEX", True)
    for name in ("EGRESS_GUARD_MODE", "EGRESS_GUARD_AGENT"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def event():
    return {"tool_name": "exec_command", "tool_input": {
        "cmd": "Add-Content -LiteralPath C:/Users/synthetic/.codex/config.toml -Value '# test'"},
        "cwd": "C:/synthetic", "session_id": "test-session-123456789"}


def pre(ev):
    return hook.decide(ev, Identity(), False).get("hookSpecificOutput", {})


def command(ev):
    result = pre(ev)
    assert result["permissionDecision"] == "deny"
    reason = result["permissionDecisionReason"]
    assert "paste and run" in reason and "yes/no" in reason
    argv = shlex.split(reason.split("`! ", 1)[1].split("`", 1)[0])
    assert argv[1].endswith("/egress_guard/allow.py")
    return argv[2:]


def test_deny_until_owner_command_then_exactly_once():
    ev = event()
    args = command(ev)
    assert pre(ev)["permissionDecision"] == "deny"  # saying yes changes nothing
    assert allow.main(args) == 0  # simulate the owner running the printed command
    assert pre({**ev, "session_id": "another-session"})["permissionDecision"] == "deny"
    assert pre({**ev, "cwd": "C:/other"})["permissionDecision"] == "deny"
    changed = {**ev, "tool_input": {"cmd": ev["tool_input"]["cmd"] + " # changed"}}
    assert pre(changed)["permissionDecision"] == "deny"
    assert pre(ev) == {}
    assert pre(ev)["permissionDecision"] == "deny"


def test_grant_command_itself_is_blocked_for_agent():
    args = command(event())
    ev = {**event(), "tool_input": {"cmd": "whoami-guard-allow " + shlex.join(args)}}
    assert pre(ev)["permissionDecision"] == "deny"


def test_clear_revokes_and_off_does_not_grant(isolated):
    ev = event()
    args = command(ev)
    assert allow.main(args) == 0
    assert allow.main(["--clear"]) == 0
    assert pre(ev)["permissionDecision"] == "deny"
    assert allow.main(["1", "--off", "--session", ev["session_id"]]) == 0
    assert pre(ev)["permissionDecision"] == "deny"


@pytest.mark.parametrize("failure", ["expired", "broken", "unwritable", "locked"])
def test_fail_closed(isolated, monkeypatch, failure):
    ev = event()
    assert allow.main(command(ev)) == 0
    if failure == "expired":
        data = control._read(isolated)
        data[ev["session_id"]]["until"] = time.time() - 1
        control._write(isolated, data)
    elif failure == "broken":
        (isolated / control.FILE).write_text("{", encoding="utf-8")
    elif failure == "unwritable":
        def fail(*args):
            raise OSError("synthetic failure")
        monkeypatch.setattr(control, "_write", fail)
    else:
        (isolated / allow.LOCK).touch()
        monkeypatch.setattr(allow, "LOCK_WAIT", 0)
    assert pre(ev)["permissionDecision"] == "deny"


def test_no_session_no_fake_command():
    reason = pre({**event(), "session_id": ""})["permissionDecisionReason"]
    assert "no session id" in reason and "`!" not in reason


def test_no_implicit_grants_or_mixed_modes(isolated):
    args = command(event())
    for bad in (args[:2], args + ["--off"], ["--control-once=abc"],
                ["--control-once", "bad", "--session", event()["session_id"]]):
        assert allow.main(bad) == 1
    assert not (isolated / control.FILE).exists()


def test_other_checks_still_deny(monkeypatch):
    monkeypatch.setattr(hook, "CODEX", True)
    ev = event()
    ev["tool_input"] = {"command": 'echo x > ~/.egress-guard/probe; git commit -m "Co-authored-by: Claude"'}
    ev["tool_name"] = "Bash"
    assert allow.main(command(ev)) == 0
    assert "AI agent" in pre(ev)["permissionDecisionReason"]


def test_handoff_is_strict_only_for_codex(monkeypatch):
    monkeypatch.setattr(hook, "CODEX", False)
    codex = hook._owner_handoff(event())
    assert "NEXT RESPONSE, BEFORE ANY MORE TOOLS" in codex
    assert "<user_shell_command>" in codex and "Exit code: 0" in codex
    assert "do not wait for 'done'/'gotowe'" in codex
    opus = hook._owner_handoff({"tool_name": "Bash"})
    assert opus == " Please paste the exception command above for the user to run with !."


def test_cli_process_executes_printed_command(isolated):
    import os
    import subprocess

    ev = event()
    result = pre(ev)
    reason = result["permissionDecisionReason"]
    argv = shlex.split(reason.split("`! ", 1)[1].split("`", 1)[0])
    result = subprocess.run(argv, capture_output=True, text=True, timeout=10,
                            env={**os.environ, "EGRESS_GUARD_HOME": str(isolated), "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stderr
    assert pre(ev) == {}


def test_parallel_retries_only_consume_once(isolated):
    from concurrent.futures import ThreadPoolExecutor

    ev = event()
    assert allow.main(command(ev)) == 0
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: control.consume(ev, isolated), range(4)))
    assert results.count(True) == 1
