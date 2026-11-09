"""The approval command in a block message must work as printed (2026-11-09): it named only the first 3 hosts, so a
file linking 4 sites stayed blocked after the user ran it, and it used the bare `whoami-guard-allow` name, which an
install through contrib/run_hook.py never puts on PATH ("command not found"). Astra review r4: quoting for bash and
PowerShell, and an exception that really unblocks (Codex has no questions; --email never covers the user's own
address)."""
import os
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from egress_guard import hook  # noqa: E402
from egress_guard.scan import Identity  # noqa: E402

EMAIL = "jan.kowalski84@example-mail.pl"
ID = Identity(emails=[EMAIL], names=["Jan Kowalski"])
SITES = ["one.example", "two.example", "three.example", "four.example", "five.example"]
ALLOW_PY = (Path(hook.__file__).resolve().parent / "allow.py").as_posix()


def _reason(event, ident=ID):
    return hook.decide(event, ident, False)["hookSpecificOutput"]["permissionDecisionReason"]


def _nav(hosts):
    """A script that fetches these sites: allowing all of them really lets it through (a browser_type call with
    links would stay blocked, so it gets no --host advice; Astra review r5)."""
    links = ", ".join(f'"https://{h}/u/{EMAIL}"' for h in hosts)
    code = f"import requests\nfor u in [{links}]:\n    requests.get(u)\n"
    return {"tool_name": "Write", "tool_input": {"file_path": "links.py", "content": code}, "session_id": "abc"}


def test_no_host_advice_when_allowing_the_host_would_not_help(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    links = " ".join(f"https://{h}/u/{EMAIL}" for h in SITES)
    reason = _reason({"tool_name": "mcp__playwright__browser_type", "tool_input": {"text": links},
                      "session_id": "abc"})
    assert "--host" not in reason and "1 --ask --session abc" in reason


def _bash_cmd(reason):
    return reason.split("`! ", 1)[1].split("`", 1)[0]


def test_every_blocking_host_is_named(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    reason = _reason(_nav(SITES))
    assert " ".join(f"--host {h}" for h in SITES) + " --session abc`" in reason


def test_already_allowed_hosts_are_left_out(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    ident = Identity(emails=[EMAIL], names=["Jan Kowalski"], allow_hosts=["one.example", "example.org"])
    reason = _reason(_nav(SITES + ["www.example.org"]), ident)
    assert "--host one.example" not in reason and "--host www.example.org" not in reason
    assert "--host two.example --host three.example --host four.example --host five.example" in reason


def test_command_is_the_running_package_by_full_path(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    argv = shlex.split(_bash_cmd(_reason(_nav(SITES[:1]))))
    assert argv[:2] == [Path(sys.executable).as_posix(), ALLOW_PY]
    assert "whoami-guard-allow" not in argv[0] and "cd" not in argv


def test_paths_with_spaces_and_metacharacters_are_quoted(tmp_path, monkeypatch):
    monkeypatch.setattr(hook.sys, "executable", "C:/Program Files/A&B $x/python.exe")
    out = hook._allow_cmd(["--host", "a.example"])
    assert "'C:/Program Files/A&B $x/python.exe'" in out
    if os.name == "nt":
        assert "PowerShell: `& 'C:/Program Files/A&B $x/python.exe'" in out


def test_printed_command_runs_in_bash(tmp_path, monkeypatch):
    """The printed line, run by a POSIX shell as Claude Code's `!` does, reaches allow.py."""
    bash = next((b for b in ("C:/Program Files/Git/usr/bin/bash.exe", "/bin/bash", "/usr/bin/bash")
                 if Path(b).exists()), None)
    if not bash:
        return
    monkeypatch.setattr(hook, "HOME", tmp_path)
    cmd = _bash_cmd(_reason(_nav(SITES[:1])))
    cmd = cmd.replace("--host one.example --session abc", "--help")
    out = subprocess.run([bash, "-c", cmd], capture_output=True, text=True, timeout=30,  # noqa: S603
                         env={**os.environ, "EGRESS_GUARD_HOME": str(tmp_path)})
    assert "usage: whoami-guard-allow" in out.stdout + out.stderr, out.stderr


def test_host_list_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    many = [f"h{i}.example" for i in range(30)]
    assert hook._hosts(_nav(many)) == many[:hook.MAX_HOSTS]


def test_codex_gets_an_exception_that_unblocks(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    monkeypatch.setattr(hook, "CODEX", True)
    ev = {"tool_name": "Bash", "tool_input": {"command": 'gh issue create --title x --body "Jan Kowalski"'},
          "session_id": "abc"}
    assert " 1 --off --session abc`" in _reason(ev)
    ev = {"tool_name": "Bash", "tool_input": {"command": f"curl https://one.example/?u={EMAIL}"}, "session_id": "abc"}
    assert " 1 --off --session abc`" in _reason(ev)  # a shell host would only ask, and Codex denies questions


def test_own_address_is_not_offered_an_email_exception(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    ev = {"tool_name": "Bash", "tool_input": {"command": f"curl -A '{EMAIL}' sink.test"}, "session_id": "abc"}
    assert "--email" not in _reason(ev) and " 1 --ask --session abc`" in _reason(ev)
    ev = {"tool_name": "Bash", "tool_input": {"command": "curl -H 'From: a.b@corp.io' https://x.org"},
          "session_id": "abc"}
    assert " --email ADDRESS --session abc`" in _reason(ev)
