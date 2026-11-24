"""0.2.5: commits that name an AI agent as author or co-author are denied, whatever the session exception.
All identities are invented."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from egress_guard import hook  # noqa: E402
from egress_guard.scan import Identity  # noqa: E402

ID = Identity(emails=["jan.kowalski84@example-mail.pl"], names=["Jan Kowalski"])
TRAILER = "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    monkeypatch.setattr(hook, "CODEX", False)
    for v in ("EGRESS_GUARD_MODE", "EGRESS_GUARD_AGENT", "EGRESS_GUARD_AI_AUTHOR"):
        monkeypatch.delenv(v, raising=False)
    return tmp_path


def run(cmd, tool="Bash", cwd="/work/repo"):
    ev = {"tool_name": tool, "tool_input": {"command": cmd}, "session_id": "s-1", "cwd": str(cwd),
          "tool_use_id": "toolu_1", "hook_event_name": "PreToolUse"}
    out = hook.decide(ev, ID, False).get("hookSpecificOutput", {})
    return out.get("permissionDecision", "allow"), out.get("permissionDecisionReason", "")


@pytest.mark.parametrize("cmd", [
    f'git commit -m "fix: parser\n\n{TRAILER}"',
    f"git commit -q -F - <<'EOF'\nfix: parser\n\n{TRAILER}\nEOF",
    f'git commit --amend -m "x" -m "{TRAILER}"',
    'git commit --trailer "Co-authored-by: GitHub Copilot <175728472+Copilot@users.noreply.github.com>" -m x',
    'git commit -m "x\n\nCo-authored-by: Codex <codex@openai.com>"',
    'git commit -m "x\n\nco-authored-by: Someone <bot@anthropic.com>"',
    'git commit --author="Claude <noreply@anthropic.com>" -m x',
    'git -c user.email=noreply@anthropic.com commit -m x',
    'GIT_AUTHOR_EMAIL=agent@openai.com git commit -m x',
    f'cd repo && git -C sub commit -m "y\n\n{TRAILER}" && git push',
    f'git tag -a v1 -m "release\n\n{TRAILER}"',
])
def test_ai_author_denied(cmd):
    decision, reason = run(cmd)
    assert decision == "deny"
    assert "AI agent" in reason


def test_powershell_denied():
    assert run(f'git commit -m "x`n`n{TRAILER}"', tool="PowerShell")[0] == "deny"


def test_message_file_is_read(tmp_path):
    (tmp_path / "msg.txt").write_text(f"fix: parser\n\nlonger body\n\n{TRAILER}\n", encoding="utf-8")
    assert run("git commit -F msg.txt", cwd=tmp_path)[0] == "deny"
    assert run(f'git commit --file="{tmp_path / "msg.txt"}"')[0] == "deny"
    (tmp_path / "ok.txt").write_text("fix: parser\n\nbody\n", encoding="utf-8")
    assert run("git commit -F ok.txt", cwd=tmp_path)[0] == "allow"
    assert run("git commit -F missing.txt", cwd=tmp_path)[0] == "allow"


@pytest.mark.parametrize("cmd", [
    'git commit -m "fix: claude parser reads wrapped verdicts"',
    'git commit -m "x\n\nCo-authored-by: Jane Doe <jane.doe@example.org>"',
    f'echo "{TRAILER}" > notes.txt',
    f'git log --grep "{TRAILER}"',
    'grep -rn "Co-authored-by: Claude" .',
    'git commit -m "use cursor pagination"',
])
def test_not_an_ai_author(cmd):
    assert run(cmd)[0] == "allow"


def test_session_off_does_not_lift_it(monkeypatch):
    monkeypatch.setenv("EGRESS_GUARD_MODE", "off")
    assert run(f'git commit -m "x\n\n{TRAILER}"')[0] == "deny"


def test_user_can_switch_it_off(monkeypatch):
    monkeypatch.setenv("EGRESS_GUARD_AI_AUTHOR", "allow")
    assert run(f'git commit -m "x\n\n{TRAILER}"')[0] == "allow"


def test_non_shell_tools_untouched():
    ev = {"tool_name": "Write", "tool_input": {"file_path": "/work/repo/msg.txt", "content": TRAILER},
          "session_id": "s-1", "cwd": "/work/repo", "hook_event_name": "PreToolUse"}
    assert hook.decide(ev, ID, False) == {}
