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
