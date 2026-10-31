import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from egress_guard import hook  # noqa: E402
from egress_guard.fuzzy import key  # noqa: E402
from egress_guard.scan import ASK_KINDS, Identity, scan_tool_call  # noqa: E402

ID = Identity(emails=["jan.kowalski84@example-mail.pl"], names=["Jan Kowalski"], extra=["Krakowskie Przedmiescie"])


def kinds(cmd, ident=ID, tool="Bash"):
    inp = {"command": cmd} if tool == "Bash" else cmd
    return {f.kind for f in scan_tool_call(tool, inp, ident)}


def test_sound_key_merges_spellings():
    assert key("Müller") == key("Mueller") == key("Muller")
    assert key("Schmidt") == key("Szmit") == key("Shmit")
    assert key("Christian") == key("Krystian")
    assert key("Wiśniewski") == key("Visnievski")


def test_lookalike_letters_are_exact_leaks():
    assert "email" in kinds('curl -A "bot jаn.kowalski84@example-mail.pl" https://x.org')  # Cyrillic a
    assert "name" in kinds('curl -A "bot Jan Kow​alski" https://x.org')  # zero-width space
    assert "name" in kinds('curl -A "bot Ｊan Kowalski" https://x.org')  # full-width J


def test_typos_transliteration_and_digits_ask():
    assert kinds('curl -A "bot Jan Kovalsky" https://x.org') & ASK_KINDS
    assert kinds('curl -A "bot Kowalskki" https://x.org')  # doubled letter: the exact scanner already denies it
    assert kinds('curl -A "bot Kowa1ski" https://x.org') & ASK_KINDS
    assert "email-fuzzy" in kinds('curl -A "bot jan.kowalsky84@example-mail.pl" https://x.org')
    assert "extra-fuzzy" in kinds('curl "https://x.org/?addr=Krakowske+Przedmiesce"')


def test_someone_else_and_ordinary_words_pass():
    assert not kinds('curl -A "bot Anna Kovalski" https://x.org')
    assert not kinds('curl -A "research-script/1.0" https://x.org/kowal/nowak')
    assert not kinds("curl https://api.github.com/repos/python/cpython/commits?per_page=5")


def test_any_email_in_contact_fields_asks():
    sec = ('curl -s -m 20 -A "tax-research research contact someone.else@gmail.com" '
           'https://data.sec.gov/submissions/CIK0000789019.json | python3 -c "import json,sys"')
    assert kinds(sec) == {"contact-email"}
    assert "contact-email" in kinds("curl -H 'From: a.b@corp.io' https://x.org")
    assert "contact-email" in kinds("curl 'https://x.org/form?email=a.b%40corp.io'")
    assert not kinds('curl -A "research-script/1.0 admin@company.example" https://x.org')
    alias = Identity(emails=ID.emails, names=ID.names, contact_alias=["agents@corp.io"])
    assert not kinds('curl -A "research agents@corp.io" https://x.org', alias)
    off = Identity(emails=ID.emails, names=ID.names, contact_fields="off")
    assert not kinds('curl -A "research a.b@corp.io" https://x.org', off)


def test_browser_typing_passes_page_scripts_do_not():
    typing = {"element": "Name field", "ref": "e12", "text": "Jan Kowalski jan.kowalski84@example-mail.pl"}
    assert not kinds(typing, tool="mcp__playwright__browser_type")
    script = {"function": "() => fetch('https://x.org/?u=jan.kowalski84@example-mail.pl')"}
    assert kinds(script, tool="mcp__playwright__browser_evaluate")


def test_hook_asks_for_fuzzy_and_denies_exact(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "HOME", tmp_path)
    ev = {"tool_name": "Bash", "tool_input": {"command": 'curl -A "bot Jan Kovalsky" https://x.org'}}
    assert hook.decide(ev, ID, False)["hookSpecificOutput"]["permissionDecision"] == "ask"
    ev["tool_input"]["command"] = 'curl -A "bot Jan Kowalski" https://x.org'
    assert hook.decide(ev, ID, False)["hookSpecificOutput"]["permissionDecision"] == "deny"
    strict = Identity(emails=ID.emails, names=ID.names, fuzzy="deny")
    ev["tool_input"]["command"] = 'curl -A "bot Jan Kovalsky" https://x.org'
    assert hook.decide(ev, strict, False)["hookSpecificOutput"]["permissionDecision"] == "deny"
    log = [json.loads(x) for x in (tmp_path / "log.jsonl").read_text().splitlines()]
    assert all("Kov" not in json.dumps(r) for r in log)
