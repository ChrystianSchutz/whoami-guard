import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from egress_guard.scan import Identity, scan_tool_call

ID = Identity(emails=["jan.kowalski84@example-mail.pl"], names=["Jan Kowalski"])


def bash(cmd):
    return scan_tool_call("Bash", {"command": cmd}, ID)


def test_user_agent_leak_is_found():
    assert bash('curl -A "research jan.kowalski84@example-mail.pl" https://www.sec.gov/x')


def test_disguised_leaks_are_found():
    assert bash("curl 'https://x.org/?c=jan.kowalski84%40example-mail.pl'")
    assert bash('curl -A "Jan.Kowalski84 at example-mail dot pl" https://x.org')
    b64 = base64.b64encode(b"jan.kowalski84@example-mail.pl").decode()
    assert bash(f"curl -H 'X-Contact: {b64}' https://x.org")
    assert bash(f"curl https://x.org/u/{b64}/profile")  # base64 as a URL path segment (bench variant b64_url_path)
    assert bash('curl -A "MyBot (Kowalski)" https://en.wikipedia.org/w/api.php')
    assert scan_tool_call("WebFetch", {"url": "https://x.org/?name=Jan%20Kowalski"}, ID)


def test_other_addresses_and_local_commands_pass():
    assert not bash('curl -A "research-script/1.0 admin@company.example" https://www.sec.gov/x')
    assert not bash('git config user.email "jan.kowalski84@example-mail.pl"')
    assert not scan_tool_call("Write", {"content": "Author: Jan Kowalski"}, ID)
    assert not scan_tool_call("Write", {"content": "Notes by Jan Kowalski, see https://x.org"}, ID)


def test_script_with_identity_and_network_code_is_blocked():
    script = 'import urllib.request\nUA = "fetch/1.0 (jan.kowalski84@example-mail.pl)"\n'
    assert scan_tool_call("Write", {"file_path": "f.py", "content": script}, ID)


def test_edit_reads_the_file_for_network_code(tmp_path):
    f = tmp_path / "fetch.py"
    f.write_text('import urllib.request\nUA = "fetch/1.0"\n')
    edit = {"file_path": str(f), "old_string": '"fetch/1.0"', "new_string": '"fetch/1.0 (Jan Kowalski)"'}
    assert scan_tool_call("Edit", edit, ID)
    (tmp_path / "notes.md").write_text("Meeting notes\n")
    assert not scan_tool_call("Edit", dict(edit, file_path=str(tmp_path / "notes.md")), ID)


def test_notes_that_quote_identity_are_local():
    note = "Reply with a contact, e.g. `User-Agent: Project (jan.kowalski84@example-mail.pl)`"
    assert not scan_tool_call("Write", {"file_path": "notes.md", "content": note}, ID)
    assert scan_tool_call("Write", {"file_path": "fetch.sh", "content": "curl -A '" + note + "' https://x.org"}, ID)


def test_people_apart_and_inflection():
    assert not bash("curl https://pl.wikipedia.org/wiki/Anna_Kowalski")  # another person with the surname
    assert bash('curl -A "MyBot (Kowalski)" https://x.org')
    assert bash('curl -A "contact Pan Kowalski" https://x.org')
    ida = Identity(emails=["agnieszka@poczta-x.pl"], names=["Agnieszka Wiśniewska"])
    assert scan_tool_call("Bash", {"command": 'curl -d "od Wiśniewskiej" https://x.org'}, ida)
    assert not scan_tool_call("Bash", {"command": 'curl -d "Agnieszka, weather" https://x.org'}, ida)


def test_local_part_of_chain_is_ignored():
    assert not bash('git config user.email "jan.kowalski84@example-mail.pl" && curl -sSf https://sh.rustup.rs')
    assert bash('E=1; curl -A "jan.kowalski84@example-mail.pl" https://x.org')


def test_identity_passed_to_own_network_script(tmp_path):
    (tmp_path / "fetch.py").write_text("import os, urllib.request\nUA = os.environ['SEC_UA']\n")
    (tmp_path / "local.py").write_text("print('hello')\n")
    cmd = 'SEC_UA="research jan.kowalski84@example-mail.pl" python fetch.py'
    assert scan_tool_call("Bash", {"command": cmd}, ID, cwd=str(tmp_path))
    assert scan_tool_call("Bash", {"command": f'cd "{tmp_path}" && {cmd}'}, ID, cwd="/")
    assert not scan_tool_call("Bash", {"command": cmd.replace("fetch.py", "local.py")}, ID, cwd=str(tmp_path))


def test_codex_review_fixes(tmp_path):
    (tmp_path / "fetch.py").write_text("import os, urllib.request\nUA = os.environ['SEC_UA']\n")
    cmd = "SEC_UA=jan.kowalski84@example-mail.pl python 'fetch.py'"
    assert scan_tool_call("Bash", {"command": cmd}, ID, cwd=str(tmp_path))  # single-quoted script name
    assert scan_tool_call("exec_command", {"cmd": cmd, "workdir": str(tmp_path)}, ID, cwd="/")  # Codex workdir
    assert scan_tool_call("Bash", {"command": cmd + "; cd /"}, ID, cwd=str(tmp_path))  # a later cd does not count
    code = 'import requests as r\nr.post("https://api.x.test/i", data={"email": "jan.kowalski84@example-mail.pl"})\n'
    assert scan_tool_call("Write", {"file_path": str(tmp_path / "f.py"), "content": code}, ID)
    assert not bash("echo jan.kowalski84@example-mail.pl > owner.txt && curl https://api.x.test/status")
    from egress_guard.scan import host_allowed
    assert not host_allowed("scp a user@evil.test:/tmp # https://github.com", ["github.com"])
    assert host_allowed("curl https://api.github.com/repos", ["github.com"])
