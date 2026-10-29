"""End-to-end: the hook as the agents run it (a fresh `python -I` process, event JSON on stdin)."""
import json
import os
import subprocess  # nosec B404
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"


def _run_hook(tmp_path, event):
    home = tmp_path / "guard"
    home.mkdir(exist_ok=True)
    (home / "identity.json").write_text(json.dumps({"emails": ["jan.kowalski84@example-mail.pl"],
                                                    "names": ["Jan Kowalski"], "autodetect": False}), encoding="utf-8")
    # -I ignores PYTHONPATH, so the source tree is put on sys.path by a tiny bootstrap instead
    code = f"import sys; sys.path.insert(0, {str(SRC)!r}); from egress_guard.hook import main; sys.exit(main())"
    r = subprocess.run([sys.executable, "-I", "-c", code], input=json.dumps(event), capture_output=True,  # noqa: S603
                       text=True, timeout=30, env=dict(os.environ, EGRESS_GUARD_HOME=str(home)))  # nosec B603
    assert r.returncode == 0, r.stderr
    return r.stdout, home


def test_hook_denies_identity_in_user_agent(tmp_path):
    ev = {"tool_name": "Bash", "tool_input": {"command": 'curl -A "bot/1.0 (jan.kowalski84@example-mail.pl)" '
                                                         "https://api.example.org/x"}}
    out, home = _run_hook(tmp_path, ev)
    d = json.loads(out)["hookSpecificOutput"]
    assert d["permissionDecision"] == "deny" and "email" in d["permissionDecisionReason"]
    log = (home / "log.jsonl").read_text(encoding="utf-8")
    assert "kowalski" not in log.lower()  # the log stores the kind, never the value


def test_hook_allows_generic_request(tmp_path):
    ev = {"tool_name": "Bash", "tool_input": {"command": 'curl -A "research-script/1.0" https://api.example.org/x'}}
    out, _ = _run_hook(tmp_path, ev)
    assert out == ""


def test_core_has_no_dependencies():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["dependencies"] == []
