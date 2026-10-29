"""PATH shim for curl / wget: refuse to run when the arguments carry the user's identity, else exec the real tool.

Works for every agent (and for scripts the agent writes that shell out to curl), because it sits on PATH, not inside
one agent's hook system. Install: put a `curl` launcher earlier on PATH than the real one, e.g.

    curl.cmd  ->  @python -I -m egress_guard.shim curl %*
    curl (sh) ->  exec python3 -I -m egress_guard.shim curl "$@"

The real binary is found by skipping the shim's own directory ($EGRESS_GUARD_SHIM_DIR) on PATH.
"""
import os
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

from egress_guard.hook import REASON, _log, load_identity
from egress_guard.scan import scan_tool_call


def real_binary(name: str) -> str | None:
    shim_dir = os.environ.get("EGRESS_GUARD_SHIM_DIR", "")
    parts = [p for p in os.environ.get("PATH", "").split(os.pathsep)
             if p and (not shim_dir or Path(p).resolve() != Path(shim_dir).resolve())]
    return shutil.which(name, path=os.pathsep.join(parts))


def main() -> int:
    if len(sys.argv) < 2:
        return 2
    tool, args = sys.argv[1], sys.argv[2:]
    ident, strict = load_identity()
    texts = [" ".join([tool, *args])]
    for i, a in enumerate(args):  # bodies and headers read from files: -d @body.json, -H @headers.txt, -K config
        if a.startswith("--") and "=" in a:  # --data-binary=@body.json, --config=file
            flag, _, val = a.partition("=")
            a = val if val.startswith("@") else ("@" + val if flag in ("--config", "--post-file", "--body-file")
                                                 else "")
        path = a[1:] if a.startswith("@") else (args[i + 1] if a in ("-K", "--config", "--post-file",
                                                                      "--body-file") and i + 1 < len(args) else "")
        if path and path != "-" and Path(path).is_file() and Path(path).stat().st_size < 2_000_000:
            texts.append(Path(path).read_text(encoding="utf-8", errors="replace"))
    found = scan_tool_call("Bash", {"command": texts}, ident, strict)
    if found:
        kinds = sorted({f.kind for f in found})
        _log({"tool": f"shim:{tool}", "blocked": True, "kinds": kinds})
        sys.stderr.write(REASON.format(kinds=", ".join(kinds)) + "\n")
        return 126
    real = real_binary(tool)
    if not real:
        sys.stderr.write(f"egress-guard shim: no real {tool} on PATH\n")
        return 127
    return subprocess.call([real, *args])  # nosec B603  # noqa: S603


if __name__ == "__main__":
    sys.exit(main())
