"""Launcher for the whoami-guard PreToolUse hook that works with `python -I`.

`python -I` (isolated mode, recommended for hooks) ignores PYTHONPATH and the user site-packages, so a
`pip install --user` copy of whoami-guard is invisible to `python -I -m egress_guard.hook`. This launcher loads a
pinned copy of the package from the folder next to it instead:

    ~/.egress-guard/run_hook.py          (this file)
    ~/.egress-guard/pkg/egress_guard/    (copy of src/egress_guard/)

Hook command:   python -I ~/.egress-guard/run_hook.py   (use the absolute path on Windows)
Exceptions:     python ~/.egress-guard/run_hook.py allow --host example.com --session ID
                (this install puts no `whoami-guard-allow` on PATH; block messages print this form with full paths)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "pkg"))

if sys.argv[1:2] == ["allow"]:
    from egress_guard.allow import main as allow_main  # noqa: E402

    sys.exit(allow_main(sys.argv[2:]))

from egress_guard.hook import main  # noqa: E402

sys.exit(main())
