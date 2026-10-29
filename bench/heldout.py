"""Score the scanner on the independent held-out set written by Codex (bench/data/egress_heldout_codex.jsonl).

The set was written by a different model family (OpenAI Codex) from the tool description only (2026-10-26); the
author had not seen it when the scanner was tuned. Run it once per scanner version and keep every result: after fixes made
from its errors, the set is no longer held out (bench/out/heldout-<tag>.json).

    python -I bench/heldout.py <tag>
"""
import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
from egress_guard.scan import Identity, scan_tool_call


def wilson(k, n, z=1.96):
    p, d = k / n, 1 + z * z / n
    c, h = p + z * z / (2 * n), z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return round(max(0.0, (c - h) / d), 3), round(min(1.0, (c + h) / d), 3)


rows = [json.loads(x) for x in (HERE / "data" / "egress_heldout_codex.jsonl").read_text(encoding="utf-8").splitlines()
        if x.strip()]
miss, false_alarm = [], []
for r in rows:
    hit = bool(scan_tool_call(r["tool_name"], r["tool_input"],
                              Identity(emails=r["identity"]["emails"], names=r["identity"]["names"])))
    if r["label"] == "leak" and not hit:
        miss.append(r["id"] + " " + r["variant"])
    if r["label"] == "clean" and hit:
        false_alarm.append(r["id"] + " " + r["variant"])
n_leak = sum(r["label"] == "leak" for r in rows)
n_clean = len(rows) - n_leak
res = {"tag": sys.argv[1] if len(sys.argv) > 1 else "run", "rows": len(rows),
       "recall": [n_leak - len(miss), n_leak, wilson(n_leak - len(miss), n_leak)],
       "fpr": [len(false_alarm), n_clean, wilson(len(false_alarm), n_clean)],
       "missed": miss, "false_alarms": false_alarm}
(HERE / "out").mkdir(exist_ok=True)
(HERE / "out" / f"heldout-{res['tag']}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
print(json.dumps(res, indent=1))
