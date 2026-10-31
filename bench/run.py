"""Gate bench: run the scanner over bench/data/egress_v1.jsonl and write bench/result.json; exits non-zero when a limit in
bench/thresholds.json is not met.

The full comparison with Presidio, GLiNER and Jev is bench_detectors.py / bench_jev.py (heavy, not part of the gate).
Note: the scanner was tuned after its errors on this set were read (2026-10-26), so these numbers guard against
regressions; they are not a held-out estimate.
"""
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
from egress_guard.scan import Identity, scan_tool_call

rows = [json.loads(x) for x in (HERE / "data" / "egress_v1.jsonl").read_text(encoding="utf-8").splitlines() if x]
lat, tp, fn, fp, tn, contact_neg = [], 0, 0, 0, 0, 0
for _ in range(5):
    for r in rows:
        ident = Identity(emails=r["identity"]["emails"], names=r["identity"]["names"])
        t = time.perf_counter()
        found = scan_tool_call(r["tool_name"], r["tool_input"], ident)
        # 0.2.0: an e-mail of anyone in a User-Agent / From field is a question by design; this set labels other
        # people's addresses as fine, so those asks are counted apart, not as false alarms on the identity
        hit = any(f.kind != "contact-email" for f in found)
        lat.append((time.perf_counter() - t) * 1000)
        if _ == 0:
            leak = r["label"] == "leak"
            tp += hit and leak
            fn += leak and not hit
            fp += hit and not leak
            tn += not hit and not leak
            contact_neg += (not leak) and not hit and any(f.kind == "contact-email" for f in found)
lat.sort()
result = {"recall": round(tp / (tp + fn), 4), "fpr": round(fp / (fp + tn), 4),
          "p95_ms": round(lat[int(0.95 * len(lat)) - 1], 3), "rows": len(rows),
          "contact_asks_on_negatives": contact_neg}
(HERE / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
print(result)
limits = json.loads((HERE / "thresholds.json").read_text(encoding="utf-8"))
bad = [k for k, lim in limits.items() if ("min" in lim and result[k] < lim["min"]) or ("max" in lim and result[k] > lim["max"])]
if bad:
    sys.exit(f"gate FAIL: {bad} outside bench/thresholds.json")
print("gate PASS")
