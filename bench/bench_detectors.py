"""Detector benchmark for agent egress PII (synthetic identities, bench/data/egress_v1.jsonl).

Each system runs in its own interpreter/venv inside the lab, so the script has three sub-commands:

  predict   --system S [--threads N]  -> bench/out/<S>.json  (per-row prediction or entity spans + warm latency)
  coldstart --system S                -> one call in a fresh process (timed by the caller, see `cold`)
  cold      --system S --python P     -> runs `coldstart` 3x in fresh processes, stores the median wall time
  aggregate                            -> bench/reports/detectors-<date>.json + markdown tables on stdout

Systems
  egress_guard        src/egress_guard/scan.py (identity-aware, normalised, network gate)
  exact_match         case-insensitive substring of the user's e-mail or full name (the "20-line hook" baseline)
  regex_email         any e-mail address anywhere = leak (plain regex)
  presidio_pattern    Presidio EmailRecognizer only (no NLP engine)
  presidio_sm/lg      Presidio AnalyzerEngine with spaCy en_core_web_sm / en_core_web_lg (EMAIL_ADDRESS, PERSON)
  gliner_multi_pii    urchade/gliner_multi_pii-v1 on CPU, labels person/email
  gliner_pii_edge     knowledgator/gliner-pii-edge-v1.0 on CPU, labels person/email
Model systems are scored twice: "generic" (any e-mail/person found = leak) and "+id" (only spans that match the
user's identity, and only for tool calls that egress-guard's network gate would scan).
"""
import argparse
import json
import math
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
from egress_guard.scan import NETWORK, Identity, fold, scan_tool_call, strings_of

DATA = HERE / "data" / "egress_v1.jsonl"
OUT = HERE / "out"
REPORTS = HERE / "reports"
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
MODEL_SYSTEMS = {"presidio_pattern", "presidio_sm", "presidio_lg", "gliner_multi_pii", "gliner_pii_edge"}
GLINER_IDS = {"gliner_multi_pii": "urchade/gliner_multi_pii-v1", "gliner_pii_edge": "knowledgator/gliner-pii-edge-v1.0"}
GLINER_LABELS = ["person", "email"]


def load_rows():
    return [json.loads(line) for line in DATA.open(encoding="utf-8")]


def text_of(row):
    return "\n".join(strings_of(row["tool_input"]))


# ---------------------------------------------------------------- detectors: f(row) -> bool or list of spans
def make_detector(system):
    if system == "egress_guard":
        def det(row):
            ident = Identity(emails=row["identity"]["emails"], names=row["identity"]["names"])
            return bool(scan_tool_call(row["tool_name"], row["tool_input"], ident))
        return det
    if system == "exact_match":
        def det(row):
            t = text_of(row).lower()
            needles = [e.lower() for e in row["identity"]["emails"]] + [n.lower() for n in row["identity"]["names"]]
            return any(n in t for n in needles)
        return det
    if system == "regex_email":
        return lambda row: bool(EMAIL_RE.search(text_of(row)))
    if system == "presidio_pattern":
        from presidio_analyzer.predefined_recognizers import EmailRecognizer
        rec = EmailRecognizer()

        def det(row):
            t = text_of(row)
            return [("EMAIL_ADDRESS", t[r.start:r.end]) for r in rec.analyze(t, ["EMAIL_ADDRESS"], None)]
        return det
    if system in ("presidio_sm", "presidio_lg"):
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        model = "en_core_web_sm" if system == "presidio_sm" else "en_core_web_lg"
        nlp = NlpEngineProvider(nlp_configuration={"nlp_engine_name": "spacy",
                                                   "models": [{"lang_code": "en", "model_name": model}]}).create_engine()
        eng = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])

        def det(row):
            t = text_of(row)
            return [(r.entity_type, t[r.start:r.end])
                    for r in eng.analyze(t, language="en", entities=["EMAIL_ADDRESS", "PERSON"])]
        return det
    if system in GLINER_IDS:
        from gliner import GLiNER
        m = GLiNER.from_pretrained(GLINER_IDS[system])
        m.eval()

        def det(row):
            return [(e["label"], e["text"]) for e in m.predict_entities(text_of(row), GLINER_LABELS, threshold=0.5)]
        return det
    raise SystemExit(f"unknown system {system}")


# ---------------------------------------------------------------- identity filter for generic detectors
def span_is_user(kind, span, ident):
    s = fold(span)
    if "@" in s or kind.lower().startswith("email"):
        for e in ident["emails"]:
            local, dom = fold(e).rsplit("@", 1)
            if fold(e) in s or (local.split("+")[0] in s and dom in s):
                return True
        return False
    for n in ident["names"]:
        parts = fold(n).split()
        if fold(n) in s or (len(parts[-1]) >= 3 and re.search(r"\b" + re.escape(parts[-1]), s)):
            return True
    return False


def gated(row):
    """egress-guard's default gate: Bash/PowerShell only when the command talks to the network; never Write/Edit."""
    if row["tool_name"] in ("Write", "Edit", "apply_patch", "NotebookEdit"):
        return False
    if row["tool_name"] in ("Bash", "PowerShell", "exec_command", "shell"):
        return bool(NETWORK.search(text_of(row)))
    return True


# ---------------------------------------------------------------- sub-commands
def cmd_predict(a):
    if a.threads:
        try:
            import torch
            torch.set_num_threads(a.threads)
        except ImportError:
            pass
    rows = load_rows()
    t0 = time.perf_counter()
    det = make_detector(a.system)
    load_s = time.perf_counter() - t0
    for row in rows[:20]:  # warm-up
        det(row)
    preds, lat = {}, []
    for rep in range(a.reps):
        for row in rows:
            t = time.perf_counter_ns()
            p = det(row)
            lat.append((time.perf_counter_ns() - t) / 1e6)
            if rep == 0:
                preds[row["id"]] = p
    OUT.mkdir(exist_ok=True)
    out = {"system": a.system, "threads": a.threads, "load_s": round(load_s, 3), "reps": a.reps,
           "latency_ms": lat, "pred": preds, "python": sys.version.split()[0]}
    (OUT / f"{a.system}.json").write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    print(f"{a.system}: load {load_s:.2f}s, p50 {pct(lat, 50):.3f} ms, p95 {pct(lat, 95):.3f} ms")


def cmd_coldstart(a):
    det = make_detector(a.system)
    det(load_rows()[0])


def cmd_cold(a):
    times = []
    for _ in range(3):
        t = time.perf_counter()
        subprocess.run([a.python, "-I", str(Path(__file__).resolve()), "coldstart", "--system", a.system],
                       check=True, env={**os.environ, "HF_HUB_OFFLINE": "1"})
        times.append(time.perf_counter() - t)
    p = OUT / f"{a.system}.json"
    d = json.loads(p.read_text(encoding="utf-8"))
    d["cold_start_s"] = round(statistics.median(times), 3)
    d["cold_start_runs_s"] = [round(x, 3) for x in times]
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    print(f"{a.system}: cold start (fresh process, import + load + 1 call) median {d['cold_start_s']} s")


def pct(xs, q):
    xs = sorted(xs)
    k = (len(xs) - 1) * q / 100
    lo, hi = math.floor(k), math.ceil(k)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def wilson(k, n, z=1.96):
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def rate(k, n):
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci95": wilson(k, n)}


def scored_variants(d, rows_by_id):
    """{variant name: {row id: bool}} for one system's output file."""
    if d["system"] not in MODEL_SYSTEMS:
        return {d["system"]: {i: bool(p) for i, p in d["pred"].items()}}
    gen = {i: bool(spans) for i, spans in d["pred"].items()}
    idf = {i: gated(rows_by_id[i]) and any(span_is_user(k, s, rows_by_id[i]["identity"]) for k, s in spans)
           for i, spans in d["pred"].items()}
    return {d["system"]: gen, d["system"] + "+id": idf}


def cmd_aggregate(a):
    rows = load_rows()
    by_id = {r["id"]: r for r in rows}
    systems, per_variant = {}, {}
    for f in sorted(OUT.glob("*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        lat = d["latency_ms"]
        for name, pred in scored_variants(d, by_id).items():
            res = {}
            for split in ("test", "all"):
                sel = [r for r in rows if split == "all" or r["split"] == split]
                leaks = [r for r in sel if r["label"] == "leak"]
                clean = [r for r in sel if r["label"] == "clean"]
                res[split] = {"recall": rate(sum(pred[r["id"]] for r in leaks), len(leaks)),
                              "fpr": rate(sum(pred[r["id"]] for r in clean), len(clean))}
            res["latency_ms"] = {"p50": round(pct(lat, 50), 4), "p95": round(pct(lat, 95), 4),
                                 "p99": round(pct(lat, 99), 4), "max": round(max(lat), 3), "n_calls": len(lat)}
            res["load_s"] = d["load_s"]
            res["cold_start_s"] = d.get("cold_start_s")
            res["threads"] = d.get("threads")
            systems[name] = res
            pv = {}
            for r in rows:
                if r["split"] != "test":
                    continue
                pv.setdefault((r["label"], r["variant"]), []).append(pred[r["id"]])
            per_variant[name] = {f"{lab}:{v}": [sum(x), len(x)] for (lab, v), x in sorted(pv.items())}
    misses = {name: sorted(f"{lab}:{v}" for lab_v, (k, n) in pv.items()
                           for lab, v in [lab_v.split(":", 1)] if (lab == "leak" and k < n) or (lab == "clean" and k))
              for name, pv in per_variant.items()}
    result = {"dataset": str(DATA.relative_to(HERE.parent)), "rows": len(rows),
              "test": {"leak": sum(1 for r in rows if r["split"] == "test" and r["label"] == "leak"),
                       "clean": sum(1 for r in rows if r["split"] == "test" and r["label"] == "clean")},
              "date": a.date, "systems": systems, "per_variant_test": per_variant, "imperfect_variants_test": misses}
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / f"detectors-{a.date}.json").write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    print(markdown_tables(result))


def markdown_tables(res):
    """Main table + per-variant recall/FP table (test split) as markdown, for the summary report."""
    def ci(r):
        return f"{r['rate']:.3f} [{r['ci95'][0]:.3f}, {r['ci95'][1]:.3f}]"
    lines = [("| system | recall (test) [95% CI] | FPR (test) [95% CI] | recall (all) | FPR (all) | p50 ms | p95 ms "
              "| load s | cold start s |"), "|---|---|---|---|---|---|---|---|---|"]
    for name, s in sorted(res["systems"].items(), key=lambda kv: -kv[1]["test"]["recall"]["rate"]
                          + kv[1]["test"]["fpr"]["rate"]):
        lines.append(f"| {name} | {ci(s['test']['recall'])} | {ci(s['test']['fpr'])} | "
                     f"{s['all']['recall']['rate']:.3f} | {s['all']['fpr']['rate']:.3f} | {s['latency_ms']['p50']:.3f} | "
                     f"{s['latency_ms']['p95']:.3f} | {s['load_s']} | {s['cold_start_s']} |")
    names = sorted(res["per_variant_test"])
    lines += ["", "| variant (test, k/n flagged) | " + " | ".join(names) + " |", "|---" * (len(names) + 1) + "|"]
    keys = sorted(res["per_variant_test"][names[0]], key=lambda k: (not k.startswith("leak"), k))
    for k in keys:
        lines.append(f"| {k} | " + " | ".join("{}/{}".format(*res["per_variant_test"][n][k]) for n in names) + " |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("predict")
    p.add_argument("--system", required=True)
    p.add_argument("--threads", type=int, default=0)
    p.add_argument("--reps", type=int, default=1)
    p = sub.add_parser("coldstart")
    p.add_argument("--system", required=True)
    p = sub.add_parser("cold")
    p.add_argument("--system", required=True)
    p.add_argument("--python", default=sys.executable)
    p = sub.add_parser("aggregate")
    p.add_argument("--date", default="2026-10-26")
    a = ap.parse_args()
    {"predict": cmd_predict, "coldstart": cmd_coldstart, "cold": cmd_cold, "aggregate": cmd_aggregate}[a.cmd](a)


if __name__ == "__main__":
    main()
