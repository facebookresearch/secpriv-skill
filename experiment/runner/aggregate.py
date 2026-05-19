"""
Aggregates per-run results into the tables and statistics needed by the paper.

Reads results/<config>/run*.json for each configuration, computes mean and stdev
across runs, and prints a markdown summary.

Outputs:
- results/aggregate.json   — machine-readable
- results/aggregate.md     — copy-paste-ready table for the paper

Usage:
    python3 aggregate.py
"""

from __future__ import annotations

import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

CANONICAL_CATS = [
    # security
    "sql_injection",
    "command_injection",
    "path_traversal",
    "xss",
    "auth_bypass",
    "hardcoded_secret",
    "deserialization",
    "eval_injection",
    "infinite_loop",
    "agent_csrf",
    "second_order_sqli",
    # privacy
    "pii_leakage",
    "data_retention",
    "consent_bypass",
    "third_party_sharing",
    "re_identification_risk",
    "data_minimization",
    "purpose_creep",
]

CONFIGS = [
    "secpriv_sonnet",
    "no_skill_sonnet",
    "secpriv_haiku",
    "detector_only_sonnet",
    "two_skill_sonnet",
]


def _load_runs(cfg: str) -> list[dict]:
    d = RESULTS / cfg
    if not d.exists():
        return []
    runs = []
    for p in sorted(d.glob("run*.json")):
        runs.append(json.loads(p.read_text()))
    return runs


def _mean_std(xs: list[float]) -> tuple[float, float]:
    if not xs:
        return (0.0, 0.0)
    m = sum(xs) / len(xs)
    var = sum((x - m) ** 2 for x in xs) / len(xs)
    return (m, math.sqrt(var))


def aggregate_config(cfg: str) -> dict | None:  # noqa: C901
    runs = _load_runs(cfg)
    if not runs:
        return None
    summaries = [r["summary"] for r in runs]
    p_mean, p_std = _mean_std([s["precision"] for s in summaries])
    r_mean, r_std = _mean_std([s["recall"] for s in summaries])
    f_mean, f_std = _mean_std([s["f1"] for s in summaries])
    tn_pass_mean, _ = _mean_std([s["tn_pass"] for s in summaries])
    tn_total = summaries[0]["tn_cases"]
    parse_fail_mean, _ = _mean_std([s["parse_failures"] for s in summaries])
    lat_mean, _ = _mean_std([s["mean_latency_s"] for s in summaries])

    # Per-category recall: average recall across runs.
    cat_recalls: dict[str, list[float]] = {}
    for r in runs:
        for cat, info in r.get("per_category", {}).items():
            cat_recalls.setdefault(cat, []).append(info["recall"] or 0.0)
    per_cat = {}
    for cat in CANONICAL_CATS:
        if cat not in cat_recalls:
            per_cat[cat] = {"recall": None, "std": None, "n_runs": 0}
            continue
        m, s = _mean_std(cat_recalls[cat])
        per_cat[cat] = {
            "recall": round(m, 4),
            "std": round(s, 4),
            "n_runs": len(cat_recalls[cat]),
        }

    # Per-case stability: fraction of cases producing identical (sorted-category-set) emitted outcomes across runs.
    if len(runs) >= 2:
        case_outcomes: dict[str, list[tuple]] = {}
        for r in runs:
            for c in r["cases"]:
                key = c["case_id"]
                emitted = tuple(
                    sorted({(f["category"], f["surface"]) for f in c["emitted"]})
                )
                case_outcomes.setdefault(key, []).append(emitted)
        tp_stable = 0
        tp_total = 0
        tn_stable = 0
        tn_total_c = 0
        for cid, outs in case_outcomes.items():
            kind = next(
                c["kind"] for r in runs for c in r["cases"] if c["case_id"] == cid
            )
            stable = len(set(outs)) == 1
            if "_tp" in kind:
                tp_total += 1
                if stable:
                    tp_stable += 1
            elif "_tn" in kind:
                tn_total_c += 1
                if stable:
                    tn_stable += 1
        stability = {
            "tp_stable": tp_stable,
            "tp_total": tp_total,
            "tn_stable": tn_stable,
            "tn_total": tn_total_c,
        }
    else:
        stability = None

    return {
        "config": cfg,
        "n_runs": len(runs),
        "precision": (round(p_mean, 4), round(p_std, 4)),
        "recall": (round(r_mean, 4), round(r_std, 4)),
        "f1": (round(f_mean, 4), round(f_std, 4)),
        "tn_pass": round(tn_pass_mean, 1),
        "tn_total": tn_total,
        "parse_failures": round(parse_fail_mean, 1),
        "mean_latency_s": round(lat_mean, 1),
        "per_category": per_cat,
        "stability": stability,
    }


def aggregate_cross_domain(cfg: str) -> dict | None:
    """Filter to cross_tp + cross_tn cases and recompute precision/recall/F1."""
    runs = _load_runs(cfg)
    if not runs:
        return None
    tps, fps, fns, tn_pass = [], [], [], 0
    for r in runs:
        rt, rf, rn = 0, 0, 0
        for c in r["cases"]:
            if not c["kind"].startswith("cross_"):
                continue
            rt += c["match"]["tp"]
            rf += c["match"]["fp"]
            rn += c["match"]["fn"]
            if c["kind"] == "cross_tn" and c["match"].get("tn_case_pass"):
                tn_pass += 1
        tps.append(rt)
        fps.append(rf)
        fns.append(rn)
    tp_m = sum(tps) / len(tps)
    fp_m = sum(fps) / len(fps)
    fn_m = sum(fns) / len(fns)
    p = tp_m / (tp_m + fp_m) if (tp_m + fp_m) else 0.0
    rc = tp_m / (tp_m + fn_m) if (tp_m + fn_m) else 0.0
    f1 = 2 * p * rc / (p + rc) if (p + rc) else 0.0
    return {
        "config": cfg,
        "tp": tp_m,
        "fp": fp_m,
        "fn": fn_m,
        "precision": round(p, 4),
        "recall": round(rc, 4),
        "f1": round(f1, 4),
        "tn_pass_total": tn_pass,
    }


def main() -> None:
    out: dict = {"by_config": {}, "cross_domain": {}}
    print("=" * 70)
    print(f"{'Config':<26} {'Prec':>8} {'Recall':>8} {'F1':>8} {'TN':>10} {'Lat':>7}")
    print("-" * 70)
    for cfg in CONFIGS:
        agg = aggregate_config(cfg)
        if agg is None:
            print(f"{cfg:<26} (no runs)")
            continue
        out["by_config"][cfg] = agg
        prc = f"{agg['precision'][0]:.3f}±{agg['precision'][1]:.2f}"
        rec = f"{agg['recall'][0]:.3f}±{agg['recall'][1]:.2f}"
        f1 = f"{agg['f1'][0]:.3f}±{agg['f1'][1]:.2f}"
        tn = f"{agg['tn_pass']:.0f}/{agg['tn_total']}"
        print(
            f"{cfg:<26} {prc:>10} {rec:>10} {f1:>10} {tn:>10} {agg['mean_latency_s']:>5.1f}s"
        )
    print("=" * 70)

    print("\n--- Cross-domain (6 cases) ---")
    print(f"{'Config':<26} {'Prec':>8} {'Recall':>8} {'F1':>8}")
    for cfg in CONFIGS:
        a = aggregate_cross_domain(cfg)
        if a is None:
            continue
        out["cross_domain"][cfg] = a
        print(f"{cfg:<26} {a['precision']:>8.3f} {a['recall']:>8.3f} {a['f1']:>8.3f}")

    # Per-category recall.
    print("\n--- Per-category recall (SecPriv-Sonnet) ---")
    sp = out["by_config"].get("secpriv_sonnet")
    if sp:
        print(f"{'Category':<28} {'Recall':>8} {'Std':>6}")
        for cat, info in sp["per_category"].items():
            if info["recall"] is None:
                continue
            print(f"{cat:<28} {info['recall']:>8.3f} {info['std']:>6.3f}")

    # Stability.
    for cfg in CONFIGS:
        agg = out["by_config"].get(cfg)
        if not agg or not agg.get("stability"):
            continue
        s = agg["stability"]
        if s["tp_total"]:
            tp_pct = 100 * s["tp_stable"] / s["tp_total"]
            tn_pct = 100 * s["tn_stable"] / max(1, s["tn_total"])
            print(
                f"\n[{cfg}] TP stability: {s['tp_stable']}/{s['tp_total']} = {tp_pct:.0f}% | "
                f"TN stability: {s['tn_stable']}/{s['tn_total']} = {tn_pct:.0f}%"
            )

    (RESULTS / "aggregate.json").write_text(json.dumps(out, indent=2))
    print(f"\nWritten to {RESULTS / 'aggregate.json'}")


if __name__ == "__main__":
    main()
