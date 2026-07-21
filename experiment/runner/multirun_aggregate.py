# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

"""Aggregate N>=2 repeated runs into mean +/- 95% CI, with paired-by-run diffs.

Addresses reviewer critique D4 (single-run point estimates).  Reads the r1..rN
result files for each configuration on a benchmark and reports mean and a 95%
confidence interval (small-sample t, dof=N-1).  For the key contrasts it computes
a paired-by-run difference (metric_A[run i] - metric_B[run i]) and its CI; if the
CI excludes 0 the difference is significant at the run level.  Stdlib only.

Usage:
    python3 runner/multirun_aggregate.py 128     # controlled benchmark
    python3 runner/multirun_aggregate.py cve      # real-CVE probe
    python3 runner/multirun_aggregate.py micro    # transformation micro-benchmark
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

RUNNER = Path(__file__).resolve().parent
EXPERIMENT = RUNNER.parent
sys.path.insert(0, str(RUNNER))
import evaluate as E  # noqa: E402
import score_cve_probe as S  # noqa: E402

# t_{0.975, dof} for small-sample 95% CIs.
T_975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365}

# benchmark -> (gt_file, run-id prefix, [(label, config_dir), ...], metric-fn key)
BENCH = {
    "128": (
        "ground_truth.json",
        "r",
        [
            ("SecPriv", "secpriv_sonnet"),
            ("Detector-only", "detector_only_sonnet"),
            ("C6-matched", "two_skill_matched"),
            ("No-skill", "no_skill_sonnet"),
        ],
        "match",
    ),
    "cve": (
        "ground_truth_cve.json",
        "cve_r",
        [
            ("SecPriv", "secpriv_sonnet"),
            ("Naked", "no_skill_sonnet"),
            ("Conservative", "no_skill_conservative"),
        ],
        "cve",
    ),
    "micro": (
        "ground_truth_transform.json",
        "tf_r",
        [("C1", "secpriv_sonnet"), ("C7", "no_shared_classifier")],
        "match",
    ),
}


def _mean_ci(xs: list[float]) -> tuple[float, float]:
    n = len(xs)
    if n == 0:
        return (0.0, 0.0)
    m = sum(xs) / n
    if n == 1:
        return (m, 0.0)
    sd = math.sqrt(sum((x - m) ** 2 for x in xs) / (n - 1))
    half = T_975.get(n - 1, 2.0) * sd / math.sqrt(n)
    return (m, half)


def _score_match_run(path: Path) -> dict:
    """P/R/F1/TN-rate for one run using stored per-case match fields."""
    cases = json.loads(path.read_text())["cases"]
    tp = fp = fn = tn_ok = tn_tot = 0
    for c in cases:
        m = c.get("match") or {}
        tp += m.get("tp", 0)
        fp += m.get("fp", 0)
        fn += m.get("fn", 0)
        if c["kind"].endswith("_tn"):
            tn_tot += 1
            tn_ok += 1 if m.get("tn_case_pass") else 0
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"P": p, "R": r, "F1": f1, "TN": tn_ok / tn_tot if tn_tot else 0.0}


def _score_cve_run(path: Path, gt: dict, aliases: dict, canon: set) -> dict:
    """Detection (Tier-1) and fixed-file noise for one CVE-probe run."""
    res = {c["case_id"]: c for c in json.loads(path.read_text())["cases"]}

    def emit(cid):
        fs = E.normalize_findings(
            E._extract_json_array(res.get(cid, {}).get("raw_output", "")) or [], aliases
        )
        for f in fs:
            f["category"] = S._canon(f["category"], canon)
        return fs

    pre = [c for c in gt.values() if c["kind"] == "security_tp"]
    post = [c for c in gt.values() if c["kind"] == "security_tn"]
    det = 0
    for c in pre:
        fam = S._accepts(c["expected_findings"][0]["category"])
        fs = emit(c["case_id"])
        if any(
            f["category"] in fam and f["file"] == Path(rel).name.lower()
            for rel in c["files"]
            for f in fs
        ):
            det += 1
    noise = sum(len(emit(c["case_id"])) for c in post)
    return {"Detect": det / len(pre), "Noise": noise / len(post)}


def main() -> None:
    which = sys.argv[1] if len(sys.argv) > 1 else "128"
    gt_file, prefix, configs, kind = BENCH[which]
    aliases = E._load_aliases()
    canon = set(aliases.values())
    gt = {
        c["case_id"]: c for c in json.loads((EXPERIMENT / gt_file).read_text())["cases"]
    }

    # collect per-run metric dicts per config
    per_config: dict[str, list[dict]] = {}
    for label, cfgdir in configs:
        runs = []
        for i in range(1, 8):
            p = EXPERIMENT / "results" / cfgdir / f"{prefix}{i}.json"
            if not p.exists():
                continue
            runs.append(
                _score_match_run(p)
                if kind == "match"
                else _score_cve_run(p, gt, aliases, canon)
            )
        per_config[label] = runs

    metrics = ["P", "R", "F1", "TN"] if kind == "match" else ["Detect", "Noise"]
    n_runs = max((len(v) for v in per_config.values()), default=0)
    print(f"\n=== {which} benchmark: N={n_runs} runs, mean +/- 95% CI ===\n")
    header = "Config".ljust(16) + "".join(m.rjust(16) for m in metrics)
    print(header)
    for label, _ in configs:
        runs = per_config[label]
        if not runs:
            print(f"{label:16s}{'(no runs)':>16}")
            continue
        cells = []
        for m in metrics:
            mean, half = _mean_ci([r[m] for r in runs])
            cells.append(f"{mean:.2f}+/-{half:.2f}".rjust(16))
        print(f"{label:16s}" + "".join(cells) + f"   (n={len(runs)})")

    # paired-by-run diffs vs the first config (SecPriv / C1)
    base_label = configs[0][0]
    base = per_config[base_label]
    print(f"\n  paired-by-run diff (vs {base_label}); * = 95% CI excludes 0:")
    for label, _ in configs[1:]:
        other = per_config[label]
        k = min(len(base), len(other))
        if k < 2:
            continue
        for m in metrics:
            diffs = [base[i][m] - other[i][m] for i in range(k)]
            mean, half = _mean_ci(diffs)
            sig = "*" if abs(mean) > half > 0 else " "
            print(
                f"    {base_label} - {label:14s} {m:7s}: {mean:+.3f} +/- {half:.3f} {sig}"
            )


if __name__ == "__main__":
    main()
