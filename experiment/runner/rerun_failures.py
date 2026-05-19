"""
Re-run only the parse-failure cases from a completed run and patch the results
back into the original run JSON. Does NOT re-run cases that already succeeded.

Usage:
    python3 runner/rerun_failures.py --config secpriv_sonnet --run-id run1
    python3 runner/rerun_failures.py --config secpriv_haiku --run-id run1
    python3 runner/rerun_failures.py --config detector_only_sonnet --run-id run1
"""

from __future__ import annotations

import argparse
import json

# Import everything from the main evaluator
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import (
    _load_aliases,
    build_system_prompt,
    CaseResult,
    GT_PATH,
    load_config,
    per_category,
    ROOT,
    run_case,
    summarize,
)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--run-id", default="run1")
    args = ap.parse_args()

    run_path = ROOT / "results" / args.config / f"{args.run_id}.json"
    if not run_path.exists():
        print(f"Not found: {run_path}")
        return

    data = json.loads(run_path.read_text())
    gt = json.loads(GT_PATH.read_text())
    gt_by_id = {c["case_id"]: c for c in gt["cases"]}
    aliases = _load_aliases()
    cfg = load_config(args.config)
    system_prompt = build_system_prompt(cfg)

    failed_ids = [c["case_id"] for c in data["cases"] if not c["parse_ok"]]
    print(f"[{args.config}/{args.run_id}] {len(failed_ids)} parse failures to re-run")
    if not failed_ids:
        print("Nothing to re-run.")
        return

    patched = 0
    for i, case_id in enumerate(failed_ids, 1):
        gt_case = gt_by_id.get(case_id)
        if not gt_case:
            print(
                f"  [{i}/{len(failed_ids)}] {case_id} not found in ground truth, skipping"
            )
            continue
        print(f"  [{i}/{len(failed_ids)}] re-running {case_id}...", end=" ", flush=True)
        result = run_case(cfg, system_prompt, gt_case, aliases)
        if result.parse_ok:
            # Patch into original data
            for j, c in enumerate(data["cases"]):
                if c["case_id"] == case_id:
                    data["cases"][j] = asdict(result)
                    break
            patched += 1
            print(
                f"OK (emitted={len(result.emitted)} tp={result.match['tp']} "
                f"fp={result.match['fp']} fn={result.match['fn']})"
            )
        else:
            print("STILL FAILED (retries exhausted)")

    # Recompute summary
    results_objs = []
    for c in data["cases"]:
        r = CaseResult(
            case_id=c["case_id"],
            file=c["file"],
            kind=c["kind"],
            emitted=c.get("emitted", []),
            raw_output=c.get("raw_output", ""),
            parse_ok=c.get("parse_ok", False),
            match=c.get("match", {}),
            meta=c.get("meta", {}),
        )
        results_objs.append(r)

    data["summary"] = summarize(results_objs)
    data["per_category"] = per_category(results_objs, gt["cases"])
    data["rerun_patched"] = patched

    run_path.write_text(json.dumps(data, indent=2))
    s = data["summary"]
    print(
        f"\n[{args.config}/{args.run_id}] Patched {patched}/{len(failed_ids)} failures."
    )
    print(
        f"  Updated: P={s['precision']:.3f} R={s['recall']:.3f} F1={s['f1']:.3f} "
        f"TN={s['tn_pass']}/{s['tn_cases']} parse_fail={s['parse_failures']}"
    )


if __name__ == "__main__":
    main()
