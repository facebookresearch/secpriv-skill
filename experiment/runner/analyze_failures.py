# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Inspects results/<config>/run*.json and prints, for each missed TP and each FP,
the case_id, the unmatched expected/emitted, and a heuristic failure-mode label.

Heuristic labels (per the paper's failure-mode taxonomy):
- adversarial-evasion: FP on a TN case whose boundary mentions a safety construct
  the model failed to recognize (salted hash, decorator, parameterized).
- semantic-understanding: missed TP whose category requires intent/cross-construct reasoning
  (purpose_creep, second_order_sqli, agent_csrf, consent temporal ordering).
- absence-enumeration: missed TP whose category requires noticing a missing construct
  (data_retention, re_identification_risk, hardcoded_secret in some cases).

Usage:
    python3 analyze_failures.py --config secpriv_sonnet
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

ABSENCE_CATS = {"data_retention", "re_identification_risk", "data_minimization"}
SEMANTIC_CATS = {"purpose_creep", "second_order_sqli", "agent_csrf", "consent_bypass"}


def label_miss(expected: dict) -> str:
    cat = expected["category"]
    if cat in ABSENCE_CATS:
        return "absence-enumeration"
    if cat in SEMANTIC_CATS:
        return "semantic-understanding"
    return "other"


def label_fp(case: dict) -> str:
    boundary = (
        (case.get("kind") == "security_tn")
        or (case.get("kind") == "privacy_tn")
        or (case.get("kind") == "cross_tn")
    )
    if boundary:
        return "adversarial-evasion"
    return "spurious"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--run-id", default="run1")
    args = ap.parse_args()

    p = RESULTS / args.config / f"{args.run_id}.json"
    if not p.exists():
        print(f"Not found: {p}")
        return
    data = json.loads(p.read_text())

    misses: list[dict] = []
    fps: list[dict] = []
    for c in data["cases"]:
        for ef in c["match"].get("unmatched_expected", []):
            misses.append(
                {
                    "case_id": c["case_id"],
                    "kind": c["kind"],
                    "category": ef["category"],
                    "label": label_miss(ef),
                }
            )
        if c["match"]["fp"] > 0:
            for em in c["match"].get("unmatched_emitted", []):
                fps.append(
                    {
                        "case_id": c["case_id"],
                        "kind": c["kind"],
                        "category": em["category"],
                        "label": label_fp(c),
                    }
                )

    print(f"=== {args.config} / {args.run_id} ===")
    print(f"Misses ({len(misses)}):")
    for m in misses:
        print(
            f"  {m['case_id']:9s} kind={m['kind']:11s} cat={m['category']:24s} → {m['label']}"
        )
    by_label: dict[str, int] = {}
    for m in misses:
        by_label[m["label"]] = by_label.get(m["label"], 0) + 1
    print(f"  by label: {by_label}")

    print(f"\nFalse positives ({len(fps)}):")
    for f in fps:
        print(
            f"  {f['case_id']:9s} kind={f['kind']:11s} cat={f['category']:24s} → {f['label']}"
        )
    fp_by_label: dict[str, int] = {}
    for f in fps:
        fp_by_label[f["label"]] = fp_by_label.get(f["label"], 0) + 1
    print(f"  by label: {fp_by_label}")


if __name__ == "__main__":
    main()
