"""
Re-scores existing per-run results against TWO ground-truth definitions:
- STRICT:    a finding matches only if it lines up with an `expected_findings` entry
- PERMISSIVE: a finding matches if it lines up with `expected_findings` OR
              `acceptable_findings` (multi-label ground truth).

Reads each results/<config>/run*.json, recomputes match.tp/fp/fn under both
definitions using the same alias table and ±10-line proximity, and writes
results/rescored.json with the rescored summaries.

Usage:
    python3 rescore.py
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
GT_PATH = ROOT / "ground_truth.json"
ALIASES_PATH = Path(__file__).resolve().parent / "aliases.json"

LINE_TOLERANCE = 10
MIN_CONFIDENCE = 0.8


def _load_aliases() -> dict[str, str]:
    raw = json.loads(ALIASES_PATH.read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def _normalize(emitted: list[dict], aliases: dict[str, str]) -> list[dict]:
    out = []
    for f in emitted:
        cat = aliases.get(
            f.get("category", "").strip().lower(), f.get("category", "").strip().lower()
        )
        try:
            line = int(f.get("line", 0))
        except (TypeError, ValueError):
            line = 0
        out.append(
            {"category": cat, "surface": f.get("surface", "").lower(), "line": line}
        )
    return out


def _match(emitted: list[dict], targets: list[dict]) -> tuple[int, int, int]:
    matched_t = set()
    matched_e = set()
    for ei, ef in enumerate(emitted):
        for ti, tf in enumerate(targets):
            if ti in matched_t:
                continue
            if ef["category"] != tf["category"]:
                continue
            if abs(ef["line"] - int(tf["line"])) > LINE_TOLERANCE:
                continue
            matched_t.add(ti)
            matched_e.add(ei)
            break
    tp = len(matched_t)
    fp = len(emitted) - len(matched_e)
    fn = len(targets) - tp
    return tp, fp, fn


def _summarize(per_case: list[dict]) -> dict:
    tp = sum(c["tp"] for c in per_case)
    fp = sum(c["fp"] for c in per_case)
    fn = sum(c["fn"] for c in per_case)
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(f1, 4),
    }


def main() -> None:  # noqa: C901
    aliases = _load_aliases()
    gt = {c["case_id"]: c for c in json.loads(GT_PATH.read_text())["cases"]}

    out: dict = {"strict": {}, "permissive": {}}
    for cfg_dir in sorted(RESULTS.iterdir()):
        if not cfg_dir.is_dir():
            continue
        for rp in sorted(cfg_dir.glob("run*.json")):
            data = json.loads(rp.read_text())
            cfg = data["config"]
            run = data["run_id"]
            strict_cases = []
            perm_cases = []
            for c in data["cases"]:
                emitted = c["emitted"]
                gtc = gt.get(c["case_id"], {})
                expected = gtc.get("expected_findings", [])
                acceptable = gtc.get("acceptable_findings", [])
                # Strict: targets = expected.  FP = anything not matching expected.
                stp, sfp, sfn = _match(emitted, expected)
                strict_cases.append({"tp": stp, "fp": sfp, "fn": sfn})
                # Permissive: a finding matches if it hits expected OR acceptable.
                # We compute: targets_perm = expected.  Then any leftover emitted
                # that match an acceptable target are not counted as FP.
                # Easiest: match against expected first, then for each leftover
                # emitted finding, see if it matches an acceptable.
                ptp, pfp, pfn = stp, sfp, sfn
                if acceptable and emitted:
                    # Identify which emitted findings were matched by strict pass.
                    matched_e = set()
                    for ei, ef in enumerate(emitted):
                        norm = {
                            "category": aliases.get(
                                ef.get("category", "").lower(),
                                ef.get("category", "").lower(),
                            ),
                            "surface": ef.get("surface", "").lower(),
                            "line": int(ef.get("line", 0) or 0),
                        }
                        for _ti, tf in enumerate(expected):
                            if (
                                norm["category"] == tf["category"]
                                and abs(norm["line"] - int(tf["line"]))
                                <= LINE_TOLERANCE
                            ):
                                matched_e.add(ei)
                                break
                    # For each unmatched emitted, check acceptable.
                    saved_fp = 0
                    matched_acc = set()
                    for ei in range(len(emitted)):
                        if ei in matched_e:
                            continue
                        ef = emitted[ei]
                        cat = ef.get("category", "").lower()
                        cat = aliases.get(cat, cat)
                        try:
                            line = int(ef.get("line", 0) or 0)
                        except (TypeError, ValueError):
                            line = 0
                        for ai, af in enumerate(acceptable):
                            if ai in matched_acc:
                                continue
                            if cat != af["category"]:
                                continue
                            if abs(line - int(af["line"])) > LINE_TOLERANCE:
                                continue
                            matched_acc.add(ai)
                            saved_fp += 1
                            break
                    pfp = max(0, sfp - saved_fp)
                perm_cases.append({"tp": ptp, "fp": pfp, "fn": pfn})

            out["strict"].setdefault(cfg, {})[run] = _summarize(strict_cases)
            out["permissive"].setdefault(cfg, {})[run] = _summarize(perm_cases)

    (RESULTS / "rescored.json").write_text(json.dumps(out, indent=2) + "\n")

    # Print comparison
    print("\n" + "=" * 78)
    print(f"{'Configuration':<28} {'Mode':<11} {'Prec':>7} {'Rec':>7} {'F1':>7}")
    print("-" * 78)
    for cfg in sorted(out["strict"]):
        for run in sorted(out["strict"][cfg]):
            for mode in ["strict", "permissive"]:
                s = out[mode][cfg][run]
                print(
                    f"{cfg + '/' + run:<28} {mode:<11} {s['precision']:>7.3f} {s['recall']:>7.3f} {s['f1']:>7.3f}"
                )
        print()
    print("=" * 78)


if __name__ == "__main__":
    main()
