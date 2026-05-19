# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
SecPriv evaluation harness.

Runs one configuration of (skill methodology, model) over all 34 cases in the
ground truth, parses each model output as JSON, normalizes categories via the
alias table, matches against ground truth using category + line-proximity
(±10 lines), and writes per-run results plus a summary.

Usage:
    python3 evaluate.py --config secpriv_sonnet
    python3 evaluate.py --config no_skill_sonnet
    python3 evaluate.py --config secpriv_haiku
    python3 evaluate.py --config detector_only_sonnet
    python3 evaluate.py --config two_skill_sonnet

The --runs flag controls how many independent invocations per case (default 1).
The --max-cases flag limits the run for smoke tests.

Skill prompt files are read from ../*.md (parent directory of experiment/).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # experiment/
PAPER_ROOT = ROOT.parent  # secpriv_eval/
RESULTS_DIR = ROOT / "results"
ALIASES_PATH = Path(__file__).resolve().parent / "aliases.json"
GT_PATH = ROOT / "ground_truth.json"

# Per-skill methodology files in PAPER_ROOT.
UNIFIED_SKILL = PAPER_ROOT / "SKILL.md"
SECREVIEW_SKILL = PAPER_ROOT.parent / "secreview_eval" / "SKILL.md"
PRIVREVIEW_SKILL = PAPER_ROOT.parent / "privreview_eval" / "SKILL.md"

LINE_TOLERANCE = 10
DEFAULT_TIMEOUT = 600  # seconds
MIN_CONFIDENCE = 0.8


# ============================================================
# Configurations
# ============================================================


@dataclass
class Config:
    name: str
    model: str  # claude --model alias: "sonnet" or "haiku"
    skill_paths: list[Path]  # one or more SKILL.md files concatenated
    minimal_prompt: bool = False  # True = no skill, just minimal "review this" prompt


def load_config(name: str) -> Config:
    if name == "secpriv_sonnet":
        return Config(name, "sonnet", [UNIFIED_SKILL])
    if name == "secpriv_haiku":
        return Config(name, "haiku", [UNIFIED_SKILL])
    if name == "no_skill_sonnet":
        return Config(name, "sonnet", [], minimal_prompt=True)
    if name == "two_skill_sonnet":
        # SecReview + PrivReview run separately, results unioned.  Implemented by
        # running two passes per case (see run_case below).
        return Config(name, "sonnet", [SECREVIEW_SKILL, PRIVREVIEW_SKILL])
    if name == "detector_only_sonnet":
        # Phases 1-3 only — no validator/suppression.  Implemented by
        # appending an instruction that disables Phase 4.
        return Config(name, "sonnet", [UNIFIED_SKILL])
    raise ValueError(f"unknown config: {name}")


MINIMAL_PROMPT = (
    "You are a code reviewer. Examine the provided code file for SECURITY weaknesses "
    "and PRIVACY violations. Return a JSON array of findings. Each finding must have "
    "fields: surface (security|privacy), category, severity (HIGH|MEDIUM|LOW), "
    "confidence (0.0-1.0), file, line, description. Return only the JSON array; no "
    "prose. If nothing is wrong, return []."
)

DETECTOR_ONLY_SUFFIX = (
    "\n\n## OVERRIDE: Skip Phase 4 (validator) and Phase 5 (mapping). Emit ALL "
    "candidate findings from Phase 3 with confidence >= 0.5. Do NOT apply any "
    "suppression rules."
)

USER_TEMPLATE = (
    "Review the following file for security and privacy issues. Return a JSON "
    "array per the instructions.\n\n"
    "FILE: {fname}\n\n"
    "```python\n{code}\n```\n"
)


def build_system_prompt(cfg: Config) -> str:
    if cfg.minimal_prompt:
        return MINIMAL_PROMPT
    pieces = [p.read_text() for p in cfg.skill_paths]
    text = "\n\n---\n\n".join(pieces)
    if cfg.name == "detector_only_sonnet":
        text = text + DETECTOR_ONLY_SUFFIX
    return text


# ============================================================
# Model invocation
# ============================================================


def _strip_codefence(s: str) -> str:
    s = s.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```$", "", s)
    return s


def _extract_json_array(s: str) -> list[dict] | None:
    """Find the first JSON array in s.  Returns None on failure."""
    s = _strip_codefence(s)
    # Greedy match the outermost [...] block.
    m = re.search(r"\[(?:.|\n)*\]", s)
    if not m:
        # Sometimes the model returns just `[]` or a stray scalar.
        try:
            v = json.loads(s)
            return v if isinstance(v, list) else None
        except json.JSONDecodeError:
            return None
    candidate = m.group(0)
    try:
        v = json.loads(candidate)
        return v if isinstance(v, list) else None
    except json.JSONDecodeError:
        return None


def invoke_model(
    system_prompt: str,
    user_prompt: str,
    model: str,
    timeout: int = DEFAULT_TIMEOUT,
    max_retries: int = 3,
) -> tuple[str | None, dict]:
    """Calls `claude -p` with the given prompts.  Returns (raw_output, meta).

    Retries up to max_retries times if the output is empty (transient API issue).
    meta contains: latency_s, returncode, stderr (truncated), retries."""
    cmd = [
        "claude",
        "-p",
        "--bare",
        "--model",
        model,
        "--append-system-prompt",
        system_prompt,
        "--output-format",
        "text",
        user_prompt,
    ]
    for attempt in range(max_retries):
        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            latency = time.time() - t0
            stdout = proc.stdout or ""
            if len(stdout.strip()) > 0:
                return stdout, {
                    "latency_s": round(latency, 2),
                    "returncode": proc.returncode,
                    "stderr": (proc.stderr or "")[-500:],
                    "retries": attempt,
                }
            if attempt < max_retries - 1:
                time.sleep(5 * (attempt + 1))
                continue
            return stdout, {
                "latency_s": round(latency, 2),
                "returncode": proc.returncode,
                "stderr": (proc.stderr or "")[-500:],
                "retries": attempt,
                "empty_output": True,
            }
        except subprocess.TimeoutExpired:
            if attempt < max_retries - 1:
                time.sleep(5)
                continue
            return None, {
                "latency_s": timeout,
                "returncode": -1,
                "stderr": "TIMEOUT",
                "retries": attempt,
            }
        except Exception as e:
            return None, {
                "latency_s": round(time.time() - t0, 2),
                "returncode": -2,
                "stderr": str(e)[:500],
                "retries": attempt,
            }


# ============================================================
# Output parsing & matching
# ============================================================


def _load_aliases() -> dict[str, str]:
    raw = json.loads(ALIASES_PATH.read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def normalize_findings(findings: list[dict], aliases: dict[str, str]) -> list[dict]:
    out: list[dict] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        cat = str(f.get("category", "")).strip().lower()
        cat = aliases.get(cat, cat)
        try:
            line = int(f.get("line", 0))
        except (TypeError, ValueError):
            line = 0
        try:
            conf = float(f.get("confidence", 1.0))
        except (TypeError, ValueError):
            conf = 1.0
        if conf < MIN_CONFIDENCE:
            continue
        surface = str(f.get("surface", "")).strip().lower()
        out.append(
            {
                "surface": surface,
                "category": cat,
                "line": line,
                "confidence": conf,
                "severity": str(f.get("severity", "")).upper(),
            }
        )
    return out


def match_case(emitted: list[dict], expected: list[dict]) -> dict:
    """Return per-case TP/FP/FN counts and the matched / unmatched lists."""
    matched_expected_indices: set[int] = set()
    matched_emitted_indices: set[int] = set()

    # For each emitted finding, find a not-yet-matched expected finding.
    for ei, ef in enumerate(emitted):
        for xi, xf in enumerate(expected):
            if xi in matched_expected_indices:
                continue
            if ef["category"] != xf["category"]:
                continue
            if abs(ef["line"] - int(xf["line"])) > LINE_TOLERANCE:
                continue
            matched_expected_indices.add(xi)
            matched_emitted_indices.add(ei)
            break

    tp = len(matched_expected_indices)
    fp = len(emitted) - len(matched_emitted_indices)
    fn = len(expected) - tp

    unmatched_emitted = [
        emitted[i] for i in range(len(emitted)) if i not in matched_emitted_indices
    ]
    unmatched_expected = [
        expected[i] for i in range(len(expected)) if i not in matched_expected_indices
    ]

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn_case_pass": (len(expected) == 0 and len(emitted) == 0),
        "unmatched_emitted": unmatched_emitted,
        "unmatched_expected": unmatched_expected,
    }


# ============================================================
# Per-case execution
# ============================================================


@dataclass
class CaseResult:
    case_id: str
    file: str
    kind: str
    emitted: list[dict] = field(default_factory=list)
    raw_output: str = ""
    parse_ok: bool = False
    match: dict = field(default_factory=dict)
    meta: dict = field(default_factory=dict)


def run_case(
    cfg: Config, system_prompt: str, case: dict, aliases: dict[str, str]
) -> CaseResult:
    code_path = ROOT / case["file"]
    code = code_path.read_text()
    user_prompt = USER_TEMPLATE.format(fname=case["file"], code=code)

    if cfg.name == "two_skill_sonnet":
        # Run security skill, then privacy skill, then union.
        results: list[dict] = []
        meta: dict = {"sub_calls": []}
        for skill_path in cfg.skill_paths:
            sub_system = skill_path.read_text()
            raw, m = invoke_model(sub_system, user_prompt, cfg.model)
            meta["sub_calls"].append({"skill": skill_path.name, "meta": m})
            if raw is None:
                continue
            arr = _extract_json_array(raw)
            if arr:
                results.extend(arr)
        norm = normalize_findings(results, aliases)
        match = match_case(norm, case["expected_findings"])
        return CaseResult(
            case_id=case["case_id"],
            file=case["file"],
            kind=case["kind"],
            emitted=norm,
            raw_output="<two_skill: see meta.sub_calls>",
            parse_ok=True,
            match=match,
            meta=meta,
        )

    raw, meta = invoke_model(system_prompt, user_prompt, cfg.model)
    if raw is None:
        return CaseResult(
            case_id=case["case_id"],
            file=case["file"],
            kind=case["kind"],
            raw_output="",
            parse_ok=False,
            match=match_case([], case["expected_findings"]),
            meta=meta,
        )
    arr = _extract_json_array(raw)
    parse_ok = arr is not None
    norm = normalize_findings(arr or [], aliases)
    match = match_case(norm, case["expected_findings"])
    return CaseResult(
        case_id=case["case_id"],
        file=case["file"],
        kind=case["kind"],
        emitted=norm,
        raw_output=raw[:4000],
        parse_ok=parse_ok,
        match=match,
        meta=meta,
    )


# ============================================================
# Aggregate
# ============================================================


def summarize(results: list[CaseResult]) -> dict:
    tp = sum(r.match["tp"] for r in results)
    fp = sum(r.match["fp"] for r in results)
    fn = sum(r.match["fn"] for r in results)
    tn_total = sum(
        1
        for r in results
        if not r.match.get("unmatched_expected") and r.kind.endswith("_tn")
    )
    tn_pass = sum(
        1 for r in results if r.match.get("tn_case_pass") and r.kind.endswith("_tn")
    )
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    parse_failures = sum(1 for r in results if not r.parse_ok)
    mean_latency = sum(r.meta.get("latency_s", 0) or 0 for r in results) / max(
        1, len(results)
    )

    # Per-category recall (over all expected findings).
    cat_expected: dict[str, int] = {}
    for r in results:
        for ef in r.match.get("unmatched_expected", []) or []:
            cat_expected[ef["category"]] = cat_expected.get(ef["category"], 0) + 1
    # Caught = total expected per category - missed per category, but we need totals from GT.
    # Simpler: walk results' expected lists from match data.  We tracked unmatched_expected
    # as missed; we need total per category.  Recompute here by re-walking results.

    return {
        "n_cases": len(results),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tn_cases": tn_total,
        "tn_pass": tn_pass,
        "tn_rate": round(tn_pass / tn_total, 4) if tn_total else None,
        "parse_failures": parse_failures,
        "mean_latency_s": round(mean_latency, 2),
    }


def per_category(results: list[CaseResult], gt_cases: list[dict]) -> dict:
    """Per-category recall computed against ground truth totals."""
    expected_per_cat: dict[str, int] = {}
    for c in gt_cases:
        for ef in c["expected_findings"]:
            expected_per_cat[ef["category"]] = (
                expected_per_cat.get(ef["category"], 0) + 1
            )

    missed_per_cat: dict[str, int] = {}
    for r in results:
        for ef in r.match.get("unmatched_expected", []):
            missed_per_cat[ef["category"]] = missed_per_cat.get(ef["category"], 0) + 1

    out = {}
    for cat, total in sorted(expected_per_cat.items()):
        missed = missed_per_cat.get(cat, 0)
        caught = total - missed
        out[cat] = {
            "expected": total,
            "caught": caught,
            "missed": missed,
            "recall": round(caught / total, 4) if total else None,
        }
    return out


# ============================================================
# Main
# ============================================================


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--config",
        required=True,
        choices=[
            "secpriv_sonnet",
            "secpriv_haiku",
            "no_skill_sonnet",
            "two_skill_sonnet",
            "detector_only_sonnet",
        ],
    )
    ap.add_argument("--run-id", default="run1", help="Run label, e.g. run1, run2")
    ap.add_argument(
        "--max-cases", type=int, default=0, help="Smoke-test limit (0 = all)"
    )
    ap.add_argument(
        "--only-kind",
        default=None,
        help="Limit to one kind (e.g. security_tp, privacy_tn, cross_tp)",
    )
    ap.add_argument(
        "--only-tn",
        action="store_true",
        help="Limit to all TN cases (security_tn + privacy_tn + cross_tn)",
    )
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    args = ap.parse_args()

    cfg = load_config(args.config)
    aliases = _load_aliases()
    gt = json.loads(GT_PATH.read_text())
    cases = gt["cases"]
    if args.only_tn:
        cases = [c for c in cases if c["kind"].endswith("_tn")]
    elif args.only_kind:
        cases = [c for c in cases if c["kind"] == args.only_kind]
    if args.max_cases:
        cases = cases[: args.max_cases]

    system_prompt = build_system_prompt(cfg)

    out_dir = RESULTS_DIR / cfg.name
    out_dir.mkdir(parents=True, exist_ok=True)

    print(
        f"[{cfg.name} / {args.run_id}] {len(cases)} cases, model={cfg.model}",
        flush=True,
    )
    results: list[CaseResult] = []
    t0 = time.time()
    for i, case in enumerate(cases, 1):
        r = run_case(cfg, system_prompt, case, aliases)
        results.append(r)
        marker = "ok " if r.parse_ok else "FAIL"
        print(
            f"  [{i:2d}/{len(cases)}] {r.case_id:9s} kind={r.kind:11s} "
            f"emitted={len(r.emitted):2d} tp={r.match['tp']} fp={r.match['fp']} fn={r.match['fn']} "
            f"latency={r.meta.get('latency_s', 0):5.1f}s parse={marker}",
            flush=True,
        )

    elapsed = time.time() - t0
    summary = summarize(results)
    pcat = per_category(results, gt["cases"])
    summary["wall_time_s"] = round(elapsed, 1)

    out_path = out_dir / f"{args.run_id}.json"
    out_path.write_text(
        json.dumps(
            {
                "config": cfg.name,
                "model": cfg.model,
                "run_id": args.run_id,
                "summary": summary,
                "per_category": pcat,
                "cases": [asdict(r) for r in results],
            },
            indent=2,
        )
    )

    print(f"\n[{cfg.name} / {args.run_id}] DONE in {elapsed:.0f}s")
    print(
        f"  precision={summary['precision']:.3f} recall={summary['recall']:.3f} "
        f"f1={summary['f1']:.3f}"
    )
    print(
        f"  TN={summary['tn_pass']}/{summary['tn_cases']}  parse_failures={summary['parse_failures']}"
    )
    print(f"  written to {out_path}")


if __name__ == "__main__":
    main()
