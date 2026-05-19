"""
SecPriv benchmark generator.

Writes the canonical 128-case benchmark used by the paper. The 34 cases
inherited from earlier benchmark iterations are kept under their original
filenames; the remaining 94 cases are authored here.

Layout:
  Security: 20 categories x 3 variants = 60 TPs
            15 near-miss TNs (10 calibration + 5 held-out)
  Privacy:  10 categories x 3 variants = 30 TPs
            15 near-miss TNs (10 calibration + 5 held-out)
  Cross:    3 TP + 5 TN = 8

The script is split into three sub-modules (_generate_sec.py,
_generate_priv.py, _generate_cross.py) so each file stays readable.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from _generate_cross import build_cross
from _generate_priv import build_privacy
from _generate_sec import build_security

ROOT = Path(__file__).resolve().parent.parent
TC = ROOT / "test_cases"
GT_PATH = ROOT / "ground_truth.json"


def add_case(
    cases: list[dict],
    case_id: str,
    subdir: str,
    filename: str,
    body: str,
    kind: str,
    expected: list[dict],
    boundary: str | None = None,
    holdout: bool = False,
    inherited: bool = False,
    acceptable: list[dict] | None = None,
) -> None:
    """Adds a case to the manifest. Writes the file unless inherited=True."""
    path = TC / subdir / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    if not inherited:
        body = textwrap.dedent(body).lstrip("\n")
        path.write_text(body)
    rec = {
        "case_id": case_id,
        "file": str(path.relative_to(ROOT)),
        "kind": kind,
        "expected_findings": expected,
    }
    if boundary:
        rec["boundary"] = boundary
    if holdout:
        rec["holdout"] = True
    if inherited:
        rec["inherited"] = True
    if acceptable:
        rec["acceptable_findings"] = acceptable
    cases.append(rec)


def main() -> None:
    cases: list[dict] = []
    build_security(cases, add_case)
    build_privacy(cases, add_case)
    build_cross(cases, add_case)

    gt = {
        "schema_version": "1.0",
        "description": "SecPriv combined benchmark — 128 cases.",
        "cases": cases,
        "canonical_categories": [
            # 20 security
            "sql_injection",
            "command_injection",
            "path_traversal",
            "xss",
            "xss_dom",
            "auth_bypass",
            "hardcoded_secret",
            "deserialization",
            "eval_injection",
            "infinite_loop",
            "agent_csrf",
            "second_order_sqli",
            "ssrf",
            "open_redirect",
            "crypto_misuse",
            "xxe",
            "ssti",
            "csrf",
            "race_condition",
            "insecure_logging",
            # 10 privacy
            "pii_leakage",
            "data_retention",
            "consent_bypass",
            "third_party_sharing",
            "re_identification_risk",
            "data_minimization",
            "purpose_creep",
            "insecure_storage",
            "cross_border_transfer",
            "right_to_erasure",
        ],
    }
    GT_PATH.write_text(json.dumps(gt, indent=2) + "\n")

    counts: dict[str, int] = {}
    holdout_counts: dict[str, int] = {}
    inherited_count = 0
    for c in cases:
        counts[c["kind"]] = counts.get(c["kind"], 0) + 1
        if c.get("holdout"):
            holdout_counts[c["kind"]] = holdout_counts.get(c["kind"], 0) + 1
        if c.get("inherited"):
            inherited_count += 1
    print(
        f"Wrote {len(cases)} cases ({inherited_count} inherited, {len(cases) - inherited_count} new):"
    )
    for k in sorted(counts):
        ho = holdout_counts.get(k, 0)
        ho_str = f" (holdout: {ho})" if ho else ""
        print(f"  {k}: {counts[k]}{ho_str}")
    print(f"Ground truth: {GT_PATH}")


if __name__ == "__main__":
    main()
