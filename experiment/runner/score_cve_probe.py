# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

"""Tiered scorer for the real-CVE probe (D3).

Whole-file "TN = clean" and exact category+line matching are meaningless on real
code (real files carry many latent issues, and the advisory CWE may not be the
single label the model chooses). We therefore report the field-standard pair of
signals used in vuln-detection work -- detection (recall on the known CVE) and
clearance (the finding moves with the fix) -- at three granularities:

  Tier 1 (file-level):  a finding whose category is in the CVE's *family* appears
                        anywhere in a patched file.               (loosest)
  Tier 2 (localized):   such a finding within +/-K lines of the vulnerable region
                        (deleted/replaced hunk lines, OR -- for insertion-only
                        fixes that merely ADD a guard -- the pre-file lines that
                        bracket the insertion point).
  Tier 3 (strict):      exact advisory category within +/-K of the deleted hunk
                        (the original, over-strict metric; kept for comparison).

Clearance (post): of the localized detections, how many disappear at the patched
region in the fixed file. Changed line ranges come from difflib-ing the stored
pre/post files. Stdlib-only.

The category *family* map absorbs defensible neighbours (e.g. the model calling a
missing-URL-validation SSRF "open_redirect", or an object-fetch path-traversal
that is co-listed CWE-918 "ssrf"). It is deliberately conservative; the
hand-adjudicated verdicts in probe_cve_adjudication (see D3 docs) are the
authority for N=15 and are stricter than Tier 1 on two cases.
"""

from __future__ import annotations

import difflib
import json
import sys
from pathlib import Path

RUNNER = Path(__file__).resolve().parent
EXPERIMENT = RUNNER.parent
sys.path.insert(0, str(RUNNER))
import evaluate as E  # noqa: E402

K = 10  # line tolerance

# expected advisory category -> set of model categories accepted as the same vuln
FAMILY: dict[str, set[str]] = {
    "path_traversal": {"path_traversal", "xxe", "open_redirect", "ssrf"},
    "command_injection": {
        "command_injection",
        "eval_injection",
        "deserialization",
    },
    "xss": {"xss", "xss_dom", "ssti"},
    "xxe": {"xxe", "ssrf"},
    "ssrf": {"ssrf", "open_redirect"},
    "auth_bypass": {"auth_bypass", "csrf", "agent_csrf"},
    "sql_injection": {"sql_injection", "second_order_sqli"},
    "open_redirect": {"open_redirect", "ssrf"},
    "crypto_misuse": {"crypto_misuse", "hardcoded_secret", "insecure_storage"},
}


def _accepts(expected: str) -> set[str]:
    return FAMILY.get(expected, {expected})


# Keyword -> canonical, applied to EVERY run's category strings so a baseline
# that writes free-form English ("Path Traversal", "XXE Injection") is credited
# the same as SecPriv's structured labels. Fairness fix (reviewer D2, reversed):
# SecPriv already emits canonical categories, so this is a no-op on its output;
# it only rescues baselines that don't use the taxonomy. Order matters (first
# substring hit wins); the 30 canonical names are recognized as themselves.
_KEYWORDS: list[tuple[str, str]] = [
    ("second order", "second_order_sqli"),
    ("sql inj", "sql_injection"),
    ("command inj", "command_injection"),
    ("os command", "command_injection"),
    ("child_process", "command_injection"),
    ("eval inj", "eval_injection"),
    ("code inj", "eval_injection"),
    ("deserial", "deserialization"),
    ("dom", "xss_dom"),
    ("cross-site scripting", "xss"),
    ("cross site scripting", "xss"),
    ("xss", "xss"),
    ("template inj", "ssti"),
    ("ssti", "ssti"),
    ("xml external", "xxe"),
    ("xxe", "xxe"),
    ("server-side request", "ssrf"),
    ("server side request", "ssrf"),
    ("ssrf", "ssrf"),
    ("open redirect", "open_redirect"),
    ("path travers", "path_traversal"),
    ("directory travers", "path_traversal"),
    ("arbitrary file", "path_traversal"),
    ("local file inclusion", "path_traversal"),
    ("csrf", "csrf"),
    ("cross-site request", "csrf"),
    ("idor", "auth_bypass"),
    ("insecure direct object", "auth_bypass"),
    ("broken access", "auth_bypass"),
    ("access control", "auth_bypass"),
    ("missing authoriz", "auth_bypass"),
    ("improper authoriz", "auth_bypass"),
    ("missing authentic", "auth_bypass"),
    ("authoriz", "auth_bypass"),
    ("authentic", "auth_bypass"),
    ("auth bypass", "auth_bypass"),
    ("privilege", "auth_bypass"),
    ("hardcoded", "hardcoded_secret"),
    ("hard-coded", "hardcoded_secret"),
    ("secret", "hardcoded_secret"),
    ("credential", "hardcoded_secret"),
    ("weak hash", "crypto_misuse"),
    ("weak crypto", "crypto_misuse"),
    ("insecure random", "crypto_misuse"),
    ("insufficient random", "crypto_misuse"),
    ("crypto", "crypto_misuse"),
    ("toctou", "race_condition"),
    ("race condition", "race_condition"),
    ("logging", "insecure_logging"),
    ("sensitive data in log", "insecure_logging"),
]


def _canon(cat: str, canonical: set[str]) -> str:
    """Map a free-form category to canonical; no-op if already canonical."""
    c = (cat or "").strip().lower().replace(" ", "_")
    if c in canonical:
        return c
    low = (cat or "").lower()
    for kw, canon in _KEYWORDS:
        if kw in low:
            return canon
    return c


def _regions(pre_path: Path, post_path: Path) -> tuple[set[int], set[int], set[int]]:
    """Return (deleted_pre_lines, post_changed_lines, insertion_anchor_pre_lines)."""
    pre = pre_path.read_text().splitlines()
    post = post_path.read_text().splitlines()
    sm = difflib.SequenceMatcher(None, pre, post, autojunk=False)
    deleted: set[int] = set()
    post_lines: set[int] = set()
    anchors: set[int] = set()
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "delete"):
            deleted.update(range(i1 + 1, i2 + 1))
        if tag in ("replace", "insert"):
            post_lines.update(range(j1 + 1, j2 + 1))
        if tag == "insert":
            # a guard was added between pre lines i1 and i1+1: both bracket the vuln
            anchors.update({max(i1, 1), i1 + 1})
    return deleted, post_lines, anchors


def _near(line: int, targets: set[int]) -> bool:
    return bool(targets) and any(abs(line - t) <= K for t in targets)


def _results_path(run: str) -> Path:
    """Find the run's results JSON under any config dir (haiku, sonnet, ...)."""
    for cfg_dir in sorted((EXPERIMENT / "results").glob("*")):
        p = cfg_dir / f"{run}.json"
        if p.exists():
            return p
    raise FileNotFoundError(f"no results/*/{run}.json found")


def _score_case(
    pre: dict,
    emit_pre: list[dict],
    emit_post: list[dict],
    fam: set[str],
    exp: str,
) -> tuple[bool, bool, bool, bool]:
    """Score one (possibly multi-file) CVE case.

    Returns (d1_file, d2_localized, d3_strict, cleared). Clearance is case-wide:
    it holds only when EVERY file with a localized pre-fix detection has no
    localized post-fix finding; a case with no localized detection is not
    counted as cleared.
    """
    d1 = d2 = d3 = False
    loc_files = cleared_files = 0
    for rel in pre["files"]:
        base = Path(rel).name.lower()
        deleted, post_lines, anchors = _regions(
            EXPERIMENT / rel, EXPERIMENT / rel.replace("/pre/", "/post/")
        )
        vuln = deleted | anchors
        in_file = [f for f in emit_pre if f["file"] == base]
        fam_hits = [f for f in in_file if f["category"] in fam]
        loc_hits = [f for f in fam_hits if _near(f["line"], vuln)]
        strict = [
            f for f in in_file if f["category"] == exp and _near(f["line"], deleted)
        ]
        if fam_hits:
            d1 = True
        if loc_hits:
            d2 = True
            loc_files += 1
            post_hits = [
                f
                for f in emit_post
                if f["file"] == base
                and f["category"] in fam
                and _near(f["line"], post_lines | vuln)
            ]
            if not post_hits:
                cleared_files += 1
        if strict:
            d3 = True
    clr = loc_files > 0 and cleared_files == loc_files
    return d1, d2, d3, clr


def main() -> None:
    run = sys.argv[1] if len(sys.argv) > 1 else "cve_haiku"
    aliases = E._load_aliases()
    gt = {
        c["case_id"]: c
        for c in json.loads((EXPERIMENT / "ground_truth_cve.json").read_text())["cases"]
    }
    res = {c["case_id"]: c for c in json.loads(_results_path(run).read_text())["cases"]}

    canonical = set(aliases.values())

    def _emit(case_id: str) -> list[dict]:
        fs = E.normalize_findings(
            E._extract_json_array(res[case_id].get("raw_output", "")) or [], aliases
        )
        for f in fs:
            f["category"] = _canon(f["category"], canonical)
        return fs

    pre_cases = [c for c in gt.values() if c["kind"] == "security_tp"]
    t1 = t2 = t3 = cleared = 0
    total_findings = 0
    rows = []
    for pre in pre_cases:
        cid = pre["case_id"]
        post_id = cid[:-4] + "-post"
        exp = (
            pre["expected_findings"][0]["category"] if pre["expected_findings"] else ""
        )
        fam = _accepts(exp)
        emit_pre = _emit(cid)
        emit_post = _emit(post_id)
        total_findings += len(emit_pre)
        d1, d2, d3, clr = _score_case(pre, emit_pre, emit_post, fam, exp)
        t1 += d1
        t2 += d2
        t3 += d3
        cleared += clr
        rows.append((cid.split("-", 2)[1], exp, d1, d2, d3, clr))

    n = len(pre_cases)
    if n == 0:
        print(f"Real-CVE probe ({run}) — no CVE cases to score")
        return
    print(f"Real-CVE probe ({run}) — {n} CVEs, K=+/-{K} lines, family-aware\n")
    print(f"  Tier 1  file-level detection (family, anywhere): {t1}/{n} = {t1 / n:.2f}")
    print(
        f"  Tier 2  localized detection (family, +/-{K}, incl. insertion): {t2}/{n} = {t2 / n:.2f}"
    )
    print(f"  Tier 3  strict (exact category @ deleted hunk):  {t3}/{n} = {t3 / n:.2f}")
    print(f"  clearance (localized finding gone after fix):    {cleared}/{t2 or 1}")
    print(
        f"  mean findings emitted per vulnerable file set:   {total_findings / n:.1f}"
    )
    print("\n  per case (cve, expected, T1_file, T2_loc, T3_strict, cleared):")
    for cve, exp, d1, d2, d3, clr in rows:
        print(
            f"    {cve:20s} {exp:18s} T1={int(d1)} T2={int(d2)} T3={int(d3)} clr={int(clr)}"
        )


if __name__ == "__main__":
    main()
